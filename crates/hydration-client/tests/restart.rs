//! The framework against its own death: kill the client mid-operation, start a
//! fresh one over the same directory, and prove the recovery is fail-closed.
//!
//! The client restarts amnesiac, by design. There is no cursor file, no upload
//! journal, no in-flight record: the delta cursor is a process-local variable,
//! the upload queue is a `HashMap` that dies with the process, and the durable
//! position lives inside the *provider's* store. What the client has instead is
//! a recovery sequence — sweep the scratch names, rescan the directory, requeue
//! what the stamps say was never sent — and the claim that sequence makes is
//! the subject of this file: **a restart at any moment costs at most one
//! redundant transfer, and never loses content or serves the wrong bytes.**
//!
//! The provider half of that claim — the cursor never advances past unapplied
//! changes, a crash between the tree and token writes is survivable — is pinned
//! by `hydration-graph/tests/discover.rs`. The per-decision rules of the rescan
//! walk are unit tests beside `dirty_files`. What neither covers, and this file
//! does, is the client-side sequence end to end: the states a kill actually
//! leaves on disk, fed to a fresh `Store`, `TmpfilePlacer` and `run_upload`
//! exactly the way `daemon_loop::run` feeds them at startup.
//!
//! No process is really killed here. A kill's entire legacy is the on-disk
//! state at the moment it landed — memory is gone, and nothing here fsyncs
//! late enough to matter — so each test *constructs* that state, from the write
//! order the shipping code is known to follow, and then runs the restart
//! sequence over it. What a real `SIGKILL` adds is covered elsewhere: the
//! privileged suites kill a live worker (`fail_closed.rs`), and the reference
//! adapter kills a real hydration client under the conformance run.

use hydration_client::delta::{apply, Applied, Change};
use hydration_client::place::TmpfilePlacer;
use hydration_client::store::{self, Store};
use hydration_client::upload::{run_upload, Outcome, Sink, Uploaded};
use hydration_protocol::{stamp, FileId};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

fn scratch(name: &str) -> PathBuf {
    // `HYDRATION_TEST_DIR` overrides this at run time, so the suite can be
    // pointed at a btrfs, ext4 or xfs mount without rebuilding.
    test_scratch::scratch(env!("CARGO_TARGET_TMPDIR"), &format!("restart/{name}"))
}

fn file_id(p: &Path) -> FileId {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(p).expect("stat");
    FileId {
        fsid: md.dev(),
        ino: md.ino(),
    }
}

/// Move a file's mtime to a fixed, distant instant.
///
/// Not decoration — the same reasoning as the `dirty_files` unit tests: the
/// kernel stamps mtime from a coarse clock, so a write microseconds after
/// `stamp::write` can land on the same nanosecond and read `Clean`. A test
/// built that way asserts nothing, because the state it claims to set up never
/// existed. Every state constructed here moves the mtime explicitly and then
/// asserts the stamp state it meant to create.
fn set_mtime(path: &Path, secs: u64) {
    let f = std::fs::OpenOptions::new().append(true).open(path).unwrap();
    f.set_times(
        std::fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(secs)),
    )
    .unwrap();
}

/// A file that has been through the framework and is currently clean —
/// content, identity, stamp — as `hostile_cloud.rs` builds one.
fn synced(dir: &Path, rel: &str, body: &[u8], cloud_id: &str, etag: &str) -> PathBuf {
    let p = dir.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&p, body).unwrap();
    store::set_xattr(&p, store::XATTR_ID, cloud_id.as_bytes()).unwrap();
    store::set_xattr(&p, store::XATTR_ETAG, etag.as_bytes()).unwrap();
    stamp::write(&p).unwrap();
    p
}

/// The restart, as `daemon_loop::run` performs it: sweep the scratch names
/// first, then a fresh scan into a fresh `Store`. Everything the old process
/// held in memory is deliberately not carried over — that is the point.
fn restart(root: &Path) -> Store {
    TmpfilePlacer::sweep_scratch(root).expect("sweep scratch names");
    let mut fresh = Store::new();
    fresh.scan(root).expect("rescan the sync root");
    fresh
}

/// A cloud that records what reaches it, so a test can assert not only that
/// recovery worked but what it cost.
#[derive(Default)]
struct CloudRecorder {
    uploads: Vec<(PathBuf, Option<String>)>,
    removes: Vec<String>,
}

impl Sink for CloudRecorder {
    fn upload(&mut self, path: &Path, existing: Option<&str>) -> io::Result<Uploaded> {
        self.uploads
            .push((path.to_path_buf(), existing.map(str::to_owned)));
        Ok(Uploaded {
            cloud_id: existing.unwrap_or("fresh-object").to_owned(),
            etag: Some("etag-after-upload".into()),
        })
    }

    fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
        self.removes.push(cloud_id.to_owned());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

/// A kill before the upload ran at all: the edit was queued, the queue died
/// with the process, and the only record of the edit is the stamp mismatch on
/// disk. The restart must find it from that alone and send it — as a
/// *conditional* update of the object it already names, not a blind create.
///
/// The wrong-but-plausible implementation this rejects is a queue journal
/// replayed on startup: there is none, so an implementation that needed one
/// would lose this edit silently, and the file would sit dirty until the next
/// remote change destroyed it.
#[test]
fn an_edit_the_crash_left_unsent_is_found_and_sent_from_the_stamp_alone() {
    let dir = scratch("unsent-edit");
    let p = synced(&dir, "notes.txt", b"first draft", "id-notes", "etag-1");
    std::fs::write(&p, b"second draft, never uploaded").unwrap();
    set_mtime(&p, 1_700_000_000);
    assert_eq!(
        stamp::state(&p).unwrap(),
        stamp::State::Dirty,
        "the constructed state must actually be dirty"
    );

    // -- the process dies here; nothing in memory survives ------------------

    let mut store = restart(&dir);
    let mut cloud = CloudRecorder::default();
    let outcome = run_upload(file_id(&p), &mut store, &mut cloud);

    assert_eq!(
        outcome,
        Outcome::Sent {
            cloud_id: "id-notes".into()
        }
    );
    assert_eq!(
        cloud.uploads,
        vec![(p.clone(), Some("id-notes".into()))],
        "one upload, addressed to the object the file already names — a None \
         here is a blind create that would duplicate the object"
    );
    assert_eq!(cloud.removes, Vec::<String>::new());
    assert_eq!(
        stamp::state(&p).unwrap(),
        stamp::State::Clean,
        "sent means stamped; a file left dirty is re-sent by every restart"
    );
}

/// The state a kill *inside* `run_upload` leaves, at the worst moment: the
/// bytes went out and `adopt_cloud_id` recorded the id and etag, but the
/// process died before the stamp write. The file carries an id and bytes with
/// no stamp to vouch for them — and it stays that way: the resync walk
/// deliberately skips unstamped files with an id, and an echo of the object
/// re-stamps nothing.
fn crashed_between_id_and_stamp(dir: &Path, rel: &str) -> PathBuf {
    let p = dir.join(rel);
    std::fs::write(&p, b"bytes an unstamped file cannot vouch for").unwrap();
    store::set_xattr(&p, store::XATTR_ID, b"id-report").unwrap();
    store::set_xattr(&p, store::XATTR_ETAG, b"etag-after-upload").unwrap();
    set_mtime(&p, 1_700_000_000);
    assert_eq!(
        stamp::state(&p).unwrap(),
        stamp::State::Unstamped,
        "the kill landed before the first stamp this inode would have carried"
    );
    p
}

/// A remote *change* to the object arriving after that crash must be refused,
/// not applied.
///
/// The wrong-but-plausible implementation this rejects is the guard as it
/// stood: only `Dirty` was refused, and `Unstamped` fell through to
/// `place()`. An edit made to the crashed file after the restart is invisible
/// — no stamp means the walk cannot see it change and nothing queues it — so
/// "unstamped with an id facing a real change" is indistinguishable from
/// "someone wrote to it and we were not told", and placing over it counts
/// destroying those bytes as a successful update.
#[test]
fn a_crash_between_the_id_and_the_stamp_never_lets_a_remote_change_take_the_bytes() {
    let dir = scratch("id-no-stamp-update");
    let p = crashed_between_id_and_stamp(&dir, "report.pdf");
    let body_before = std::fs::read(&p).unwrap();

    let mut store = restart(&dir);
    let mut placer = TmpfilePlacer::new(&dir).expect("open the sync root");
    let remote_change = [Change::Upserted {
        cloud_id: "id-report".into(),
        path: "report.pdf".into(),
        size: 4096,
        etag: Some("etag-someone-else".into()),
    }];
    let pass = apply(
        &dir,
        &remote_change,
        &mut store,
        &HashSet::new(),
        &mut placer,
    )
    .expect("apply");

    assert_eq!(pass.updated, 0, "the change must not be applied: {pass:?}");
    assert_eq!(
        pass.kept_local.len(),
        1,
        "and must be refused out loud, not skipped in silence: {pass:?}"
    );
    assert_eq!(
        std::fs::read(&p).unwrap(),
        body_before,
        "the bytes survived the remote change"
    );
}

/// And the echo of the object the crashed upload created is still a no-op:
/// the id, etag and size all match, so `is_current` answers before any guard
/// is asked. Without this the refusal above would turn every such crash into
/// a permanent conflict over a file that matches the cloud byte for byte —
/// the exact defect the `is_current`-first ordering was introduced to fix.
#[test]
fn positive_control_the_echo_of_the_crashed_upload_is_a_no_op_not_a_conflict() {
    let dir = scratch("id-no-stamp-echo");
    let p = crashed_between_id_and_stamp(&dir, "report.pdf");
    let size = std::fs::metadata(&p).unwrap().len();

    let mut store = restart(&dir);
    let mut placer = TmpfilePlacer::new(&dir).expect("open the sync root");
    let echo = [Change::Upserted {
        cloud_id: "id-report".into(),
        path: "report.pdf".into(),
        size,
        etag: Some("etag-after-upload".into()),
    }];
    let pass = apply(&dir, &echo, &mut store, &HashSet::new(), &mut placer).expect("apply");

    assert_eq!(
        pass,
        Applied::default(),
        "an echo of what the crashed run sent is nothing to do, not a conflict"
    );
}

/// The delete side of the same crash: the file's id is in the index, so a
/// remote delete reaches it — and its bytes are exactly as unvouched-for as
/// on the upsert side. A delete is the more destructive of the two, and a
/// state the crash manufactured must not be what decides it.
#[test]
fn a_crash_between_the_id_and_the_stamp_never_lets_a_remote_delete_take_the_bytes() {
    let dir = scratch("id-no-stamp-delete");
    let p = crashed_between_id_and_stamp(&dir, "report.pdf");

    let mut store = restart(&dir);
    let mut placer = TmpfilePlacer::new(&dir).expect("open the sync root");
    let remote_delete = [Change::Removed {
        cloud_id: "id-report".into(),
    }];
    let pass = apply(
        &dir,
        &remote_delete,
        &mut store,
        &HashSet::new(),
        &mut placer,
    )
    .expect("apply");

    assert_eq!(pass.removed, 0, "the delete must not be applied: {pass:?}");
    assert_eq!(pass.kept_local.len(), 1, "and must be named: {pass:?}");
    assert!(p.exists(), "the bytes survived the remote delete");
}

// ---------------------------------------------------------------------------
// The delta batch
// ---------------------------------------------------------------------------

/// The client's half of "the cursor never advances past unapplied changes".
///
/// The provider refuses to commit until the framework hands back a different
/// cursor, so a crash after the changes were applied — but before the round
/// was acknowledged — means the *same batch arrives again* after the restart.
/// That refusal is only affordable if the replay is free: an `apply` that
/// re-placed every object would punch every hydrated file back to a
/// placeholder on every crash, and the "safe" cursor rule would itself be the
/// data loss.
#[test]
fn the_batch_a_crash_left_unacknowledged_replays_as_a_no_op() {
    let dir = scratch("replayed-batch");
    let batch = [
        Change::Upserted {
            cloud_id: "id-a".into(),
            path: "docs/a.txt".into(),
            size: 64,
            etag: Some("etag-a".into()),
        },
        Change::Upserted {
            cloud_id: "id-b".into(),
            path: "b.bin".into(),
            size: 4096,
            etag: Some("etag-b".into()),
        },
    ];

    let first = {
        let mut store = Store::new();
        let mut placer = TmpfilePlacer::new(&dir).expect("open the sync root");
        apply(&dir, &batch, &mut store, &HashSet::new(), &mut placer).expect("first apply")
    };
    assert_eq!(first.created, 2, "the first pass placed both objects");
    let id_a = file_id(&dir.join("docs/a.txt"));
    let id_b = file_id(&dir.join("b.bin"));

    // -- crash before the acknowledgement; the provider will replay ----------

    let mut store = restart(&dir);
    let mut placer = TmpfilePlacer::new(&dir).expect("reopen the sync root");
    let replay =
        apply(&dir, &batch, &mut store, &HashSet::new(), &mut placer).expect("replayed apply");

    assert_eq!(
        replay,
        Applied::default(),
        "a replayed batch must change nothing — created/updated here means \
         every crash re-places every object it had already placed"
    );
    assert_eq!(
        file_id(&dir.join("docs/a.txt")),
        id_a,
        "the replay must keep the inode: a fresh placement punches a file a \
         reader may have hydrated in the meantime"
    );
    assert_eq!(file_id(&dir.join("b.bin")), id_b);
}

/// A removal in the replayed batch names an object the crashed pass already
/// removed. Applying it again must be silence, not an error — and, the half
/// with teeth: it must not take a *new* local file that has nothing to do
/// with the removed object.
#[test]
fn a_replayed_removal_is_silent_and_takes_nothing_new() {
    let dir = scratch("replayed-removal");
    // The crashed pass already applied the removal: the file is gone.
    let batch = [Change::Removed {
        cloud_id: "id-gone".into(),
    }];
    // A file the user created after the removal was applied and before the
    // crash. It has no cloud identity; the replay must leave it alone.
    let unrelated = dir.join("new-notes.txt");
    std::fs::write(&unrelated, b"unsent user content").unwrap();

    let mut store = restart(&dir);
    let mut placer = TmpfilePlacer::new(&dir).expect("open the sync root");
    let replay =
        apply(&dir, &batch, &mut store, &HashSet::new(), &mut placer).expect("replayed apply");

    assert_eq!(
        replay,
        Applied::default(),
        "removing what is already absent is a no-op, not a failure — an \
         error here would set `retryable` and pin the cursor forever"
    );
    assert!(
        unrelated.exists(),
        "the replayed removal took a file that never carried the removed \
         object's id — never destroy content that exists nowhere else"
    );
}

// ---------------------------------------------------------------------------
// The startup sequence itself
// ---------------------------------------------------------------------------

/// A kill between `linkat` and `renameat` leaves a completed placeholder
/// under a scratch name. The restart sequence sweeps before the first pass
/// runs — in that order, because the next pass may place the same object
/// again, and litter that survives a pass is litter the user has to explain.
#[test]
fn scratch_litter_from_a_crashed_placement_is_gone_before_the_next_pass_places_over_it() {
    let dir = scratch("crashed-placement");
    // What the kill left: the placer's scratch name, fully built.
    let litter = dir.join(".report.pdf.hydration-3");
    std::fs::write(&litter, b"").unwrap();

    let mut store = restart(&dir);
    let mut placer = TmpfilePlacer::new(&dir).expect("open the sync root");
    let batch = [Change::Upserted {
        cloud_id: "id-report".into(),
        path: "report.pdf".into(),
        size: 512,
        etag: Some("etag-r".into()),
    }];
    let pass =
        apply(&dir, &batch, &mut store, &HashSet::new(), &mut placer).expect("apply after sweep");

    assert_eq!(
        pass.created, 1,
        "the object the crash interrupted is placed"
    );
    assert!(
        !litter.exists(),
        "the scratch name outlived the restart; nothing later ever removes it"
    );
    assert_eq!(
        std::fs::metadata(dir.join("report.pdf")).unwrap().len(),
        512,
        "and the real name carries the real placeholder"
    );
}

/// The negative control for the sweep's aim: a restart may only take scratch
/// names. The manifest and the user's own dotfiles ride through every crash
/// and every recovery — a sweep that takes more than it must is itself the
/// data loss the sequence exists to prevent.
#[test]
fn positive_control_the_restart_sweep_takes_only_scratch_names() {
    let dir = scratch("sweep-aim");
    std::fs::write(dir.join(".report.pdf.hydration-7"), b"").unwrap();
    std::fs::write(dir.join(".hydration-manifest"), b"manifest").unwrap();
    std::fs::write(dir.join(".bashrc"), b"user dotfile").unwrap();
    std::fs::write(dir.join("kept.txt"), b"user content").unwrap();

    restart(&dir);

    assert!(!dir.join(".report.pdf.hydration-7").exists());
    for kept in [".hydration-manifest", ".bashrc", "kept.txt"] {
        assert!(
            dir.join(kept).exists(),
            "the restart sweep took {kept}, which is not scratch"
        );
    }
}

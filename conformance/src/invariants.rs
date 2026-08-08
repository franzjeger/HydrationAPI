//! The invariants themselves.
//!
//! Each one corresponds to a section of DESIGN.md and to a bug that shipped in a
//! real client. The doc comment on each states the guarantee in the same words
//! as the specification, so the test and the spec cannot drift apart.
//!
//! These panic on failure rather than returning errors: a conformance failure is
//! not a condition to be handled, and the panic message is the report.

use crate::{CloudOp, FetchBehaviour, Harness, Outcome};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::time::Duration;

const UPLOAD_WINDOW: Duration = Duration::from_secs(10);

/// Blocks allocated to a file. Zero means "metadata only, no content here".
fn blocks(path: &std::path::Path) -> u64 {
    fs::metadata(path).expect("stat placeholder").blocks()
}

/// §5.1 — A locally created file keeps one identity for its whole life.
///
/// > A file created locally has stable `st_ino` from `create` to `unlink`,
/// > regardless of upload state.
///
/// The bug: a created file got a temporary `_local_*` id so it was usable before
/// the upload finished, and the real cloud id replaced it on completion. Because
/// the path column was unique, the two could never coexist, so there was always
/// an instant where the inode named an id the database did not have. A read
/// landing there found no row, concluded there was no content anywhere, and
/// dropped the entry — so reading a file you had just created could delete it.
/// Three data-loss bugs and three later races all came from that one swap.
pub fn identity_is_stable<H: Harness>(h: &mut H) -> Outcome {
    let path = h.sync_dir().join("created.txt");

    let mut f = fs::File::create(&path).expect("create through the mount");
    f.write_all(b"scaffolded by npm init\n").expect("write");
    f.sync_all().expect("fsync");
    drop(f);

    let ino_before = fs::metadata(&path).expect("stat after create").ino();

    // The upload adopts the real cloud id here. Nothing about the file the
    // kernel already handed out may change underneath it.
    h.settle();

    let ino_after = fs::metadata(&path).expect("stat after upload").ino();
    assert_eq!(
        ino_before, ino_after,
        "inode changed when the cloud id was adopted: {ino_before} -> {ino_after}. \
         A reader holding this file saw it become a different file."
    );

    let mut content = Vec::new();
    fs::File::open(&path)
        .expect("open after adoption")
        .read_to_end(&mut content)
        .expect("read after adoption");
    assert_eq!(
        content, b"scaffolded by npm init\n",
        "content changed across id adoption"
    );

    Outcome::Pass
}

/// §5.2 — Size and mtime are the local copy, immediately.
///
/// > `stat` reflects the last local write at once, whatever the upload is doing.
///
/// The bug: `getattr` answered from a database whose size only changed when a
/// delta pass or a completed upload wrote it back. Between `write()` and the
/// upload landing — seconds to minutes — `stat` returned the old size and the
/// file read back empty, while `fsync()` returned success. Durability promised
/// and not delivered. The assertion below is the one that reported
/// `left: 0, right: 23`.
pub fn size_is_local_truth<H: Harness>(h: &mut H) -> Outcome {
    let path = h.sync_dir().join("package.json");
    let payload = b"scaffolded by npm init\n"; // 23 bytes

    let mut f = fs::File::create(&path).expect("create");
    f.write_all(payload).expect("write");
    f.sync_all().expect("fsync");
    drop(f);

    // No settle. The whole point is that the truth is local and immediate.
    let md = fs::metadata(&path).expect("stat immediately after write");
    assert_eq!(
        md.len(),
        payload.len() as u64,
        "stat reported {} bytes for a file that was just given {}",
        md.len(),
        payload.len()
    );

    let read_back = fs::read(&path).expect("read immediately after write");
    assert_eq!(read_back, payload, "file read back as something else");

    Outcome::Pass
}

/// §5.3 — POSIX mode survives, including the exec bit.
///
/// > Mode survives dehydration, rehydration and a full resync.
///
/// The cloud does not store it. The exec bit decides whether a program can run,
/// so losing it across an eviction turns a working script into a broken one with
/// no visible cause.
pub fn mode_survives_dehydration<H: Harness>(h: &mut H) -> Outcome {
    let path = h.sync_dir().join("script.sh");

    let script = b"#!/bin/sh\necho hello\n";
    fs::write(&path, script).expect("write script");
    let mut perms = fs::metadata(&path).expect("stat").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path, perms).expect("chmod +x");
    h.settle();
    let size_before = fs::metadata(&path).expect("stat").len();

    h.dehydrate("script.sh");
    let md = fs::metadata(&path).expect("stat while dehydrated");
    assert_eq!(
        md.permissions().mode() & 0o777,
        0o755,
        "mode lost while the file was dehydrated"
    );
    assert_eq!(
        md.len(),
        size_before,
        "size lost while dehydrated: a placeholder must keep the real size"
    );

    // Reading rehydrates. The mode must still be there afterwards.
    let content = fs::read(&path).expect("read rehydrates");
    assert_eq!(
        content, script,
        "a dehydrated file did not rehydrate: the read produced something else"
    );
    assert_eq!(
        fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
        0o755,
        "mode lost across the rehydration round trip"
    );

    Outcome::Pass
}

/// §5.4 — An atomically saved file stays under the name it was saved as.
///
/// > No upload can succeed under a name the file does not have when the bytes
/// > are sent.
///
/// The bug: `write temp → rename over target` is how vim, VS Code and most build
/// tools save. The upload of the temp file was already in flight, having started
/// under the temp name, so the cloud ended up holding the file under
/// `README.md.tmp.194149.5089d5eff10a`. The next delta dragged that name back
/// down: the target vanished and the temp file appeared. No bytes were lost, but
/// it reads exactly like data loss — and a cleanup of "orphaned" temp files
/// would have made it real.
pub fn atomic_save_keeps_its_name<H: Harness>(h: &mut H) -> Outcome {
    h.seed_remote("README.md", b"original\n", "etag-1");
    let target = h.sync_dir().join("README.md");
    let temp = h.sync_dir().join("README.md.tmp.194149.5089d5eff10a");

    fs::read(&target).expect("hydrate the target first");

    // Arrange the race: the temp file's upload must be in flight at the moment
    // the rename lands, which is what happens in practice.
    h.hold_uploads();
    fs::write(&temp, b"edited\n").expect("write temp file");
    assert!(
        h.wait_for_upload_start(UPLOAD_WINDOW),
        "no upload started for the temp file; the race cannot be arranged"
    );
    fs::rename(&temp, &target).expect("rename temp over target");
    h.release_uploads();
    h.settle();

    assert!(target.exists(), "the target file disappeared after an atomic save");
    assert_eq!(
        fs::read(&target).expect("read target"),
        b"edited\n",
        "the target does not hold the saved content"
    );
    assert!(!temp.exists(), "the temp name survived the rename");

    let remote = h
        .remote("README.md")
        .expect("the cloud does not hold the file under its real name");
    assert_eq!(remote.content, b"edited\n", "the cloud holds stale content");
    assert!(
        h.remote("README.md.tmp.194149.5089d5eff10a").is_none(),
        "the cloud is holding the file under the temp name"
    );

    Outcome::Pass
}

/// §5.5 — A delete during an upload sticks.
///
/// > Once `unlink` has returned, the file is not in the cloud afterwards —
/// > not even if the upload was in flight and succeeded.
///
/// The bug: on completion the upload re-read its row, found it gone, and fell
/// back to its own stale in-memory copy with `.unwrap_or(item)`. That put the
/// file back, and since the upload had just created it in the cloud, it came
/// back with its content. Absence of the local file is a positive statement —
/// the delete is the newer intention — not missing data to be filled in.
pub fn delete_beats_inflight_upload<H: Harness>(h: &mut H) -> Outcome {
    let path = h.sync_dir().join("scratch.txt");

    h.hold_uploads();
    fs::write(&path, b"transient\n").expect("create and write");
    assert!(
        h.wait_for_upload_start(UPLOAD_WINDOW),
        "no upload started; the delete-during-upload race cannot be arranged"
    );

    fs::remove_file(&path).expect("unlink inside the upload window");
    h.release_uploads();
    h.settle();

    assert!(
        h.remote("scratch.txt").is_none(),
        "the file came back in the cloud after being deleted locally"
    );
    assert!(!path.exists(), "the file came back locally");

    // If the upload had already created the remote object, the framework owes a
    // delete for it. Either it never uploaded, or it cleaned up.
    let ops = h.ops_observed();
    let created = ops
        .iter()
        .any(|op| matches!(op, CloudOp::Put { name, .. } if name == "scratch.txt"));
    let deleted = ops.iter().any(|op| matches!(op, CloudOp::Delete { .. }));
    assert!(
        !created || deleted,
        "the upload created the remote object and nothing deleted it"
    );

    Outcome::Pass
}

/// §5.6 — `fsync` never claims durability it did not deliver.
///
/// > `fsync` returns success only when the data survives a reboot. The count of
/// > unsent changes is always right, including those waiting out a debounce.
///
/// The bug: the client implemented no `fsync` at all, so the kernel got `ENOSYS`,
/// remembered it, stopped sending `FSYNC`, and every `fsync()` succeeded for
/// free — over a file that `stat` said was empty.
///
/// The crash half of this cannot be asserted in-process; a real power-cut test
/// belongs in a VM. What is asserted here is the lie that actually shipped:
/// success returned over data the filesystem could not then produce.
pub fn fsync_does_not_lie<H: Harness>(h: &mut H) -> Outcome {
    let path = h.sync_dir().join("durable.txt");
    let payload = b"must survive\n";

    let mut f = fs::File::create(&path).expect("create");
    f.write_all(payload).expect("write");
    f.sync_all().expect("fsync must succeed or report why");
    drop(f);

    // Whatever fsync just promised must be visible right now, through a fresh
    // open, with no sync pass having run.
    let mut content = Vec::new();
    fs::File::open(&path)
        .expect("reopen after fsync")
        .read_to_end(&mut content)
        .expect("read after fsync");
    assert_eq!(
        content, payload,
        "fsync returned success over data the filesystem could not produce"
    );
    assert_eq!(
        fs::metadata(&path).expect("stat").len(),
        payload.len() as u64,
        "fsync returned success while stat disagreed about the size"
    );

    // fsync promises local durability, not upload. The change must still be
    // counted as unsent, or the user is shown "synced" over work on one machine.
    assert!(
        h.pending_uploads() >= 1,
        "an unsent change is not counted as pending; status would claim synced"
    );

    Outcome::Pass
}

/// §5.7 — Hydration that disagrees with the placeholder yields `EIO`, never
/// partial or wrong content.
///
/// > A placeholder is either fully hydrated with the content it promised, or it
/// > is left untouched and the reader gets `EIO`. There is no third outcome.
///
/// The placeholder's size comes from cloud metadata at creation. If the object
/// changes before anyone reads it, hydration fills a file whose `st_size` is
/// wrong — while a reader is already blocked inside `read()`. Correcting the
/// size underneath a live reader is not safe: shrinking a file that is mapped
/// gives SIGBUS past the new end. So the only sound answer is to refuse.
pub fn hydration_mismatch_fails_closed<H: Harness>(h: &mut H) -> Outcome {
    h.seed_remote("report.pdf", &vec![b'x'; 4096], "etag-1");
    let path = h.sync_dir().join("report.pdf");

    assert_eq!(
        blocks(&path),
        0,
        "a freshly seeded placeholder already has content"
    );

    // The cloud object changed after the placeholder was made.
    h.set_fetch_behaviour("report.pdf", FetchBehaviour::Short { bytes: 2048 });

    let err = fs::read(&path).expect_err("a short hydration must not succeed");
    assert!(
        matches!(err.kind(), ErrorKind::Other | ErrorKind::InvalidData) || err.raw_os_error() == Some(libc_eio()),
        "expected EIO for a hydration that disagrees with the placeholder, got {err:?}"
    );

    assert_eq!(
        blocks(&path),
        0,
        "a partially filled placeholder survived the failed hydration; \
         it now looks hydrated and is not"
    );

    // Once the metadata is resynced, the same read must succeed.
    h.set_fetch_behaviour("report.pdf", FetchBehaviour::Honest);
    h.settle();
    let content = fs::read(&path).expect("read after resync");
    assert_eq!(
        content.len(),
        fs::metadata(&path).expect("stat").len() as usize,
        "content length still disagrees with st_size after resync"
    );

    Outcome::Pass
}

/// §6a — Losing the hydration worker fails closed.
///
/// > With the worker gone, reading a dehydrated file gives an error, never
/// > zeros, and the file stays dehydrated.
///
/// Measured on Linux 7.1.6: bare fanotify fails *open*. Kill the daemon and a
/// dehydrated placeholder reads back as zeros with exit 0 — silent corruption,
/// and worse than FUSE, which at least reports `ENOTCONN`. A supervisor holding
/// the same fanotify group turns that into `EIO`.
pub fn worker_death_fails_closed<H: Harness>(h: &mut H) -> Outcome {
    if !h.has_separable_worker() {
        return Outcome::NotApplicable(
            "implementation has no separable hydration worker; \
             fail-closed is a property of its transport instead"
                .into(),
        );
    }

    h.seed_remote("big.bin", &vec![b'z'; 4096], "etag-1");
    let path = h.sync_dir().join("big.bin");
    assert_eq!(blocks(&path), 0, "seeded file is not a placeholder");

    h.kill_hydration_worker();

    match fs::read(&path) {
        Ok(bytes) => panic!(
            "read succeeded with the hydration worker dead, returning {} bytes \
             (all zero: {}). This is silent data corruption.",
            bytes.len(),
            bytes.iter().all(|b| *b == 0)
        ),
        Err(e) => {
            assert!(
                e.raw_os_error().is_some(),
                "expected an OS error with the worker dead, got {e:?}"
            );
        }
    }

    assert_eq!(
        blocks(&path),
        0,
        "the file gained content while the worker was dead"
    );

    Outcome::Pass
}

fn libc_eio() -> i32 {
    5
}

/// Every invariant, in specification order.
pub fn run_all<H: Harness>(h: &mut H) -> Vec<(&'static str, Outcome)> {
    vec![
        ("5.1 identity is stable", identity_is_stable(h)),
        ("5.2 size is local truth", size_is_local_truth(h)),
        ("5.3 mode survives dehydration", mode_survives_dehydration(h)),
        ("5.4 atomic save keeps its name", atomic_save_keeps_its_name(h)),
        ("5.5 delete beats in-flight upload", delete_beats_inflight_upload(h)),
        ("5.6 fsync does not lie", fsync_does_not_lie(h)),
        ("5.7 hydration mismatch fails closed", hydration_mismatch_fails_closed(h)),
        ("6a worker death fails closed", worker_death_fails_closed(h)),
    ]
}

//! The framework against a cloud that behaves the way real ones do.
//!
//! Everything so far has been measured against [`FolderCloud`], a directory
//! standing in for a service. It is honest about the framework's own logic and
//! dishonest about the world: it never fails halfway, never changes an object
//! between listing it and serving it, never reuses an id, never returns a path
//! that collides with another, and never hands back fewer bytes than it promised.
//!
//! A real service does all of those, and the next thing anyone builds on this is
//! a Microsoft Graph provider. So this file is the adversarial half: each test
//! makes the cloud misbehave in one specific way a real one does, and asserts
//! that the framework's answer is *safe* rather than merely different. The bar
//! throughout is the one the whole project is built around — **never silently
//! serve or keep the wrong bytes**, and never destroy content that exists
//! nowhere else.
//!
//! Where the framework's answer is "refuse", that is a pass. Where it is
//! "quietly accept", that is the bug.

use hydration_client::delta::{apply, safe_join, Applied, Change};
use hydration_client::place::TmpfilePlacer;
use hydration_client::store::{self, Store};
use hydration_client::upload::{run_upload, Outcome, Queue, Sink, TestClock, Uploaded};
use hydration_protocol::{stamp, FileId};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("hostile")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

fn file_id(p: &Path) -> FileId {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(p).expect("stat");
    FileId {
        fsid: md.dev(),
        ino: md.ino(),
    }
}

fn upserted(path: &str, size: u64, id: &str, etag: Option<&str>) -> Change {
    Change::Upserted {
        cloud_id: id.into(),
        path: path.into(),
        size,
        etag: etag.map(Into::into),
    }
}

fn run(root: &Path, changes: &[Change]) -> Applied {
    let mut store = Store::new();
    let mut placer = TmpfilePlacer::new(root);
    apply(root, changes, &mut store, &HashSet::new(), &mut placer).expect("apply")
}

/// A file that has been through the framework and is currently clean.
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

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

/// The single most likely real-world failure: a transfer that ends early.
///
/// A dropped connection, a proxy timeout, a 206 answered as a 200. The rule
/// (§5.7) is that a fetch delivers the whole object or fails — there is no
/// partial success — and this is where an implementor most easily gets it wrong,
/// because returning what arrived *looks* like cooperation.
///
/// Tested against the check that cannot be bypassed: the helper's, which refuses
/// on the declared length before reading a single byte of the body. A daemon
/// offering 4 GB for a 12-byte placeholder gets a rejection, not an allocation.
#[test]
fn the_helper_refuses_a_response_whose_length_disagrees() {
    use hydration_protocol::transport::{DaemonConn, HelperConn};
    use hydration_protocol::FetchResponse;

    for (offered, actual, expected) in [
        (500u64, 1000u64, "short"),
        (2000, 1000, "long"),
        (u64::MAX / 2, 1000, "absurd"),
    ] {
        let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut helper = HelperConn::new(a).unwrap();
        let mut daemon = DaemonConn::new(b).unwrap();

        // The daemon claims a length that is not the placeholder's.
        daemon
            .send(FetchResponse::Ready {
                id: 1,
                len: offered,
            })
            .unwrap();

        let got = helper.recv(actual);
        assert!(
            got.is_err(),
            "the helper accepted a {expected} length ({offered} for a {actual}-byte \
             placeholder); a reader would have been handed the wrong bytes"
        );
    }
}

/// And the honest case still works, or the check above would be passing for the
/// wrong reason.
#[test]
fn the_helper_accepts_a_response_whose_length_agrees() {
    use hydration_protocol::transport::{DaemonConn, HelperConn};
    use std::io::Write;

    let (a, b) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut helper = HelperConn::new(a).unwrap();
    let mut daemon = DaemonConn::new(b).unwrap();
    let body = vec![b'H'; 64];
    daemon.send_ready(1, &body).unwrap();
    let _ = std::io::stdout().flush();

    let (resp, got) = helper.recv(64).expect("an honest response was refused");
    assert_eq!(got, body);
    assert_eq!(resp.id(), 1);
}

// ---------------------------------------------------------------------------
// Listing and identity
// ---------------------------------------------------------------------------

/// Two objects claiming the same path.
///
/// Real services allow it — case-insensitive backends colliding, a rename race,
/// two clients writing concurrently. Whatever the framework does, it must not
/// end up with a file whose recorded id belongs to a different object than its
/// content, because every later fetch would then serve the wrong file's bytes.
#[test]
fn two_objects_claiming_one_path_do_not_produce_a_mismatched_file() {
    let dir = scratch("collide");
    run(
        &dir,
        &[
            upserted("report.pdf", 100, "cloud-A", Some("etag-A")),
            upserted("report.pdf", 250, "cloud-B", Some("etag-B")),
        ],
    );

    let p = dir.join("report.pdf");
    let id = String::from_utf8(store::get_xattr(&p, store::XATTR_ID).unwrap().unwrap()).unwrap();
    let etag =
        String::from_utf8(store::get_xattr(&p, store::XATTR_ETAG).unwrap().unwrap()).unwrap();
    let size = std::fs::metadata(&p).unwrap().len();

    // Whichever won, the three have to describe the same object. A file
    // recording cloud-A's id with cloud-B's size would fetch A's bytes into a
    // placeholder promising B's length, and §5.7 would then refuse every read of
    // it forever — a file that exists and can never be opened.
    let expected_size = if id == "cloud-A" { 100 } else { 250 };
    let expected_etag = if id == "cloud-A" { "etag-A" } else { "etag-B" };
    assert_eq!(size, expected_size, "id {id} does not match the size");
    assert_eq!(etag, expected_etag, "id {id} does not match the etag");
}

/// A service that reuses an id for different content, distinguished only by
/// etag. Graph does not promise ids are content-addressed, and a placeholder
/// that keeps a stale size is unreadable rather than merely stale (§5.7).
#[test]
fn a_reused_id_with_a_new_version_still_refreshes_the_size() {
    let dir = scratch("reused-id");
    run(&dir, &[upserted("a.bin", 100, "cloud-1", Some("v1"))]);
    run(&dir, &[upserted("a.bin", 4096, "cloud-1", Some("v2"))]);

    let p = dir.join("a.bin");
    assert_eq!(
        std::fs::metadata(&p).unwrap().len(),
        4096,
        "the placeholder still promises the old length; every read of it would \
         be refused by the length check"
    );
}

/// The nastier version of the same thing: a new version with an *identical*
/// size and a reused etag. The framework cannot tell this apart and will skip
/// it — the documented blind spot. What must not happen is anything worse than
/// staleness.
#[test]
fn an_undetectable_remote_edit_leaves_a_readable_file_not_a_broken_one() {
    let dir = scratch("undetectable");
    run(&dir, &[upserted("a.bin", 100, "cloud-1", Some("same"))]);
    let before = std::fs::metadata(dir.join("a.bin")).unwrap();
    run(&dir, &[upserted("a.bin", 100, "cloud-1", Some("same"))]);
    let after = std::fs::metadata(dir.join("a.bin")).unwrap();

    use std::os::unix::fs::MetadataExt;
    assert_eq!(before.ino(), after.ino(), "an identical change re-placed");
    assert_eq!(after.len(), 100);
    // Stale, and readable. That is the acceptable failure; an unreadable file
    // would not be.
}

/// Paths a real service will hand back, and one it should never be able to.
#[test]
fn service_supplied_paths_are_handled_or_refused_but_never_misinterpreted() {
    let dir = scratch("paths");
    for (rel, allowed) in [
        ("Bilder/påske 2024/bilde.jpg", true),
        ("emoji 🎉/note.txt", true),
        ("trailing space /x.txt", true),
        ("a\tb.txt", true),
        // Everything below either escapes or names something of ours.
        ("../escape.txt", false),
        ("/absolute.txt", false),
        (".hydration-manifest", false),
        ("sub/../../out.txt", false),
        ("", false),
    ] {
        let joined = safe_join(&dir, rel);
        assert_eq!(
            joined.is_some(),
            allowed,
            "{rel:?} was {} and should not have been",
            if joined.is_some() {
                "accepted"
            } else {
                "refused"
            }
        );
        if let Some(p) = joined {
            assert!(
                p.starts_with(&dir),
                "{rel:?} resolved outside the sync root: {}",
                p.display()
            );
        }
    }
}

/// A remote rename: the same object arriving under a new path.
///
/// `FolderCloud` cannot produce this — it keys objects by name — but every real
/// service does, and it is the shape most likely to leave the sync directory
/// with two files claiming one object. Two files with one cloud id means a later
/// remote delete removes an arbitrary one of them, and an edit to the other is
/// uploaded over the object the first still points at.
#[test]
fn an_object_that_moved_does_not_leave_two_files_claiming_it() {
    let dir = scratch("remote-rename");
    run(&dir, &[upserted("old/name.txt", 64, "cloud-1", Some("e1"))]);
    assert!(dir.join("old/name.txt").exists());

    // The service now reports the same object at a different path.
    run(&dir, &[upserted("new/name.txt", 64, "cloud-1", Some("e1"))]);

    let mut claiming = Vec::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else if store::get_xattr(&e.path(), store::XATTR_ID)
                .ok()
                .flatten()
                .as_deref()
                == Some(b"cloud-1".as_slice())
            {
                claiming.push(e.path());
            }
        }
    }
    assert_eq!(
        claiming.len(),
        1,
        "an object that moved left {} files claiming it: {claiming:?}",
        claiming.len()
    );
}

/// A path long enough to break something. Real drives have deep trees, and a
/// framework that panics on one is worse than one that refuses it.
#[test]
fn a_very_deep_path_fails_cleanly_rather_than_panicking() {
    let dir = scratch("deep");
    let deep = (0..60)
        .map(|i| format!("d{i}"))
        .collect::<Vec<_>>()
        .join("/");
    let rel = format!("{deep}/file.txt");
    let out = run(&dir, &[upserted(&rel, 16, "cloud-1", Some("e"))]);
    assert_eq!(
        out.created + out.failed.len(),
        1,
        "a deep path was neither created nor reported as failed: {out:?}"
    );
}

// ---------------------------------------------------------------------------
// Uploading
// ---------------------------------------------------------------------------

/// An upload that fails after the object exists remotely.
///
/// A real service can create the object and then fail the response — a timeout
/// after commit, a 500 on the final chunk. The client sees an error and must not
/// conclude the file is sent: if it stamped it clean, the local edit would never
/// be retried and a later remote change would replace it.
#[test]
fn an_upload_that_fails_leaves_the_file_dirty_and_retryable() {
    struct FailsAfterCommit;
    impl Sink for FailsAfterCommit {
        fn upload(&mut self, _p: &Path, _e: Option<&str>) -> io::Result<Uploaded> {
            Err(io::Error::new(io::ErrorKind::TimedOut, "gateway timeout"))
        }
        fn remove(&mut self, _id: &str) -> io::Result<()> {
            Ok(())
        }
    }

    let dir = scratch("upload-fails");
    let p = dir.join("doc.txt");
    std::fs::write(&p, b"an edit that must not be forgotten").unwrap();

    let mut store = Store::new();
    store.scan(&dir).unwrap();
    let outcome = run_upload(file_id(&p), &mut store, &mut FailsAfterCommit);
    assert!(matches!(outcome, Outcome::Failed(_)), "{outcome:?}");
    assert_ne!(
        stamp::state(&p).unwrap(),
        stamp::State::Clean,
        "a failed upload marked the file as sent; the edit would never be retried"
    );
}

/// A service that renames the object under us — returns a different id for what
/// we thought was an update. The framework must end up recording the id the
/// service actually used, or every later fetch asks for an object that is gone.
#[test]
fn a_service_that_changes_the_id_on_update_is_recorded_correctly() {
    struct Renumbers;
    impl Sink for Renumbers {
        fn upload(&mut self, _p: &Path, existing: Option<&str>) -> io::Result<Uploaded> {
            assert_eq!(existing, Some("cloud-old"), "the old id was not offered");
            Ok(Uploaded {
                cloud_id: "cloud-new".into(),
                etag: Some("v2".into()),
            })
        }
        fn remove(&mut self, _id: &str) -> io::Result<()> {
            Ok(())
        }
    }

    let dir = scratch("renumber");
    let p = synced(&dir, "doc.txt", b"content", "cloud-old", "v1");
    std::fs::write(&p, b"edited content").unwrap();

    let mut store = Store::new();
    store.scan(&dir).unwrap();
    let outcome = run_upload(file_id(&p), &mut store, &mut Renumbers);
    assert!(matches!(outcome, Outcome::Sent { .. }), "{outcome:?}");
    assert_eq!(
        store::get_xattr(&p, store::XATTR_ID).unwrap().unwrap(),
        b"cloud-new",
        "the file still points at an object the service has replaced"
    );
}

/// Throttling. A real service answers 429 for a while and then works. The
/// framework must not treat that as a reason to give up on the file.
#[test]
fn a_throttled_upload_is_retried_rather_than_dropped() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Throttles(AtomicUsize);
    impl Sink for Throttles {
        fn upload(&mut self, _p: &Path, _e: Option<&str>) -> io::Result<Uploaded> {
            if self.0.fetch_add(1, Ordering::SeqCst) < 2 {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "429 slow down"));
            }
            Ok(Uploaded {
                cloud_id: "cloud-1".into(),
                etag: Some("v1".into()),
            })
        }
        fn remove(&mut self, _id: &str) -> io::Result<()> {
            Ok(())
        }
    }

    let dir = scratch("throttled");
    let p = dir.join("doc.txt");
    std::fs::write(&p, b"content").unwrap();
    let mut sink = Throttles(AtomicUsize::new(0));
    let mut store = Store::new();
    store.scan(&dir).unwrap();

    // Two refusals, then success. The framework's retry surface is the resync
    // walk: a failed upload leaves the file unstamped, and an unstamped file
    // with content and no cloud id is exactly what the walk queues.
    for _ in 0..2 {
        let _ = run_upload(file_id(&p), &mut store, &mut sink);
        assert_ne!(
            stamp::state(&p).unwrap(),
            stamp::State::Clean,
            "a throttled upload was recorded as sent"
        );
    }
    let outcome = run_upload(file_id(&p), &mut store, &mut sink);
    assert!(matches!(outcome, Outcome::Sent { .. }), "{outcome:?}");
    assert_eq!(stamp::state(&p).unwrap(), stamp::State::Clean);
}

// ---------------------------------------------------------------------------
// The rule that outranks all of them
// ---------------------------------------------------------------------------

/// However badly the cloud behaves, local content that exists nowhere else
/// survives.
///
/// This is the invariant the whole framework is for, so it is asserted against
/// the worst combination available: a service that lists a file it has never
/// been given, with a plausible id and etag, while the local copy has never been
/// uploaded.
#[test]
fn no_amount_of_bad_cloud_behaviour_destroys_unsent_local_content() {
    let dir = scratch("survives");
    let p = dir.join("thesis.txt");
    std::fs::write(&p, b"eight months of work, never uploaded").unwrap();

    for change in [
        upserted("thesis.txt", 0, "cloud-1", Some("e")),
        upserted("thesis.txt", 999_999, "cloud-2", None),
        Change::Removed {
            cloud_id: "cloud-1".into(),
        },
    ] {
        run(&dir, &[change.clone()]);
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"eight months of work, never uploaded",
            "destroyed by {change:?}"
        );
    }
}

/// And the same for content that *was* uploaded but has been edited since,
/// which is the case a lost notification produces.
#[test]
fn an_edit_after_upload_survives_a_hostile_listing() {
    let dir = scratch("edited-survives");
    let p = synced(&dir, "notes.txt", b"the version we sent", "cloud-1", "v1");
    std::fs::write(&p, b"a later version that exists only here").unwrap();

    let out = run(&dir, &[upserted("notes.txt", 19, "cloud-1", Some("v1"))]);
    assert_eq!(out.kept_local.len(), 1, "{out:?}");
    assert_eq!(
        std::fs::read(&p).unwrap(),
        b"a later version that exists only here"
    );
}

/// A delta batch where one change is nonsense must not stop the rest.
///
/// Real feeds contain items a client cannot act on — an object type it does not
/// handle, a path it must refuse. Abandoning the batch would mean one bad item
/// halts sync indefinitely, since the same batch comes back every time.
#[test]
fn one_unusable_change_does_not_abandon_the_batch() {
    let dir = scratch("mixed-batch");
    let out = run(
        &dir,
        &[
            upserted("good-1.txt", 10, "cloud-1", Some("e")),
            upserted("../evil.txt", 10, "cloud-2", Some("e")),
            upserted("good-2.txt", 20, "cloud-3", Some("e")),
        ],
    );
    assert_eq!(out.created, 2, "{out:?}");
    assert_eq!(out.failed.len(), 1, "{out:?}");
    assert!(dir.join("good-1.txt").exists() && dir.join("good-2.txt").exists());
}

/// A cursor that the service rejects — the delta token expired, which Graph does
/// routinely — means a full listing arrives instead. The reconciler must behave
/// the same either way, or a resync would look like "everything is new".
#[test]
fn a_full_listing_after_an_expired_cursor_is_not_treated_as_all_new() {
    let dir = scratch("expired-cursor");
    let full = [
        upserted("a.txt", 10, "cloud-1", Some("e1")),
        upserted("b.txt", 20, "cloud-2", Some("e2")),
    ];
    let first = run(&dir, &full);
    assert_eq!(first.created, 2);

    // The token expired; the service replays the world.
    let second = run(&dir, &full);
    assert_eq!(
        (second.created, second.updated),
        (0, 0),
        "a replayed listing was treated as news: {second:?}"
    );
}

/// The queue must survive being told about a file that no longer exists, which
/// is what a delete racing a change notification produces.
#[test]
fn a_change_for_a_vanished_file_is_not_an_error() {
    let dir = scratch("vanished");
    let p = dir.join("gone.txt");
    std::fs::write(&p, b"here for now").unwrap();
    let id = file_id(&p);
    std::fs::remove_file(&p).unwrap();

    let mut q = Queue::new(Duration::from_secs(0), TestClock::default());
    q.touch(id);
    let mut store = Store::new();
    store.scan(&dir).unwrap();

    struct NeverCalled;
    impl Sink for NeverCalled {
        fn upload(&mut self, p: &Path, _e: Option<&str>) -> io::Result<Uploaded> {
            panic!("uploaded a file that does not exist: {}", p.display())
        }
        fn remove(&mut self, _id: &str) -> io::Result<()> {
            Ok(())
        }
    }
    let outcome = run_upload(id, &mut store, &mut NeverCalled);
    assert!(
        matches!(outcome, Outcome::NothingToDo | Outcome::DeletedInstead),
        "{outcome:?}"
    );
}

// ---------------------------------------------------------------------------
// Renames, in the batch shapes a real service actually produces
// ---------------------------------------------------------------------------

/// A move with nothing else changed must not be reported as a conflict.
///
/// The rename fix consults an index built once, before the loop — and its own
/// rename invalidates that index. Every later consultation in the same pass then
/// answers about a path that no longer exists, and the "never uploaded" guard
/// fires on a file that plainly was. The user is shown a conflict that does not
/// exist, and the size and etag refresh is skipped.
#[test]
fn a_move_is_not_reported_as_a_conflict() {
    let dir = scratch("move-clean");
    run(&dir, &[upserted("old/name.txt", 64, "cloud-1", Some("e1"))]);
    let out = run(&dir, &[upserted("new/name.txt", 64, "cloud-1", Some("e1"))]);

    assert_eq!(out.moved, 1, "{out:?}");
    assert!(
        out.kept_local.is_empty(),
        "a byte-identical move was reported as a conflict: {out:?}"
    );
}

/// On Graph a move bumps the version tag, so "same id, new path, new version" is
/// the normal representation of dragging a file in the web UI — not an exotic
/// batch. The move must not swallow the update.
#[test]
fn a_move_that_also_changes_the_content_applies_both() {
    let dir = scratch("move-and-edit");
    run(&dir, &[upserted("old/a.bin", 5, "cloud-1", Some("e1"))]);
    let out = run(&dir, &[upserted("new/a.bin", 9999, "cloud-1", Some("e2"))]);

    let p = dir.join("new/a.bin");
    assert_eq!(out.moved, 1, "{out:?}");
    assert_eq!(
        std::fs::metadata(&p).unwrap().len(),
        9999,
        "the placeholder still promises the old size; every read of it is refused \
         by the length check until the object changes again: {out:?}"
    );
    assert_eq!(
        store::get_xattr(&p, store::XATTR_ETAG).unwrap().unwrap(),
        b"e2"
    );
}

/// Microsoft documents that one delta enumeration may return the same item more
/// than once across pages, last occurrence winning. A provider that concatenates
/// pages produces exactly this, and the first version of the rename fix answered
/// it by recreating the two-claimant corruption it was written to prevent.
#[test]
fn the_same_object_twice_in_one_batch_leaves_one_file() {
    let dir = scratch("repeated");
    run(&dir, &[upserted("a.txt", 10, "cloud-1", Some("e1"))]);
    run(
        &dir,
        &[
            upserted("b.txt", 10, "cloud-1", Some("e1")),
            upserted("c.txt", 10, "cloud-1", Some("e1")),
        ],
    );
    assert_eq!(
        claimants(&dir, b"cloud-1").len(),
        1,
        "one object ended up claimed by {:?}",
        claimants(&dir, b"cloud-1")
    );
    assert!(
        dir.join("c.txt").exists(),
        "the last occurrence did not win"
    );
}

/// Two objects swapping paths in one batch. Both renames see an occupied
/// destination and refuse, which is right — but a refusal that nothing ever
/// retries is a permanent wrong state, because the cursor has already moved on.
#[test]
fn two_objects_swapping_paths_are_retried_not_abandoned() {
    let dir = scratch("swap");
    run(
        &dir,
        &[
            upserted("a.txt", 10, "cloud-A", Some("e")),
            upserted("b.txt", 20, "cloud-B", Some("e")),
        ],
    );
    let out = run(
        &dir,
        &[
            upserted("b.txt", 10, "cloud-A", Some("e")),
            upserted("a.txt", 20, "cloud-B", Some("e")),
        ],
    );
    assert!(
        out.failed.is_empty() || out.retryable,
        "a swap was refused with nothing to retry it: {out:?}"
    );
}

fn claimants(dir: &Path, id: &[u8]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            if e.file_type().unwrap().is_dir() {
                stack.push(e.path());
            } else if store::get_xattr(&e.path(), store::XATTR_ID)
                .ok()
                .flatten()
                .as_deref()
                == Some(id)
            {
                found.push(e.path());
            }
        }
    }
    found.sort();
    found
}

/// A file uploaded from a subdirectory must not be moved to the root by the
/// next delta pass.
///
/// The reference provider recorded only the basename. That was harmless while
/// nothing acted on the path a listing reported — and stopped being harmless the
/// moment the delta pass learned to translate a remote move into a local rename.
/// It is also the code an implementor copies, so it modelled the mistake.
#[test]
fn an_upload_from_a_subdirectory_keeps_its_path() {
    use hydration_client::delta::Discover;
    use hydration_client::providers::FolderCloud;

    let dir = scratch("subdir-path");
    let cloud = dir.join(".cloud");
    std::fs::create_dir_all(dir.join("Documents")).unwrap();
    let p = dir.join("Documents/report.pdf");
    std::fs::write(&p, b"a report in a subdirectory").unwrap();

    let mut sink = FolderCloud::open(&cloud).unwrap().rooted_at(&dir);
    let mut store = Store::new();
    store.scan(&dir).unwrap();
    let outcome = run_upload(file_id(&p), &mut store, &mut sink);
    assert!(matches!(outcome, Outcome::Sent { .. }), "{outcome:?}");

    let (changes, _) = sink.changes(&Default::default()).unwrap();
    let paths: Vec<String> = changes
        .iter()
        .filter_map(|c| match c {
            Change::Upserted { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        paths,
        vec!["Documents/report.pdf".to_string()],
        "the upload recorded a name instead of a path; the next delta pass would \
         move the user's file to the sync root"
    );
}

/// A size no real object has.
///
/// It becomes the placeholder's length, and every hydration allocates that many
/// bytes to serve it — so an exabyte upsert is a sparse file the filesystem
/// creates happily and a daemon that tries to allocate it on first read.
#[test]
fn an_absurd_size_is_refused_rather_than_becoming_a_placeholder() {
    let dir = scratch("absurd-size");
    let out = run(
        &dir,
        &[
            upserted("huge.bin", u64::MAX / 2, "cloud-1", Some("e")),
            upserted("ok.bin", 1024, "cloud-2", Some("e")),
        ],
    );
    assert_eq!(out.created, 1, "{out:?}");
    assert_eq!(out.failed, vec!["huge.bin".to_string()], "{out:?}");
    assert!(!dir.join("huge.bin").exists());
}

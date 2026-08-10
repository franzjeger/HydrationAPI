//! The upload rules, each against the bug it exists to prevent.
//!
//! Every one of these was a shipped data-loss bug in a real FUSE client, found
//! by hand, over a week. They run on a clock the test moves, so the race is
//! arranged rather than waited for — the reason they stayed hidden the first
//! time is that reproducing them by sleeping does not work.

use hydration_client::store::{self, Store};
use hydration_client::upload::{run_upload, Outcome, Queue, Sink, TestClock, Uploaded};
use hydration_protocol::FileId;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DEBOUNCE: Duration = Duration::from_secs(900);

fn scratch(name: &str) -> PathBuf {
    // `HYDRATION_TEST_DIR` overrides this at run time, so the suite can be
    // pointed at a btrfs, ext4 or xfs mount without rebuilding.
    test_scratch::scratch(env!("CARGO_TARGET_TMPDIR"), &format!("upload/{name}"))
}

fn file_id(p: &Path) -> FileId {
    let md = std::fs::metadata(p).expect("stat");
    FileId {
        fsid: md.dev(),
        ino: md.ino(),
    }
}

/// Records what the cloud was actually asked to do, which is the only place
/// several of these bugs are visible.
#[derive(Default, Clone)]
struct Recorder {
    ops: Arc<Mutex<Vec<String>>>,
    next: Arc<Mutex<u32>>,
    /// Runs while the upload is "in flight", so a test can delete the file at
    /// exactly the wrong moment.
    during: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl Recorder {
    fn ops(&self) -> Vec<String> {
        self.ops.lock().unwrap().clone()
    }
}

impl Sink for Recorder {
    fn upload(&mut self, path: &Path, _existing: Option<&str>) -> io::Result<Uploaded> {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        self.ops.lock().unwrap().push(format!("PUT {name}"));
        // The upload is in flight from here until it returns.
        if let Some(f) = &self.during {
            f();
        }
        let mut n = self.next.lock().unwrap();
        *n += 1;
        Ok(Uploaded {
            cloud_id: format!("cloud-{n}"),
            etag: Some(format!("etag-{n}")),
        })
    }

    fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
        self.ops.lock().unwrap().push(format!("DELETE {cloud_id}"));
        Ok(())
    }
}

/// Rule 1: nothing goes out until the file has been quiet.
#[test]
fn an_edit_waits_out_the_quiet_period() {
    let clock = TestClock::default();
    let mut q = Queue::new(DEBOUNCE, clock.clone());
    let f = FileId { fsid: 1, ino: 1 };

    q.touch(f);
    assert!(
        q.due().is_empty(),
        "an upload started the moment it was queued"
    );

    clock.advance(DEBOUNCE - Duration::from_secs(1));
    assert!(q.due().is_empty(), "the quiet period ended early");

    clock.advance(Duration::from_secs(2));
    assert_eq!(q.due(), vec![f], "the edit never became due");
}

/// Rule 1: rewriting extends the window rather than queueing a second upload.
///
/// This is what stops ten saves becoming ten uploads that collide on the way
/// out — the churn that produced a stream of 409s in the client this replaces.
#[test]
fn rewriting_pushes_the_deadline_out_instead_of_queueing_again() {
    let clock = TestClock::default();
    let mut q = Queue::new(DEBOUNCE, clock.clone());
    let f = FileId { fsid: 1, ino: 1 };

    q.touch(f);
    clock.advance(DEBOUNCE - Duration::from_secs(1));
    q.touch(f); // the user saves again

    assert_eq!(
        q.waiting(),
        1,
        "a second upload was queued for the same file"
    );
    clock.advance(Duration::from_secs(2));
    assert!(
        q.due().is_empty(),
        "the second write did not extend the quiet period"
    );

    clock.advance(DEBOUNCE);
    assert_eq!(q.due(), vec![f]);
}

/// Rule 4: the count includes edits still waiting.
///
/// With a fifteen-minute window the waiting kind is the common one. A status
/// that omitted them would say "everything synced" over work that has not left
/// the machine — which is the same class of lie as the `fsync` bug.
#[test]
fn the_pending_count_includes_edits_that_have_not_started() {
    let clock = TestClock::default();
    let mut q = Queue::new(DEBOUNCE, clock.clone());

    assert_eq!(q.pending(), 0);
    q.touch(FileId { fsid: 1, ino: 1 });
    q.touch(FileId { fsid: 1, ino: 2 });
    assert_eq!(
        q.pending(),
        2,
        "waiting edits were not counted as unsent; the user would be shown 'synced'"
    );
}

/// Rule 1, the other half: a file written and deleted inside the window never
/// reaches the cloud at all.
#[test]
fn a_file_deleted_inside_the_quiet_period_never_uploads() {
    let dir = scratch("deleted-early");
    let path = dir.join("scratch.txt");
    std::fs::write(&path, b"transient").unwrap();
    let f = file_id(&path);

    let clock = TestClock::default();
    let mut q = Queue::new(DEBOUNCE, clock.clone());
    let mut store = Store::new();
    store.scan(&dir).unwrap();
    let mut sink = Recorder::default();

    q.touch(f);
    std::fs::remove_file(&path).unwrap();
    q.cancel(&f);

    clock.advance(DEBOUNCE * 2);
    assert!(q.due().is_empty(), "a deleted file was still queued");
    assert!(
        sink.ops().is_empty(),
        "something reached the cloud for a file that was deleted before it settled"
    );
    let _ = (&mut sink, &mut store);
}

/// Rule 2: the upload is addressed by the name the file has when the bytes go
/// out, not the one it had when the job was queued.
///
/// The bug: `write temp → rename over target` is how vim, VS Code and most build
/// tools save. The upload had captured the temp name, so the cloud ended up
/// holding the file as `README.md.tmp.194149.5089d5eff10a` and the next delta
/// dragged that name back down over the real one.
#[test]
fn an_atomic_save_uploads_under_the_name_the_file_ended_up_with() {
    let dir = scratch("atomic-save");
    let target = dir.join("README.md");
    let temp = dir.join("README.md.tmp.194149.5089d5eff10a");
    std::fs::write(&temp, b"edited\n").unwrap();
    let f = file_id(&temp);

    let clock = TestClock::default();
    let mut q = Queue::new(DEBOUNCE, clock.clone());
    let mut sink = Recorder::default();

    // Queued while the file is still called the temp name.
    q.touch(f);

    // The editor completes its save.
    std::fs::rename(&temp, &target).unwrap();

    let mut store = Store::new();
    store.scan(&dir).unwrap();

    clock.advance(DEBOUNCE * 2);
    assert_eq!(q.due(), vec![f]);
    let outcome = q.run_one(f, &mut store, &mut sink);

    assert!(matches!(outcome, Outcome::Sent { .. }), "{outcome:?}");
    assert_eq!(
        sink.ops(),
        vec!["PUT README.md"],
        "the upload went out under a name the file no longer had"
    );
}

/// Rule 3: a delete that lands while the upload is in flight still wins.
///
/// The bug: on completion the upload re-read its row, found it gone, and fell
/// back to its own stale in-memory copy — which put the file back in the cloud
/// complete with its contents. Absence is a decision, not missing information.
#[test]
fn a_delete_during_the_upload_removes_what_the_upload_just_created() {
    let dir = scratch("delete-inflight");
    let path = dir.join("churn.bin");
    std::fs::write(&path, b"transient").unwrap();
    let f = file_id(&path);

    let mut store = Store::new();
    store.scan(&dir).unwrap();

    // The delete lands strictly inside the upload window, every run.
    let doomed = path.clone();
    let sink_ops = Arc::new(Mutex::new(Vec::new()));
    let mut sink = Recorder {
        ops: Arc::clone(&sink_ops),
        next: Arc::new(Mutex::new(0)),
        during: Some(Arc::new(move || {
            let _ = std::fs::remove_file(&doomed);
        })),
    };

    let clock = TestClock::default();
    let mut q = Queue::new(DEBOUNCE, clock.clone());
    q.touch(f);
    clock.advance(DEBOUNCE * 2);

    let outcome = q.run_one(f, &mut store, &mut sink);

    assert_eq!(
        outcome,
        Outcome::DeletedInstead,
        "the upload finished and left the file in the cloud after it was deleted"
    );
    let ops = sink.ops();
    assert_eq!(
        ops.len(),
        2,
        "expected an upload and then a delete: {ops:?}"
    );
    assert!(ops[0].starts_with("PUT"), "{ops:?}");
    assert!(
        ops[1].starts_with("DELETE"),
        "the remote copy the upload created was not removed: {ops:?}"
    );
    assert!(!path.exists(), "the deleted file came back locally");
}

/// Rule 3, the cheap case: the file was gone before the bytes were due.
#[test]
fn a_file_gone_before_its_turn_uploads_nothing() {
    let dir = scratch("gone-early");
    let path = dir.join("vanished.txt");
    std::fs::write(&path, b"x").unwrap();
    let f = file_id(&path);
    let mut store = Store::new();
    store.scan(&dir).unwrap();
    std::fs::remove_file(&path).unwrap();

    let clock = TestClock::default();
    let mut q = Queue::new(DEBOUNCE, clock.clone());
    let mut sink = Recorder::default();
    q.touch(f);
    clock.advance(DEBOUNCE * 2);

    assert_eq!(q.run_one(f, &mut store, &mut sink), Outcome::NothingToDo);
    assert!(sink.ops().is_empty(), "{:?}", sink.ops());
}

/// Shutdown must not take the window's work with it.
#[test]
fn flushing_releases_everything_that_was_waiting() {
    let clock = TestClock::default();
    let mut q = Queue::new(DEBOUNCE, clock.clone());
    q.touch(FileId { fsid: 1, ino: 1 });
    q.touch(FileId { fsid: 1, ino: 2 });
    assert!(q.due().is_empty());

    q.flush_now();
    assert_eq!(
        q.due().len(),
        2,
        "a restart would have taken these edits with it"
    );
}

/// §5.1 at this layer: recording the cloud ID does not change what the file is.
#[test]
fn learning_the_cloud_id_does_not_change_the_inode() {
    let dir = scratch("identity");
    let path = dir.join("created.txt");
    std::fs::write(&path, b"scaffolded by npm init\n").unwrap();
    let before = file_id(&path);

    let mut store = Store::new();
    store.scan(&dir).unwrap();
    let mut sink = Recorder::default();
    let clock = TestClock::default();
    let mut q = Queue::new(DEBOUNCE, clock.clone());
    q.touch(before);
    clock.advance(DEBOUNCE * 2);

    assert!(matches!(
        q.run_one(before, &mut store, &mut sink),
        Outcome::Sent { .. }
    ));

    assert_eq!(
        file_id(&path),
        before,
        "the file changed identity when it learned its cloud id — the swap this \
         design exists to remove"
    );
    assert_eq!(
        store::get_xattr(&path, store::XATTR_ID)
            .unwrap()
            .map(|v| String::from_utf8(v).unwrap()),
        Some("cloud-1".to_string()),
        "the cloud id was not recorded on the file"
    );
    // And the entry still resolves, under the same identity it always had.
    assert_eq!(
        store.lookup(&before).unwrap().cloud_id.as_deref(),
        Some("cloud-1")
    );
}

/// An edit made while the upload is in flight must not be blessed as sent.
///
/// The stamp says "this content is what the framework last wrote", and a delta
/// pass refuses to overwrite a file whose stamp disagrees with it. Stamping from
/// the file *after* the transfer records whatever landed during it — so an edit
/// made mid-upload reads as clean, is never re-queued, and is destroyed by the
/// next remote change. The bytes that went out were the older ones.
#[test]
fn an_edit_during_the_upload_is_not_recorded_as_sent() {
    use hydration_protocol::stamp::{self, State};

    /// Edits the file while "uploading" it, which is what a slow transfer plus
    /// an impatient user amounts to.
    struct EditsMidFlight;
    impl Sink for EditsMidFlight {
        fn upload(&mut self, path: &Path, _existing: Option<&str>) -> io::Result<Uploaded> {
            let sent = std::fs::read(path)?;
            // The user saves again before the transfer finishes.
            std::fs::write(path, b"a much later version written during the upload")?;
            Ok(Uploaded {
                cloud_id: "cloud-1".into(),
                etag: Some(format!("{}", sent.len())),
            })
        }
        fn remove(&mut self, _cloud_id: &str) -> io::Result<()> {
            Ok(())
        }
    }

    let dir = scratch("edit-mid-upload");
    let p = dir.join("doc.txt");
    std::fs::write(&p, b"the version that gets sent").unwrap();

    let mut store = Store::new();
    store.scan(&dir).unwrap();
    let id = file_id(&p);
    let outcome = run_upload(id, &mut store, &mut EditsMidFlight);
    assert!(
        matches!(outcome, Outcome::Sent { .. }),
        "unexpected: {outcome:?}"
    );

    assert_eq!(
        stamp::state(&p).unwrap(),
        State::Dirty,
        "the edit that landed during the upload was recorded as sent; it will \
         never be re-queued and the next remote change will destroy it"
    );
}

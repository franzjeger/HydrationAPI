//! Measured: an empty sync root cannot delete anything from the cloud.
//!
//! The question this answers came from a live setup, not from theory. A sync
//! root was rebuilt from scratch — a fresh, empty btrfs subvolume — while the
//! account behind it held a quarter of a million objects. If local absence were
//! ever read as "the user deleted this", the first pass over that mount would
//! empty the account.
//!
//! Reading the code says it cannot: `run_upload` returns `NothingToDo` before it
//! touches the sink whenever the store does not know the file, and the store is
//! built by walking the local tree. But "reading the code says" is exactly the
//! standard this project rejects for anything that costs real data if it is
//! wrong, so this measures it instead.
//!
//! The second test is not decoration. Without it the first would pass against a
//! sink that is simply incapable of recording a deletion, which is the failure
//! mode that makes a green test worse than no test: it would report safety for
//! the one reason that has nothing to do with safety.

use hydration_client::delta::{apply, Change};
use hydration_client::place::TmpfilePlacer;
use hydration_client::store::Store;
use hydration_client::upload::{run_upload, Known, Outcome, Sink, Uploaded};
use hydration_protocol::FileId;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

fn scratch(name: &str) -> PathBuf {
    // `HYDRATION_TEST_DIR` overrides this at run time so the suite can be
    // pointed at btrfs, ext4 or xfs without rebuilding.
    test_scratch::scratch(env!("CARGO_TARGET_TMPDIR"), &format!("empty-mount/{name}"))
}

fn file_id(p: &Path) -> FileId {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(p).expect("stat");
    FileId {
        fsid: md.dev(),
        ino: md.ino(),
    }
}

/// A cloud that records what was asked of it and refuses nothing.
///
/// `delete_on_upload` reproduces the one race that legitimately reaches
/// `remove`: the local file disappears while its bytes are in flight, so the
/// object the upload has just created is the thing that has to go.
#[derive(Default)]
struct RecordingSink {
    removed: Vec<String>,
    uploaded: Vec<PathBuf>,
    delete_on_upload: Option<PathBuf>,
    next_id: usize,
}

impl Sink for RecordingSink {
    fn upload(&mut self, path: &Path, _existing: Option<Known<'_>>) -> io::Result<Uploaded> {
        self.uploaded.push(path.to_path_buf());
        if let Some(victim) = self.delete_on_upload.take() {
            std::fs::remove_file(&victim)?;
        }
        self.next_id += 1;
        Ok(Uploaded {
            cloud_id: format!("cloud-{}", self.next_id),
            etag: None,
        })
    }

    fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
        self.removed.push(cloud_id.to_owned());
        Ok(())
    }
}

/// The claim: nothing local, everything remote, and the cloud keeps everything.
#[test]
fn an_empty_mount_deletes_nothing() {
    let root = scratch("empty");
    // Deliberately not populated. This is the live situation: the mount was
    // replaced, so every object in the account exists only remotely.
    let mut store = Store::new();
    let found = store.scan(&root).expect("scan");
    assert_eq!(found, 0, "the mount under test has to actually be empty");

    // A file id that once existed and no longer does — the strongest form of the
    // input, because it is a real id rather than an invented one. Anything that
    // reached the queue during a wipe would look exactly like this.
    let ghost = root.join("ghost");
    std::fs::write(&ghost, b"gone in a moment").expect("write");
    let ghost_id = file_id(&ghost);
    std::fs::remove_file(&ghost).expect("remove");

    let mut sink = RecordingSink::default();
    let outcome = run_upload(ghost_id, &mut store, &mut sink);

    assert_eq!(outcome, Outcome::NothingToDo);
    assert!(
        sink.removed.is_empty(),
        "an absent local file asked the cloud to delete {:?}",
        sink.removed
    );
    assert!(
        sink.uploaded.is_empty(),
        "an absent local file was sent as content: {:?}",
        sink.uploaded
    );
}

/// The control: the same sink, in the one case that *must* delete.
///
/// If this ever stops recording a removal, the test above is measuring nothing.
#[test]
fn the_recorder_does_see_a_deletion_when_one_is_owed() {
    let root = scratch("control");
    let mut store = Store::new();
    let mut placer = TmpfilePlacer::new(&root).expect("open the sync root");

    // A real local file, known to the store, exactly as one that had been
    // written and was waiting out its debounce.
    let path = root.join("doomed.txt");
    std::fs::write(&path, b"content that is about to vanish").expect("write");
    apply(
        &root,
        &[] as &[Change],
        &mut store,
        &HashSet::new(),
        &mut placer,
    )
    .expect("apply");
    store.scan(&root).expect("scan");
    let id = file_id(&path);
    assert!(
        store.lookup(&id).is_some(),
        "the control needs the store to know this file"
    );

    // The race: the file goes away while its bytes are in flight.
    let mut sink = RecordingSink {
        delete_on_upload: Some(path.clone()),
        ..Default::default()
    };
    let outcome = run_upload(id, &mut store, &mut sink);

    assert_eq!(
        outcome,
        Outcome::DeletedInstead,
        "a file deleted mid-upload must not be left in the cloud"
    );
    assert_eq!(
        sink.removed.len(),
        1,
        "the recorder failed to see a deletion it was owed: {:?}",
        sink.removed
    );
}

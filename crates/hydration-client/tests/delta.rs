//! Delta reconciliation: what happens when the cloud has news.
//!
//! The rule under test throughout is §5.2 applied to the arriving side: the
//! local copy is the truth. A delta pass may create and may refresh, but it must
//! never replace content that exists nowhere else.

use hydration_client::delta::{apply, Applied, Change, Materialise};
use hydration_client::store::{self, Store};
use hydration_client::upload::{Queue, TestClock};
use hydration_protocol::FileId;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("delta")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("scratch");
    d
}

fn file_id(p: &Path) -> FileId {
    let md = std::fs::metadata(p).expect("stat");
    FileId {
        fsid: md.dev(),
        ino: md.ino(),
    }
}

/// Stands in for the privileged creation path. What it does is not under test
/// here; that it is called with the right arguments, and not called at all when
/// local work would be lost, is.
#[derive(Default)]
struct Recorder {
    placed: Vec<String>,
    removed: Vec<String>,
}

impl Materialise for Recorder {
    fn place(
        &mut self,
        path: &Path,
        size: u64,
        cloud_id: &str,
        etag: Option<&str>,
    ) -> io::Result<()> {
        self.placed.push(path.display().to_string());
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.set_len(size)?;
        store::set_xattr(path, hydration_protocol::xattr::DEHYDRATED, b"1")?;
        store::set_xattr(path, store::XATTR_ID, cloud_id.as_bytes())?;
        if let Some(e) = etag {
            store::set_xattr(path, store::XATTR_ETAG, e.as_bytes())?;
        }
        Ok(())
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        self.removed.push(path.display().to_string());
        std::fs::remove_file(path)
    }
}

fn upserted(path: &str, size: u64, id: &str) -> Change {
    Change::Upserted {
        cloud_id: id.into(),
        path: path.into(),
        size,
        etag: Some("etag-1".into()),
    }
}

fn run(root: &Path, changes: &[Change], q: &Queue<TestClock>, m: &mut Recorder) -> Applied {
    let mut store = Store::new();
    apply(root, changes, &mut store, q, m).expect("apply")
}

#[test]
fn a_new_cloud_object_becomes_a_placeholder() {
    let dir = scratch("new");
    let q = Queue::new(Duration::from_secs(900), TestClock::default());
    let mut m = Recorder::default();

    let out = run(
        &dir,
        &[upserted("sub/report.pdf", 4096, "cloud-1")],
        &q,
        &mut m,
    );

    assert_eq!(out.created, 1, "{out:?}");
    let p = dir.join("sub/report.pdf");
    assert_eq!(std::fs::metadata(&p).unwrap().len(), 4096);
    assert_eq!(
        store::get_xattr(&p, store::XATTR_ID).unwrap().unwrap(),
        b"cloud-1"
    );
}

/// The rule this module exists for.
///
/// An edit waiting out the debounce lives only on this machine. Replacing it
/// with a placeholder for the cloud's older version destroys work that exists
/// nowhere else — silently, because from the user's side the file simply
/// reverts.
#[test]
fn an_unsent_local_edit_is_never_replaced_by_the_cloud_version() {
    let dir = scratch("unsent");
    let p = dir.join("notes.txt");
    std::fs::write(&p, b"the edit i just made and have not uploaded").unwrap();

    let clock = TestClock::default();
    let mut q = Queue::new(Duration::from_secs(900), clock.clone());
    q.touch(file_id(&p));

    let mut m = Recorder::default();
    let out = run(&dir, &[upserted("notes.txt", 9, "cloud-1")], &q, &mut m);

    assert_eq!(out.kept_local, vec!["notes.txt".to_string()], "{out:?}");
    assert_eq!(out.updated, 0);
    assert!(m.placed.is_empty(), "the local edit was overwritten");
    assert_eq!(
        std::fs::read(&p).unwrap(),
        b"the edit i just made and have not uploaded"
    );
}

/// Local content the cloud has never seen is in the same position even with
/// nothing queued: there is no remote copy to fall back on.
#[test]
fn local_content_that_was_never_uploaded_is_kept() {
    let dir = scratch("never-uploaded");
    let p = dir.join("draft.md");
    std::fs::write(&p, b"written offline, never sent").unwrap();
    // Deliberately no cloud id, and nothing queued.

    let q = Queue::new(Duration::from_secs(900), TestClock::default());
    let mut m = Recorder::default();
    let out = run(&dir, &[upserted("draft.md", 5, "cloud-9")], &q, &mut m);

    assert_eq!(out.kept_local, vec!["draft.md".to_string()], "{out:?}");
    assert_eq!(std::fs::read(&p).unwrap(), b"written offline, never sent");
}

/// A file that is already a placeholder can be refreshed freely — there is no
/// local content to lose.
#[test]
fn an_existing_placeholder_is_refreshed() {
    let dir = scratch("refresh");
    let mut m = Recorder::default();
    let q = Queue::new(Duration::from_secs(900), TestClock::default());

    run(&dir, &[upserted("a.bin", 100, "cloud-1")], &q, &mut m);
    let out = run(&dir, &[upserted("a.bin", 250, "cloud-1")], &q, &mut m);

    assert_eq!(out.updated, 1, "{out:?}");
    assert_eq!(std::fs::metadata(dir.join("a.bin")).unwrap().len(), 250);
}

/// A removal names an object, not a path — the file may have been renamed here
/// since, and matching by name would miss it.
#[test]
fn a_remote_deletion_finds_the_file_even_after_a_local_rename() {
    let dir = scratch("removed");
    let mut m = Recorder::default();
    let q = Queue::new(Duration::from_secs(900), TestClock::default());
    run(&dir, &[upserted("old-name.bin", 64, "cloud-5")], &q, &mut m);

    std::fs::rename(dir.join("old-name.bin"), dir.join("new-name.bin")).unwrap();

    let out = run(
        &dir,
        &[Change::Removed {
            cloud_id: "cloud-5".into(),
        }],
        &q,
        &mut m,
    );

    assert_eq!(out.removed, 1, "{out:?}");
    assert!(!dir.join("new-name.bin").exists(), "the file survived");
}

/// And a removal loses to an unsent local edit, for the same reason an upsert
/// does: the edit is the newer intention here, and nothing else has a copy.
#[test]
fn a_remote_deletion_does_not_destroy_an_unsent_local_edit() {
    let dir = scratch("removed-vs-edit");
    let mut m = Recorder::default();
    let clock = TestClock::default();
    let mut q = Queue::new(Duration::from_secs(900), clock);
    run(&dir, &[upserted("doc.txt", 32, "cloud-3")], &q, &mut m);

    let p = dir.join("doc.txt");
    std::fs::write(&p, b"edited here after the remote delete was issued").unwrap();
    q.touch(file_id(&p));

    let out = run(
        &dir,
        &[Change::Removed {
            cloud_id: "cloud-3".into(),
        }],
        &q,
        &mut m,
    );

    assert!(p.exists(), "an unsent edit was deleted by a remote removal");
    assert_eq!(out.removed, 0);
    assert_eq!(out.kept_local.len(), 1, "{out:?}");
}

/// A removal for something we never had is the state we wanted, not a failure.
#[test]
fn a_removal_for_an_unknown_object_is_not_an_error() {
    let dir = scratch("unknown-removal");
    let q = Queue::new(Duration::from_secs(900), TestClock::default());
    let mut m = Recorder::default();

    let out = run(
        &dir,
        &[Change::Removed {
            cloud_id: "never-heard-of-it".into(),
        }],
        &q,
        &mut m,
    );
    assert_eq!(out, Applied::default(), "{out:?}");
}

/// The cloud supplies these paths, so they are untrusted input.
#[test]
fn a_cloud_path_that_escapes_the_sync_root_is_refused() {
    let dir = scratch("escape");
    let q = Queue::new(Duration::from_secs(900), TestClock::default());
    let mut m = Recorder::default();

    let out = run(
        &dir,
        &[
            upserted("../../../tmp/evil", 10, "cloud-1"),
            upserted("/etc/cron.d/evil", 10, "cloud-2"),
        ],
        &q,
        &mut m,
    );

    assert_eq!(out.created, 0);
    assert_eq!(out.failed.len(), 2, "{out:?}");
    assert!(
        m.placed.is_empty(),
        "a remote service placed a file outside the sync directory: {:?}",
        m.placed
    );
}

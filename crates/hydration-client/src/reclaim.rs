//! Giving the disk back, without asking the privileged side for anything.
//!
//! Eviction was the last thing in §8 with no trigger, and the reason was §6b: a
//! trigger has to name a file, and the privileged side never accepts a
//! destination from the unprivileged one. Handing root a path to punch a hole in
//! is worse than handing it a path to write to — it is arbitrary destruction as
//! root — and handing out the ability to suppress events on a named inode is the
//! ability to make any file read as zeros.
//!
//! The way out is the one placeholder creation already found. A placeholder does
//! not have to be made by hollowing out the file that is there; it can be built
//! on an anonymous inode and swapped in. [`TmpfilePlacer`] already does exactly
//! that, and it needs no privilege at all — so eviction is just placement over a
//! file that currently has content, and the privileged half is not involved.
//!
//! What changes versus punching a hole in place:
//!
//! - **The inode is replaced.** Anyone holding the old file open keeps reading
//!   the content they opened — which is better than having it removed from
//!   underneath them — and its blocks are freed when they let go. Hard links to
//!   the old inode keep the content, so eviction frees nothing for those until
//!   the last link is gone; that is the honest outcome, since the content is
//!   still reachable by another name.
//! - **No ignore mark has to be removed.** The old inode's mark dies with it and
//!   the new inode has never had one, so the file is intercepted again by
//!   construction rather than by a privileged call that has to be sequenced
//!   correctly.
//!
//! [`crate::place::TmpfilePlacer`] is the mechanism; this module is the decision.
//! `hydrationd`'s own `evict` still exists for a caller that *does* hold the
//! fanotify group — the conformance adapter is one — and punches in place there.

use crate::delta::Materialise;
use crate::place::TmpfilePlacer;
use crate::store::{self, Store};
use hydration_protocol::{stamp, FileId};
use std::collections::HashSet;
use std::io;
use std::path::Path;

/// Why a file was left alone.
///
/// Every one of these is a refusal to destroy something, so they are values a
/// caller can show rather than errors it can ignore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// No content here to reclaim.
    AlreadyDehydrated,
    /// Nothing in the cloud has this file's content. Throwing it away to save
    /// disk would be indistinguishable from deleting it, and the user would
    /// find out by reading zeros.
    NotUploaded,
    /// Edited since we last sent it. The local copy is the only copy of those
    /// bytes.
    ChangedSinceUpload,
    /// An edit is waiting out the debounce, or is being sent right now.
    UploadPending,
    /// Not a regular file, or not ours to touch.
    NotEligible(String),
}

/// What was reclaimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reclaimed {
    pub bytes: u64,
}

/// Turn a file with content back into a placeholder.
///
/// `waiting` and `sending` are snapshots of the upload queue: edits waiting out
/// the debounce, and uploads already under way. Both are consulted rather than locked, for the reason
/// [`crate::delta::apply`] documents: holding the queue across this would block
/// the thread that reports local edits, so the very edits that should stop an
/// eviction could not reach the queue in time to do it.
pub fn reclaim(
    root: &Path,
    path: &Path,
    store: &mut Store,
    waiting: &HashSet<FileId>,
    sending: &HashSet<FileId>,
) -> io::Result<Result<Reclaimed, Refused>> {
    let md = match std::fs::metadata(path) {
        Ok(md) if md.is_file() => md,
        Ok(_) => {
            return Ok(Err(Refused::NotEligible(
                "not a regular file".to_string(),
            )))
        }
        Err(e) => return Err(e),
    };
    if !path.starts_with(root) {
        return Ok(Err(Refused::NotEligible(
            "outside the sync directory".to_string(),
        )));
    }
    if path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(hydration_protocol::names::is_internal)
    {
        return Ok(Err(Refused::NotEligible(
            "one of the framework's own files".to_string(),
        )));
    }
    if store::get_xattr(path, hydration_protocol::xattr::DEHYDRATED)?.is_some() {
        return Ok(Err(Refused::AlreadyDehydrated));
    }

    use std::os::unix::fs::MetadataExt;
    let id = FileId {
        fsid: md.dev(),
        ino: md.ino(),
    };
    if waiting.contains(&id) || sending.contains(&id) {
        return Ok(Err(Refused::UploadPending));
    }

    // The whole point of eviction is that the content can be fetched again.
    let Some(cloud_id) = store::get_xattr(path, store::XATTR_ID)?
        .and_then(|v| String::from_utf8(v).ok())
        .filter(|s| !s.is_empty())
    else {
        return Ok(Err(Refused::NotUploaded));
    };

    // And that what is up there is *this* content. A file edited since it was
    // sent has bytes that exist only here, and no notification is needed to see
    // it — the stamp is what makes this answerable without one, which is the
    // whole reason it exists.
    match stamp::state(path)? {
        stamp::State::Clean => {}
        // Unstamped means the framework has never made this file clean, so it
        // cannot claim the cloud copy matches. Refusing is the safe reading, and
        // the file will be picked up by the next resync walk and sent.
        stamp::State::Dirty | stamp::State::Unstamped => {
            return Ok(Err(Refused::ChangedSinceUpload))
        }
    }

    let etag = store::get_xattr(path, store::XATTR_ETAG)?.and_then(|v| String::from_utf8(v).ok());

    // Built anonymously and swapped in, so the file is never observable in a
    // half-evicted state: it is either the full content or a complete
    // placeholder, and nothing in between is ever reachable by name.
    let mut placer = TmpfilePlacer::new(root);
    placer.place(path, md.len(), &cloud_id, etag.as_deref())?;

    // The store's entry pointed at the old inode, which no longer exists.
    store.forget(&id);
    Ok(Ok(Reclaimed { bytes: md.len() }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/reclaim-tests")
            .join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A file that has been sent and not touched since.
    fn synced(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        store::set_xattr(&p, store::XATTR_ID, b"cloud-1").unwrap();
        store::set_xattr(&p, store::XATTR_ETAG, b"etag-1").unwrap();
        stamp::write(&p).unwrap();
        p
    }

    fn run(dir: &Path, p: &Path) -> Result<Reclaimed, Refused> {
        let mut store = Store::new();
        store.scan(dir).unwrap();
        reclaim(dir, p, &mut store, &HashSet::new(), &HashSet::new()).unwrap()
    }

    #[test]
    fn a_synced_file_gives_its_disk_back_and_keeps_its_identity() {
        use std::os::unix::fs::MetadataExt;
        let dir = scratch("basic");
        let p = synced(&dir, "report.pdf", &vec![b'x'; 8192]);

        assert_eq!(run(&dir, &p).unwrap(), Reclaimed { bytes: 8192 });

        let md = std::fs::metadata(&p).unwrap();
        assert_eq!(md.len(), 8192, "the size no longer describes the object");
        assert_eq!(md.blocks(), 0, "the disk was not returned");
        assert_eq!(
            store::get_xattr(&p, store::XATTR_ID).unwrap().unwrap(),
            b"cloud-1"
        );
        assert!(
            store::get_xattr(&p, hydration_protocol::xattr::DEHYDRATED)
                .unwrap()
                .is_some(),
            "the placeholder is unmarked and would never be intercepted"
        );
    }

    /// The rule the module exists for. A file whose only copy is this one is not
    /// a candidate at any price.
    #[test]
    fn a_file_the_cloud_does_not_have_is_never_evicted() {
        let dir = scratch("not-uploaded");
        let p = dir.join("draft.md");
        std::fs::write(&p, b"written offline, never sent").unwrap();
        stamp::write(&p).unwrap();

        assert_eq!(run(&dir, &p), Err(Refused::NotUploaded));
        assert_eq!(std::fs::read(&p).unwrap(), b"written offline, never sent");
    }

    /// Edited since it was sent: those bytes exist only here, and no
    /// notification is needed to see it.
    #[test]
    fn a_file_edited_since_the_upload_is_never_evicted() {
        let dir = scratch("edited");
        let p = synced(&dir, "notes.txt", b"the version we sent");
        std::fs::write(&p, b"a later version that was never sent anywhere").unwrap();

        assert_eq!(run(&dir, &p), Err(Refused::ChangedSinceUpload));
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"a later version that was never sent anywhere"
        );
    }

    #[test]
    fn a_file_with_an_edit_waiting_is_never_evicted() {
        use std::os::unix::fs::MetadataExt;
        let dir = scratch("waiting");
        let p = synced(&dir, "doc.txt", b"content");
        let md = std::fs::metadata(&p).unwrap();
        let id = FileId {
            fsid: md.dev(),
            ino: md.ino(),
        };

        let mut store = Store::new();
        store.scan(&dir).unwrap();
        let waiting: HashSet<FileId> = [id].into_iter().collect();
        assert_eq!(
            reclaim(&dir, &p, &mut store, &waiting, &HashSet::new()).unwrap(),
            Err(Refused::UploadPending)
        );
        // And the same file being sent right now.
        assert_eq!(
            reclaim(&dir, &p, &mut store, &HashSet::new(), &[id].into_iter().collect()).unwrap(),
            Err(Refused::UploadPending)
        );
        assert_eq!(std::fs::read(&p).unwrap(), b"content");
    }

    #[test]
    fn evicting_a_placeholder_is_refused_rather_than_repeated() {
        let dir = scratch("already");
        let p = synced(&dir, "a.bin", &vec![b'y'; 256]);
        run(&dir, &p).unwrap();
        assert_eq!(run(&dir, &p), Err(Refused::AlreadyDehydrated));
    }

    /// The trigger names a file, so the name is untrusted input.
    #[test]
    fn a_path_outside_the_sync_directory_is_refused() {
        let dir = scratch("outside");
        let outside = dir.parent().unwrap().join("not-ours.txt");
        std::fs::write(&outside, b"someone else's file").unwrap();

        let mut store = Store::new();
        store.scan(&dir).unwrap();
        assert!(matches!(
            reclaim(&dir, &outside, &mut store, &HashSet::new(), &HashSet::new()).unwrap(),
            Err(Refused::NotEligible(_))
        ));
        assert_eq!(std::fs::read(&outside).unwrap(), b"someone else's file");
    }

    /// And the framework's own files are not the user's to reclaim.
    #[test]
    fn the_manifest_is_not_a_candidate() {
        let dir = scratch("manifest");
        let p = dir.join(hydration_protocol::names::MANIFEST);
        std::fs::write(&p, b"# the manifest").unwrap();

        let mut store = Store::new();
        store.scan(&dir).unwrap();
        assert!(matches!(
            reclaim(&dir, &p, &mut store, &HashSet::new(), &HashSet::new()).unwrap(),
            Err(Refused::NotEligible(_))
        ));
    }
}

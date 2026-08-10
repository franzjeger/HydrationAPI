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
/// `rel` is relative to `root` and is untrusted: it comes from whoever asked for
/// the eviction, which in practice is a socket. It is resolved through the same
/// [`crate::delta::safe_join`] the cloud's paths go through, and then through
/// the filesystem, so neither `..` nor a symlinked subdirectory can lead this
/// out of the sync directory.
///
/// `waiting` and `sending` are snapshots of the upload queue: edits waiting out
/// the debounce, and uploads already under way. Both are consulted rather than locked, for the reason
/// [`crate::delta::apply`] documents: holding the queue across this would block
/// the thread that reports local edits, so the very edits that should stop an
/// eviction could not reach the queue in time to do it.
pub fn reclaim(
    root: &Path,
    rel: &str,
    store: &mut Store,
    waiting: &HashSet<FileId>,
    sending: &HashSet<FileId>,
) -> io::Result<Result<Reclaimed, Refused>> {
    // Confinement is structural, not checked.
    //
    // The first version took an absolute path and asked whether it began with
    // the root. `Path::starts_with` compares components lexically and does not
    // resolve `..`, so *every* escaping path began with the root and passed —
    // `evict ../SECRET.txt` replaced a file outside the sync directory with a
    // placeholder whose cloud id resolves nowhere, which is that file's content
    // destroyed and read as zeros forever. `safe_join` already existed for
    // exactly this, on the delta side, and refuses `..`, absolute paths and the
    // framework's own names outright.
    let Some(joined) = crate::delta::safe_join(root, rel) else {
        return Ok(Err(Refused::NotEligible(format!(
            "{rel:?} is not a path inside the sync directory"
        ))));
    };

    let md = match std::fs::metadata(&joined) {
        Ok(md) if md.is_file() => md,
        Ok(_) => return Ok(Err(Refused::NotEligible("not a regular file".to_string()))),
        Err(e) => return Err(e),
    };

    // And then symlinks, which no amount of component checking catches: a
    // symlinked subdirectory inside the root gives a path that is entirely
    // `Normal` and still lands outside. Resolved forms contain no `..` and no
    // links, so comparing them is sound in a way comparing the originals is not.
    let (Ok(real), Ok(real_root)) = (joined.canonicalize(), root.canonicalize()) else {
        return Ok(Err(Refused::NotEligible(
            "could not resolve the path".to_string(),
        )));
    };
    if !real.starts_with(&real_root) {
        return Ok(Err(Refused::NotEligible(
            "resolves outside the sync directory".to_string(),
        )));
    }
    let path = &real;

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

    // What the old inode actually held. Not `md.len()`: that is the logical
    // size, and the two differ in both directions. A file already partly
    // sparse holds less than its length, and on a filesystem that spills
    // extended attributes into a block of their own the placeholder that
    // replaces it does not reach zero — §8z measures one full block on ext4
    // with a 128- or 256-byte inode, and nothing at all on btrfs, xfs, or ext4
    // with room in the inode.
    //
    // Reporting the length would therefore claim space back that was never
    // freed, differently on different filesystems, and a quota built on that
    // number overshoots by a block per file: 390 MiB across a hundred thousand
    // files at a 4 KiB block size.
    let held_before = md.blocks() * 512;

    // Built anonymously and swapped in, so the file is never observable in a
    // half-evicted state: it is either the full content or a complete
    // placeholder, and nothing in between is ever reachable by name.
    let mut placer = TmpfilePlacer::new(root);
    placer.place(path, md.len(), &cloud_id, etag.as_deref())?;

    // Measured rather than assumed, for the same reason §5.8 probes for the
    // floor instead of hard-coding it: the answer depends on the filesystem,
    // its inode size, and its block size, and this code does not get to know
    // which one it is running on.
    let held_after = std::fs::symlink_metadata(path)
        .map(|m| m.blocks() * 512)
        .unwrap_or(0);

    // The store's entry pointed at the old inode, which no longer exists.
    store.forget(&id);
    Ok(Ok(Reclaimed {
        bytes: held_before.saturating_sub(held_after),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydration_protocol::holds_data;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    fn scratch(name: &str) -> PathBuf {
        // Not /tmp: this needs a filesystem with O_TMPFILE and user extended
        // attributes. `HYDRATION_TEST_DIR` points it at whichever one is under
        // test; unset, it lands beside the target directory as before.
        //
        // `CARGO_TARGET_TMPDIR` is not available to a unit test inside the
        // library — cargo only sets it for integration tests — so the fallback
        // is spelled out from the manifest directory.
        test_scratch::scratch(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
            &format!("reclaim-tests/{name}"),
        )
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

    fn run(dir: &Path, rel: &str) -> Result<Reclaimed, Refused> {
        let mut store = Store::new();
        store.scan(dir).unwrap();
        reclaim(dir, rel, &mut store, &HashSet::new(), &HashSet::new()).unwrap()
    }

    #[test]
    fn a_synced_file_gives_its_disk_back_and_keeps_its_identity() {
        let dir = scratch("basic");
        let p = synced(&dir, "report.pdf", &vec![b'x'; 8192]);

        assert_eq!(run(&dir, "report.pdf").unwrap(), Reclaimed { bytes: 8192 });

        let md = std::fs::metadata(&p).unwrap();
        assert_eq!(md.len(), 8192, "the size no longer describes the object");
        assert!(!holds_data(&p).unwrap(), "the content was not returned");
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

        assert_eq!(run(&dir, "draft.md"), Err(Refused::NotUploaded));
        assert_eq!(std::fs::read(&p).unwrap(), b"written offline, never sent");
    }

    /// Edited since it was sent: those bytes exist only here, and no
    /// notification is needed to see it.
    #[test]
    fn a_file_edited_since_the_upload_is_never_evicted() {
        let dir = scratch("edited");
        let p = synced(&dir, "notes.txt", b"the version we sent");
        std::fs::write(&p, b"a later version that was never sent anywhere").unwrap();

        assert_eq!(run(&dir, "notes.txt"), Err(Refused::ChangedSinceUpload));
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"a later version that was never sent anywhere"
        );
    }

    #[test]
    fn a_file_with_an_edit_waiting_is_never_evicted() {
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
            reclaim(&dir, "doc.txt", &mut store, &waiting, &HashSet::new()).unwrap(),
            Err(Refused::UploadPending)
        );
        // And the same file being sent right now.
        assert_eq!(
            reclaim(
                &dir,
                "doc.txt",
                &mut store,
                &HashSet::new(),
                &[id].into_iter().collect()
            )
            .unwrap(),
            Err(Refused::UploadPending)
        );
        assert_eq!(std::fs::read(&p).unwrap(), b"content");
    }

    #[test]
    fn evicting_a_placeholder_is_refused_rather_than_repeated() {
        let dir = scratch("already");
        synced(&dir, "a.bin", &vec![b'y'; 256]);
        run(&dir, "a.bin").unwrap();
        assert_eq!(run(&dir, "a.bin"), Err(Refused::AlreadyDehydrated));
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
            reclaim(
                &dir,
                outside.to_str().unwrap(),
                &mut store,
                &HashSet::new(),
                &HashSet::new()
            )
            .unwrap(),
            Err(Refused::NotEligible(_))
        ));
        assert_eq!(std::fs::read(&outside).unwrap(), b"someone else's file");
    }

    /// The shape the first guard let through.
    ///
    /// It compared components lexically, and `Path::starts_with` does not
    /// resolve `..` — so every escaping path *began* with the root and passed.
    /// Eviction then replaced a file outside the sync directory with a
    /// placeholder whose cloud id resolves nowhere, which is that file's content
    /// destroyed and reading it as zeros forever.
    ///
    /// The escape is only interesting for a file that has hydration xattrs, and
    /// that is not exotic: a rename out of the sync tree preserves them, and a
    /// second sync root under a shared parent is reachable as `../other/x`.
    #[test]
    fn a_path_that_walks_out_of_the_sync_directory_is_refused() {
        let dir = scratch("escape");
        let victim = dir.parent().unwrap().join("escape-victim.txt");
        std::fs::write(&victim, b"the only copy of this").unwrap();
        // Given the same marks a file that had once been synced would carry.
        store::set_xattr(&victim, store::XATTR_ID, b"cloud-1").unwrap();
        stamp::write(&victim).unwrap();

        let mut store = Store::new();
        store.scan(&dir).unwrap();
        assert!(
            matches!(
                reclaim(
                    &dir,
                    "../escape-victim.txt",
                    &mut store,
                    &HashSet::new(),
                    &HashSet::new()
                )
                .unwrap(),
                Err(Refused::NotEligible(_))
            ),
            "a `..` walked out of the sync directory and evicted someone else's file"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"the only copy of this");
    }

    /// Every shape a caller might send, refused without the daemon minding.
    ///
    /// The control socket is line-oriented and takes the argument verbatim, so
    /// these are literally what arrives. A refusal has to be a value, not a
    /// panic: the daemon serving this is the same one holding every reader's
    /// hydration open.
    #[test]
    fn hostile_arguments_are_refused_and_none_of_them_panic() {
        let dir = scratch("hostile");
        let mut store = Store::new();
        store.scan(&dir).unwrap();
        for arg in [
            "../../../etc/hosts",
            "/etc/passwd",
            "..",
            "",
            ".",
            "./x",
            "a/../../b",
            "sub/../../../out",
            ".hydration-manifest",
            "\u{0}weird",
        ] {
            let out = reclaim(&dir, arg, &mut store, &HashSet::new(), &HashSet::new());
            assert!(
                matches!(out, Ok(Err(Refused::NotEligible(_))) | Err(_)),
                "{arg:?} was not refused: {out:?}"
            );
        }
    }

    /// And the same escape through a symlinked subdirectory, which no amount of
    /// component checking catches — the path is entirely `Normal`.
    #[test]
    fn a_symlinked_subdirectory_cannot_be_used_to_escape() {
        let dir = scratch("symlink-escape");
        let victim = dir.parent().unwrap().join("symlink-victim.txt");
        std::fs::write(&victim, b"also the only copy").unwrap();
        store::set_xattr(&victim, store::XATTR_ID, b"cloud-1").unwrap();
        stamp::write(&victim).unwrap();
        std::os::unix::fs::symlink(dir.parent().unwrap(), dir.join("out")).unwrap();

        let mut store = Store::new();
        store.scan(&dir).unwrap();
        assert!(
            matches!(
                reclaim(
                    &dir,
                    "out/symlink-victim.txt",
                    &mut store,
                    &HashSet::new(),
                    &HashSet::new()
                )
                .unwrap(),
                Err(Refused::NotEligible(_))
            ),
            "a symlinked subdirectory led eviction out of the sync directory"
        );
        assert_eq!(std::fs::read(&victim).unwrap(), b"also the only copy");
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
            reclaim(
                &dir,
                hydration_protocol::names::MANIFEST,
                &mut store,
                &HashSet::new(),
                &HashSet::new()
            )
            .unwrap(),
            Err(Refused::NotEligible(_))
        ));
    }
}

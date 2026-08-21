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

use crate::place::{ConditionalPlace, ReplacementGuard, TmpfilePlacer};
use crate::store::{self, Store};
use hydration_protocol::{stamp, FileId};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

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
    /// The user asked to keep this on device — directly, or through a pinned
    /// ancestor directory. `via` names where the pin actually is, which is not
    /// the file itself when a folder was pinned. Refusing is the whole point.
    Pinned { via: PathBuf },
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
    reclaim_with(root, rel, store, waiting, sending, |_| {})
}

/// The eviction decision with one seam at the race boundary.
///
/// Production passes a no-op. The regression test replaces the target here,
/// after every eligibility check but before the atomic conditional exchange,
/// so the data-loss interleaving is deterministic rather than scheduler luck.
fn reclaim_with(
    root: &Path,
    rel: &str,
    store: &mut Store,
    waiting: &HashSet<FileId>,
    sending: &HashSet<FileId>,
    before_replace: impl FnOnce(&Path),
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

    // Sync-ignore: an ignored path is never evicted, even by an explicit `evict`.
    // Defence-in-depth to the enumerator's skip, and load-bearing where the file
    // carries a cloud id — the no-cloud-id gate below would otherwise let a real
    // `.git/` file be dehydrated into a placeholder. Loaded fresh so the answer
    // matches the current `.hydration-ignore`, not a possibly-stale store.
    if crate::store::load_ignore(root).is_ignored(std::path::Path::new(rel)) {
        return Ok(Err(Refused::NotEligible(format!(
            "{rel:?} is sync-ignored and is kept as a real local file"
        ))));
    }

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

    // Keep on Device wins over every reason to evict, and this is the place it is
    // honored: the one chokepoint both the manual path and any future auto-
    // eviction policy pass through to do the inode swap. Checked before the
    // upload snapshot, the stamp read, and placement — a pinned file is simply
    // not touched. The pin may live on an ancestor directory, so the whole chain
    // up to the sync root is consulted; nothing is stamped on the child, so a
    // file that arrived later under a pinned folder is covered with no write to
    // it. See `docs/KEEP-ON-DEVICE-GROUNDWORK.md` §1.4 and §3.2.
    if let Some(via) = pinned_self_or_ancestor(path, &real_root)? {
        return Ok(Err(Refused::Pinned { via }));
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
    //
    // Opened per eviction rather than held, because eviction is rare and the
    // descriptor a placer pins would otherwise keep a detached sync filesystem
    // alive for the life of the daemon. Opening here also means the root is
    // resolved once, at the start of the swap, rather than separately by each
    // syscall that makes it up.
    //
    // `real_root`, not `root`. The placer works out where to put a file by
    // taking the path apart against its own root, so the two have to be in the
    // same form — and `path` is `real`, which is canonical. Handed the
    // uncanonical `root` it refused every eviction the moment the caller's root
    // contained a `..` or a symlink, which is what `crates/…/../../target` in
    // the test harness is. Refusing was the right response to being given two
    // paths that do not agree; agreeing is better.
    let guard = ReplacementGuard::from_metadata(&md);
    let mut placer = TmpfilePlacer::new(&real_root)?;
    before_replace(path);
    match placer.place_if_unchanged(path, md.len(), &cloud_id, etag.as_deref(), guard)? {
        ConditionalPlace::Placed => {}
        ConditionalPlace::TargetChanged => {
            // The file at the name is not the inode/content state approved above.
            // In particular, an editor's atomic save landed after the queue
            // snapshot and clean-stamp check. The exchange already put it back.
            return Ok(Err(Refused::ChangedSinceUpload));
        }
    }

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

/// Is `path`, or any directory above it up to and including the sync root,
/// pinned? Returns the pinning path so the refusal can name it.
///
/// The pin is stored only where the user set it; a folder pin is honored by this
/// walk, not by a bit copied onto every child — so a file that arrives later
/// under a pinned directory is protected with nothing written to it. Both `path`
/// and `real_root` are already canonical (no `..`, no symlinks) when `reclaim`
/// calls this, so the ancestor chain is the real one and the walk stops exactly
/// at the root rather than climbing out of the sync directory toward `/`.
fn pinned_self_or_ancestor(path: &Path, real_root: &Path) -> io::Result<Option<PathBuf>> {
    for anc in path.ancestors() {
        if store::is_pinned(anc)? {
            return Ok(Some(anc.to_path_buf()));
        }
        if anc == real_root {
            break;
        }
    }
    Ok(None)
}

/// Set or clear the "keep on device" pin on a file *or directory* named by an
/// untrusted `rel`.
///
/// Confined exactly like [`reclaim`] — through [`crate::delta::safe_join`], then
/// canonicalisation, then a prefix check on the resolved paths — but without its
/// regular-file gate, because a pin is meaningful on a directory: it protects the
/// subtree through the ancestor-walk `pinned_self_or_ancestor` does. Writing the
/// mark fires no pre-content event and needs no privilege, so like eviction it
/// stays wholly on the unprivileged side and §6b never comes into it.
///
/// A path that does not resolve inside the sync directory comes back as
/// [`Refused::NotEligible`], so the caller surfaces it the way it surfaces an
/// eviction refusal.
pub fn set_pin(root: &Path, rel: &str, on: bool) -> io::Result<Result<(), Refused>> {
    let Some(joined) = crate::delta::safe_join(root, rel) else {
        return Ok(Err(Refused::NotEligible(format!(
            "{rel:?} is not a path inside the sync directory"
        ))));
    };
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
    if on {
        store::set_pinned(&real)?;
    } else {
        store::clear_pinned(&real)?;
    }
    Ok(Ok(()))
}

/// List the dehydrated regular files under a confined directory, as paths
/// relative to the sync root — the enumeration half of a folder "Keep on
/// Device", kept in the daemon so the reads that follow can happen one at a time
/// in a third-party process (§6a-ter), not here.
///
/// Content-free: it reads directory entries and one `getxattr` per file, and
/// never opens a file — so listing a subtree does not hydrate any of it. The
/// framework's own names are skipped at every depth (`names::is_internal`), and
/// symlinks are not followed, so the walk cannot be led outside the subtree the
/// confinement already fixed. A name a line cannot carry (one with a newline) is
/// left off rather than corrupting the list; such a file stays hydratable on its
/// own.
pub fn pending(root: &Path, rel: &str) -> io::Result<Result<Vec<String>, Refused>> {
    let Some(joined) = crate::delta::safe_join(root, rel) else {
        return Ok(Err(Refused::NotEligible(format!(
            "{rel:?} is not a path inside the sync directory"
        ))));
    };
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
    if !real.is_dir() {
        return Ok(Err(Refused::NotEligible("not a directory".to_string())));
    }
    let mut out = Vec::new();
    collect_dehydrated(&real, &real_root, &mut out)?;
    // Sorted so the order is a property of the tree, not of readdir: a caller
    // hydrating top-down, and a test asserting on the list, both want it stable.
    out.sort();
    Ok(Ok(out))
}

/// Depth-first, skipping the framework's own files and not following symlinks.
fn collect_dehydrated(dir: &Path, root: &Path, out: &mut Vec<String>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if hydration_protocol::names::is_internal(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_dehydrated(&path, root, out)?;
        } else if file_type.is_file()
            && store::get_xattr(&path, hydration_protocol::xattr::DEHYDRATED)?.is_some()
        {
            if let Ok(rel) = path.strip_prefix(root) {
                let rel = rel.to_string_lossy();
                if !rel.contains(['\n', '\r']) {
                    out.push(rel.into_owned());
                }
            }
        }
        // A symlink is neither `is_dir` nor `is_file` here, so it is skipped —
        // the walk never leaves the subtree the confinement fixed.
    }
    Ok(())
}

/// Every resident file the auto-eviction policy could dehydrate, as
/// [`crate::evict_policy::Candidate`]s for `plan` to rank.
///
/// A content-free walk of the sync root — `read_dir` plus a few `getxattr`s per
/// file, never a read, so enumerating never hydrates anything (the mirror of
/// [`pending`], for the opposite population). It pre-filters to what `reclaim`
/// would accept, so `plan` is not handed files the executor would only refuse:
/// it skips placeholders (`DEHYDRATED`), pinned files and subtrees, files the
/// cloud does not hold (`NotUploaded`), and files edited since upload
/// (`stamp != Clean`). The pre-filter is an optimisation only —
/// [`reclaim`] stays the sole authority when the driver acts on each `rel`.
///
/// The pin check is memoised down the walk: each directory's own pin is read
/// once and the "an ancestor is pinned" verdict flows to its children, so a
/// pressure sweep does not pay `depth` × `getxattr` per file — the cost the
/// Keep-on-Device groundwork flagged for exactly this policy.
pub fn evictable_candidates(root: &Path) -> io::Result<Vec<crate::evict_policy::Candidate>> {
    let real_root = root.canonicalize()?;
    let ignore = crate::store::load_ignore(&real_root);
    let mut out = Vec::new();
    collect_residents(&real_root, &real_root, false, &ignore, &mut out)?;
    Ok(out)
}

fn collect_residents(
    dir: &Path,
    root: &Path,
    ancestor_pinned: bool,
    ignore: &hydration_protocol::ignore::IgnoreSet,
    out: &mut Vec<crate::evict_policy::Candidate>,
) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;

    // One `getxattr` per directory: this directory's own pin, folded with the
    // ancestors'. Children inherit the verdict, so the walk is `O(dirs)` pin
    // reads, not `O(files × depth)`.
    let dir_pinned = ancestor_pinned || store::is_pinned(dir)?;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if hydration_protocol::names::is_internal(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let file_type = entry.file_type()?;
        let path = entry.path();
        // Sync-ignore: an ignored subtree (`.git/` and anything a
        // `.hydration-ignore` names) is never an eviction target. Load-bearing,
        // not defence-in-depth: an already-uploaded `.git/` file carries a cloud
        // id, so the no-cloud-id gate below does NOT protect it, and dehydrating a
        // real repo file into a placeholder is exactly the corruption to avoid.
        if path
            .strip_prefix(root)
            .is_ok_and(|rel| ignore.is_ignored(rel))
        {
            continue;
        }
        if file_type.is_dir() {
            collect_residents(&path, root, dir_pinned, ignore, out)?;
            continue;
        }
        // A symlink is neither `is_dir` nor `is_file`, so it is skipped and the
        // walk never leaves the tree.
        if !file_type.is_file() {
            continue;
        }

        // Cheapest skip first, because the tree is mostly placeholders: a
        // dehydrated file is not a resident and holds no disk to reclaim.
        if store::get_xattr(&path, hydration_protocol::xattr::DEHYDRATED)?.is_some() {
            continue;
        }
        // Keep on Device wins: a pinned file, or one under a pinned directory.
        if dir_pinned || store::is_pinned(&path)? {
            continue;
        }
        // The cloud must hold it, or evicting it destroys the only copy.
        let has_cloud_id = store::get_xattr(&path, store::XATTR_ID)?
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        if !has_cloud_id {
            continue;
        }
        // And it must be unchanged since we sent it — the same `Clean` gate
        // `reclaim` re-applies per file.
        if hydration_protocol::stamp::state(&path)? != hydration_protocol::stamp::State::Clean {
            continue;
        }

        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        let rel = rel.to_string_lossy();
        if rel.contains(['\n', '\r']) {
            continue;
        }
        let md = std::fs::symlink_metadata(&path)?;
        // Recency: the last acquisition if the framework has one, else the file's
        // own mtime — never treated as "oldest" when absent (see the `hydrated`
        // module).
        let recency =
            hydration_protocol::hydrated::at(&path)?.unwrap_or_else(|| md.mtime().max(0) as u64);
        out.push(crate::evict_policy::Candidate {
            rel: rel.into_owned(),
            // Measured, not logical: what the placeholder actually gives back.
            reclaimable: md.blocks() * 512,
            recency,
        });
    }
    Ok(())
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

    /// The target name is not a lock.
    ///
    /// Editors normally save by renaming a new inode over the old one. If that
    /// lands after eviction's queue/stamp checks, a plain `rename` of the
    /// placeholder deletes the only copy of the edit. The hook puts that exact
    /// interleaving under test without depending on thread scheduling.
    #[test]
    fn an_atomic_save_after_the_clean_check_is_preserved() {
        let dir = scratch("atomic-save-during-eviction");
        let path = synced(&dir, "report.docx", b"the version already in the cloud");
        let replacement = dir.join("report.docx.new");
        let new_body = b"the user's new version, not uploaded anywhere";
        std::fs::write(&replacement, new_body).unwrap();

        let mut store = Store::new();
        store.scan(&dir).unwrap();
        let outcome = reclaim_with(
            &dir,
            "report.docx",
            &mut store,
            &HashSet::new(),
            &HashSet::new(),
            |target| std::fs::rename(&replacement, target).unwrap(),
        )
        .unwrap();

        assert_eq!(outcome, Err(Refused::ChangedSinceUpload));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            new_body,
            "the atomic save was replaced by the eviction placeholder"
        );
        assert!(
            store::get_xattr(&path, hydration_protocol::xattr::DEHYDRATED)
                .unwrap()
                .is_none(),
            "the restored edit was left marked as a placeholder"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|entry| {
                hydration_protocol::names::is_scratch(&entry.file_name().to_string_lossy())
            })
            .collect();
        assert!(leftovers.is_empty(), "eviction left scratch names behind");
    }

    #[test]
    fn an_in_place_write_after_the_clean_check_is_preserved() {
        let dir = scratch("in-place-write-during-eviction");
        let path = synced(&dir, "notes.txt", b"sent");
        let new_body = b"an in-place edit which exists only here";

        let mut store = Store::new();
        store.scan(&dir).unwrap();
        let outcome = reclaim_with(
            &dir,
            "notes.txt",
            &mut store,
            &HashSet::new(),
            &HashSet::new(),
            |target| std::fs::write(target, new_body).unwrap(),
        )
        .unwrap();

        assert_eq!(outcome, Err(Refused::ChangedSinceUpload));
        assert_eq!(std::fs::read(&path).unwrap(), new_body);
        assert!(
            store::get_xattr(&path, hydration_protocol::xattr::DEHYDRATED)
                .unwrap()
                .is_none()
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

    /// A resident `.git/` file that *was* uploaded — cloud id, clean stamp — is
    /// never an eviction candidate. Load-bearing, not defence-in-depth: the
    /// no-cloud-id gate does not protect it (it has one), so only the sync-ignore
    /// keeps a real repo file from being dehydrated into a placeholder.
    #[test]
    fn an_ignored_never_uploaded_file_is_never_an_eviction_candidate() {
        let dir = scratch("ignored-not-evictable");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("repo/.git")).unwrap();
        synced(&dir.join("repo/.git"), "index", &vec![b'g'; 8192]); // cloud id + clean
        synced(&dir, "report.pdf", &vec![b'x'; 8192]); // an ordinary resident

        let candidates = evictable_candidates(&dir).unwrap();
        let rels: Vec<&str> = candidates.iter().map(|c| c.rel.as_str()).collect();
        assert!(
            rels.contains(&"report.pdf"),
            "an ordinary resident must still be a candidate: {rels:?}"
        );
        assert!(
            !rels.iter().any(|r| r.contains(".git")),
            "a resident .git/ file (with a cloud id) was an eviction candidate: {rels:?}"
        );

        // The explicit reclaim entry refuses it too, so an `evict` verb cannot
        // dehydrate it either.
        assert!(matches!(
            run(&dir, "repo/.git/index"),
            Err(Refused::NotEligible(_))
        ));
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

    /// The whole point of the pin: a file the user asked to keep is not a
    /// candidate, even when it is otherwise perfectly evictable — synced, clean,
    /// idle. The refusal names the file itself.
    #[test]
    fn a_pinned_file_is_never_evicted() {
        let dir = scratch("pinned-file");
        let p = synced(&dir, "keep.pdf", &vec![b'k'; 8192]);
        store::set_pinned(&p).unwrap();

        match run(&dir, "keep.pdf") {
            Err(Refused::Pinned { via }) => assert_eq!(via, p.canonicalize().unwrap()),
            other => panic!("a pinned file was not refused: {other:?}"),
        }
        assert!(holds_data(&p).unwrap(), "a pinned file lost its content");
    }

    /// A folder pin protects the files under it — including one created *after*
    /// the pin, carrying no mark of its own. This is the test that tells the
    /// ancestor-walk apart from stamping the bit onto every child: a stamping
    /// design writes nothing to a child that did not exist when the folder was
    /// pinned, so it would evict it. The refusal names the directory.
    #[test]
    fn a_file_under_a_pinned_directory_is_never_evicted() {
        let dir = scratch("pinned-dir");
        let sub = dir.join("keep-me");
        std::fs::create_dir_all(&sub).unwrap();
        store::set_pinned(&sub).unwrap();

        // Created after the pin, and never marked itself.
        let child = synced(&sub, "later.bin", &vec![b'c'; 4096]);
        assert!(
            !store::is_pinned(&child).unwrap(),
            "the child should carry no pin of its own — inheritance is by walk"
        );

        match run(&dir, "keep-me/later.bin") {
            Err(Refused::Pinned { via }) => assert_eq!(via, sub.canonicalize().unwrap()),
            other => panic!("a file under a pinned directory was not refused: {other:?}"),
        }
        assert!(holds_data(&child).unwrap(), "a pinned subtree lost content");
    }

    /// The guard fires before placement: a pinned file's inode does not change,
    /// because nothing was swapped in — while an unpinned control in the same
    /// tree *is* evicted and its inode *does* change. Without the control the
    /// first assertion cannot tell "guard fired" from "placement never ran for
    /// some other reason".
    #[test]
    fn the_pin_check_runs_before_placement_and_a_control_is_still_evicted() {
        let dir = scratch("pin-before-place");
        let pinned = synced(&dir, "pinned.bin", &vec![b'p'; 8192]);
        let control = synced(&dir, "control.bin", &vec![b'c'; 8192]);
        store::set_pinned(&pinned).unwrap();

        let ino_before = std::fs::metadata(&pinned).unwrap().ino();
        assert!(matches!(
            run(&dir, "pinned.bin"),
            Err(Refused::Pinned { .. })
        ));
        assert_eq!(
            std::fs::metadata(&pinned).unwrap().ino(),
            ino_before,
            "the inode was replaced — placement ran on a pinned file"
        );

        let ctrl_before = std::fs::metadata(&control).unwrap().ino();
        assert!(run(&dir, "control.bin").is_ok());
        assert_ne!(
            std::fs::metadata(&control).unwrap().ino(),
            ctrl_before,
            "the control was not actually evicted, so the inode check proves nothing"
        );
    }

    /// Un-pinning makes a file a candidate again — and does not itself evict
    /// anything. "Keep on Device" and "Free Up Space" stay two deliberate acts,
    /// and the inverse of the pin is the un-pin, not an eviction.
    #[test]
    fn unpinning_restores_eligibility_and_does_not_itself_evict() {
        let dir = scratch("unpin");
        let p = synced(&dir, "toggle.bin", &vec![b't'; 8192]);
        store::set_pinned(&p).unwrap();
        assert!(matches!(
            run(&dir, "toggle.bin"),
            Err(Refused::Pinned { .. })
        ));

        store::clear_pinned(&p).unwrap();
        assert!(
            holds_data(&p).unwrap(),
            "clearing a pin evicted the file by itself"
        );
        assert!(
            run(&dir, "toggle.bin").is_ok(),
            "an unpinned file is a candidate again"
        );
    }

    /// `set_pin` is confined exactly like `reclaim`: the escaping arguments that
    /// cannot evict cannot pin either, and none of them panic. (Degenerate but
    /// in-root arguments like `""` are a separate question — they name the root,
    /// which is a legitimate if heavy thing to pin — so only genuine escapes are
    /// asserted here.)
    #[test]
    fn set_pin_confines_like_evict() {
        let dir = scratch("pin-hostile");
        for arg in [
            "../../../etc/hosts",
            "/etc/passwd",
            "..",
            "a/../../b",
            ".hydration-manifest",
            "\u{0}weird",
        ] {
            let out = set_pin(&dir, arg, true);
            assert!(
                matches!(out, Ok(Err(Refused::NotEligible(_))) | Err(_)),
                "{arg:?} was not refused by set_pin: {out:?}"
            );
        }
    }

    /// A dehydrated placeholder, for `pending`'s purposes, is a file that carries
    /// the mark — the mark is what "is a placeholder" means, and `pending` reads
    /// it, never the block layout.
    fn dehydrated(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, b"").unwrap();
        store::set_xattr(&p, hydration_protocol::xattr::DEHYDRATED, b"1").unwrap();
        p
    }

    /// `pending` lists the dehydrated regular files under a directory, relative
    /// to the sync root and at any depth — and lists nothing else: not a hydrated
    /// file, not a directory, and not the framework's own names *even when one is
    /// marked* (the is_internal skip is by name, so it holds regardless).
    #[test]
    fn pending_lists_only_dehydrated_regular_files_and_skips_internal_names() {
        let dir = scratch("pending-list");
        let sub = dir.join("tree/sub");
        std::fs::create_dir_all(&sub).unwrap();

        dehydrated(&dir.join("tree"), "a.bin");
        dehydrated(&sub, "b.bin");
        // A hydrated file (no mark) must not appear...
        std::fs::write(dir.join("tree/resident.txt"), b"present").unwrap();
        // ...and an internal name must not appear even when it carries the mark.
        let manifest = dehydrated(&dir.join("tree"), hydration_protocol::names::MANIFEST);
        let _ = manifest;

        let got = match pending(&dir, "tree").unwrap() {
            Ok(v) => v,
            other => panic!("pending refused a real directory: {other:?}"),
        };
        assert_eq!(
            got,
            vec!["tree/a.bin".to_string(), "tree/sub/b.bin".to_string()]
        );
    }

    /// `pending` is confined exactly like the other verbs, and it takes a
    /// directory — the escapes that cannot evict cannot enumerate, and a plain
    /// file is refused rather than silently returning nothing.
    #[test]
    fn pending_confines_to_the_subtree_and_wants_a_directory() {
        let dir = scratch("pending-confine");
        for arg in ["../..", "/etc", "..", ".hydration-manifest", "\u{0}x"] {
            let out = pending(&dir, arg);
            assert!(
                matches!(out, Ok(Err(Refused::NotEligible(_))) | Err(_)),
                "{arg:?} was not refused by pending: {out:?}"
            );
        }
        dehydrated(&dir, "lonely.bin");
        assert!(
            matches!(
                pending(&dir, "lonely.bin"),
                Ok(Err(Refused::NotEligible(_)))
            ),
            "pending accepted a file where it needs a directory"
        );
    }

    /// The enumerator proposes only what `reclaim` would accept: one evictable
    /// resident here, and nothing for each of the reasons `reclaim` refuses — a
    /// placeholder, a pinned file, an edited file, an un-uploaded file, and the
    /// framework's own names.
    #[test]
    fn enumerate_lists_only_evictable_residents() {
        use std::os::unix::fs::MetadataExt;
        let dir = scratch("enumerate");

        // The one candidate: synced == uploaded, clean, resident, unpinned.
        let good = synced(&dir, "keep-me-not.bin", &vec![b'g'; 8192]);

        // None of these may appear:
        dehydrated(&dir, "placeholder.bin"); // a placeholder, no disk to reclaim
        let pinned = synced(&dir, "pinned.bin", &vec![b'p'; 8192]);
        store::set_pinned(&pinned).unwrap(); // pinned
        let dirty = synced(&dir, "dirty.bin", b"the version we sent");
        std::fs::write(&dirty, b"a newer version, never sent").unwrap(); // edited since upload
        let offline = dir.join("offline.bin");
        std::fs::write(&offline, b"written offline, never uploaded").unwrap();
        stamp::write(&offline).unwrap(); // clean but no cloud id
        std::fs::write(dir.join(hydration_protocol::names::MANIFEST), b"# internal").unwrap();

        let got = evictable_candidates(&dir).unwrap();
        assert_eq!(
            got.len(),
            1,
            "expected only the one evictable resident, got {got:?}"
        );
        assert_eq!(got[0].rel, "keep-me-not.bin");
        // No hydrated_at was recorded, so recency falls back to the file's mtime.
        assert_eq!(
            got[0].recency,
            std::fs::metadata(&good).unwrap().mtime().max(0) as u64
        );
        assert!(
            got[0].reclaimable >= 8192,
            "reclaimable should reflect the resident's blocks: {}",
            got[0].reclaimable
        );
    }

    /// Nested residents are found with their nested rel path, and a resident
    /// under a pinned directory is skipped by the memoised ancestor check — the
    /// pin protects a whole subtree from the sweep, not just a named file.
    #[test]
    fn enumerate_finds_nested_residents_and_skips_a_pinned_subtree() {
        let dir = scratch("enumerate-nested");
        let deep = dir.join("a/b");
        std::fs::create_dir_all(&deep).unwrap();
        synced(&deep, "deep.bin", &vec![b'd'; 4096]);

        let kept = dir.join("keep");
        std::fs::create_dir_all(&kept).unwrap();
        store::set_pinned(&kept).unwrap();
        synced(&kept, "under-pin.bin", &vec![b'u'; 4096]);

        let mut rels: Vec<String> = evictable_candidates(&dir)
            .unwrap()
            .into_iter()
            .map(|c| c.rel)
            .collect();
        rels.sort();
        assert_eq!(
            rels,
            vec!["a/b/deep.bin".to_string()],
            "listed a file under a pinned directory, or missed the nested one"
        );
    }
}

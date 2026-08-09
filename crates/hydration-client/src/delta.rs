//! Bringing changes down from the cloud.
//!
//! Everything so far has been about what happens to a file that already exists
//! locally. This is the other direction: an object appears, changes or vanishes
//! in the cloud, and the sync directory has to end up agreeing.
//!
//! The rule that shapes the whole module is the one §5.2 already states, applied
//! to the arriving side:
//!
//! > **The local copy is the truth.** A delta pass may create, and it may update
//! > a file it has not been asked to leave alone — but it must never overwrite
//! > local content that has not been sent yet.
//!
//! A sync engine that gets this wrong loses the user's work in the most
//! confusing way available: their edit disappears and is replaced by an older
//! version they did not ask for, with no error and nothing to point at.

use crate::store::Store;
use crate::upload::Queue;
use hydration_protocol::FileId;
use std::io;
use std::path::{Path, PathBuf};

/// What the cloud says happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Present in the cloud with this content. Covers both "new" and "changed":
    /// the framework decides which by looking at what is on disk, because the
    /// cloud's opinion of what is new is not reliable across a resync.
    Upserted {
        cloud_id: String,
        /// Relative to the sync root. Directories are implied by the path.
        path: String,
        size: u64,
        etag: Option<String>,
    },
    /// Gone from the cloud.
    Removed { cloud_id: String },
}

/// Where a delta pass left off, so the next one does not start over.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cursor(pub Option<String>);

/// Discovering changes is the client's job, because only it knows the service.
pub trait Discover: Send {
    /// Changes since `cursor`, and where to resume.
    ///
    /// May return the whole world when `cursor` is empty — the reconciler is
    /// written so that a full listing and an incremental one behave the same.
    fn changes(&mut self, cursor: &Cursor) -> io::Result<(Vec<Change>, Cursor)>;
}

/// Making a placeholder exist is a privileged operation.
///
/// Not because of file permissions — the daemon can write to its own sync
/// directory — but because giving a file its size inside a watched mount fires a
/// pre-content event, and closing that window needs the fanotify group. So the
/// mechanism is injected, and the reconciler below is the same either way.
pub trait Materialise: Send {
    /// Create a placeholder at `path` (absolute), or update an existing one's
    /// recorded size and identity.
    fn place(
        &mut self,
        path: &Path,
        size: u64,
        cloud_id: &str,
        etag: Option<&str>,
    ) -> io::Result<()>;

    /// Remove a file the cloud no longer has.
    fn remove(&mut self, path: &Path) -> io::Result<()>;
}

/// What a delta pass did, for the status a user is shown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    pub created: usize,
    pub updated: usize,
    pub removed: usize,
    /// Changes deliberately not applied because local content would have been
    /// lost. Not an error, and not silent: these are what a conflict UI is for.
    pub kept_local: Vec<String>,
    pub failed: Vec<String>,
}

/// Apply a set of changes to the sync directory.
///
/// `queue` is consulted rather than modified: a file with an edit waiting to go
/// up is one whose local copy is newer than anything the cloud can tell us
/// about, and the delta pass leaves it alone.
pub fn apply<M: Materialise, C: crate::upload::Clock>(
    root: &Path,
    changes: &[Change],
    store: &mut Store,
    queue: &Queue<C>,
    mat: &mut M,
) -> io::Result<Applied> {
    let mut out = Applied::default();
    store.scan(root)?;

    // Cloud id -> local file, for the removal half. Built once rather than per
    // change, because a removal names an object and not a path.
    let by_cloud_id = store.by_cloud_id();

    for change in changes {
        match change {
            Change::Upserted {
                cloud_id,
                path,
                size,
                etag,
            } => {
                let Some(abs) = safe_join(root, path) else {
                    out.failed.push(path.clone());
                    continue;
                };

                match std::fs::metadata(&abs) {
                    // Nothing there: this is the ordinary case, a new object.
                    Err(_) => match mat.place(&abs, *size, cloud_id, etag.as_deref()) {
                        Ok(()) => out.created += 1,
                        Err(_) => out.failed.push(path.clone()),
                    },
                    Ok(md) => {
                        let id = file_id(&md);
                        // An edit waiting to be sent is newer than anything the
                        // cloud has to say. Replacing it with a placeholder
                        // would throw away work that exists nowhere else — the
                        // one outcome this framework must never produce.
                        if queue.is_waiting(&id) {
                            out.kept_local.push(path.clone());
                            continue;
                        }
                        // Local content that has never been uploaded is in the
                        // same position, even with nothing queued: there is no
                        // remote copy of it to fall back on.
                        let known = store.lookup(&id).and_then(|e| e.cloud_id);
                        if known.is_none() && md.len() > 0 {
                            out.kept_local.push(path.clone());
                            continue;
                        }
                        // And the queue is not enough on its own.
                        //
                        // `is_waiting` only knows about edits somebody told us
                        // about, and change detection is lossy in ways that have
                        // been measured: the notify queue overflows in under two
                        // seconds under an unpack, `truncate(2)` produces no
                        // event at all, and nothing at all is reported while the
                        // helper is down. Every one of those gaps ends here — at
                        // a `place()` that renames a placeholder over content
                        // that exists nowhere else, counted as a successful
                        // update.
                        //
                        // So the file is asked directly whether it still looks
                        // the way the framework left it. Silence is not evidence.
                        if matches!(
                            hydration_protocol::stamp::state(&abs),
                            Ok(hydration_protocol::stamp::State::Dirty)
                        ) {
                            out.kept_local.push(path.clone());
                            continue;
                        }
                        match mat.place(&abs, *size, cloud_id, etag.as_deref()) {
                            Ok(()) => out.updated += 1,
                            Err(_) => out.failed.push(path.clone()),
                        }
                    }
                }
            }

            Change::Removed { cloud_id } => {
                let Some(entry) = by_cloud_id.get(cloud_id) else {
                    // Never had it, or it is already gone. Both are the state we
                    // wanted.
                    continue;
                };
                let id = file_id(&match std::fs::metadata(&entry.path) {
                    Ok(md) => md,
                    Err(_) => continue,
                });
                // Same rule from the other side: a local edit outlives a remote
                // delete, because the edit is the newer intention *here* and
                // nothing else has a copy of it.
                if queue.is_waiting(&id) {
                    out.kept_local.push(entry.path.display().to_string());
                    continue;
                }
                // Same check as the upsert side, for the same reason: a delete
                // is the more destructive of the two, and a lost notification
                // must not be what decides it.
                if matches!(
                    hydration_protocol::stamp::state(&entry.path),
                    Ok(hydration_protocol::stamp::State::Dirty)
                ) {
                    out.kept_local.push(entry.path.display().to_string());
                    continue;
                }
                match mat.remove(&entry.path) {
                    Ok(()) => out.removed += 1,
                    Err(_) => out.failed.push(entry.path.display().to_string()),
                }
            }
        }
    }
    Ok(out)
}

fn file_id(md: &std::fs::Metadata) -> FileId {
    use std::os::unix::fs::MetadataExt;
    FileId {
        fsid: md.dev(),
        ino: md.ino(),
    }
}

/// Join a cloud-supplied relative path onto the root, refusing anything that
/// would leave it.
///
/// The path comes from a remote service, so it is untrusted input in the
/// ordinary sense: `..`, an absolute path, or a leading `/` would place files
/// outside the sync directory. Rejecting rather than sanitising, because a
/// sanitised path silently means something other than what the cloud said.
pub fn safe_join(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() {
        return None;
    }
    let p = Path::new(rel);
    if p.is_absolute() {
        return None;
    }
    for c in p.components() {
        match c {
            std::path::Component::Normal(n) => {
                // A cloud object may not claim one of the framework's own names.
                //
                // Without this, a remote service — or anything that can write to
                // the account — could name an object `.hydration-manifest` and
                // have a delta pass replace §6d's mechanism with a placeholder:
                // the file that tells a restoring user what is missing would
                // become a file with no content. It is refused rather than
                // renamed, because a renamed path silently means something other
                // than what the cloud said.
                if n.to_str()
                    .is_some_and(hydration_protocol::names::is_internal)
                {
                    return None;
                }
            }
            // Everything else — ParentDir, RootDir, Prefix, CurDir — either
            // escapes or is meaningless here.
            _ => return None,
        }
    }
    Some(root.join(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_that_would_escape_the_sync_root_is_refused() {
        let root = Path::new("/home/frank/OneDrive");
        assert!(safe_join(root, "notes.txt").is_some());
        assert!(safe_join(root, "sub/notes.txt").is_some());

        // Each of these puts a file somewhere the user did not ask for, on the
        // say-so of a remote service.
        assert!(safe_join(root, "../../../etc/cron.d/evil").is_none());
        assert!(safe_join(root, "/etc/passwd").is_none());
        assert!(safe_join(root, "sub/../../out").is_none());
        assert!(safe_join(root, "").is_none());
        assert!(safe_join(root, "./x").is_none());
    }

    /// The framework's own files are not addressable from the cloud.
    #[test]
    fn a_cloud_object_cannot_claim_one_of_our_own_names() {
        let root = Path::new("/home/frank/OneDrive");
        assert!(safe_join(root, ".hydration-manifest").is_none());
        assert!(safe_join(root, ".hydration-manifest.tmp").is_none());
        assert!(safe_join(root, "sub/.hydration-manifest").is_none());
        assert!(safe_join(root, "sub/.report.pdf.hydration-4").is_none());
        // A name that merely looks similar is the user's business, not ours.
        assert!(safe_join(root, ".hydration-notes.txt").is_some());
    }
}

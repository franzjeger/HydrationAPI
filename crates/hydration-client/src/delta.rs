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
    /// A cloud folder, including an empty one. The root is represented by an
    /// empty path so its identity can be recorded on the sync root itself.
    FolderUpserted {
        cloud_id: String,
        path: String,
        /// A metadata version suitable for conditional namespace writes.
        /// This is deliberately separate from a file's content version.
        etag: Option<String>,
    },
    /// Gone from the cloud.
    Removed { cloud_id: String },
    /// A folder gone from the cloud. The path is carried because directories
    /// are not part of the inode-oriented file store.
    FolderRemoved { cloud_id: String, path: String },
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

    /// Whether the sync root still leads to the filesystem this materialiser was
    /// opened against.
    ///
    /// Asked between changes so a pass can stop when the ground moves under it.
    /// `hydrationd` detaches the sync mount when it fails closed, and until
    /// 2026-08-12 a pass that met that carried on to completion: 147,540
    /// placeholders into the bare directory underneath, reported as
    /// `+147540 failed 0`.
    ///
    /// This is not what makes that safe — [`TmpfilePlacer`] resolves every
    /// syscall through a descriptor on the root, so it cannot write outside the
    /// filesystem it opened whatever a path later means. This decides *when to
    /// stop*, which is a different and much more forgiving job: being late by a
    /// few changes costs a few refusals, where being wrong about the
    /// destination cost a silent tree of unhydratable files.
    ///
    /// Defaults to `true` for the doubles and the demo cloud, which have no
    /// mount to lose.
    ///
    /// [`TmpfilePlacer`]: crate::place::TmpfilePlacer
    fn root_still_current(&self) -> io::Result<bool> {
        Ok(true)
    }
}

/// A change that was refused, and which of the four rules refused it.
///
/// The reason used to be dropped on the floor, and a live account showed why that
/// was not good enough: a 2.77 GiB file logged `kept local copy of …` on every
/// pass, indefinitely, and the line said nothing that could be acted on. Every
/// condition below evaluates cleanly against a file from outside — the stamp
/// matched, the cloud id was present, the queue was empty — so from the log alone
/// there was no way to tell which rule was firing, or whether the refusal was
/// protecting anything at all.
///
/// "Never invent a diagnostic" cuts both ways: a diagnostic that names no cause
/// is one the reader has to invent for themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    /// As the change named it, so it can be matched against the service's view.
    pub path: String,
    pub why: Why,
}

/// Why a change was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// An edit is queued for upload. It is newer than anything the cloud can say
    /// and exists nowhere else.
    EditWaiting,
    /// Local content with no cloud id: never uploaded, so there is no remote copy
    /// to fall back on.
    NeverUploaded,
    /// The file no longer looks the way the framework left it, so somebody wrote
    /// to it and we were not told.
    ChangedUnderneath,
}

impl std::fmt::Display for Why {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EditWaiting => write!(f, "an edit is waiting to be uploaded"),
            Self::NeverUploaded => write!(f, "it has never been uploaded"),
            Self::ChangedUnderneath => {
                write!(f, "it has changed since the framework last wrote it")
            }
        }
    }
}

impl Kept {
    pub fn new(path: &str, why: Why) -> Self {
        Self {
            path: path.to_string(),
            why,
        }
    }
}

/// A change that could not be applied, and what stopped it.
///
/// [`Kept`]'s argument from the other side, and it cost an afternoon on
/// 2026-08-11 to learn that it applies here too. A scratch mount owned by root
/// made every `Materialise::place` fail with `EACCES`, and each one logged
/// `could not apply <path>` — the identical line a refused path, an absurd size
/// or an occupied destination produces. So the smoke failure was bisected
/// against the daemon to arrive at something the errno had been holding the
/// whole time.
///
/// "Never invent a diagnostic" is usually read as a rule against making causes
/// up. It forbids omitting them too: a line naming no cause is one the reader
/// has to invent a cause for, and the first guess was the kernel path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    /// As the change named it, so it can be matched against the service's view.
    /// Removals name the local path instead — a removal carries no path of its
    /// own, only an object id.
    pub path: String,
    pub why: Failure,
}

/// What stopped a change from being applied.
///
/// The three that come from a syscall carry the message and not the
/// `io::Error`, because `Applied` is `Clone` and `Eq` — a caller comparing two
/// passes is how "nothing happened" is recognised — and `io::Error` is neither.
/// The text is `io::Error`'s own; nothing here rewrites it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// `safe_join` refused the path the change arrived with.
    PathRefused,
    /// The change claims a size past [`MAX_OBJECT`].
    TooLarge { size: u64 },
    /// The object moved, and something else already holds the destination.
    /// Retryable: the change that frees it may be later in the same feed.
    DestinationOccupied,
    /// The local rename that would have followed the object to its new path.
    Rename(String),
    /// `Materialise::place` — creating a placeholder, or refreshing one.
    Place(String),
    /// `Materialise::remove` — deleting a file the cloud no longer has.
    Remove(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // All three of `safe_join`'s refusals, because the path is on the
            // same line and the reader can see which one it was. Naming a
            // single one would be a guess.
            Self::PathRefused => write!(
                f,
                "the path is empty, escapes the sync root, or claims one of our own names"
            ),
            Self::TooLarge { size } => {
                write!(
                    f,
                    "it claims {size} bytes, past the {MAX_OBJECT}-byte limit"
                )
            }
            Self::DestinationOccupied => write!(f, "another file is already at that path"),
            Self::Rename(e) => write!(f, "renaming the local file failed: {e}"),
            Self::Place(e) => write!(f, "writing the placeholder failed: {e}"),
            Self::Remove(e) => write!(f, "removing the local file failed: {e}"),
        }
    }
}

impl Failed {
    pub fn new(path: &str, why: Failure) -> Self {
        Self {
            path: path.to_string(),
            why,
        }
    }
}

/// What a delta pass did, for the status a user is shown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    pub created: usize,
    pub updated: usize,
    pub removed: usize,
    /// Objects that arrived under a new path and were renamed locally rather
    /// than duplicated.
    pub moved: usize,
    /// Changes deliberately not applied because local content would have been
    /// lost. Not an error, and not silent: these are what a conflict UI is for.
    pub kept_local: Vec<Kept>,
    /// Changes that could not be applied, each with what stopped it.
    pub failed: Vec<Failed>,
    /// At least one failure could succeed on a later pass — a rename blocked by
    /// a destination that another change will free, most often.
    ///
    /// The caller must not advance its cursor past a pass with this set. A delta
    /// service does not replay a consumed change, so a transient refusal that is
    /// never retried is indistinguishable from a permanent one: the local name
    /// stays wrong until the object happens to change again.
    pub retryable: bool,
    /// Set when the pass gave up partway because the sync root stopped being the
    /// mount it started against.
    ///
    /// Deliberately not an `Err`. `hydrationd` detaching the mount is a
    /// *deliberate* fail-closed action, so a pass running into it is the system
    /// working, not the system breaking — and a caller that logged it as a
    /// failure would be reporting an alarm for the thing that prevented one. The
    /// counts alongside it are real: what this says is that there was more, and
    /// that the cursor must stay where it is.
    pub stopped: Option<Stopped>,
}

/// Why a pass ended before it ran out of changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    /// The sync root now leads somewhere else — detached, or replaced by a
    /// different mount at the same path.
    MountChanged,
    /// Whether it still leads to the same place could not be established, which
    /// is treated as if it did not. A root that cannot be vouched for is not a
    /// root to keep writing into.
    MountUnverifiable(String),
}

impl std::fmt::Display for Stopped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MountChanged => write!(
                f,
                "the sync root is no longer the mount this pass started against"
            ),
            Self::MountUnverifiable(e) => write!(
                f,
                "could not confirm the sync root is still the same mount ({e})"
            ),
        }
    }
}

/// Apply a set of changes to the sync directory.
///
/// `waiting` is a *snapshot* of the upload queue, taken before the pass and not
/// a handle onto it. A file with an edit waiting to go up is one whose local
/// copy is newer than anything the cloud can tell us about, and the delta pass
/// leaves it alone — but reading that from the live queue would mean holding its
/// lock for the length of the pass, which blocks the thread that delivers change
/// notifications and makes every edit made *during* the pass invisible to the
/// very check meant to protect it.
pub fn apply<M: Materialise>(
    root: &Path,
    changes: &[Change],
    store: &mut Store,
    waiting: &std::collections::HashSet<FileId>,
    mat: &mut M,
) -> io::Result<Applied> {
    let mut out = Applied::default();
    // Nothing to apply means nothing to look at.
    //
    // The scan below walks the whole sync root, and `by_cloud_id` right after it
    // stats and reads two extended attributes from every file it found. On the
    // measured account that is about a million system calls, and the delta loop
    // ran it every eight seconds to establish that the cloud had not changed:
    // 48% of a core, permanently, on a tree of 167,890 files.
    //
    // A caller that wants the index refreshed on a quiet tree has to ask for it
    // — `Store::scan` is public and the daemon loop does exactly that, on a
    // cadence that suits keeping the lineage record fresh rather than one that
    // suits polling a service.
    if changes.is_empty() {
        return Ok(out);
    }
    store.scan(root)?;

    // Cloud id -> local file, for the removal half. Built once rather than per
    // change, because a removal names an object and not a path.
    let mut by_cloud_id = store.by_cloud_id();
    let mut folders = folders_by_cloud_id(root)?;

    // At most one change per object, last one winning.
    //
    // Not tidiness. Microsoft documents that a single delta enumeration may
    // return the same item more than once across pages, with the last occurrence
    // authoritative — so a provider that concatenates pages hands us two changes
    // for one object as a matter of course. Applying both in sequence created a
    // second local file claiming the same id, which is the exact corruption the
    // rename handling below exists to prevent.
    for change in coalesce(changes) {
        // Per change, not per pass.
        //
        // The pass this replaces asked once, at the top of the round, and a
        // round applying 147,540 changes takes minutes — so the answer was
        // stale for almost all of it, and on 2026-08-12 the mount went away
        // four minutes into one. Per change is affordable because of what the
        // question is asked with: one `statx` for the unique mount id, measured
        // at 0.24 µs against 13.38 µs for the `/proc/self/mountinfo` parse it
        // replaces (`probes/mountcheck_cost.c`) — 0.03 s across a pass of that
        // size, against 1.97 s.
        //
        // Cost is the smaller half of the argument. `mountinfo` answers "*a*
        // mount is at this path", and the id answers "*the* mount is", which is
        // the question with a correct answer during the seconds between a
        // detach and the remount that follows it.
        //
        // Nothing about placement depends on this. `TmpfilePlacer` cannot write
        // outside the filesystem it opened, so a check that arrives a change
        // late costs a refusal rather than a file in the wrong place. It is here
        // to stop cleanly, and it is checked before the change rather than after
        // so a pass that stops has not half-applied the change it stopped on.
        match mat.root_still_current() {
            Ok(true) => {}
            Ok(false) => {
                out.stopped = Some(Stopped::MountChanged);
                out.retryable = true;
                break;
            }
            Err(e) => {
                out.stopped = Some(Stopped::MountUnverifiable(e.to_string()));
                out.retryable = true;
                break;
            }
        }
        let change = &change;
        match change {
            Change::FolderUpserted {
                cloud_id,
                path,
                etag,
            } => {
                let Some(abs) = folder_path(root, path) else {
                    out.failed.push(Failed::new(path, Failure::PathRefused));
                    continue;
                };
                if let Some(existing) = folders.get(cloud_id) {
                    if existing != &abs && existing.exists() {
                        if abs.exists() {
                            out.failed
                                .push(Failed::new(path, Failure::DestinationOccupied));
                            out.retryable = true;
                            continue;
                        }
                        if let Some(parent) = abs.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        if let Err(e) = std::fs::rename(existing, &abs) {
                            out.failed
                                .push(Failed::new(path, Failure::Rename(e.to_string())));
                            out.retryable = true;
                            continue;
                        }
                        out.moved += 1;
                    }
                }
                match std::fs::metadata(&abs) {
                    Ok(md) if !md.is_dir() => {
                        out.failed
                            .push(Failed::new(path, Failure::DestinationOccupied));
                        out.retryable = true;
                        continue;
                    }
                    Ok(_) => {}
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        if let Err(e) = std::fs::create_dir_all(&abs) {
                            out.failed
                                .push(Failed::new(path, Failure::Place(e.to_string())));
                            out.retryable = true;
                            continue;
                        }
                        out.created += 1;
                    }
                    Err(e) => {
                        out.failed
                            .push(Failed::new(path, Failure::Place(e.to_string())));
                        out.retryable = true;
                        continue;
                    }
                }
                let occupied = crate::store::get_xattr(&abs, crate::store::XATTR_ID)
                    .ok()
                    .flatten()
                    .is_some_and(|id| id != cloud_id.as_bytes());
                if occupied {
                    out.failed
                        .push(Failed::new(path, Failure::DestinationOccupied));
                    out.retryable = true;
                    continue;
                }
                if let Err(e) =
                    crate::store::set_xattr(&abs, crate::store::XATTR_ID, cloud_id.as_bytes())
                {
                    out.failed
                        .push(Failed::new(path, Failure::Place(e.to_string())));
                    out.retryable = true;
                    continue;
                }
                let tag_result = match etag {
                    Some(etag) => {
                        crate::store::set_xattr(&abs, crate::store::XATTR_ETAG, etag.as_bytes())
                    }
                    None => crate::store::remove_xattr(&abs, crate::store::XATTR_ETAG),
                };
                if let Err(e) = tag_result {
                    out.failed
                        .push(Failed::new(path, Failure::Place(e.to_string())));
                    out.retryable = true;
                    continue;
                }
                folders.insert(cloud_id.clone(), abs);
            }
            Change::Upserted {
                cloud_id,
                path,
                size,
                etag,
            } => {
                let Some(abs) = safe_join(root, path) else {
                    out.failed.push(Failed::new(path, Failure::PathRefused));
                    continue;
                };

                // The size is untrusted in the same way the path is.
                //
                // It becomes the placeholder's length, and every hydration then
                // allocates that many bytes to serve it. A service reporting an
                // exabyte — through a bug, a signed/unsigned slip, or malice —
                // produces a sparse file the filesystem creates happily and a
                // daemon that tries to allocate it on first read. Refused rather
                // than clamped: a placeholder promising a length nobody meant is
                // the §5.7 failure, and silently choosing a different one would
                // be inventing an object.
                if *size > MAX_OBJECT {
                    out.failed
                        .push(Failed::new(path, Failure::TooLarge { size: *size }));
                    continue;
                }

                // The object may already be here under a different name.
                //
                // Every real service renames — a user drags a file into another
                // folder, and the next delta reports the same object at a new
                // path. Treating that as a new object leaves *two* local files
                // recording one cloud id, and that is not untidy, it is
                // dangerous: a later remote delete removes an arbitrary one of
                // them, and an edit to the other is uploaded over the object the
                // first still points at.
                //
                // A local rename is the honest translation. It preserves the
                // inode, so the upload queue, the stamp and anything holding the
                // file open all stay correct — and it is the only handling that
                // cannot end with two claimants.
                if let Some(existing) = by_cloud_id.get(cloud_id) {
                    if existing.path != abs && existing.path.exists() {
                        if abs.exists() {
                            // Something else is already at the destination —
                            // two objects swapping paths, most likely. Placing
                            // anyway would produce the two-claimant state this
                            // branch exists to prevent, so it is reported rather
                            // than resolved by guessing.
                            //
                            // Marked retryable, because a refusal nothing ever
                            // retries is a permanent wrong state: the caller
                            // advances its cursor and the service never mentions
                            // these objects again.
                            out.failed
                                .push(Failed::new(path, Failure::DestinationOccupied));
                            out.retryable = true;
                            continue;
                        }
                        if let Some(parent) = abs.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        if let Err(e) = std::fs::rename(&existing.path, &abs) {
                            out.failed
                                .push(Failed::new(path, Failure::Rename(e.to_string())));
                            out.retryable = true;
                            continue;
                        }
                        out.moved += 1;
                        // The index has to follow, or the next change naming
                        // this object looks it up at a path that no longer
                        // exists and creates a second file for it.
                        if let Some(e) = by_cloud_id.get_mut(cloud_id) {
                            e.path = abs.clone();
                        }
                        store.remember(file_id(&std::fs::metadata(&abs)?), &abs);
                    }
                }

                match std::fs::metadata(&abs) {
                    // Nothing there: this is the ordinary case, a new object.
                    Err(_) => match mat.place(&abs, *size, cloud_id, etag.as_deref()) {
                        Ok(()) => out.created += 1,
                        Err(e) => out
                            .failed
                            .push(Failed::new(path, Failure::Place(e.to_string()))),
                    },
                    Ok(md) => {
                        let id = file_id(&md);
                        // Nothing to do is the common case, and it is decided
                        // *before* the protections below, not after.
                        //
                        // Both feeds re-present unchanged objects on every
                        // round: `Discover` promises a full listing behaves
                        // like an incremental one, and the Graph provider
                        // returns its whole tree each pass for exactly that
                        // reason. So most upserts describe a file that is
                        // already right, and applying one is a no-op — there
                        // is no `place()` to refuse, and therefore nothing for
                        // `kept_local` to be about. (Before this check existed
                        // at all, every echo was re-placed: a file the user
                        // had just written and successfully uploaded became a
                        // placeholder seconds later, which on a laptop that is
                        // offline by morning is their content gone.)
                        //
                        // When this check ran after the stamp check, a stale
                        // stamp turned that no-op into a permanent conflict. A
                        // live account showed the shape: a worker killed
                        // between writing a range into a placeholder and
                        // `settle_range`'s re-stamp left the file dirty, and
                        // nothing re-stamps a file nobody touches — so the
                        // echo of the unchanged object was refused as
                        // `ChangedUnderneath` every five seconds, indefinitely,
                        // for a file whose id, version and size all matched.
                        // Not one byte would have moved in either direction,
                        // and the "conflict" could not be resolved from either
                        // side.
                        //
                        // This is not a weakening of the guards below: they
                        // exist so `place()` never destroys content that was
                        // not sent, and on this path `place()` is not reached
                        // at all. A dirty file facing a change that would
                        // apply something still falls through to them.
                        if is_current(&abs, cloud_id, etag.as_deref(), *size) {
                            continue;
                        }
                        // An edit waiting to be sent is newer than anything the
                        // cloud has to say. Replacing it with a placeholder
                        // would throw away work that exists nowhere else — the
                        // one outcome this framework must never produce.
                        if waiting.contains(&id) {
                            out.kept_local.push(Kept::new(path, Why::EditWaiting));
                            continue;
                        }
                        // Local content that has never been uploaded is in the
                        // same position, even with nothing queued: there is no
                        // remote copy of it to fall back on.
                        // Read off the file, not out of the index.
                        //
                        // The index was built before the loop and the rename
                        // above invalidates it — `Store::lookup` re-verifies
                        // against the filesystem, so after a move it answers
                        // `None` for a file that plainly exists. Every move then
                        // tripped the "never uploaded" guard and was reported as
                        // a conflict, and its size and version update was
                        // silently dropped. The id travels with the inode; the
                        // index is redundant for this question.
                        let known = crate::store::get_xattr(&abs, crate::store::XATTR_ID)
                            .ok()
                            .flatten()
                            .filter(|v| !v.is_empty());
                        if known.is_none() && md.len() > 0 {
                            out.kept_local.push(Kept::new(path, Why::NeverUploaded));
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
                            out.kept_local.push(Kept::new(path, Why::ChangedUnderneath));
                            continue;
                        }
                        match mat.place(&abs, *size, cloud_id, etag.as_deref()) {
                            Ok(()) => out.updated += 1,
                            Err(e) => out
                                .failed
                                .push(Failed::new(path, Failure::Place(e.to_string()))),
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
                if waiting.contains(&id) {
                    out.kept_local.push(Kept::new(
                        &entry.path.display().to_string(),
                        Why::EditWaiting,
                    ));
                    continue;
                }
                // Same check as the upsert side, for the same reason: a delete
                // is the more destructive of the two, and a lost notification
                // must not be what decides it.
                if matches!(
                    hydration_protocol::stamp::state(&entry.path),
                    Ok(hydration_protocol::stamp::State::Dirty)
                ) {
                    out.kept_local.push(Kept::new(
                        &entry.path.display().to_string(),
                        Why::ChangedUnderneath,
                    ));
                    continue;
                }
                match mat.remove(&entry.path) {
                    Ok(()) => out.removed += 1,
                    Err(e) => out.failed.push(Failed::new(
                        &entry.path.display().to_string(),
                        Failure::Remove(e.to_string()),
                    )),
                }
            }
            Change::FolderRemoved { cloud_id, path } => {
                let Some(existing) = folders.get(cloud_id) else {
                    continue;
                };
                if existing == root {
                    // The provider rejects root deletion, but this boundary is
                    // destructive enough to defend independently.
                    out.failed.push(Failed::new(
                        path,
                        Failure::Remove("the sync root cannot be removed".into()),
                    ));
                    continue;
                }
                match std::fs::remove_dir(existing) {
                    Ok(()) => {
                        out.removed += 1;
                        folders.remove(cloud_id);
                    }
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        folders.remove(cloud_id);
                    }
                    // Local content outlives a remote folder deletion. Files
                    // beneath are reconciled independently; a non-empty folder
                    // is not recursively erased by this operation.
                    Err(e) if e.raw_os_error() == Some(libc::ENOTEMPTY) => {
                        // The directory has local content, so it survives as a
                        // local-only folder. Its deleted cloud identity must
                        // not survive with it: a later cloud folder at this
                        // path is a different object and must not collide with
                        // a stale claim.
                        let detached =
                            crate::store::remove_xattr(existing, crate::store::XATTR_ETAG)
                                .and_then(|()| {
                                    crate::store::remove_xattr(existing, crate::store::XATTR_ID)
                                });
                        match detached {
                            Ok(()) => {
                                folders.remove(cloud_id);
                            }
                            Err(e) => {
                                out.failed
                                    .push(Failed::new(path, Failure::Remove(e.to_string())));
                                out.retryable = true;
                            }
                        }
                    }
                    Err(e) => {
                        out.failed
                            .push(Failed::new(path, Failure::Remove(e.to_string())));
                        out.retryable = true;
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Whether the local file already is what the change describes.
///
/// Identity first: a different object at this path is news whatever else
/// matches. Then the version.
///
/// When the cloud supplies no etag there is nothing authoritative to compare, so
/// size stands in. That is weaker — a same-size remote edit is missed — but the
/// alternative is to treat every listing as news, which is the failure this
/// function exists to prevent, and a provider that wants edits noticed reliably
/// has to supply an etag.
fn is_current(abs: &Path, cloud_id: &str, etag: Option<&str>, size: u64) -> bool {
    let local_id = crate::store::get_xattr(abs, crate::store::XATTR_ID)
        .ok()
        .flatten();
    if local_id.as_deref() != Some(cloud_id.as_bytes()) {
        return false;
    }
    let local_etag = crate::store::get_xattr(abs, crate::store::XATTR_ETAG)
        .ok()
        .flatten();
    // Size is checked whatever the etags say. A provider that reports the same
    // version with a different size is contradicting itself, and believing the
    // etag over the bytes would leave a placeholder promising a length the
    // object no longer has — §5.7's failure, arrived at by agreeing with the
    // cloud too readily. Erring towards a refresh costs a round trip; erring the
    // other way is silent.
    if !std::fs::metadata(abs).is_ok_and(|md| md.len() == size) {
        return false;
    }
    match (etag, local_etag.as_deref()) {
        (Some(remote), Some(local)) => remote.as_bytes() == local,
        (None, _) => true,
        // The cloud has a version and we recorded none: we cannot claim to be
        // current.
        (Some(_), None) => false,
    }
}

/// The largest object a change may claim, beyond which it is refused.
///
/// The helper enforces the same limit independently, because this one runs on
/// the side §6b assumes may be compromised — but the number is defined once, so
/// the two cannot drift into disagreeing about what "too large" means.
pub use hydration_protocol::MAX_OBJECT;

/// One change per object, last occurrence winning, order otherwise preserved.
fn coalesce(changes: &[Change]) -> Vec<Change> {
    let mut last: std::collections::HashMap<(&str, u8), usize> = std::collections::HashMap::new();
    for (i, c) in changes.iter().enumerate() {
        let id = match c {
            Change::Upserted { cloud_id, .. }
            | Change::FolderUpserted { cloud_id, .. }
            | Change::Removed { cloud_id }
            | Change::FolderRemoved { cloud_id, .. } => cloud_id.as_str(),
        };
        last.insert((id, change_class(c)), i);
    }
    changes
        .iter()
        .enumerate()
        .filter(|(i, c)| {
            let id = match c {
                Change::Upserted { cloud_id, .. }
                | Change::FolderUpserted { cloud_id, .. }
                | Change::Removed { cloud_id }
                | Change::FolderRemoved { cloud_id, .. } => cloud_id.as_str(),
            };
            last.get(&(id, change_class(c))) == Some(i)
        })
        .map(|(_, c)| c.clone())
        .collect()
}

fn change_class(change: &Change) -> u8 {
    match change {
        Change::Removed { .. } => 0,
        Change::FolderRemoved { .. } => 1,
        Change::Upserted { .. } => 2,
        Change::FolderUpserted { .. } => 3,
    }
}

fn folder_path(root: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() {
        Some(root.to_path_buf())
    } else {
        safe_join(root, rel)
    }
}

fn folders_by_cloud_id(root: &Path) -> io::Result<std::collections::HashMap<String, PathBuf>> {
    let mut found = std::collections::HashMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        if let Some(raw) = crate::store::get_xattr(&dir, crate::store::XATTR_ID)? {
            let id = String::from_utf8(raw).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("folder at {} has a non-UTF-8 cloud identity", dir.display()),
                )
            })?;
            if !id.is_empty() {
                if found.contains_key(&id) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("folder cloud identity {id:?} is claimed more than once"),
                    ));
                }
                found.insert(id, dir.clone());
            }
        }
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    Ok(found)
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

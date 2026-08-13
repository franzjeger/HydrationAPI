//! Seeing a name go away, rather than noticing it is gone.
//!
//! # Why absence is not enough
//!
//! Until this existed, "the user deleted this file" was inferred from the file
//! not being there at scan time, and that inference was only ever used to
//! *cancel* a queued upload. Cancelling on a bad inference costs an upload.
//! Propagating on one costs the user's data.
//!
//! A file is absent for at least four reasons, and only the first is a deletion:
//!
//!   * the user removed it,
//!   * the delta pass has not placed it yet,
//!   * placement failed, or
//!   * the sync root is empty, or unmounted, or the wrong directory.
//!
//! The last of those is the one that empties an account. This repository has
//! already met it: a sync root was rebuilt as a fresh, empty subvolume while the
//! account behind it held a quarter of a million objects, and
//! `empty_mount_never_deletes` exists because acting on that absence would have
//! deleted all of them.
//!
//! # And the one that is not a deletion at all
//!
//! An atomic save — git's index, and how most editors write — destroys a name
//! exactly the way a deletion does: the old inode is unlinked and a new one
//! takes the name. By absence at any later moment the two are identical. A
//! design that propagated on absence would delete a cloud object every time
//! somebody saved a file.
//!
//! The kernel distinguishes them and nothing else does. Measured,
//! `probes/deleteevents.c`, on 7.2/btrfs:
//!
//! ```text
//!   unlink                DELETE      name=inprobe-victim
//!   rename(tmp, victim)   MOVED_FROM  name=inprobe-tmp
//!                         MOVED_TO    name=inprobe-victim
//! ```
//!
//! The overwritten name is never reported as a delete.
//!
//! # Why inotify, and why here
//!
//! fanotify can report this too, and the same probe measured how: not on a mount
//! mark (`EINVAL`), and not with `FAN_MARK_FILESYSTEM` when the sync root is a
//! btrfs subvolume (`EXDEV`), which leaves a non-recursive directory mark. All
//! of it needs `CAP_SYS_ADMIN`, which means the privileged helper, a protocol
//! message, and a new responsibility for the process §6b wants to keep small —
//! for a decision that is about the cloud, which the helper never speaks to.
//!
//! inotify needs no privilege and answers the same question. Its budget on the
//! measured machine is 524288 watches against 21395 directories: four percent.
//! So this lives on the unprivileged side, where the deletion is actually
//! carried out, and the privileged half does not change at all.
//!
//! # What losing events costs
//!
//! Nothing dangerous, and that is deliberate. An overflow means removals were
//! missed, so objects stay in the cloud that the user deleted locally — a
//! sync that is behind, which the next deletion or a manual pass fixes. The
//! failure runs towards keeping data, which is the only direction this module is
//! allowed to fail in.

use std::collections::HashMap;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

const IN_DELETE: u32 = 0x0000_0200;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_CREATE: u32 = 0x0000_0100;
const IN_ISDIR: u32 = 0x4000_0000;
const IN_IGNORED: u32 = 0x0000_8000;
const IN_Q_OVERFLOW: u32 = 0x0000_4000;
const IN_EXCL_UNLINK: u32 = 0x0400_0000;

/// What every watch asks for.
///
/// `IN_CREATE` is not about files: it is how a directory created after the walk
/// gets a watch of its own, without which everything inside it would be
/// invisible. `IN_EXCL_UNLINK` keeps an already-unlinked-but-open file from
/// generating more events on a name that no longer exists.
const WATCH_MASK: u32 = IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_EXCL_UNLINK;

/// A name that went away, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gone {
    /// Relative to the sync root, `/`-separated — the same key the lineage
    /// record and the manifest use.
    pub path: String,
    /// True when the name was moved rather than unlinked, and the destination
    /// was not somewhere else inside the sync root.
    ///
    /// Kept apart because it is a different fact even though it has the same
    /// consequence: a file dragged out of the sync folder is gone from the
    /// cloud's point of view, and a user who did that would be surprised to find
    /// it still there — but a *reader* of a log wants to know which happened.
    pub moved_out: bool,
}

/// One object whose name changed while it stayed inside the sync root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Renamed {
    pub from: String,
    pub to: String,
    pub is_dir: bool,
}

/// Local namespace changes observed in one drain.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Batch {
    pub gone: Vec<Gone>,
    pub renamed: Vec<Renamed>,
    /// Directories moved out are deliberately not folded into `gone`: deleting
    /// a cloud folder can recursively delete an account-sized subtree.
    pub folders_moved_out: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MoveHalf {
    path: String,
    is_dir: bool,
}

/// Watches the sync root for names that go away.
pub struct Removals {
    fd: OwnedFd,
    /// Watch descriptor to the directory it watches, relative to the root.
    dirs: HashMap<i32, String>,
    root: PathBuf,
    /// Set when the kernel dropped events. Removals were missed; nothing is
    /// wrongly reported.
    lost: bool,
    /// Rename halves which ended the previous drain without their destination.
    ///
    /// inotify orders `IN_MOVED_FROM` before `IN_MOVED_TO`, but does not promise
    /// that a reader observes both halves in one non-blocking drain. Reporting
    /// an unmatched first half immediately can therefore turn an ordinary move
    /// inside the sync root into a cloud deletion. Hold it through one complete
    /// later drain; a matching destination cancels it, while a second drain
    /// without one proves the name moved out of the watched tree.
    pending_moves: HashMap<u32, MoveHalf>,
}

impl Removals {
    /// Start watching, and walk the tree to place a watch on every directory.
    ///
    /// The walk is the expensive part and it happens once. After that the set
    /// maintains itself: a directory created inside a watched one announces
    /// itself with `IN_CREATE`, and one that goes away takes its watch with it.
    pub fn watch(root: &Path) -> io::Result<Self> {
        // IN_NONBLOCK: `take` must be able to say "nothing happened" rather than
        // block the caller's loop.
        let raw = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut me = Self {
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            dirs: HashMap::new(),
            root: root.to_path_buf(),
            lost: false,
            pending_moves: HashMap::new(),
        };
        me.add_tree(root);
        Ok(me)
    }

    /// How many directories are being watched.
    pub fn watched(&self) -> usize {
        self.dirs.len()
    }

    /// Whether the kernel dropped events since the last [`take`](Self::take).
    pub fn lost_events(&self) -> bool {
        self.lost
    }

    fn add_tree(&mut self, dir: &Path) {
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            self.add_one(&d);
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                // `file_type` rather than `metadata`: it comes from the directory
                // entry on every filesystem this runs on and costs no `stat`,
                // which over twenty thousand directories is the difference
                // between a walk and a stall.
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    stack.push(e.path());
                }
            }
        }
    }

    fn add_one(&mut self, dir: &Path) {
        let Some(rel) = self.relative(dir) else {
            return;
        };
        let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()) else {
            return;
        };
        let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), c.as_ptr(), WATCH_MASK) };
        if wd < 0 {
            // A directory that cannot be watched is one whose deletions will not
            // be seen — which means its objects stay in the cloud. Safe, and
            // worth saying once rather than per directory.
            let e = io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::ENOSPC) {
                eprintln!(
                    "hydration-sync: out of inotify watches at {} directories; \
                     deletions below {} will not be noticed. Raise \
                     fs.inotify.max_user_watches.",
                    self.dirs.len(),
                    dir.display()
                );
            }
            return;
        }
        self.dirs.insert(wd, rel);
    }

    fn relative(&self, path: &Path) -> Option<String> {
        let rel = path.strip_prefix(&self.root).ok()?;
        Some(rel.to_str()?.to_string())
    }

    /// Everything that went away since the last call.
    ///
    /// Never blocks. An empty answer means nothing happened, which is the
    /// ordinary case.
    pub fn take(&mut self) -> Batch {
        self.lost = false;
        let mut out = Batch::default();
        // A rename *within* the sync root is not a removal, and the kernel says
        // so by giving the two halves the same cookie. Pairing has to happen
        // across the whole drain rather than within one `read`, because a
        // sufficiently large batch can split the pair across two.
        let previous_moves = std::mem::take(&mut self.pending_moves);
        let mut moved_from: HashMap<u32, MoveHalf> = HashMap::new();
        let mut moved_to: HashMap<u32, MoveHalf> = HashMap::new();
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                break;
            }
            let mut off = 0usize;
            let n = n as usize;
            while off + std::mem::size_of::<libc::inotify_event>() <= n {
                // Read field by field rather than casting the buffer: the events
                // are packed and a `*const inotify_event` into an unaligned
                // offset is undefined behaviour, not merely untidy.
                let base = &buf[off..];
                let wd = i32::from_ne_bytes(base[0..4].try_into().unwrap());
                let mask = u32::from_ne_bytes(base[4..8].try_into().unwrap());
                let cookie = u32::from_ne_bytes(base[8..12].try_into().unwrap());
                let len = u32::from_ne_bytes(base[12..16].try_into().unwrap()) as usize;
                let name_bytes = &base[16..(16 + len).min(base.len())];
                let name = name_bytes
                    .split(|b| *b == 0)
                    .next()
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .unwrap_or("")
                    .to_string();
                off += 16 + len;

                if mask & IN_Q_OVERFLOW != 0 {
                    self.lost = true;
                    continue;
                }
                if mask & IN_IGNORED != 0 {
                    self.dirs.remove(&wd);
                    continue;
                }
                let Some(dir) = self.dirs.get(&wd).cloned() else {
                    continue;
                };
                if name.is_empty() {
                    continue;
                }
                let path = if dir.is_empty() {
                    name.clone()
                } else {
                    format!("{dir}/{name}")
                };

                if mask & IN_CREATE != 0 {
                    if mask & IN_ISDIR != 0 {
                        let abs = self.root.join(&path);
                        // The whole subtree, not just this directory: between the
                        // `mkdir` and this event, anything could already have been
                        // created inside it.
                        self.add_tree(&abs);
                    }
                    continue;
                }
                if mask & IN_MOVED_TO != 0 {
                    moved_to.insert(
                        cookie,
                        MoveHalf {
                            path: path.clone(),
                            is_dir: mask & IN_ISDIR != 0,
                        },
                    );
                    if mask & IN_ISDIR != 0 {
                        let abs = self.root.join(&path);
                        self.add_tree(&abs);
                    }
                    continue;
                }
                if mask & IN_MOVED_FROM != 0 {
                    moved_from.insert(
                        cookie,
                        MoveHalf {
                            path,
                            is_dir: mask & IN_ISDIR != 0,
                        },
                    );
                    continue;
                }
                if mask & IN_DELETE != 0 && mask & IN_ISDIR == 0 {
                    out.gone.push(Gone {
                        path,
                        moved_out: false,
                    });
                }
            }
        }

        let (moved_out, pending, renamed) =
            settle_moves(previous_moves, moved_from, moved_to, self.lost);
        self.pending_moves = pending;
        for item in moved_out {
            if item.is_dir {
                out.folders_moved_out.push(item.path);
            } else {
                out.gone.push(Gone {
                    path: item.path,
                    moved_out: true,
                });
            }
        }
        out.renamed = renamed;
        out
    }
}

/// Pair rename halves without assuming one non-blocking drain receives both.
///
/// New unmatched sources are retained. Sources retained by the previous drain
/// expire only after this drain also failed to produce their destination. An
/// overflow drops every conclusion: the missing event may have been precisely
/// the destination which would have cancelled a destructive removal.
fn settle_moves(
    mut previous: HashMap<u32, MoveHalf>,
    mut current: HashMap<u32, MoveHalf>,
    destinations: HashMap<u32, MoveHalf>,
    lost: bool,
) -> (Vec<MoveHalf>, HashMap<u32, MoveHalf>, Vec<Renamed>) {
    if lost {
        return (Vec::new(), HashMap::new(), Vec::new());
    }
    let mut renamed = Vec::new();
    for (cookie, to) in destinations {
        if let Some(from) = previous.remove(&cookie).or_else(|| current.remove(&cookie)) {
            renamed.push(Renamed {
                from: from.path,
                to: to.path,
                is_dir: from.is_dir || to.is_dir,
            });
        }
    }
    let moved_out = previous.into_values().collect();
    (moved_out, current, renamed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        test_scratch::scratch(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
            &format!("removals-tests/{name}"),
        )
    }

    /// Give the kernel a moment to queue what was just done.
    ///
    /// inotify delivery is not synchronous with the syscall that caused it, and
    /// a test that read immediately would pass or fail on timing rather than on
    /// behaviour — the kind of green that means nothing.
    fn settle() {
        std::thread::sleep(std::time::Duration::from_millis(120));
    }

    #[test]
    fn an_unlinked_file_is_reported_by_its_path() {
        let dir = scratch("unlink");
        std::fs::write(dir.join("gone.txt"), b"x").unwrap();
        let mut w = Removals::watch(&dir).unwrap();

        std::fs::remove_file(dir.join("gone.txt")).unwrap();
        settle();

        let batch = w.take();
        assert!(batch.renamed.is_empty());
        assert!(batch.folders_moved_out.is_empty());
        let gone = batch.gone;
        assert_eq!(gone.len(), 1, "expected one removal, got {gone:?}");
        assert_eq!(gone[0].path, "gone.txt");
        assert!(!gone[0].moved_out);
    }

    /// The one that must never be wrong.
    #[test]
    fn an_atomic_save_is_not_a_removal() {
        let dir = scratch("atomic-save");
        std::fs::write(dir.join("doc.txt"), b"old").unwrap();
        let mut w = Removals::watch(&dir).unwrap();

        std::fs::write(dir.join("doc.txt.tmp"), b"new").unwrap();
        std::fs::rename(dir.join("doc.txt.tmp"), dir.join("doc.txt")).unwrap();
        settle();

        let batch = w.take();
        assert_eq!(
            batch.gone,
            vec![],
            "a save was reported as a deletion; propagating that would remove a \
             cloud object every time the user pressed save"
        );
        assert_eq!(
            batch.renamed,
            [Renamed {
                from: "doc.txt.tmp".into(),
                to: "doc.txt".into(),
                is_dir: false,
            }]
        );
    }

    /// And neither is a rename inside the tree.
    #[test]
    fn a_rename_within_the_sync_root_is_not_a_removal() {
        let dir = scratch("rename-inside");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        let mut w = Removals::watch(&dir).unwrap();

        std::fs::rename(dir.join("a.txt"), dir.join("sub/b.txt")).unwrap();
        settle();

        let batch = w.take();
        assert_eq!(
            batch.gone,
            vec![],
            "moving a file to another folder was read as deleting it"
        );
        assert_eq!(
            batch.renamed,
            [Renamed {
                from: "a.txt".into(),
                to: "sub/b.txt".into(),
                is_dir: false,
            }]
        );
    }

    /// Moving it *out* is a removal, and says so.
    #[test]
    fn a_file_moved_out_of_the_sync_root_is_a_removal() {
        let dir = scratch("moved-out");
        let away = scratch("moved-out-target");
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        let mut w = Removals::watch(&dir).unwrap();

        // Same filesystem, so this is a rename rather than a copy-and-delete.
        std::fs::rename(dir.join("a.txt"), away.join("a.txt")).unwrap();
        settle();

        assert_eq!(
            w.take().gone,
            vec![],
            "a move is held for its possible second half"
        );
        let gone = w.take().gone;
        assert_eq!(gone.len(), 1, "expected one removal, got {gone:?}");
        assert_eq!(gone[0].path, "a.txt");
        assert!(gone[0].moved_out, "a move out was recorded as an unlink");
    }

    #[test]
    fn a_folder_moved_out_never_enters_the_file_delete_stream() {
        let dir = scratch("folder-moved-out");
        let away = scratch("folder-moved-out-target");
        std::fs::create_dir(dir.join("album")).unwrap();
        std::fs::write(dir.join("album/photo.jpg"), b"x").unwrap();
        let mut w = Removals::watch(&dir).unwrap();

        std::fs::rename(dir.join("album"), away.join("album")).unwrap();
        settle();
        assert_eq!(w.take(), Batch::default());
        let batch = w.take();

        assert!(batch.gone.is_empty(), "a folder reached file deletion");
        assert_eq!(batch.folders_moved_out, ["album"]);
    }

    #[test]
    fn rename_halves_split_across_drains_are_still_paired() {
        let previous = HashMap::from([(
            41,
            MoveHalf {
                path: "before.txt".into(),
                is_dir: false,
            },
        )]);
        let destinations = HashMap::from([(
            41,
            MoveHalf {
                path: "after.txt".into(),
                is_dir: false,
            },
        )]);
        let (gone, pending, renamed) = settle_moves(previous, HashMap::new(), destinations, false);
        assert!(gone.is_empty(), "the first half was misread as a move out");
        assert!(pending.is_empty());
        assert_eq!(
            renamed,
            [Renamed {
                from: "before.txt".into(),
                to: "after.txt".into(),
                is_dir: false,
            }]
        );
    }

    #[test]
    fn an_unmatched_move_expires_after_one_later_drain() {
        let current = HashMap::from([(
            73,
            MoveHalf {
                path: "gone.txt".into(),
                is_dir: false,
            },
        )]);
        let (gone, pending, renamed) = settle_moves(HashMap::new(), current, HashMap::new(), false);
        assert!(gone.is_empty());
        assert!(renamed.is_empty());
        assert_eq!(pending.get(&73).map(|m| m.path.as_str()), Some("gone.txt"));

        let (gone, pending, renamed) = settle_moves(pending, HashMap::new(), HashMap::new(), false);
        assert_eq!(gone[0].path, "gone.txt");
        assert!(pending.is_empty());
        assert!(renamed.is_empty());
    }

    #[test]
    fn an_overflow_discards_pending_destructive_conclusions() {
        let previous = HashMap::from([(
            99,
            MoveHalf {
                path: "unknown.txt".into(),
                is_dir: false,
            },
        )]);
        let current = HashMap::from([(
            100,
            MoveHalf {
                path: "also-unknown.txt".into(),
                is_dir: false,
            },
        )]);
        let (gone, pending, renamed) = settle_moves(previous, current, HashMap::new(), true);
        assert!(gone.is_empty());
        assert!(pending.is_empty());
        assert!(renamed.is_empty());
    }

    /// A directory made after the walk still has its contents watched.
    #[test]
    fn a_directory_created_later_is_watched_too() {
        let dir = scratch("new-dir");
        let mut w = Removals::watch(&dir).unwrap();

        std::fs::create_dir(dir.join("fresh")).unwrap();
        std::fs::write(dir.join("fresh/x.txt"), b"x").unwrap();
        settle();
        let _ = w.take(); // the create, which is not a removal
        std::fs::remove_file(dir.join("fresh/x.txt")).unwrap();
        settle();

        let gone = w.take().gone;
        assert_eq!(gone.len(), 1, "expected one removal, got {gone:?}");
        assert_eq!(
            gone[0].path, "fresh/x.txt",
            "a deletion inside a directory created after the walk was invisible"
        );
    }

    #[test]
    fn nested_directories_are_all_watched_from_the_start() {
        let dir = scratch("nested");
        std::fs::create_dir_all(dir.join("a/b/c")).unwrap();
        std::fs::write(dir.join("a/b/c/deep.txt"), b"x").unwrap();
        let mut w = Removals::watch(&dir).unwrap();
        assert!(
            w.watched() >= 4,
            "the walk placed {} watches for four directories",
            w.watched()
        );

        std::fs::remove_file(dir.join("a/b/c/deep.txt")).unwrap();
        settle();

        let gone = w.take().gone;
        assert_eq!(gone.len(), 1, "expected one removal, got {gone:?}");
        assert_eq!(gone[0].path, "a/b/c/deep.txt");
    }

    #[test]
    fn a_quiet_tree_reports_nothing() {
        let dir = scratch("quiet");
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        let mut w = Removals::watch(&dir).unwrap();
        settle();
        assert_eq!(w.take(), Batch::default());
        assert!(!w.lost_events());
    }
}

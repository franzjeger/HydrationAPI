//! Creating a placeholder without asking the privileged side for anything.
//!
//! This is the part of delta sync that looked, for a long time, like it had to
//! cross the privilege boundary. Giving a file its size inside a marked mount
//! fires a pre-content event, and the only process that can answer that event is
//! the root helper — so the unprivileged daemon appeared unable to create its
//! own placeholders without either handing root a destination to write to, or
//! borrowing root's ability to suppress events on a chosen inode.
//!
//! Both of those are worse than they sound. Handing root a path means root walks
//! a path the daemon controls, produces root-owned results, and — since the
//! placeholder's stored `mode` is applied by whoever creates it — lets a `mode`
//! of `06755` become a setuid-root binary whose content the same daemon later
//! supplies. Lending out an ignore mark means the daemon can name any inode and
//! have events on it suppressed, which is the ability to make a file read as
//! zeros: precisely the failure this framework exists to prevent.
//!
//! `O_TMPFILE` removes the dilemma rather than managing it. The placeholder is
//! built on an anonymous inode — one with no name, that nothing can traverse to
//! — and `linkat` gives it its name only once it is already complete. Measured
//! on 7.1.6 (`probes/tmpfile.c`):
//!
//! ```text
//!   events after create:            0
//!   events observed while sizing:   1   <- nlink=0, size=0
//!   events during linkat:           0
//!   result: size=4096 blocks=0, dehydrated mark present
//! ```
//!
//! So sizing is *not* silent. The one event it fires is answered by the worker
//! on a property rather than a claim: the event precedes the truncate taking
//! effect, so the inode is still **empty** when the worker looks, and an empty
//! file has no bytes that a reader could be served instead of real content.
//! Allowing it is not a shortcut past hydration — it is what hydrating a
//! zero-length file would do.
//!
//! An earlier version of this module set a `user.hydration.building` xattr and
//! the worker trusted it. That was exploitable: every `user.*` attribute is
//! writable by any process sharing the file's uid, so forging it on a real
//! placeholder, letting a reader block on it and then unlinking it made the
//! helper serve zeros. The rule has to rest on something the file *is*, not on
//! something someone *says*.
//!
//! [`hydrationd`'s worker rule]: ../../hydrationd/daemon/struct.Worker.html
//!
//! What this buys, in the terms of DESIGN.md §6b: there is no destination in the
//! protocol at all. The privileged half is not merely careful about paths the
//! daemon sends it — it is never sent one.
//!
//! # Why nothing here resolves a path from the root down
//!
//! Every operation below goes through a descriptor on the sync root, opened once
//! and held. That is not a tidiness preference; it is the whole of the fix for
//! the failure of 2026-08-12, and the reasoning is worth having in full because
//! the obvious alternative — check the mount, then act — cannot work.
//!
//! `hydrationd` detaches the sync mount when it fails closed. From this side the
//! sync root then resolves to the bare directory that was underneath it, which
//! looks like an ordinary empty directory waiting to be filled. A pass that was
//! already running filled it: 147,540 placeholders, 37 MB, into a btrfs
//! subvolume nothing can ever mark, every one of them reading back as zeros and
//! indistinguishable from a real file. The pass reported `+147540 failed 0`.
//!
//! A check cannot close that. `is_mount_point` at the top of a round holds for
//! an instant, and a round applying 147,540 changes takes minutes; moving it
//! inside the loop narrows the window to the gap between the check and the
//! `linkat`, but a window that is never zero, entered 147,540 times, on a
//! failure this silent, is not a fix — it is the same bug with a smaller
//! probability attached.
//!
//! Not an argument — measured. `mount_vanishes.rs` was run against a build with
//! the per-change check in place and this descriptor removed, so the check was
//! the only thing standing:
//!
//! ```text
//!   per-change check only:      1 placeholder in the bare directory
//!   neither:                  381 placeholders in the bare directory
//!   both:                       0
//! ```
//!
//! One, not none. That one is the change whose check passed microseconds before
//! the detach landed, and it is what the window looks like when it is as narrow
//! as a check can make it. On the rig that would be one unhydratable file per
//! detach, indistinguishable from a real one, found by whatever opens it next.
//!
//! A descriptor has no window. It refers to the directory it was opened on, and
//! detaching a mount does not change what an open descriptor means — so
//! `openat`, `mkdirat`, `linkat` and `renameat` relative to it land on the
//! filesystem this placer was opened against or they do not happen. The mount
//! going away stops being something to detect in time and becomes something that
//! cannot redirect us at all. Detecting it is still worth doing, and
//! [`TmpfilePlacer::root_still_current`] is that — but it decides *when to
//! stop*, not *where bytes go*, and only the second of those can be got wrong
//! catastrophically.

use crate::delta::Materialise;
use crate::store;
use hydration_protocol::mount::MountIdentity;
use hydration_protocol::xattr;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

/// Builds placeholders on anonymous inodes and links them into place.
pub struct TmpfilePlacer {
    root: PathBuf,
    /// The sync root itself, held open for as long as this placer lives.
    ///
    /// Every path below is resolved relative to this rather than from `/`, so
    /// the destination is decided by what was verified at open time and not by
    /// what the path happens to mean when the syscall runs.
    dir: OwnedFd,
    /// The mount `root` led to when it was opened. Compared against the path's
    /// current mount to notice that the ground moved — see
    /// [`TmpfilePlacer::root_still_current`].
    mount: MountIdentity,
    /// Distinguishes concurrent link attempts in the same directory. Not for
    /// uniqueness against an attacker — the name exists for microseconds inside
    /// a directory the user owns — but so two passes cannot collide.
    seq: u64,
}

impl TmpfilePlacer {
    /// Open the sync root and pin it.
    ///
    /// Fallible where it used to be infallible, and that is the point: a placer
    /// that could not open its root has no business being handed changes to
    /// apply, and the alternative is discovering it one `place()` at a time.
    ///
    /// The mount identity is captured here, in the same breath as the open, so
    /// that what is recorded is the mount the descriptor actually landed on.
    pub fn new(root: impl Into<PathBuf>) -> io::Result<Self> {
        let root = root.into();
        let dir = open_dir(&root)?;
        // Off the descriptor, not off the path. Between the open above and a
        // `capture(&root)` the mount could be replaced, and the placer would
        // then hold a descriptor on one filesystem and an identity belonging to
        // another — a guard that reports a swap that did not happen, or misses
        // one that did.
        let mount = MountIdentity::of_fd(dir.as_fd())?;
        Ok(Self {
            root,
            dir,
            mount,
            seq: 0,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the sync root path still leads to the mount this placer pinned.
    ///
    /// Nothing depends on this for safety — the descriptor already decides where
    /// bytes go. It exists so a pass can *stop*, because carrying on writing
    /// into a filesystem the user can no longer reach is work nobody asked for,
    /// and because `hydrationd` detaching the mount is a deliberate action that
    /// the client should report rather than absorb in silence.
    ///
    /// One `statx`, measured at 0.24 µs against 13.38 µs for a `mountinfo`
    /// parse (`probes/mountcheck_cost.c`), which is what makes it affordable per
    /// item instead of per round.
    pub fn root_still_current(&self) -> io::Result<bool> {
        self.mount.still_current(&self.root)
    }

    /// The path as components below the root, or `None` if it is not below it.
    ///
    /// Everything downstream operates relative to the pinned descriptor, so an
    /// absolute path has to be turned back into a relative one first. A path
    /// that does not start with the root is refused rather than reinterpreted:
    /// `delta::safe_join` builds every path this receives by joining onto the
    /// same root, so anything else is a caller that has gone wrong, and quietly
    /// resolving it from `/` is exactly the redirection this module exists to
    /// make impossible.
    fn relative<'a>(&self, path: &'a Path) -> Option<&'a Path> {
        let rel = path.strip_prefix(&self.root).ok()?;
        // `strip_prefix` is happy with a result that climbs back out, and
        // `openat` would follow it.
        (!rel.as_os_str().is_empty() && rel.components().all(|c| matches!(c, Component::Normal(_))))
            .then_some(rel)
    }

    /// Remove scratch names left by a crash between `linkat` and `rename`.
    ///
    /// The window is small and what it leaves behind is a complete, correct
    /// placeholder rather than anything dangerous — but it is visible in the
    /// user's sync folder and will never be cleaned up by anything else, so it
    /// is swept at startup. Recursive, because placeholders are created at
    /// whatever depth the cloud says.
    pub fn sweep_scratch(root: &Path) -> io::Result<usize> {
        let mut removed = 0;
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                let name = e.file_name();
                let name = name.to_string_lossy();
                if e.file_type().is_ok_and(|t| t.is_dir()) {
                    stack.push(e.path());
                } else if is_scratch(&name) && std::fs::remove_file(e.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }

    /// An anonymous inode on the pinned filesystem.
    ///
    /// Same filesystem is not a preference: `linkat` cannot cross one, so an
    /// inode created anywhere else could never be given its name. Measured for
    /// both boundaries this could face — two filesystems, and two btrfs
    /// subvolumes of one filesystem, which is what production actually crossed —
    /// in `probes/tmpfile_exdev.c`; both refuse with `EXDEV`.
    ///
    /// Anchored on the root descriptor rather than on the destination directory.
    /// The destination is reached through that same descriptor, so the two are
    /// always on one filesystem and the link can never be the thing that fails;
    /// anchoring on a re-resolved path is what let the inode be created on
    /// whatever the sync root had turned into.
    fn anonymous(&self) -> io::Result<OwnedFd> {
        use std::os::fd::FromRawFd;
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                c".".as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                0o644 as libc::c_uint,
            )
        };
        if fd < 0 {
            // Worth distinguishing, because it is a filesystem capability and
            // not a mistake: O_TMPFILE is absent on some backing stores, and the
            // caller has no other way to tell that from a permission problem.
            let e = io::Error::last_os_error();
            return Err(match e.raw_os_error() {
                Some(libc::EOPNOTSUPP) => io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("{} does not support O_TMPFILE", self.root.display()),
                ),
                _ => e,
            });
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn set(fd: &OwnedFd, name: &str, value: &[u8]) -> io::Result<()> {
        let n = std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "xattr name"))?;
        let r = unsafe {
            libc::fsetxattr(
                fd.as_raw_fd(),
                n.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            )
        };
        (r == 0).then_some(()).ok_or_else(io::Error::last_os_error)
    }

    /// Give the anonymous inode a name.
    ///
    /// `linkat` refuses to replace an existing name, which is what makes it safe
    /// here and also why an update cannot use it directly. So an update links to
    /// a scratch name in the same directory and renames over the target: rename
    /// is atomic, and a reader either sees the whole old file or the whole new
    /// placeholder — the same guarantee §5.4 asks of applications saving files.
    ///
    /// `rel` is relative to the pinned root, and every syscall here names that
    /// descriptor. The scratch name is built from `rel` rather than from the
    /// absolute path for the same reason.
    fn link_into_place(&self, fd: &OwnedFd, rel: &Path, seq: u64) -> io::Result<()> {
        let proc = format!("/proc/self/fd/{}", fd.as_raw_fd());
        match linkat_into(&proc, self.dir.as_fd(), rel) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            Err(_) => {}
        }
        let dir = rel.parent().unwrap_or(Path::new(""));
        let base = rel.file_name().and_then(|n| n.to_str()).unwrap_or("f");
        let scratch = dir.join(format!(".{base}.hydration-{seq}"));
        let _ = unlinkat(self.dir.as_fd(), &scratch);
        linkat_into(&proc, self.dir.as_fd(), &scratch)?;
        // Rename touches no content, so it fires no pre-content event — the
        // placeholder arrives complete or not at all.
        renameat(self.dir.as_fd(), &scratch, rel).inspect_err(|_| {
            let _ = unlinkat(self.dir.as_fd(), &scratch);
        })
    }

    /// Create every directory on the way to `rel`'s parent, under the root.
    ///
    /// `mkdirat` a component at a time rather than `create_dir_all`, which takes
    /// an absolute path and would build the tree wherever that path now leads.
    /// The 2026-08-12 incident left directories as well as files behind; a
    /// skeleton of empty directories is less harmful than a placeholder that
    /// reads as zeros, but it is still a tree in the user's home that looks like
    /// their sync folder and that nothing else will ever remove.
    fn make_parents(&self, rel: &Path) -> io::Result<()> {
        let Some(parent) = rel.parent() else {
            return Ok(());
        };
        let mut so_far = PathBuf::new();
        for c in parent.components() {
            so_far.push(c);
            let c = cstr(&so_far)?;
            let r = unsafe { libc::mkdirat(self.dir.as_raw_fd(), c.as_ptr(), 0o755) };
            if r != 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}

use hydration_protocol::names::is_scratch;

fn cstr(p: &Path) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(p.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn open_dir(path: &Path) -> io::Result<OwnedFd> {
    use std::os::fd::FromRawFd;
    let c = cstr(path)?;
    // `O_PATH` would be enough to name things relative to, and is not enough to
    // create an `O_TMPFILE` inode under. One descriptor doing both jobs is worth
    // more than the narrower open.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn linkat_into(proc_path: &str, dir: BorrowedFd<'_>, rel: &Path) -> io::Result<()> {
    let from = std::ffi::CString::new(proc_path.as_bytes()).unwrap();
    let to = cstr(rel)?;
    let r = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            from.as_ptr(),
            dir.as_raw_fd(),
            to.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    (r == 0).then_some(()).ok_or_else(io::Error::last_os_error)
}

fn renameat(dir: BorrowedFd<'_>, from: &Path, to: &Path) -> io::Result<()> {
    let (f, t) = (cstr(from)?, cstr(to)?);
    let r = unsafe { libc::renameat(dir.as_raw_fd(), f.as_ptr(), dir.as_raw_fd(), t.as_ptr()) };
    (r == 0).then_some(()).ok_or_else(io::Error::last_os_error)
}

fn unlinkat(dir: BorrowedFd<'_>, rel: &Path) -> io::Result<()> {
    let c = cstr(rel)?;
    let r = unsafe { libc::unlinkat(dir.as_raw_fd(), c.as_ptr(), 0) };
    (r == 0).then_some(()).ok_or_else(io::Error::last_os_error)
}

impl Materialise for TmpfilePlacer {
    fn place(
        &mut self,
        path: &Path,
        size: u64,
        cloud_id: &str,
        etag: Option<&str>,
    ) -> io::Result<()> {
        let rel = self.relative(path).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is not below the sync root {}; refusing rather than \
                     resolving it from /",
                    path.display(),
                    self.root.display()
                ),
            )
        })?;
        self.make_parents(rel)?;

        let fd = self.anonymous()?;

        // Order is load-bearing. Every xattr goes on before the file has a size
        // and long before it has a name, so the inode is never observable in a
        // half-built state: it is either anonymous and incomplete, or named and
        // finished.
        //
        // The mark in particular has to precede the sizing, or the worker sees
        // an unmarked file, concludes its content is already present, and leaves
        // a permanent ignore mark — which then follows the inode through
        // `linkat` into the sync directory and produces a placeholder that is
        // silently never intercepted again. That is this project's recurring
        // trap (§6a-ter) in its sixth disguise.
        Self::set(&fd, xattr::DEHYDRATED, b"1")?;
        Self::set(&fd, store::XATTR_ID, cloud_id.as_bytes())?;
        if let Some(e) = etag {
            Self::set(&fd, store::XATTR_ETAG, e.as_bytes())?;
        }

        // The one event. The worker allows it because the inode is nameless and
        // still empty — the event precedes the truncate — and an empty file has
        // no content anyone could be served instead of the real thing.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), size as libc::off_t) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // Stamped while still anonymous, so the file has never existed under a
        // name in an unstamped state. A placeholder with no stamp reads as
        // "content the framework has never touched", which is what protects a
        // user's own files from being replaced — so a placeholder that arrived
        // without one would be protected from the very refresh it needs.
        let _ = hydration_protocol::stamp::write_fd(fd.as_fd());

        self.seq += 1;
        let seq = self.seq;
        self.link_into_place(&fd, rel, seq)
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        // Through the descriptor like everything else. A removal aimed at a path
        // that has stopped meaning what it meant is the same hazard pointed the
        // other way: `remove_file` on the bare directory underneath a detached
        // mount would delete whatever the user happens to keep there.
        let Some(rel) = self.relative(path) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is not below the sync root {}",
                    path.display(),
                    self.root.display()
                ),
            ));
        };
        match unlinkat(self.dir.as_fd(), rel) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }

    fn root_still_current(&self) -> io::Result<bool> {
        TmpfilePlacer::root_still_current(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydration_protocol::holds_data;

    fn scratch(name: &str) -> PathBuf {
        // Deliberately not /tmp: this needs a filesystem with both O_TMPFILE
        // and user xattrs, and the target directory is on the same one the
        // framework is developed against.
        // Not /tmp: this needs a filesystem with O_TMPFILE and user extended
        // attributes. `HYDRATION_TEST_DIR` points it at whichever one is under
        // test; unset, it lands beside the target directory as before.
        //
        // `CARGO_TARGET_TMPDIR` is not available to a unit test inside the
        // library — cargo only sets it for integration tests — so the fallback
        // is spelled out from the manifest directory.
        test_scratch::scratch(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
            &format!("place-tests/{name}"),
        )
    }

    /// Without a marked mount this exercises construction rather than the event
    /// rule — the point being that the result is a correct placeholder, and that
    /// nothing observable is left behind. The event half is measured by
    /// `probes/tmpfile.c` and asserted by the privileged conformance run.
    #[test]
    fn builds_a_placeholder_with_no_content_and_the_right_identity() {
        let dir = scratch("basic");
        let mut p = TmpfilePlacer::new(&dir).unwrap();
        let target = dir.join("sub/report.pdf");
        p.place(&target, 8192, "cloud-1", Some("etag-a")).unwrap();

        let md = std::fs::metadata(&target).unwrap();
        assert_eq!(md.len(), 8192);
        assert!(
            !holds_data(&target).unwrap(),
            "the placeholder holds content — asked with SEEK_DATA rather than \
             st_blocks, which on a filesystem whose inodes cannot hold the \
             identity attributes charges a block for them and reports the same \
             number for an empty placeholder and a file with a byte in it"
        );
        assert_eq!(
            store::get_xattr(&target, store::XATTR_ID).unwrap().unwrap(),
            b"cloud-1"
        );
        assert!(store::get_xattr(&target, xattr::DEHYDRATED)
            .unwrap()
            .is_some());
    }

    /// A regression guard against a mechanism that was removed for being
    /// exploitable.
    ///
    /// The first version of placeholder creation set `user.hydration.building`
    /// and the helper trusted it to allow an event without hydrating. Any
    /// process with the file's uid can set that xattr, so forging it on a real
    /// placeholder made the helper serve zeros to a reader. The name is asserted
    /// absent here so that reintroducing the mark shows up as a failing test
    /// rather than as a passing one.
    #[test]
    fn the_placer_writes_no_xattr_the_helper_would_trust() {
        let dir = scratch("no-trusted-xattr");
        let mut p = TmpfilePlacer::new(&dir).unwrap();
        let target = dir.join("a.bin");
        p.place(&target, 128, "cloud-1", None).unwrap();

        assert_eq!(
            store::get_xattr(&target, "user.hydration.building").unwrap(),
            None,
            "the construction mark is back; it is forgeable and must not be trusted"
        );
    }

    /// Refreshing an existing placeholder goes through rename, so there is no
    /// moment at which the name is missing or the file is half-sized.
    #[test]
    fn an_existing_file_is_replaced_atomically() {
        let dir = scratch("replace");
        let mut p = TmpfilePlacer::new(&dir).unwrap();
        let target = dir.join("a.bin");
        p.place(&target, 100, "cloud-1", None).unwrap();
        let first = std::fs::metadata(&target).unwrap();

        p.place(&target, 250, "cloud-1", Some("etag-2")).unwrap();
        let second = std::fs::metadata(&target).unwrap();

        assert_eq!(second.len(), 250);
        use std::os::unix::fs::MetadataExt;
        assert_ne!(first.ino(), second.ino(), "expected a fresh inode");
        assert_eq!(
            store::get_xattr(&target, store::XATTR_ETAG)
                .unwrap()
                .unwrap(),
            b"etag-2"
        );
        // The scratch name is an implementation detail that must not outlive the
        // call; a leftover would be visible to the user in their sync folder.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("hydration-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "scratch names left behind: {leftovers:?}"
        );
    }

    /// A crash between `linkat` and `rename` leaves a complete placeholder under
    /// a scratch name. Harmless to read, but it is litter in the user's folder
    /// and nothing else would ever remove it.
    #[test]
    fn scratch_names_left_by_a_crash_are_swept() {
        let dir = scratch("sweep");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join(".a.bin.hydration-3"), b"").unwrap();
        std::fs::write(dir.join("sub/.b.bin.hydration-9"), b"").unwrap();
        std::fs::write(dir.join("keep.txt"), b"x").unwrap();
        std::fs::write(dir.join(".hydration-manifest"), b"x").unwrap();

        assert_eq!(TmpfilePlacer::sweep_scratch(&dir).unwrap(), 2);
        assert!(dir.join("keep.txt").exists());
        assert!(
            dir.join(".hydration-manifest").exists(),
            "the sweep took the manifest, which is not scratch"
        );
    }

    #[test]
    fn the_scratch_pattern_matches_only_what_the_placer_creates() {
        assert!(is_scratch(".report.pdf.hydration-7"));
        assert!(is_scratch(".a.hydration-12"));
        // The manifest, and everything else a user might reasonably have.
        assert!(!is_scratch(".hydration-manifest"));
        assert!(!is_scratch(".hydration-manifest.tmp"));
        assert!(!is_scratch(".hydration-"));
        assert!(!is_scratch("report.pdf"));
        assert!(!is_scratch(".bashrc"));
        assert!(!is_scratch(".notes.hydration-draft"));
    }

    #[test]
    fn removing_something_already_gone_is_not_an_error() {
        let dir = scratch("remove");
        let mut p = TmpfilePlacer::new(&dir).unwrap();
        p.remove(&dir.join("never-existed")).unwrap();
    }

    /// Neither half of the placer will act on a path that is not below its root.
    ///
    /// The root is a descriptor, so a path outside it has no meaning here at
    /// all — there is nothing to resolve it against. Refusing is the only honest
    /// answer, and it has to be the answer for `remove` as well as `place`: a
    /// deletion aimed at a path that stopped meaning what it meant is the same
    /// hazard with the sign flipped.
    #[test]
    fn a_path_outside_the_root_is_refused_rather_than_resolved() {
        let dir = scratch("outside");
        let mut p = TmpfilePlacer::new(&dir).unwrap();

        // Somewhere else entirely, and — the one that matters — a path that
        // starts with the root's text and climbs back out of it. `strip_prefix`
        // accepts the second, and `openat` would happily follow the `..`.
        for bad in [
            PathBuf::from("/tmp/elsewhere.bin"),
            dir.join("../escaped.bin"),
            dir.join("sub/../../escaped.bin"),
        ] {
            assert!(
                p.place(&bad, 16, "cloud-1", None).is_err(),
                "placed at {}, which is not below {}",
                bad.display(),
                dir.display()
            );
            assert!(
                p.remove(&bad).is_err(),
                "removed {}, which is not below {}",
                bad.display(),
                dir.display()
            );
            assert!(
                !bad.exists(),
                "{} exists after being refused",
                bad.display()
            );
        }
    }

    /// The root a placer pins is the one it was opened on, not the one the path
    /// leads to later.
    ///
    /// Renaming the directory out from under an open placer is the cheapest
    /// unprivileged stand-in for the mount being detached: in both cases the
    /// path the placer was given stops leading where it led. The privileged
    /// suite does it with a real mount (`tests/mount_vanishes.rs`); this runs
    /// everywhere and fails for the same reason.
    #[test]
    fn a_placer_follows_its_descriptor_and_not_its_path() {
        let dir = scratch("renamed-away");
        let mut p = TmpfilePlacer::new(&dir).unwrap();

        let moved = dir.with_extension("moved");
        let _ = std::fs::remove_dir_all(&moved);
        std::fs::rename(&dir, &moved).unwrap();
        // A fresh, empty directory back at the original name — which is exactly
        // what the sync root becomes when the mount under it goes away.
        std::fs::create_dir_all(&dir).unwrap();

        p.place(&dir.join("a.bin"), 4096, "cloud-1", None).unwrap();

        assert!(
            !dir.join("a.bin").exists(),
            "the placeholder landed in the new directory at the old path — the \
             placer resolved the path again instead of using what it pinned"
        );
        assert!(
            moved.join("a.bin").exists(),
            "the placeholder is in neither directory"
        );
        // And the check does *not* notice this, which is the point rather than a
        // gap: the new directory is on the same filesystem, so the mount id is
        // unchanged and `root_still_current` truthfully says so. A rename is not
        // a mount change. What kept the placeholder out of the wrong directory
        // was the descriptor, with the check contributing nothing — which is the
        // division of labour this module is built on, visible in one assertion.
        assert!(
            p.root_still_current().unwrap(),
            "a rename within one filesystem was reported as a mount change"
        );
    }
}

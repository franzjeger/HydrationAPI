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
//! on 6.17 (`probes/tmpfile.c`):
//!
//! ```text
//!   events after create:            0
//!   events observed while sizing:   1   <- nlink=0, construction mark set
//!   events during linkat:           0
//!   result: size=4096 blocks=0, dehydrated mark present
//! ```
//!
//! So sizing is *not* silent, and the one event it fires is what
//! [`hydrationd`'s worker rule] answers: an inode with `nlink == 0` carrying the
//! construction mark has no reader that could be served wrong data, because
//! nothing can open it. Everything else about the placeholder — its xattrs, its
//! mode, its identity — is set before it has a name, and is therefore never
//! observable in a half-built state.
//!
//! [`hydrationd`'s worker rule]: ../../hydrationd/daemon/struct.Worker.html
//!
//! What this buys, in the terms of DESIGN.md §6b: there is no destination in the
//! protocol at all. The privileged half is not merely careful about paths the
//! daemon sends it — it is never sent one.

use crate::delta::Materialise;
use crate::store;
use hydration_protocol::xattr;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

/// Builds placeholders on anonymous inodes and links them into place.
pub struct TmpfilePlacer {
    root: PathBuf,
    /// Distinguishes concurrent link attempts in the same directory. Not for
    /// uniqueness against an attacker — the name exists for microseconds inside
    /// a directory the user owns — but so two passes cannot collide.
    seq: u64,
}

impl TmpfilePlacer {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            seq: 0,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// An anonymous inode on the same filesystem as `dir`.
    ///
    /// Same filesystem is not a preference: `linkat` cannot cross one, so an
    /// inode created anywhere else could never be given its name.
    fn anonymous(dir: &Path) -> io::Result<OwnedFd> {
        use std::os::fd::FromRawFd;
        let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
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
                    format!("{} does not support O_TMPFILE", dir.display()),
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

    fn unset(fd: &OwnedFd, name: &str) -> io::Result<()> {
        let n = std::ffi::CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "xattr name"))?;
        let r = unsafe { libc::fremovexattr(fd.as_raw_fd(), n.as_ptr()) };
        (r == 0).then_some(()).ok_or_else(io::Error::last_os_error)
    }

    /// Give the anonymous inode a name.
    ///
    /// `linkat` refuses to replace an existing name, which is what makes it safe
    /// here and also why an update cannot use it directly. So an update links to
    /// a scratch name in the same directory and renames over the target: rename
    /// is atomic, and a reader either sees the whole old file or the whole new
    /// placeholder — the same guarantee §5.4 asks of applications saving files.
    fn link_into_place(fd: &OwnedFd, target: &Path, seq: u64) -> io::Result<()> {
        let proc = format!("/proc/self/fd/{}", fd.as_raw_fd());
        match linkat(&proc, target) {
            Ok(()) => return Ok(()),
            Err(e) if e.kind() != io::ErrorKind::AlreadyExists => return Err(e),
            Err(_) => {}
        }
        let dir = target.parent().unwrap_or(Path::new("."));
        let base = target.file_name().and_then(|n| n.to_str()).unwrap_or("f");
        let scratch = dir.join(format!(".{base}.hydration-{seq}"));
        let _ = std::fs::remove_file(&scratch);
        linkat(&proc, &scratch)?;
        // Rename touches no content, so it fires no pre-content event — the
        // placeholder arrives complete or not at all.
        std::fs::rename(&scratch, target).inspect_err(|_| {
            let _ = std::fs::remove_file(&scratch);
        })
    }
}

fn linkat(proc_path: &str, target: &Path) -> io::Result<()> {
    let from = std::ffi::CString::new(proc_path.as_bytes()).unwrap();
    let to = std::ffi::CString::new(target.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let r = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
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
        let dir = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "placeholder path has no parent")
        })?;
        std::fs::create_dir_all(dir)?;

        let fd = Self::anonymous(dir)?;

        // Order is load-bearing, and it is the reason this works at all.
        //
        // The construction mark has to be on the inode *before* the event fires,
        // or the worker sees an unmarked file and treats it as one: it leaves a
        // permanent ignore mark, which then follows the inode through `linkat`
        // into the sync directory and produces a placeholder that is silently
        // never intercepted again. That is this project's recurring trap — a
        // write inside a marked mount by the one process that could answer the
        // event — in its sixth disguise, and the ordering here is what disarms
        // it.
        Self::set(&fd, xattr::BUILDING, b"1")?;
        Self::set(&fd, xattr::DEHYDRATED, b"1")?;
        Self::set(&fd, store::XATTR_ID, cloud_id.as_bytes())?;
        if let Some(e) = etag {
            Self::set(&fd, store::XATTR_ETAG, e.as_bytes())?;
        }

        // The one event. Answered by the worker's nameless rule.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), size as libc::off_t) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // Cleared before the inode has a name, so a file with a name never
        // carries it. If this failed we would be linking in a file the worker
        // would later allow without hydrating — a file that reads as zeros — so
        // it is an error and not a cleanup step.
        Self::unset(&fd, xattr::BUILDING)?;

        self.seq += 1;
        Self::link_into_place(&fd, path, self.seq)
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            r => r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        // Deliberately not /tmp: this needs a filesystem with both O_TMPFILE
        // and user xattrs, and the target directory is on the same one the
        // framework is developed against.
        let d = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/place-tests")
            .join(name);
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Without a marked mount this exercises construction rather than the event
    /// rule — the point being that the result is a correct placeholder, and that
    /// nothing observable is left behind. The event half is measured by
    /// `probes/tmpfile.c` and asserted by the privileged conformance run.
    #[test]
    fn builds_a_placeholder_with_no_content_and_the_right_identity() {
        let dir = scratch("basic");
        let mut p = TmpfilePlacer::new(&dir);
        let target = dir.join("sub/report.pdf");
        p.place(&target, 8192, "cloud-1", Some("etag-a")).unwrap();

        let md = std::fs::metadata(&target).unwrap();
        assert_eq!(md.len(), 8192);
        use std::os::unix::fs::MetadataExt;
        assert_eq!(md.blocks(), 0, "the placeholder occupies disk");
        assert_eq!(
            store::get_xattr(&target, store::XATTR_ID).unwrap().unwrap(),
            b"cloud-1"
        );
        assert!(store::get_xattr(&target, xattr::DEHYDRATED)
            .unwrap()
            .is_some());
    }

    /// A file carrying the construction mark is one the worker will allow
    /// without hydrating. If one ever reached the sync directory it would read
    /// as zeros, so its absence is the invariant, not a tidiness check.
    #[test]
    fn a_linked_placeholder_never_carries_the_construction_mark() {
        let dir = scratch("no-building-mark");
        let mut p = TmpfilePlacer::new(&dir);
        let target = dir.join("a.bin");
        p.place(&target, 128, "cloud-1", None).unwrap();

        assert_eq!(
            store::get_xattr(&target, xattr::BUILDING).unwrap(),
            None,
            "a named file carries the construction mark: it would read as zeros"
        );
    }

    /// Refreshing an existing placeholder goes through rename, so there is no
    /// moment at which the name is missing or the file is half-sized.
    #[test]
    fn an_existing_file_is_replaced_atomically() {
        let dir = scratch("replace");
        let mut p = TmpfilePlacer::new(&dir);
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
        assert!(leftovers.is_empty(), "scratch names left behind: {leftovers:?}");
    }

    #[test]
    fn removing_something_already_gone_is_not_an_error() {
        let dir = scratch("remove");
        let mut p = TmpfilePlacer::new(&dir);
        p.remove(&dir.join("never-existed")).unwrap();
    }
}

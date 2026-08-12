//! Which mount a path led to, at one moment, in a form that can be re-asked.
//!
//! Both halves need this and they must not disagree about it, which is why it is
//! here rather than in either of them.
//!
//! * `hydrationd` takes it immediately after marking, so it can prove later that
//!   its mark is still on the mount readers actually traverse. A mark on a
//!   replaced mount is still a *valid* mark — the group is open, the worker is
//!   answering — and it protects nobody.
//!
//! * `hydration-client` takes it when it opens the sync root, so a delta pass
//!   can tell that the ground moved underneath it. `hydrationd` detaches the
//!   mount on its way out as a deliberate fail-closed action, and from the
//!   client's side the sync root then looks like an ordinary empty directory
//!   waiting to be filled with placeholders that nothing can ever hydrate.
//!
//! # Why the unique mount id, and not the obvious one
//!
//! `probes/mntid.c`, on this kernel:
//!
//! ```text
//! first mount:   STATX_MNT_ID = 31   STATX_MNT_ID_UNIQUE = 2147500463
//! second mount:  STATX_MNT_ID = 31   STATX_MNT_ID_UNIQUE = 2147500479
//! ```
//!
//! Unmount and remount the same path, and the small id — field 1 of
//! `/proc/self/mountinfo` — comes straight back. A check built on it compares
//! equal across exactly the replacement it exists to catch, which is the same
//! shape as the `st_blocks` trap in §8z: the number that looks like the answer
//! reads the same for both states. The 64-bit id is not reused, and is the only
//! one of the two that can carry this.
//!
//! # Why not "is the path still a mount point"
//!
//! Because that is a weaker question, and cheaper to answer wrongly. Measured
//! (`probes/mountcheck_cost.c`, 35 mounts, 4394 bytes of `mountinfo`):
//!
//! ```text
//!   mountinfo read+parse:    13.38 us
//!   statx unique mnt id:      0.24 us   (57x cheaper)
//! ```
//!
//! The cost is the lesser argument. `mountinfo` answers "*a* mount is here",
//! and this answers "*the* mount is here" — and between a detach and the
//! remount that follows it under `RequiresMountsFor=`, those two differ for as
//! long as it takes systemd to notice, which is the whole window.

use std::io;
use std::path::Path;

/// Linux 6.8. Fills the same `stx_mnt_id` field as `STATX_MNT_ID` with the id
/// that is never handed out twice.
const STATX_MNT_ID_UNIQUE: libc::c_uint = 0x0000_4000;

/// The identity of the mount a path resolved to at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountIdentity(u64);

impl MountIdentity {
    /// Taken at the moment the caller established the path was good, so what is
    /// recorded is the mount it checked rather than one that replaced it in
    /// between.
    ///
    /// The path need not be a mount point. What is captured is the mount the
    /// path *lives on*, which is the right question for both callers: a sync
    /// root whose own mount is detached starts resolving to a directory on the
    /// parent mount, and that has a different id.
    pub fn capture(path: &Path) -> io::Result<Self> {
        unique_mnt_id(path).map(Self)
    }

    /// The identity of the mount behind an already-open file descriptor.
    ///
    /// Distinct from [`capture`] in the way that matters: a descriptor keeps its
    /// mount alive and reachable, so this answers for the filesystem the holder
    /// is *actually* writing to, whatever the path now means. Comparing the two
    /// is how a caller tells that the ground moved.
    ///
    /// [`capture`]: MountIdentity::capture
    pub fn of_fd(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<Self> {
        use std::os::fd::AsRawFd;
        statx_mnt_id(fd.as_raw_fd(), c"", libc::AT_EMPTY_PATH).map(Self)
    }

    /// Whether the path still leads to the mount this identity was taken from.
    ///
    /// An error is not "unchanged". A path that cannot be stat'ed at all is a
    /// path whose mount cannot be vouched for, and the caller has to treat it
    /// the same way as a mount that was swapped.
    pub fn still_current(&self, path: &Path) -> io::Result<bool> {
        unique_mnt_id(path).map(|now| now == self.0)
    }
}

fn unique_mnt_id(path: &Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    statx_mnt_id(libc::AT_FDCWD, &c, 0)
}

fn statx_mnt_id(dirfd: libc::c_int, path: &std::ffi::CStr, flags: libc::c_int) -> io::Result<u64> {
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::statx(
            dirfd,
            path.as_ptr(),
            flags,
            STATX_MNT_ID_UNIQUE,
            &mut sx as *mut libc::statx,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // Asking is not getting. `stx_mask` reports what was actually filled, and a
    // kernel that does not know this bit returns the small, reused id in the
    // same field without complaining — which would leave the check silently
    // reading the one value measured to hide a replacement.
    if sx.stx_mask & STATX_MNT_ID_UNIQUE == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the kernel did not supply a unique mount id (needs Linux 6.8+); the \
             reusable one cannot distinguish a replaced mount",
        ));
    }
    Ok(sx.stx_mnt_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_has_a_unique_mount_id() {
        // Any path will do: the claim under test is that the kernel supplies the
        // 6.8 id at all, because everything else here is built on it being
        // present rather than silently falling back to the small one.
        let id = MountIdentity::capture(Path::new("/")).expect("root has a mount id");
        assert!(
            MountIdentity::capture(Path::new("/")).unwrap() == id,
            "the same unreplaced mount answered with two different ids"
        );
    }

    #[test]
    fn a_path_that_is_gone_is_not_reported_as_unchanged() {
        let id = MountIdentity::capture(Path::new("/")).unwrap();
        // The distinction that matters: `Err`, never `Ok(true)`. A caller that
        // treated an unreadable path as "still fine" would keep serving through
        // a mount it can no longer see.
        assert!(id
            .still_current(Path::new("/nonexistent-by-construction-9d3f"))
            .is_err());
    }

    #[test]
    fn a_descriptor_and_its_path_agree_while_nothing_has_moved() {
        // The two ways in have to give the same answer for an unchanged mount,
        // or the comparison the client makes between them would report a swap
        // on every call and stop every pass for no reason.
        let f = std::fs::File::open("/").unwrap();
        use std::os::fd::AsFd;
        assert_eq!(
            MountIdentity::of_fd(f.as_fd()).unwrap(),
            MountIdentity::capture(Path::new("/")).unwrap()
        );
    }
}

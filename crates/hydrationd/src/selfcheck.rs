//! Proving that the mark is on the mount the readers actually use.
//!
//! Marking succeeds in situations where it protects nobody, and every one of
//! them looks identical from inside the process: `fanotify_mark` returns 0, the
//! helper logs that it is watching, the unit reports active, and reads return
//! the zeros a placeholder is made of. That is the failure the whole design
//! exists to prevent, arrived at through the one path with no diagnostic.
//!
//! Two ways it happened on a real deployment, both measured:
//!
//! * **A mount namespace of our own.** `fanotify_mark(FAN_MARK_MOUNT)` marks the
//!   `vfsmount` in the *caller's* mount namespace. A systemd unit with any of
//!   `PrivateTmp=`, `ProtectKernelTunables=`, `ProtectControlGroups=`,
//!   `ProtectKernelModules=` or `PrivateNetwork=` gets a namespace of its own —
//!   each one alone is enough, verified by comparing `/proc/self/ns/mnt` against
//!   the host. The helper then marks its private copy of the sync mount while
//!   every read from the user's session goes through an unmarked one.
//!   `exposure.rs` names this trap in prose; this module is the part that
//!   notices it.
//!
//! * **The mount replaced under the mark.** The helper detaches its own mount on
//!   the way out and `RequiresMountsFor=` brings a fresh one up. Under restart
//!   cycling a process can end up holding a mark on a mount that is no longer
//!   the one reachable at the path. The mark stays valid and protects nothing.
//!
//! The first is decided once, before marking. The second cannot be: it is a
//! change over time, so it has to be re-asked while the process runs.
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

use std::io;
use std::path::Path;

/// Linux 6.8. Fills the same `stx_mnt_id` field as [`STATX_MNT_ID`] with the id
/// that is never handed out twice.
const STATX_MNT_ID_UNIQUE: libc::c_uint = 0x0000_4000;

/// Where this process's mark can take effect.
#[derive(Debug, PartialEq, Eq)]
pub enum Reach {
    /// Our mount namespace is the one `init` is in, so a mount mark applies to
    /// the same `vfsmount` everything else on the machine traverses.
    Everyone,
    /// We are in a namespace of our own. Whatever we mark, the readers this
    /// helper exists to protect are not behind it.
    OurselvesOnly { ours: String, init: String },
    /// The comparison could not be made.
    ///
    /// Deliberately not folded into either answer. Reporting `Everyone` would be
    /// a guarantee this module did not check, and refusing to start would make
    /// an unreadable `/proc/1` — which no deployment here has ever produced —
    /// into a new way for the service to be down.
    ///
    /// The ordinary reason to see this is privilege: `/proc/1/ns/mnt` is not
    /// readable by an unprivileged process, so the unit tests take this branch
    /// while `hydrationd` itself, which exits unless it is root, never does.
    Unknown(String),
}

/// Whether the mount at `path` is the one the rest of the machine traverses.
///
/// Asked of `/proc/self/mountinfo`, which needs no privilege — and that is the
/// point. The namespace comparison in [`reach`] needs to read `/proc/1/ns/mnt`,
/// which requires `CAP_SYS_PTRACE`, and the capability set this helper is
/// supposed to run with does not include it. Measured: under a systemd unit with
/// `CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_OVERRIDE`, `reach()` degrades to
/// [`Reach::Unknown`] — the guard goes quiet in exactly the deployment it exists
/// to protect.
///
/// This asks the better question anyway. Not "which namespace am I in" but "is
/// this mount a copy that receives propagation from somewhere else", which is
/// what actually decides whether a mark on it covers anyone. Measured, the same
/// mount seen two ways:
///
/// ```text
/// host:              /home/frank/OneDrive rw,noatime shared:526
/// inside a unit ns:  /home/frank/OneDrive rw,noatime shared:563 master:526
/// ```
///
/// A `master:` field means this mount is downstream of peer group 526 — it is
/// not that mount, it only hears about it. A mark here covers this copy and
/// nothing else.
pub fn mount_is_a_downstream_copy(path: &Path) -> io::Result<bool> {
    let target = path.to_string_lossy();
    let info = std::fs::read_to_string("/proc/self/mountinfo")?;
    for line in info.lines() {
        // `id parent major:minor root point opts [optional...] - fstype src super`
        // The optional fields are variable in number, which is why the ` - `
        // separator exists at all; splitting on it first is the only way to know
        // where they end.
        let Some((left, _)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<&str> = left.split_whitespace().collect();
        if fields.len() < 6 || unescape(fields[4]) != target {
            continue;
        }
        return Ok(fields[6..].iter().any(|f| f.starts_with("master:")));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{target} is not a mount point in this namespace"),
    ))
}

/// `/proc/self/mountinfo` escapes space, tab, newline and backslash as octal.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Some(c) = std::str::from_utf8(&b[i + 1..i + 4])
                .ok()
                .and_then(|o| u8::from_str_radix(o, 8).ok())
            {
                out.push(c as char);
                i += 4;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Whether a mount mark taken here reaches the rest of the machine.
pub fn reach() -> Reach {
    // The namespace's identity is the inode behind the magic link, and the link
    // text ("mnt:[4026531832]") carries it. Comparing the two strings is
    // therefore an identity comparison and not a heuristic.
    //
    // `init` rather than any particular reader: inside a container this process
    // and the users it serves share the container's namespace, and pid 1 is the
    // one process guaranteed to be in it.
    let ours = match std::fs::read_link("/proc/self/ns/mnt") {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => return Reach::Unknown(format!("/proc/self/ns/mnt: {e}")),
    };
    let init = match std::fs::read_link("/proc/1/ns/mnt") {
        Ok(p) => p.to_string_lossy().into_owned(),
        Err(e) => return Reach::Unknown(format!("/proc/1/ns/mnt: {e}")),
    };
    if ours == init {
        Reach::Everyone
    } else {
        Reach::OurselvesOnly { ours, init }
    }
}

/// The identity of the mount a path resolved to at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MountIdentity(u64);

impl MountIdentity {
    /// Taken immediately after marking, so what is recorded is the mount the
    /// mark went onto rather than one that replaced it in between.
    pub fn capture(path: &Path) -> io::Result<Self> {
        unique_mnt_id(path).map(Self)
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
    let mut sx: libc::statx = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::statx(
            libc::AT_FDCWD,
            c.as_ptr(),
            0,
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
    fn reach_never_claims_more_than_it_checked() {
        // `/proc/1/ns/mnt` needs privilege, and this suite runs as the developer
        // — so the interesting case is the one where the comparison *cannot* be
        // made. The property under test is that `reach()` says so instead of
        // defaulting to the reassuring answer, which is the only way this module
        // could reintroduce the bug it exists to catch.
        let init = std::fs::read_link("/proc/1/ns/mnt").ok();
        match (init, reach()) {
            (None, Reach::Unknown(_)) => {}
            (None, answered) => {
                panic!("init's namespace was unreadable but reach() answered {answered:?}")
            }
            (Some(i), answered) => {
                let ours = std::fs::read_link("/proc/self/ns/mnt").expect("our own ns");
                let expected = ours == i;
                assert_eq!(
                    answered == Reach::Everyone,
                    expected,
                    "reach() disagreed with the links it is built on"
                );
            }
        }
    }
}

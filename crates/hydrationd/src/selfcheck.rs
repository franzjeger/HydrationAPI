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
//! [`MountIdentity`] is the part that carries the second, and it lives in
//! `hydration-protocol` because the client needs the same answer for its own
//! reasons — a delta pass must not keep materialising into a sync root whose
//! mount this helper has detached. Two implementations of "is this still the
//! same mount" would be two chances to disagree about it.

use std::io;
use std::path::Path;

pub use hydration_protocol::mount::MountIdentity;

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

#[cfg(test)]
mod tests {
    use super::*;

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

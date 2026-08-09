//! Noticing when something else can reach the sync files.
//!
//! DESIGN.md §6.4a. The requirement is not "the sync folder has its own mount";
//! it is stricter, and worth stating in the form that is actually true:
//!
//! > No other mount in the system may expose the sync files.
//!
//! That is a property of the whole machine's mount table, not of our setup, and
//! **we cannot enforce it.** A bind mount of the parent, a container runtime, a
//! `systemd` unit with `BindPaths=` — any of them can create a second path to
//! the same files at any moment, and a read through that path bypasses hydration
//! and returns zeros.
//!
//! So it is detected instead. A hazard that cannot be prevented is one that must
//! not be silent.
//!
//! # What this does not see
//!
//! Only mounts in **our own mount namespace**. A container runtime, or a
//! `systemd` unit with `PrivateMounts=`, creates its bypass in a namespace of
//! its own: no event reaches our group, and the mount is absent from
//! `/proc/self/mountinfo`, so a re-scan finds nothing either. Those are exactly
//! the cases §6.4a names, and this module does not cover them.
//!
//! It is detectable in principle — walking `/proc/*/mountinfo` as root, or
//! `listmount()` with namespace ids — and is not implemented. Worth stating
//! plainly rather than leaving a reader to assume the check is total: a
//! detection that covers less than it appears to is its own kind of silence.
//!
//! There is a deployment trap in the same family: if `hydrationd` is itself run
//! under sandboxing that implies a private namespace, even host mounts become
//! invisible to it.
//!
//! Two measurements shape this module:
//!
//! * **`FAN_REPORT_MNT` cannot coexist with `FAN_CLASS_PRE_CONTENT`** — the call
//!   fails `EINVAL`. Mount watching needs its own group, which is why this is a
//!   separate type rather than another mask on the hydration group.
//! * **The event's `mnt_id` is not a lookup key.** It is the 64-bit unique id,
//!   not the small reused one in field 1 of `/proc/self/mountinfo`, and by the
//!   time a detach arrives the mount is gone and cannot be resolved at all. So
//!   the event is treated as a *trigger to re-examine*, never as the answer.

use crate::fanotify::{self, Group};
use std::io;
use std::path::Path;
use std::time::Duration;

/// Watches the mount namespace for mounts appearing and disappearing.
pub struct ExposureWatch {
    group: Group,
    /// Our own mount point, which is the one that is supposed to be there.
    /// Everything is keyed off this rather than off a device number — see
    /// [`ExposureWatch::current`] for why.
    ours: String,
}

/// One line of `/proc/self/mountinfo`, as far as we care about it.
struct Row {
    devno: String,
    /// The subtree of the filesystem this mount exposes.
    root: String,
    point: String,
}

impl Row {
    fn parse(line: &str) -> Option<Self> {
        // id parent major:minor root point ...
        let mut it = line.split_whitespace();
        let (_id, _parent, devno, root, point) =
            (it.next()?, it.next()?, it.next()?, it.next()?, it.next()?);
        Some(Self {
            devno: devno.to_string(),
            root: unescape(root),
            point: unescape(point),
        })
    }
}

/// Whether `outer` contains `inner` as a path prefix.
fn covers(outer: &str, inner: &str) -> bool {
    if outer == "/" || outer == inner {
        return true;
    }
    inner.starts_with(outer) && inner.as_bytes().get(outer.len()) == Some(&b'/')
}

impl ExposureWatch {
    pub fn new(mount: &Path) -> io::Result<Self> {
        let group = Group::new_mount_watch()?;
        group.mark_mount_namespace()?;
        Ok(Self {
            group,
            ours: mount.to_string_lossy().to_string(),
        })
    }

    /// Every mount point other than ours that currently reaches these files.
    ///
    /// Empty is the healthy answer. Anything else is a path a reader can take to
    /// get zeros, and the user has to be told.
    pub fn current(&self) -> io::Result<Vec<String>> {
        let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
        let rows: Vec<Row> = mounts.lines().filter_map(Row::parse).collect();

        // Our own row, found by mount point rather than by device.
        //
        // `st_dev` is the obvious key and it is wrong here: btrfs gives every
        // subvolume its own anonymous device, so the number `stat` reports for
        // the sync directory (120) does not match the one `mountinfo` reports
        // for the mount it lives on (0:110). Comparing them finds nothing, ever,
        // and the exposure warning silently never fires.
        let Some(ours) = rows.iter().find(|r| r.point == self.ours) else {
            // Never the healthy answer. If our own mount is not in the table the
            // situation is worse, not better: the sync directory is not a mount
            // point, or it has been unmounted or shadowed under us. Returning
            // "no exposures" here would be the module telling the user they are
            // safe at precisely the moment it has stopped being able to tell.
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "{} is not a mount point in this namespace; exposure cannot be \
                     checked",
                    self.ours
                ),
            ));
        };

        let mut out = Vec::new();
        for r in &rows {
            if r.point == ours.point || r.devno != ours.devno {
                continue;
            }
            // Same filesystem is not enough: two sibling subvolumes share a
            // device and cannot see each other's files. What matters is whether
            // this mount's root *contains* ours — the same subtree, or an
            // ancestor of it. That is the mount through which our files can be
            // reached by another path.
            // Symmetric on purpose. Two subtrees of one filesystem overlap if
            // *either* contains the other, and both directions are real
            // bypasses: a mount of an ancestor reaches our files, and so does
            // `mount --bind ~/OneDrive/Documents /srv/docs`. Testing one
            // direction left the second case silently unreported — which is the
            // failure this module exists to prevent, in the module itself.
            if covers(&r.root, &ours.root) || covers(&ours.root, &r.root) {
                out.push(r.point.clone());
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    /// Wait for the mount table to change, then report what reaches the files.
    ///
    /// Returns `None` if nothing happened before the timeout. The caller re-asks
    /// rather than being handed a diff, because a diff would be wrong for the
    /// detach case — the mount is gone by the time we look, so the only sound
    /// answer is the current state.
    pub fn poll(&mut self, timeout: Duration) -> io::Result<Option<Vec<String>>> {
        let mut pfd = libc::pollfd {
            fd: self.group.as_raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        if unsafe { libc::poll(&mut pfd, 1, ms) } <= 0 {
            return Ok(None);
        }

        // Drain: several mounts can land at once, and one re-examination covers
        // all of them.
        let mut buf = vec![0u8; 64 * 1024];
        let len = self.group.read_events(&mut buf)?;
        let events = fanotify::events(&buf, len);
        if events.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.current()?))
    }
}

/// `/proc/self/mountinfo` escapes space, tab, newline and backslash as octal.
///
/// Rebuilt byte by byte rather than character by character. `out.push(b as char)`
/// looks equivalent and is not: it reinterprets each byte as a code point, so a
/// UTF-8 path the kernel does *not* escape — `/home/frank/Pärm` — comes back as
/// mojibake and never compares equal to the caller's real path. The mount would
/// then never be found, and every exposure check would quietly answer "healthy"
/// for the rest of the process's life.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Some(c) = std::str::from_utf8(&b[i + 1..i + 4])
                .ok()
                .and_then(|o| u8::from_str_radix(o, 8).ok())
            {
                out.push(c);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mount_of_an_ancestor_covers_us_and_a_sibling_does_not() {
        // Two subvolumes of one filesystem share a device and cannot reach each
        // other. Treating "same device" as "same files" would warn about every
        // sibling subvolume, and a warning that fires when nothing is wrong
        // stops being read.
        assert!(covers("/", "/@onedrive"), "the fs root reaches everything");
        assert!(covers("/@onedrive", "/@onedrive"), "the same subtree");
        assert!(covers("/@home", "/@home/frank/OneDrive"), "an ancestor");
        assert!(
            !covers("/@home", "/@homework"),
            "a prefix is not an ancestor"
        );
        assert!(
            !covers("/@srv", "/@onedrive"),
            "a sibling reaches nothing of ours"
        );
    }

    #[test]
    fn a_bind_of_a_subdirectory_is_an_exposure_too() {
        // The direction that was missing. `mount --bind ~/OneDrive/Documents
        // /srv/docs` reaches our files through a mount we do not cover, and
        // testing only "is an ancestor" left it unreported.
        let ours = "/@onedrive";
        let sub = "/@onedrive/Documents";
        assert!(
            covers(sub, ours) || covers(ours, sub),
            "a bind of a subdirectory of the sync tree was not treated as an exposure"
        );
        // And a genuine sibling still is not one, in either direction.
        assert!(!covers("/@srv", ours) && !covers(ours, "/@srv"));
    }

    #[test]
    fn a_non_ascii_mount_point_survives_unescaping() {
        // Byte-preserving, not char-by-char. The kernel does not escape UTF-8,
        // so reinterpreting bytes as code points produced mojibake that never
        // matched the caller's path — and the check then answered "healthy"
        // forever without ever having looked.
        assert_eq!(unescape("/home/frank/Pärm"), "/home/frank/Pärm");
        assert_eq!(unescape("/mnt/my\\040drive"), "/mnt/my drive");
    }

    #[test]
    fn mountinfo_escapes_are_undone() {
        // A mount point with a space in it is rare and entirely legal, and
        // comparing the escaped form against a real path would silently never
        // match — so the exposure would go unreported.
        assert_eq!(unescape("/mnt/my\\040drive"), "/mnt/my drive");
        assert_eq!(unescape("/home/frank/OneDrive"), "/home/frank/OneDrive");
    }
}

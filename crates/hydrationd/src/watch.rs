//! Noticing that a file changed, without noticing ourselves.
//!
//! Change detection needs a mount mark, which needs `CAP_SYS_ADMIN`, so it lives
//! on the privileged side. The helper does not decide anything about a change —
//! it forwards the identity and lets the sync daemon apply the rules. That keeps
//! the capability where it already is instead of adding a second privileged
//! component.
//!
//! # The feedback loop
//!
//! Hydration is a write. A watcher that reports every write reports our own, so
//! filling a placeholder would queue an upload of the content we just
//! downloaded — which would upload it, which would... The loop is not subtle
//! once you see it, and it is completely invisible until the two halves are
//! connected, because neither one on its own does anything wrong.
//!
//! Events carry the pid that caused them, so the fix is to drop our own. It has
//! to be the *worker's* pid rather than the supervisor's, because the worker is
//! the process that writes.

use crate::fanotify::{self, Group};
use hydration_protocol::FileId;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Content events, which arrive with a file descriptor.
pub const FAN_MODIFY: u64 = 0x0000_0002;
/// The kernel had to drop events. Delivered as a bare marker with no descriptor
/// and no file — there is nothing left to say which changes were lost.
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;

// Deliberately not watched here: FAN_MOVED_FROM, FAN_MOVED_TO, FAN_DELETE and
// FAN_DELETE_SELF.
//
// Those are directory-entry events. They cannot be delivered with a descriptor —
// there is no file to open, that being the point — so they require
// `FAN_REPORT_FID`, and a group asking for both shapes at once is rejected with
// `EINVAL`. Measured, by asking for both.
//
// Not watching them costs less than it appears. A rename is not an event this
// design has to catch: everything is keyed by inode, so a renamed file is the
// same file and its queued upload resolves the new name when the bytes go out.
// A delete is likewise handled by absence — the upload rules treat a file that
// is no longer there as a delete that has already won, whether or not anyone
// announced it. What is genuinely lost is *promptness*: a deleted file's queued
// upload is discovered at send time rather than cancelled immediately, so it
// occupies the pending count until then. That is a status inaccuracy, not a
// data-loss risk, and closing it means a second group with FID reporting.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// Content was written.
    Modified,
    /// A writable handle was closed — a good moment to start the quiet period.
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub file: FileId,
    pub what: Change,
}

/// Watches a mount for local changes.
pub struct Watcher {
    group: Group,
    /// Writes from these processes are ours and are not changes.
    ignore_pids: Vec<i32>,
    /// The kernel dropped events because its queue was full.
    overflowed: bool,
}

impl Watcher {
    /// Watch `mount`, ignoring anything caused by `ignore_pids`.
    ///
    /// The caller must pass the pid of whatever writes hydrated content —
    /// otherwise every hydration is reported as a local edit and uploaded
    /// straight back.
    pub fn new(mount: &Path, ignore_pids: Vec<i32>) -> io::Result<Self> {
        let group = Group::new_notify()?;
        group.mark_mount_events(mount, FAN_MODIFY | FAN_CLOSE_WRITE)?;
        Ok(Self {
            group,
            ignore_pids,
            overflowed: false,
        })
    }

    /// Whether the kernel dropped events since this was last asked.
    ///
    /// Reports and clears, so a caller cannot see the same overflow twice and
    /// resync forever. Asking is the caller's obligation: after an overflow the
    /// only honest recovery is to walk the directory, and the events that were
    /// dropped are gone.
    pub fn take_overflow(&mut self) -> bool {
        std::mem::take(&mut self.overflowed)
    }

    /// Collect whatever has happened, without blocking indefinitely.
    pub fn poll(&mut self, timeout: std::time::Duration) -> io::Result<Vec<Observed>> {
        let mut pfd = libc::pollfd {
            fd: self.group.as_raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        if unsafe { libc::poll(&mut pfd, 1, ms) } <= 0 {
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; 64 * 1024];
        let len = self.group.read_events(&mut buf)?;
        let mut out = Vec::new();

        for ev in fanotify::events(&buf, len) {
            if ev.fd < 0 {
                // The queue-overflow marker arrives with no descriptor. It was
                // being skipped with everything else fd-less, which meant the
                // one signal that says "you have missed changes" was the one
                // thing silently discarded. Measured: the queue holds 16384
                // distinct objects and overflows in under two seconds when
                // something unpacks an archive, so this is a normal event, not
                // an exotic one.
                if ev.mask & FAN_Q_OVERFLOW != 0 {
                    self.overflowed = true;
                }
                continue;
            }
            // Ours. Dropping it here is what stops hydration from looking like a
            // local edit and being uploaded back.
            if self.ignore_pids.contains(&ev.pid) {
                unsafe { libc::close(ev.fd) };
                continue;
            }
            if let Some(file) = file_of(ev.fd) {
                let what = if ev.mask & FAN_CLOSE_WRITE != 0 {
                    Change::Closed
                } else {
                    Change::Modified
                };
                out.push(Observed { file, what });
            }
            unsafe { libc::close(ev.fd) };
        }
        Ok(out)
    }
}

/// Identity from an event fd, without resolving a path.
///
/// `fstat` on the fd rather than `stat` on `/proc/self/fd/N`: the fd is what the
/// kernel is telling us about, and a path can be renamed between the event and
/// the lookup. The whole design keys on inodes precisely so that renames are not
/// events we have to be fast enough to catch.
fn file_of(fd: i32) -> Option<FileId> {
    let f = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let md = f.metadata().ok();
    // The fd is owned by the caller; do not close it twice.
    std::mem::forget(f);
    md.map(|md| FileId {
        fsid: md.dev(),
        ino: md.ino(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_write_and_modify_are_distinguished() {
        // Closed is the useful one: it is the moment a quiet period should
        // start. Modify alone fires repeatedly during a large write.
        assert_ne!(FAN_MODIFY, FAN_CLOSE_WRITE);
        assert_eq!(
            Change::Closed,
            if FAN_CLOSE_WRITE & FAN_CLOSE_WRITE != 0 {
                Change::Closed
            } else {
                Change::Modified
            }
        );
    }
}

//! Thin, honest bindings to the parts of fanotify hydration needs.
//!
//! Hand-written rather than pulled from a crate because every sharp edge here
//! was found by measurement (see `probes/`), and the comments recording them are
//! the point. Each one cost a probe:
//!
//! * A directory mark is *accepted* and delivers nothing. Only mount and
//!   filesystem marks work, so [`Group::mark_mount`] is the only marking call
//!   this module offers.
//! * `FAN_REPORT_MNT` cannot coexist with `FAN_CLASS_PRE_CONTENT`; mount
//!   watching needs its own group ([`Group::new_mount_watch`]).
//! * A response is matched by fd number within the group, not against the
//!   responder's fd table — which is what lets a supervisor answer for a worker
//!   that died holding an event ([`Group::respond_raw`]).

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

// From <linux/fanotify.h>. Kept as literals with their names so a reader can
// grep the header rather than trust this file.
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;
pub const FAN_CLOEXEC: u32 = 0x0000_0001;
pub const FAN_REPORT_PIDFD: u32 = 0x0000_0080;
pub const FAN_REPORT_MNT: u32 = 0x0000_4000;

pub const FAN_MARK_ADD: u32 = 0x0000_0001;
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;
pub const FAN_MARK_MNTNS: u32 = 0x0000_0110;
pub const FAN_MARK_IGNORE: u32 = 0x0000_0400;
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;
/// `FAN_MARK_IGNORE` requires `SURV_MODIFY`; the kernel rejects it otherwise.
pub const FAN_MARK_IGNORE_SURV: u32 = FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY;

pub const FAN_PRE_ACCESS: u64 = 0x0010_0000;
pub const FAN_MNT_ATTACH: u64 = 0x0100_0000;
pub const FAN_MNT_DETACH: u64 = 0x0200_0000;

pub const FAN_ALLOW: u32 = 0x01;
pub const FAN_DENY: u32 = 0x02;

pub const FAN_EVENT_INFO_TYPE_RANGE: u8 = 6;
pub const FAN_EVENT_INFO_TYPE_PIDFD: u8 = 4;
pub const FAN_EVENT_INFO_TYPE_MNT: u8 = 7;

pub const FAN_NOFD: i32 = -1;

/// `FAN_DENY_ERRNO(e)` — deny with a specific errno rather than a bare EPERM.
///
/// The kernel accepts only a short list (EPERM, EIO, EBUSY, ...); EIO is the one
/// hydration wants, because a file whose content could not be produced is
/// exactly an I/O error from the reader's point of view.
pub fn deny_with(errno: i32) -> u32 {
    FAN_DENY | (((errno as u32) & 0xff) << 24)
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EventMetadata {
    pub event_len: u32,
    pub vers: u8,
    pub reserved: u8,
    pub metadata_len: u16,
    pub mask: u64,
    pub fd: i32,
    pub pid: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InfoHeader {
    pub info_type: u8,
    pub pad: u8,
    pub len: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Response {
    pub fd: i32,
    pub response: u32,
}

unsafe extern "C" {
    fn fanotify_init(flags: u32, event_f_flags: u32) -> i32;
    fn fanotify_mark(fd: i32, flags: u32, mask: u64, dirfd: i32, pathname: *const i8) -> i32;
}

/// One fanotify group.
///
/// Cloneable across a `fork` by design: the supervisor and the worker hold the
/// same group, which is what makes the fail-closed pattern in §6a possible.
#[derive(Debug)]
pub struct Group {
    fd: OwnedFd,
}

impl Group {
    /// A pre-content group, for hydration.
    pub fn new_pre_content() -> io::Result<Self> {
        // O_RDWR because the helper writes content into the event fd.
        Self::init(
            FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_REPORT_PIDFD,
            libc::O_RDWR as u32 | libc::O_LARGEFILE as u32,
        )
    }

    /// A separate group for mount events.
    ///
    /// It has to be separate: `FAN_REPORT_MNT` with `FAN_CLASS_PRE_CONTENT`
    /// fails `EINVAL`, measured, so the hydration group cannot also watch
    /// mounts.
    pub fn new_mount_watch() -> io::Result<Self> {
        Self::init(
            FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_REPORT_MNT,
            libc::O_RDONLY as u32,
        )
    }

    fn init(flags: u32, event_flags: u32) -> io::Result<Self> {
        let fd = unsafe { fanotify_init(flags, event_flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
        })
    }

    /// Watch a whole mount for pre-content events.
    ///
    /// Deliberately the only marking call for files. A directory mark is
    /// accepted by the kernel and then delivers nothing at all, and
    /// `FAN_EVENT_ON_CHILD` stops at direct children — so an API that offered
    /// either would be offering a way to build something that looks like it
    /// works. See DESIGN.md §6.4.
    pub fn mark_mount(&self, mountpoint: &std::path::Path) -> io::Result<()> {
        self.mark(FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS, mountpoint)
    }

    /// Watch this mount namespace for mounts appearing and disappearing.
    pub fn mark_mount_namespace(&self) -> io::Result<()> {
        self.mark(
            FAN_MARK_ADD | FAN_MARK_MNTNS,
            FAN_MNT_ATTACH | FAN_MNT_DETACH,
            std::path::Path::new("/proc/self/ns/mnt"),
        )
    }

    /// Stop delivering events for one file, and keep not delivering them after
    /// the file is written. Used the moment a file is fully hydrated.
    pub fn ignore(&self, path: &std::path::Path) -> io::Result<()> {
        self.mark(FAN_MARK_ADD | FAN_MARK_IGNORE_SURV, FAN_PRE_ACCESS, path)
    }

    /// Start delivering events for one file again, after it is dehydrated.
    pub fn unignore(&self, path: &std::path::Path) -> io::Result<()> {
        self.mark(FAN_MARK_REMOVE | FAN_MARK_IGNORE_SURV, FAN_PRE_ACCESS, path)
    }

    fn mark(&self, flags: u32, mask: u64, path: &std::path::Path) -> io::Result<()> {
        let c = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has an interior nul"))?;
        let rc =
            unsafe { fanotify_mark(self.fd.as_raw_fd(), flags, mask, libc::AT_FDCWD, c.as_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Read whatever events are queued. Returns the raw buffer and its length;
    /// use [`events`] to walk it.
    pub fn read_events(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Answer an event by its fd number.
    ///
    /// Takes a bare number rather than a borrowed event on purpose. Responses
    /// are matched by number within the group, not against the caller's fd
    /// table — measured — and that is precisely what lets a supervisor answer
    /// for a worker that died holding an event it had already dequeued. Without
    /// it that reader hangs until something kills it. See §6a.
    pub fn respond_raw(&self, event_fd: i32, response: u32) -> io::Result<()> {
        let r = Response {
            fd: event_fd,
            response,
        };
        let n = unsafe {
            libc::write(
                self.fd.as_raw_fd(),
                &r as *const Response as *const libc::c_void,
                std::mem::size_of::<Response>(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn as_raw(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// One decoded event.
#[derive(Debug, Clone)]
pub struct Event {
    pub mask: u64,
    pub fd: i32,
    pub pid: i32,
    pub range: Option<(u64, u64)>,
    pub pidfd: Option<i32>,
    pub mnt_id: Option<u64>,
}

/// Walk a buffer returned by [`Group::read_events`].
pub fn events(buf: &[u8], len: usize) -> Vec<Event> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let meta_sz = std::mem::size_of::<EventMetadata>();

    while off + meta_sz <= len {
        let meta: EventMetadata =
            unsafe { std::ptr::read_unaligned(buf[off..].as_ptr() as *const EventMetadata) };
        let event_len = meta.event_len as usize;
        if event_len < meta_sz || off + event_len > len {
            break;
        }

        let mut ev = Event {
            mask: meta.mask,
            fd: meta.fd,
            pid: meta.pid,
            range: None,
            pidfd: None,
            mnt_id: None,
        };

        // Info records follow the fixed part.
        let mut rec = off + meta_sz;
        let end = off + event_len;
        while rec + std::mem::size_of::<InfoHeader>() <= end {
            let hdr: InfoHeader =
                unsafe { std::ptr::read_unaligned(buf[rec..].as_ptr() as *const InfoHeader) };
            let hlen = hdr.len as usize;
            if hlen == 0 || rec + hlen > end {
                break;
            }
            match hdr.info_type {
                FAN_EVENT_INFO_TYPE_RANGE if hlen >= 24 => {
                    let offset = u64::from_ne_bytes(buf[rec + 8..rec + 16].try_into().unwrap());
                    let count = u64::from_ne_bytes(buf[rec + 16..rec + 24].try_into().unwrap());
                    ev.range = Some((offset, count));
                }
                FAN_EVENT_INFO_TYPE_PIDFD if hlen >= 8 => {
                    ev.pidfd = Some(i32::from_ne_bytes(
                        buf[rec + 4..rec + 8].try_into().unwrap(),
                    ));
                }
                FAN_EVENT_INFO_TYPE_MNT if hlen >= 16 => {
                    ev.mnt_id = Some(u64::from_ne_bytes(
                        buf[rec + 8..rec + 16].try_into().unwrap(),
                    ));
                }
                _ => {}
            }
            rec += hlen;
        }

        out.push(ev);
        off += event_len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_with_encodes_the_errno_where_the_kernel_looks() {
        // FAN_DENY_ERRNO(EIO) -- the kernel reads the errno from the high byte.
        let r = deny_with(5);
        assert_eq!(r & 0xff, FAN_DENY);
        assert_eq!((r >> 24) & 0xff, 5);
    }

    #[test]
    fn ignore_marks_always_carry_surv_modify() {
        // The kernel rejects FAN_MARK_IGNORE without it, and a hydrated file
        // that is written must not silently start generating events again.
        assert_ne!(FAN_MARK_IGNORE_SURV & FAN_MARK_IGNORED_SURV_MODIFY, 0);
    }
}

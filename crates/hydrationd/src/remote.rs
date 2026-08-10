//! Fetching content from the unprivileged daemon across the socket.
//!
//! This is the privileged side of §6b, and the place where the rule is actually
//! enforced rather than merely declared. Everything arriving here comes from a
//! process with no capabilities that could, in principle, be compromised — so
//! the checks below are not defensive style, they are the reason the split buys
//! anything at all.
//!
//! Three of them, in order of what they prevent:
//!
//! 1. **The file must be under the mount we marked.** The event fd already
//!    guarantees this, but the check is cheap and it is the invariant everything
//!    else assumes.
//! 2. **The declared length must match the placeholder.** Checked before the
//!    body is read, so the daemon cannot choose how much memory a root process
//!    allocates.
//! 3. **A failed fetch leaves the placeholder untouched.** §5.7. Enforced in
//!    `placeholder::hydrate_fd`, which puts the file back if the write does not
//!    complete.

use crate::daemon::Fetch;
use hydration_protocol::transport::{HelperConn, Streamed};
use hydration_protocol::{FetchRequest, FetchResponse, FileId, FromHelper};
use std::io;
use std::path::{Path, PathBuf};

/// Content, fetched over the socket from the process that holds the credentials.
pub struct SocketFetch {
    conn: HelperConn,
    /// The mount this helper marked. Nothing outside it is ever hydrated.
    mount: PathBuf,
    next_id: u64,
}

impl SocketFetch {
    pub fn new(conn: HelperConn, mount: &Path) -> Self {
        Self {
            conn,
            mount: mount.to_path_buf(),
            next_id: 1,
        }
    }

    /// The device the marked mount is on.
    ///
    /// A file on a different device is not ours no matter what its inode says,
    /// and inode numbers are only unique per filesystem — so without this a
    /// request could name a plausible inode belonging to something else
    /// entirely.
    fn mount_fsid(&self) -> io::Result<u64> {
        use std::os::unix::fs::MetadataExt;
        Ok(std::fs::metadata(&self.mount)?.dev())
    }
}

impl Fetch for SocketFetch {
    fn fetch_into(
        &mut self,
        file: FileId,
        size: u64,
        dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        progress: &mut dyn FnMut(u64),
    ) -> io::Result<()> {
        let ours = self.mount_fsid()?;
        if file.fsid != ours {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to hydrate a file on device {} from a helper marked on {ours}",
                    file.fsid
                ),
            ));
        }

        let id = self.next_id;
        self.next_id += 1;

        self.conn.send(&FromHelper::Fetch(FetchRequest {
            id,
            file,
            offset: 0,
            // v1 fetches whole objects. The event's range is a *demand* rather
            // than a hint (§8d) — answering with less than it asks for hands the
            // reader zeros — so serving ranges is a real feature and not a
            // shortcut, and it is deliberately not in this change.
            len: size,
            cgroup: None,
        }))?;

        // `size` comes from the filesystem, not from the daemon: the length the
        // body may be is decided here, before anything is read. The helper's own
        // `MAX_OBJECT` bounds it besides, because the delta pass's limit runs on
        // the side §6b assumes may be compromised.
        match self.conn.recv_streamed(id, size, dest, progress)? {
            Streamed::Complete => Ok(()),
            Streamed::Aborted { errno, reason } => Err(io::Error::new(
                io::Error::from_raw_os_error(errno).kind(),
                reason,
            )),
            Streamed::Refused(FetchResponse::Failed { errno, reason, .. }) => Err(io::Error::new(
                io::Error::from_raw_os_error(errno).kind(),
                reason,
            )),
            Streamed::Refused(FetchResponse::Denied { reason, .. }) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("policy refused this reader: {reason}"),
            )),
            Streamed::Refused(other) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected response: {other:?}"),
            )),
        }
    }
}

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
use hydration_protocol::transport::HelperConn;
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
    fn fetch(&mut self, file: FileId, size: u64) -> io::Result<Vec<u8>> {
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
            // v1 fetches whole files. The event's range is the readahead window
            // rather than what the application asked for, so honouring it would
            // be guessing with extra steps.
            len: size,
            cgroup: None,
        }))?;

        // `size` comes from the filesystem, not from the daemon: the length the
        // body is allowed to be is decided here, before anything is read.
        let (resp, body) = self.conn.recv(size)?;

        if resp.id() != id {
            // A mismatched correlation id means the stream is out of step, and
            // the next body could be matched to the wrong file. There is no safe
            // way to continue on this connection.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("response {} does not answer request {id}", resp.id()),
            ));
        }

        match resp {
            FetchResponse::Ready { .. } => Ok(body),
            FetchResponse::Failed { errno, reason, .. } => {
                Err(io::Error::from_raw_os_error(errno).chain(&reason))
            }
            FetchResponse::Denied { reason, .. } => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("the sync daemon declined: {reason}"),
            )),
        }
    }
}

/// Attach a reason to an errno without losing the errno.
trait Chain {
    fn chain(self, reason: &str) -> io::Error;
}

impl Chain for io::Error {
    fn chain(self, reason: &str) -> io::Error {
        match self.raw_os_error() {
            Some(code) => io::Error::new(self.kind(), format!("{reason} (errno {code})")),
            None => io::Error::new(self.kind(), reason.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydration_protocol::transport::DaemonConn;
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_file_on_another_device_is_refused_without_asking_the_daemon() {
        // The daemon is never consulted: if this check ever moved after the
        // request, a compromised daemon would get to see which inodes exist
        // outside the sync directory.
        let (a, b) = UnixStream::pair().unwrap();
        let daemon = DaemonConn::new(b).unwrap();
        let mut f = SocketFetch::new(HelperConn::new(a).unwrap(), Path::new("/"));

        let root_dev = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata("/").unwrap().dev()
        };
        let err = f
            .fetch(
                FileId {
                    fsid: root_dev.wrapping_add(1),
                    ino: 2,
                },
                10,
            )
            .expect_err("a file on a different device must be refused");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        drop(daemon);
    }
}

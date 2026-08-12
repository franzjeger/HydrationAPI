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
//!
//! # Reconnecting
//!
//! The connection is made once at startup — and remade here whenever it dies,
//! because the peer is a user unit that systemd restarts on upgrade, on
//! failure, and on a user's whim. Before this existed, a routine
//! `systemctl --user restart` of the sync daemon was measured (2026-08-12)
//! costing the mount: the helper's fetches failed on the dead socket for
//! `WEDGED_LIMIT`, then the worker gave up and the helper detached the mount,
//! all while a perfectly healthy client was listening at the same path.
//!
//! Reconnecting opens nothing the first connection did not. The socket lives
//! in a directory only its owner can traverse, and every reconnect re-runs the
//! same `SO_PEERCRED` uid check as the first connect — the same function, not
//! a copy. What an impersonating listener with the right uid could do is what
//! it could always do (serve content for files its uid already had write
//! access to — see `daemon_loop.rs` in the client crate for that argument),
//! and a listener with the *wrong* uid is refused, counts toward giving up,
//! and brings the deployment down through the same fail-closed path as any
//! other unreachable peer.
//!
//! The retries are bounded twice over. Within one event: a short fixed window,
//! sized for the stop-to-bind gap of a `systemctl restart` and kept well under
//! the first-byte deadline. Across events: each failure counts toward
//! [`crate::daemon::WEDGED_LIMIT`], so a client that never comes back still
//! brings the mount down instead of leaving it serving `EIO` forever behind
//! two healthy-looking units.

use crate::daemon::{is_connection_lost, Fetch};
use hydration_protocol::transport::{HelperConn, Streamed};
use hydration_protocol::{FetchRequest, FetchResponse, FileId, FromHelper, Span};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;

/// Who is on the other end of this socket, from the kernel rather than from
/// them: `(pid, uid)`, via `SO_PEERCRED`.
///
/// The uid is the authentication — a socket path is not a credential. The pid
/// is for the change reporter, which must ignore the sync daemon's own writes
/// or every placeholder it lays down is reported straight back to it as a
/// local edit.
pub fn peer_cred(sock: &UnixStream) -> io::Result<(i32, u32)> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct Ucred {
        pid: libc::pid_t,
        uid: libc::uid_t,
        gid: libc::gid_t,
    }
    let mut cred = Ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<Ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut Ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.pid, cred.uid))
}

/// Connect to the sync daemon's socket and prove who answered.
///
/// The one implementation of the check, used by the binary's first connect and
/// by every reconnect after it — two copies would drift, and the drifted one
/// would be the one that runs unattended at three in the morning.
pub fn connect_checked(socket: &Path, expected_uid: Option<u32>) -> io::Result<UnixStream> {
    let sock = UnixStream::connect(socket)?;
    // Checked with SO_PEERCRED, which the kernel fills in — not from anything
    // the peer said about itself. Without this the socket path is the only
    // authentication, and a path is not a credential.
    if let Some(expected) = expected_uid {
        let (_, actual) = peer_cred(&sock)?;
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("the sync daemon socket is owned by uid {actual}, expected {expected}"),
            ));
        }
    }
    Ok(sock)
}

/// How many times one event may knock on a freshly dead socket, and how far
/// apart.
///
/// Together they bound the in-event window at about two seconds. That is sized
/// for the one gap worth holding a reader through: `systemctl restart`'s
/// stop-to-bind gap, which is process teardown plus process startup and sits
/// comfortably inside it. A crash restart (`RestartSec=5` in the shipped unit)
/// is deliberately *not* covered per-event — that reader gets `EIO`, which the
/// deployment README already names as the correct answer while the daemon is
/// down, and the next event probes again.
///
/// The window is spent once. Only the first revival after a death gets it: a
/// path that has already failed a whole window is a client that is *down*, not
/// one mid-restart, and every later event knocks exactly once — so readers of
/// a mount whose client is gone get their `EIO` at connect-refusal speed
/// rather than two seconds each, while recovery still happens on whichever
/// knock finds the socket back.
///
/// The window must stay well under `Limits::first_byte` (30 s by default).
/// If it did not, the worker would abandon the event as a first-byte miss
/// while the reconnect was still knocking — and a miss-class wedge stops the
/// probing that a lost-class wedge exists to keep alive.
const RECONNECT_TRIES: u32 = 8;
const RECONNECT_PAUSE: std::time::Duration = std::time::Duration::from_millis(250);

/// Everything a reconnect needs that the first connection was given.
struct Reconnect {
    socket: PathBuf,
    expected_uid: Option<u32>,
    /// Told the peer's pid after every successful reconnect, so the change
    /// reporter keeps ignoring the daemon's own writes across restarts. The
    /// pid changes with every restart; the uid must not.
    peer_pid: Option<Arc<AtomicI32>>,
}

/// Content, fetched over the socket from the process that holds the credentials.
pub struct SocketFetch {
    conn: HelperConn,
    /// The mount this helper marked. Nothing outside it is ever hydrated.
    mount: PathBuf,
    next_id: u64,
    /// `None` for callers that hold an anonymous pair (tests, `spawn_split`
    /// demos): there is no path to reconnect to, and errors surface exactly as
    /// they always did.
    reconnect: Option<Reconnect>,
    /// The last exchange left the stream unusable — dead, or alive but
    /// desynchronised mid-frame, which the framing rules say must be dropped
    /// rather than resynchronised. Nothing is sent on it again; the next
    /// attempt reconnects first or fails as lost.
    dead: bool,
    /// Whether a full retry window has already been spent — and failed — since
    /// the connection died. Decides between knocking for the whole window
    /// (first failure: the peer may be mid-restart) and knocking once (it has
    /// already proven to be down, and a reader is waiting for every pause).
    /// Reset by any successful revival.
    knocked: bool,
}

impl SocketFetch {
    pub fn new(conn: HelperConn, mount: &Path) -> Self {
        Self {
            conn,
            mount: mount.to_path_buf(),
            next_id: 1,
            reconnect: None,
            dead: false,
            knocked: false,
        }
    }

    /// As [`new`](Self::new), remembering where the socket lives so the
    /// connection can be remade when the sync daemon is restarted under us.
    ///
    /// `expected_uid` is re-checked on every reconnect, exactly as the first
    /// connect checked it.
    pub fn reconnecting(
        conn: HelperConn,
        mount: &Path,
        socket: &Path,
        expected_uid: Option<u32>,
    ) -> Self {
        Self {
            reconnect: Some(Reconnect {
                socket: socket.to_path_buf(),
                expected_uid,
                peer_pid: None,
            }),
            ..Self::new(conn, mount)
        }
    }

    /// Keep `cell` naming the current peer's pid across reconnects.
    ///
    /// The change reporter filters events by pid so the daemon's own writes are
    /// not reported back to it; a restarted daemon has a new pid, and without
    /// this the filter silently stops matching after the first reconnect.
    pub fn with_peer_pid(mut self, cell: Arc<AtomicI32>) -> Self {
        if let Some(r) = &mut self.reconnect {
            r.peer_pid = Some(cell);
        }
        self
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

    /// Make the dead connection live again, or say why not in a kind that
    /// counts.
    ///
    /// Every error out of here is reported as `NotConnected` — with the real
    /// cause in the message — because the kinds a failed `connect()` naturally
    /// produces are exactly the wrong ones: `NotFound` for an unbound path and
    /// `ConnectionRefused` for a stale one, neither of which
    /// `is_connection_lost` recognises. Surfacing those raw would make an
    /// absent client look like a per-file refusal, which never counts toward
    /// giving up, and the mount would serve `EIO` forever with no clock
    /// running — the pre-reconnect incident, reintroduced by an error code.
    fn revive(&mut self) -> io::Result<()> {
        let Some(rc) = &self.reconnect else {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "the connection to the sync daemon is gone and this fetcher has no \
                 socket path to reconnect to",
            ));
        };
        // The full window only while the death is fresh: after one window has
        // failed, the peer is down rather than mid-restart, and later events
        // pay one knock instead of holding their readers through the pauses.
        let tries = if self.knocked { 1 } else { RECONNECT_TRIES };
        let mut last: Option<io::Error> = None;
        for attempt in 0..tries {
            if attempt > 0 {
                std::thread::sleep(RECONNECT_PAUSE);
            }
            match connect_checked(&rc.socket, rc.expected_uid) {
                Ok(stream) => {
                    let pid = peer_cred(&stream).map(|c| c.0).unwrap_or(0);
                    self.conn.replace(stream)?;
                    if let Some(cell) = &rc.peer_pid {
                        cell.store(pid, Ordering::SeqCst);
                    }
                    self.dead = false;
                    self.knocked = false;
                    eprintln!(
                        "[worker] reconnected to the sync daemon at {} (pid {pid})",
                        rc.socket.display()
                    );
                    return Ok(());
                }
                // Someone answered and it was not the sync daemon. Knocking
                // again in 250 ms will reach the same impostor; stop now and
                // let the failure count, so the deployment comes down through
                // the same road as any unreachable peer — where the restarted
                // helper's first connect runs this same check and refuses to
                // start.
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    last = Some(e);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let e = last.expect("at least one attempt always runs");
        let msg = format!(
            "cannot reconnect to the sync daemon at {}: {e}",
            rc.socket.display()
        );
        self.knocked = true;
        Err(io::Error::new(io::ErrorKind::NotConnected, msg))
    }
}

impl Fetch for SocketFetch {
    fn fetch_into(
        &mut self,
        file: FileId,
        size: u64,
        span: Span,
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

        // A span outside the object cannot be honoured and must not be asked
        // for: the daemon would be told to seek past the end of its own object
        // and would answer with whatever its provider made of that. The worker
        // clamps before it gets here; this is the check on the side that has to
        // live with being wrong, in the same spirit as the length check below.
        if span.end() > size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "asked for {}..{} of a placeholder that is {size} bytes",
                    span.offset,
                    span.end()
                ),
            ));
        }

        let mut retried = false;
        loop {
            if self.dead {
                self.revive()?;
            }

            let id = self.next_id;
            self.next_id += 1;

            // The length the body may be is decided here, from the span this
            // helper asked for — never from something the daemon says. The
            // helper's own `MAX_OBJECT` bounds it besides, because the delta
            // pass's limit runs on the side §6b assumes may be compromised.
            //
            // `recv_streamed` reports offsets from the start of the body, and
            // the worker writes them straight into the file, so the span's own
            // offset has to be added here. Getting this wrong writes the right
            // bytes to the wrong place, which is the quietest failure
            // available.
            let mut place = |buf: &[u8], at: u64| dest(buf, span.offset + at);
            let streamed = self
                .conn
                .send(&FromHelper::Fetch(FetchRequest {
                    id,
                    file,
                    // Exactly what the reader demanded. Sending `0..size`
                    // regardless was v1's behaviour and the reason a 4 KiB read
                    // of a multi-gigabyte object could not be served at all
                    // (§8d-bis).
                    offset: span.offset,
                    len: span.len,
                    cgroup: None,
                }))
                .and_then(|()| self.conn.recv_streamed(id, span.len, &mut place, progress));

            let streamed = match streamed {
                Ok(s) => s,
                Err(e) => {
                    // Whatever the cause, the stream cannot be trusted to be in
                    // step any more: an error mid-body leaves unread chunk
                    // bytes that the next request would parse as frames. The
                    // framing's own rule is drop, never resynchronise — so the
                    // connection is marked dead either way, and the difference
                    // the cause makes is only whether *this* reader gets a
                    // second chance.
                    self.dead = true;
                    if is_connection_lost(&e) && !retried && self.reconnect.is_some() {
                        // The peer went away, which is what a client restart
                        // looks like from here. Reconnect and re-ask for the
                        // whole span: the writes are pwrites at absolute
                        // offsets, so bytes that already landed are simply
                        // written again, and completion is judged by the span
                        // being covered — a retry can never leave a seam.
                        retried = true;
                        continue;
                    }
                    return Err(e);
                }
            };

            return match streamed {
                Streamed::Complete => Ok(()),
                Streamed::Aborted { errno, reason } => Err(io::Error::new(
                    io::Error::from_raw_os_error(errno).kind(),
                    reason,
                )),
                Streamed::Refused(FetchResponse::Failed { errno, reason, .. }) => Err(
                    io::Error::new(io::Error::from_raw_os_error(errno).kind(), reason),
                ),
                Streamed::Refused(FetchResponse::Denied { reason, .. }) => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("policy refused this reader: {reason}"),
                )),
                Streamed::Refused(other) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unexpected response: {other:?}"),
                )),
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A listener owned by the wrong uid must be refused, and the refusal must
    /// count toward giving up rather than looking like a per-file refusal.
    ///
    /// Unprivileged: the listener necessarily has *our* uid, so expecting any
    /// other uid exercises the mismatch arm. The check itself is the same
    /// `SO_PEERCRED` read the first connect does — one implementation, tested
    /// once, used everywhere.
    #[test]
    fn a_reconnect_to_the_wrong_uid_is_refused_and_counts_as_lost() {
        let dir = test_scratch::scratch(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
            "reconnect-uid",
        );
        let sock = dir.join("s.sock");
        let _ = std::fs::remove_file(&sock);
        let _listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");

        let not_us = unsafe { libc::geteuid() }.wrapping_add(12345);
        let err = connect_checked(&sock, Some(not_us))
            .expect_err("a peer with the wrong uid must be refused");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        // And through `revive`, the kind becomes one the wedge accounting
        // recognises, with the cause preserved in the message.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let mut fetch = SocketFetch::reconnecting(
            HelperConn::new(a).expect("conn"),
            std::path::Path::new("/"),
            &sock,
            Some(not_us),
        );
        fetch.dead = true;
        let err = fetch.revive().expect_err("an impostor is not a peer");
        assert!(
            crate::daemon::is_connection_lost(&err),
            "a refused reconnect must count toward the give-up clock: {err:?}"
        );
        assert!(
            err.to_string().contains("expected"),
            "the real cause is gone from the message: {err}"
        );
    }

    /// A socket path nobody has bound must fail fast, bounded, and in a kind
    /// that counts — `connect()` says `NotFound`, which the wedge accounting
    /// would read as a per-file refusal and ignore forever.
    #[test]
    fn a_reconnect_to_an_unbound_path_fails_bounded_and_counts_as_lost() {
        let dir = test_scratch::scratch(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
            "reconnect-unbound",
        );
        let sock = dir.join("never-bound.sock");
        let _ = std::fs::remove_file(&sock);

        let (a, _b) = UnixStream::pair().expect("socketpair");
        let mut fetch = SocketFetch::reconnecting(
            HelperConn::new(a).expect("conn"),
            std::path::Path::new("/"),
            &sock,
            None,
        );
        fetch.dead = true;
        let began = std::time::Instant::now();
        let err = fetch
            .revive()
            .expect_err("an unbound path cannot be connected to");
        assert!(
            crate::daemon::is_connection_lost(&err),
            "an absent client must count toward the give-up clock: {err:?}"
        );
        // Bounded: the whole window, not per attempt, and with margin for a
        // loaded machine. What it must never be is a hot loop or a hang.
        let waited = began.elapsed();
        assert!(
            waited < std::time::Duration::from_secs(10),
            "the bounded retry window ran {waited:?}"
        );
        assert!(
            waited >= RECONNECT_PAUSE,
            "no pause between attempts — this is the hot reconnect loop the \
             bound exists to prevent"
        );

        // The window is spent: a second revival against the same absent peer
        // knocks once and returns at connect-refusal speed, so a stream of
        // readers against a long-dead client does not pay the window each.
        let began = std::time::Instant::now();
        let err = fetch.revive().expect_err("still nothing to connect to");
        assert!(crate::daemon::is_connection_lost(&err), "{err:?}");
        assert!(
            began.elapsed() < RECONNECT_PAUSE,
            "a revival after a spent window still held its reader through the \
             pauses: {:?}",
            began.elapsed()
        );

        // And the single knock is still a road back: the moment something
        // binds the path, the next revival succeeds.
        let _listener = std::os::unix::net::UnixListener::bind(&sock).expect("bind");
        fetch
            .revive()
            .expect("one knock must recover once the socket is back");
        assert!(!fetch.dead, "revived, but still marked dead");
    }

    /// Without a socket path there is nothing to revive, and the error must
    /// still count as lost rather than surfacing as something refusal-shaped.
    #[test]
    fn a_fetcher_without_a_reconnect_path_reports_lost_not_refused() {
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let mut fetch =
            SocketFetch::new(HelperConn::new(a).expect("conn"), std::path::Path::new("/"));
        fetch.dead = true;
        let err = fetch.revive().expect_err("nothing to revive with");
        assert!(crate::daemon::is_connection_lost(&err), "{err:?}");
    }
}

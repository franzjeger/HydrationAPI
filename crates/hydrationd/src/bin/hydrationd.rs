//! The privileged hydration helper.
//!
//! ```text
//! hydrationd --mount /home/user/OneDrive --socket /run/user/1000/hydration-sync.sock \
//!            --peer-uid 1000
//! ```
//!
//! Holds `CAP_SYS_ADMIN` and nothing else. It never opens a network socket,
//! never sees a credential, and never accepts a path from the unprivileged side.
//!
//! It connects *out* to the sync daemon rather than accepting connections. If it
//! accepted, any local process could impersonate the daemon — and this process
//! writes what it is told into the user's files.

use hydration_protocol::transport::HelperConn;
use hydrationd::daemon::{Worker, DEFAULT_STALL};
use hydrationd::exposure::ExposureWatch;
use hydrationd::fanotify::Group;
use hydrationd::policy::Policy;
use hydrationd::remote::SocketFetch;
use hydrationd::report;
use hydrationd::selfcheck::{self, MountIdentity, Reach};
use hydrationd::supervisor::{deny, InFlight};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How often the supervisor re-asks whether its mark still covers the path.
///
/// The answer only changes when something mounts, so this is not a poll of
/// anything that moves — it is a bound on how long a replaced mount can go
/// unnoticed. One `statx` per interval, against a supervisor loop that turns ten
/// times a second and is otherwise idle.
const MOUNT_CHECK_EVERY: Duration = Duration::from_secs(2);

struct Args {
    mount: PathBuf,
    socket: PathBuf,
    peer_uid: Option<u32>,
}

fn usage() -> ! {
    eprintln!("usage: hydrationd --mount <dir> --socket <path> [--peer-uid <uid>]");
    std::process::exit(2)
}

fn parse() -> Args {
    let (mut mount, mut socket, mut peer_uid) = (None, None, None);
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--mount" => mount = it.next().map(PathBuf::from),
            "--socket" => socket = it.next().map(PathBuf::from),
            "--peer-uid" => peer_uid = it.next().and_then(|v| v.parse().ok()),
            _ => usage(),
        }
    }
    Args {
        mount: mount.unwrap_or_else(|| usage()),
        socket: socket.unwrap_or_else(|| usage()),
        peer_uid,
    }
}

/// Who is on the other end of this socket, from the kernel rather than from them.
/// The peer's pid, from the same kernel-filled structure as its uid.
///
/// Needed because writes by the sync daemon are not local edits: it is the
/// process that writes hydrated content back through the socket, and reporting
/// its writes as changes would upload every hydration straight back. Taken from
/// `SO_PEERCRED` rather than from anything the peer says about itself.
fn peer_pid(sock: &UnixStream) -> io::Result<i32> {
    peer_cred(sock).map(|c| c.0)
}

fn peer_uid(sock: &UnixStream) -> io::Result<u32> {
    peer_cred(sock).map(|c| c.1)
}

fn peer_cred(sock: &UnixStream) -> io::Result<(i32, u32)> {
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

fn connect(args: &Args) -> io::Result<UnixStream> {
    let sock = UnixStream::connect(&args.socket)?;
    // Checked with SO_PEERCRED, which the kernel fills in — not from anything
    // the peer said about itself. Without this the socket path is the only
    // authentication, and a path is not a credential.
    if let Some(expected) = args.peer_uid {
        let actual = peer_uid(&sock)?;
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("the sync daemon socket is owned by uid {actual}, expected {expected}"),
            ));
        }
    }
    Ok(sock)
}

fn main() -> io::Result<()> {
    let args = parse();
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("hydrationd: needs CAP_SYS_ADMIN (run as root)");
        std::process::exit(1);
    }
    // `metadata`, not `is_dir()`. `is_dir()` is false for every stat error, so a
    // sync root inside a 0700 home — with a capability set that dropped
    // CAP_DAC_OVERRIDE, which is exactly what the example unit specifies —
    // reported "is not a directory" and sent a deployment looking for the wrong
    // thing entirely. Print what stat actually said.
    match std::fs::metadata(&args.mount) {
        Ok(m) if m.is_dir() => {}
        Ok(_) => {
            eprintln!(
                "hydrationd: {} exists but is not a directory",
                args.mount.display()
            );
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("hydrationd: cannot stat {}: {e}", args.mount.display());
            std::process::exit(1);
        }
    }

    // Before anything is marked, because a mark taken from inside a private
    // mount namespace is the one failure with no symptom: it succeeds, this
    // process reports it is watching, and every read outside the namespace comes
    // back as zeros. See `selfcheck` for the measurement and the systemd
    // directives that cause it.
    match selfcheck::reach() {
        Reach::Everyone => {}
        Reach::OurselvesOnly { ours, init } => {
            eprintln!(
                "hydrationd: refusing to start — this process is in its own mount \
                 namespace ({ours}, init is in {init}), so a mount mark here would \
                 protect nobody and every placeholder read outside it would return \
                 zeros.\n\
                 hydrationd: under systemd, each of PrivateTmp=, PrivateNetwork=, \
                 ProtectKernelTunables=, ProtectControlGroups= and \
                 ProtectKernelModules= causes this on its own. Use \
                 RestrictAddressFamilies=AF_UNIX for network denial instead; it \
                 needs no namespace."
            );
            std::process::exit(1);
        }
        Reach::Unknown(why) => eprintln!(
            "hydrationd: WARNING — could not confirm this process shares init's \
             mount namespace ({why}); if it does not, nothing here protects anything"
        ),
    }

    // Reported before anything else, because if it is non-empty the guarantee
    // this process exists to provide is already not being kept.
    match ExposureWatch::new(&args.mount).and_then(|w| w.current()) {
        Ok(list) if !list.is_empty() => eprintln!(
            "hydrationd: WARNING — {} other mount(s) expose these files and bypass \
             hydration entirely: {list:?}",
            list.len()
        ),
        Ok(_) => eprintln!("hydrationd: no other mount exposes these files"),
        Err(e) => eprintln!("hydrationd: could not check for exposures: {e}"),
    }

    let stream = match connect(&args) {
        Ok(s) => s,
        Err(e) => {
            // Refusing to start is the right answer. Marking the mount with
            // nobody able to fetch content would make every dehydrated file
            // unreadable, which is worse than not starting.
            eprintln!(
                "hydrationd: cannot reach the sync daemon at {}: {e}",
                args.socket.display()
            );
            std::process::exit(1);
        }
    };

    // Read before the fork, because after it the child needs it and the parent
    // has no reason to ask again.
    let watched_pid = peer_pid(&stream).unwrap_or(0);

    let group = Group::new_pre_content()?;
    group.mark_mount(&args.mount)?;
    // Taken here, between the mark and the fork, so it names the mount the mark
    // actually went onto. The supervisor re-asks for as long as it runs: a mount
    // can be replaced under a live mark — this helper detaches its own on the way
    // out and `RequiresMountsFor=` puts a fresh one up — and the mark stays
    // perfectly valid while protecting a mount nobody can reach any more.
    let marked = match MountIdentity::capture(&args.mount) {
        Ok(id) => Some(id),
        Err(e) => {
            // Not fatal, and not silent. Without this the supervisor loses one
            // check; pretending it still has it would be worse than saying so.
            eprintln!(
                "hydrationd: WARNING — cannot identify the mount that was just \
                 marked ({e}); a mount replaced under this mark will not be noticed"
            );
            None
        }
    };
    let in_flight = InFlight::new();
    let worker_view = in_flight.share();

    // Fork before any thread exists: a thread holding a lock at fork time leaves
    // the child holding it forever.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }

    if child == 0 {
        let conn = HelperConn::new(stream).unwrap();

        // Change detection, on its own threads so the event loop never waits on
        // the socket. Spawned after the fork, never before.
        //
        // Both pids are ignored: our own, because the worker writes hydrated
        // content, and the daemon's, because it writes uploads and placeholders.
        // Reporting either as a local edit would upload the framework's own work
        // straight back. Pid filtering is an optimisation rather than the
        // correctness boundary — the daemon checks content before uploading —
        // but without it the loop is tight enough to matter.
        match report::Reporter::spawn(
            &args.mount,
            vec![unsafe { libc::getpid() }, watched_pid],
            conn.notifier(),
            Duration::from_millis(250),
        ) {
            Ok(_) => eprintln!(
                "[worker] watching {} for local changes",
                args.mount.display()
            ),
            // Not fatal. Hydration is the guarantee; change detection is the
            // feature, and the daemon walks the directory anyway.
            Err(e) => eprintln!("[worker] change detection unavailable: {e}"),
        }

        let fetch = SocketFetch::new(conn, &args.mount);
        let mut w = Worker::new(group, fetch, Policy::default(), worker_view);
        // No deadline on the loop itself: this is the service, not a test. The
        // per-event deadline is what bounds any single reader's wait.
        let _ = w.run(Instant::now() + Duration::from_secs(60 * 60 * 24 * 365 * 10));
        // Reached only when the worker has given up on its fetcher. Exiting is
        // the point: the supervisor is watching, and it detaches the mount and
        // exits non-zero so the unit restarts. Staying alive here would mean
        // denying every read forever while looking perfectly healthy.
        unsafe { libc::_exit(if w.fetcher_wedged() { 1 } else { 0 }) };
    }

    eprintln!(
        "hydrationd: watching {} (worker pid {child}); supervisor holding the group",
        args.mount.display()
    );

    // The supervisor. It does nothing at all while the worker is healthy, and
    // then it denies everything — because a read that cannot be served must
    // fail, not return the zeros a placeholder is made of.
    //
    // "Healthy" means *answering*, not merely alive. §6a-bis: a worker that has
    // stopped answering is worse than one that has died, because the reader it
    // is holding cannot be killed by a signal and every later operation on the
    // mount queues behind it.
    let mut status = 0;
    let mut beat = (in_flight.progress(), in_flight.liveness());
    let mut moved = Instant::now();
    let mut stalled = false;
    let mut unmarked = None;
    let mut next_mount_check = Instant::now() + MOUNT_CHECK_EVERY;
    loop {
        if unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } == child {
            break;
        }
        let now = (in_flight.progress(), in_flight.liveness());
        if now != beat {
            beat = now;
            moved = Instant::now();
        }
        // An idle worker makes no progress either; only one that is holding an
        // event can be stalling.
        if in_flight.current().is_some() && moved.elapsed() >= DEFAULT_STALL {
            stalled = true;
            break;
        }
        // Is the mark still on the mount this path leads to? Asked on a timer
        // rather than every pass: the answer changes only when something mounts,
        // and the loop turns ten times a second.
        //
        // An error counts as a failure, not as "no news". A path whose mount
        // cannot be read is a path whose protection cannot be vouched for, and
        // continuing would mean serving reads through a mount this process can
        // no longer identify.
        if let Some(id) = marked {
            if Instant::now() >= next_mount_check {
                next_mount_check = Instant::now() + MOUNT_CHECK_EVERY;
                match id.still_current(&args.mount) {
                    Ok(true) => {}
                    Ok(false) => {
                        unmarked = Some("the mount was replaced under the mark".to_string());
                        break;
                    }
                    Err(e) => {
                        unmarked = Some(format!("the marked mount can no longer be read: {e}"));
                        break;
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    if let Some(why) = &unmarked {
        eprintln!(
            "hydrationd: {why} — everything at {} is now unprotected, and reads \
             through it would return the zeros a placeholder is made of. Failing \
             closed.",
            args.mount.display()
        );
        // The worker is still alive and still answering events on a mark that no
        // longer covers the path. It has to go before the shutdown below, which
        // exists to clean up after a worker that is already gone.
        unsafe { libc::kill(child, libc::SIGKILL) };
        let grace = Instant::now() + Duration::from_secs(1);
        while Instant::now() < grace {
            if unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } == child {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    if stalled {
        eprintln!(
            "hydrationd: worker {child} has not answered anything in {}s while holding \
             an event — treating it as dead",
            DEFAULT_STALL.as_secs()
        );
        // Signal first, answer second. A worker stuck in a network fetch dies
        // here; one stuck inside a pre-content event of its own making cannot be
        // signalled at all, and is released only by the answer below.
        unsafe { libc::kill(child, libc::SIGKILL) };
        let grace = Instant::now() + Duration::from_secs(1);
        while Instant::now() < grace {
            if unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } == child {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let signal = if libc::WIFSIGNALED(status) {
        Some(libc::WTERMSIG(status))
    } else {
        None
    };
    eprintln!("hydrationd: worker exited (signal={signal:?}) — failing closed from here");

    // The event it died holding left the queue with it, so it can only be
    // answered by number.
    if let Some(stranded) = in_flight.current() {
        let _ = deny(&group, stranded);
        eprintln!("hydrationd: answered stranded event fd {stranded} with EIO");
    }
    if stalled {
        unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
    }

    // Take the mount out of the namespace, but keep denying.
    //
    // §6a-bis's third requirement. The order is the point: exiting here would
    // close the group, and a mount with no group fails *open* — every
    // placeholder becomes a source of zeros, which is the failure this whole
    // design exists to prevent. So the mount is detached lazily, which stops any
    // new access, while this process stays alive to answer everything already in
    // flight with EIO.
    //
    // Done here rather than left to systemd, so the guarantee does not depend on
    // having been deployed with the supplied units. The unit's dependency runs
    // the other way round — it makes the service depend on the mount — and what
    // it contributes is the recovery: this process exits non-zero, systemd
    // restarts it, and `RequiresMountsFor=` brings the mount back with it
    // (measured; DESIGN.md §8b).
    let detached = unsafe {
        let c = std::ffi::CString::new(args.mount.as_os_str().as_encoded_bytes()).unwrap();
        libc::umount2(c.as_ptr(), libc::MNT_DETACH) == 0
    };
    eprintln!(
        "hydrationd: {} — denying everything still in flight, then exiting non-zero",
        if detached {
            "mount detached"
        } else {
            "could not detach the mount — anything still reading through it is \
             unprotected until the unit comes back"
        }
    );

    // Denying until the mount has gone quiet. Not forever: a process that never
    // exits is one systemd never restarts, and the whole point of detaching
    // above was to reach a state the unit can recover from. Quiet means nothing
    // has arrived for long enough that nothing is left waiting on us.
    let mut buf = vec![0u8; 64 * 1024];
    let mut quiet_since = Instant::now();
    loop {
        if quiet_since.elapsed() >= Duration::from_secs(10) {
            eprintln!("hydrationd: nothing left in flight; exiting so the unit can restart");
            std::process::exit(if stalled { 75 } else { 1 });
        }
        let mut pfd = libc::pollfd {
            fd: group.as_raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 500) } <= 0 {
            continue;
        }
        quiet_since = Instant::now();
        let len = group.read_events(&mut buf)?;
        for ev in hydrationd::fanotify::events(&buf, len) {
            if ev.fd >= 0 {
                let _ = deny(&group, ev.fd);
                unsafe { libc::close(ev.fd) };
            }
        }
    }
}

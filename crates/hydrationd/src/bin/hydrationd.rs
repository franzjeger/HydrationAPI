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
use hydrationd::supervisor::{deny, InFlight};
use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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
fn peer_uid(sock: &UnixStream) -> io::Result<u32> {
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
    Ok(cred.uid)
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
    if !args.mount.is_dir() {
        eprintln!("hydrationd: {} is not a directory", args.mount.display());
        std::process::exit(1);
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

    let group = Group::new_pre_content()?;
    group.mark_mount(&args.mount)?;
    let in_flight = InFlight::new();
    let worker_view = in_flight.share();

    // Fork before any thread exists: a thread holding a lock at fork time leaves
    // the child holding it forever.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }

    if child == 0 {
        let fetch = SocketFetch::new(HelperConn::new(stream).unwrap(), &args.mount);
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
    let mut beat = in_flight.progress();
    let mut moved = Instant::now();
    let mut stalled = false;
    loop {
        if unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } == child {
            break;
        }
        let now = in_flight.progress();
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
        std::thread::sleep(Duration::from_millis(100));
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
    // `BindsTo=` in the unit covers the same ground from systemd's side. Doing it
    // here too means the guarantee does not depend on having been deployed with
    // the supplied units.
    let detached = unsafe {
        let c = std::ffi::CString::new(args.mount.as_os_str().as_encoded_bytes()).unwrap();
        libc::umount2(c.as_ptr(), libc::MNT_DETACH) == 0
    };
    eprintln!(
        "hydrationd: {} — denying everything still in flight, then exiting non-zero",
        if detached {
            "mount detached"
        } else {
            "could not detach the mount (see the unit's BindsTo=)"
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

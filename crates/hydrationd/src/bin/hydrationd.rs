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
use hydrationd::remote::{self, SocketFetch};
use hydrationd::report;
use hydrationd::selfcheck::{self, MountIdentity, Reach};
use hydrationd::supervisor::{
    deny, drain_denying, Drained, InFlight, DENY_DRAIN_CAP, DENY_DRAIN_QUIET,
};
use std::io;
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

// Who is on the other end of this socket is answered by `remote::peer_cred`
// and `remote::connect_checked` — the same functions the worker's reconnect
// path runs, deliberately, so the uid check at startup and the uid check five
// days in can never be two implementations that have drifted apart.

/// Take the sync mount out of the namespace, and say so either way.
///
/// Lazy, like the one on the shutdown path: a reader already inside is not a
/// reason to leave the door open behind it, and `MNT_DETACH` stops new access
/// immediately while letting the existing ones finish.
///
/// Silence is not an option in either direction. A detach that happened has
/// removed the user's files from where they expect them, and a detach that
/// failed has left them reachable and unprotected. Both are things the person
/// reading the journal needs told.
fn detach_or_say_why(mount: &std::path::Path) {
    let c = match std::ffi::CString::new(mount.as_os_str().as_encoded_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "hydrationd: cannot name {} to detach it: {e}",
                mount.display()
            );
            return;
        }
    };
    if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } == 0 {
        eprintln!(
            "hydrationd: detached {} — its files are out of reach rather than \
             readable as zeros",
            mount.display()
        );
    } else {
        let e = io::Error::last_os_error();
        // EINVAL here is the ordinary case, not a fault: the path is not a mount
        // point, so there was nothing of ours to take down.
        if e.raw_os_error() != Some(libc::EINVAL) {
            eprintln!(
                "hydrationd: could not detach {} ({e}) — anything reading through \
                 it is unprotected until this service comes back",
                mount.display()
            );
        }
    }
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
    // Two questions, deliberately in this order.
    //
    // The mount's own propagation is the one that decides the outcome and the one
    // that can always be asked: it comes from /proc/self/mountinfo and needs no
    // privilege. The namespace comparison needs CAP_SYS_PTRACE to read
    // /proc/1/ns/mnt, which the capability set this runs with does not include —
    // measured, it degrades to Unknown under the very unit it protects. So it is
    // used to enrich the message, never to decide.
    let ns_note = match selfcheck::reach() {
        Reach::OurselvesOnly { ours, init } => {
            format!(" (this process is in {ours}, init is in {init})")
        }
        Reach::Everyone | Reach::Unknown(_) => String::new(),
    };
    match selfcheck::mount_is_a_downstream_copy(&args.mount) {
        Ok(false) => {}
        Ok(true) => {
            eprintln!(
                "hydrationd: refusing to start — {} is a downstream copy of another \
                 mount{ns_note}, so a mark here would cover this copy and nobody \
                 else, and every placeholder read outside it would return zeros.\n\
                 hydrationd: under systemd, each of PrivateTmp=, PrivateNetwork=, \
                 ProtectKernelTunables=, ProtectControlGroups= and \
                 ProtectKernelModules= gives a unit its own mount namespace and \
                 causes this on its own. Use RestrictAddressFamilies=AF_UNIX for \
                 network denial instead; it needs no namespace.",
                args.mount.display()
            );
            std::process::exit(1);
        }
        // The sync root not being a mount at all is caught by `mark_mount` a few
        // lines below, which fails properly. Anything else is this check being
        // unable to answer, and it says so rather than passing quietly.
        Err(e) => eprintln!(
            "hydrationd: WARNING — could not confirm {} is the mount others \
             traverse ({e}); if it is not, nothing here protects anything",
            args.mount.display()
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

    // Before the mark, and it has to be: this writes inside the sync root, and a
    // write inside a marked mount by the process that answers its events is
    // §6a-ter's deadlock.
    //
    // A filesystem that keeps mtime to the whole second cannot tell a foreign
    // write inside the current second from no write at all, and the worker's
    // range record is built on exactly that comparison. The consequence is not a
    // slow path or a missed optimisation: the worker certifies the file complete,
    // clears its mark, and removes interception, with somebody else's bytes
    // inside it. Refused rather than run with a guarantee that does not hold —
    // §6.4a already refuses a sync root that is not its own mount, for the same
    // reason and in the same place.
    match selfcheck::timestamp_resolution(&args.mount) {
        Ok(selfcheck::Timestamps::Fine) => {}
        Ok(selfcheck::Timestamps::Coarse) => {
            eprintln!(
                "hydrationd: {} is on a filesystem that records mtime only to the \
                 second, so a write by anything else inside that second is \
                 indistinguishable from none — and the worker would certify a file \
                 complete, and stop intercepting it, with those bytes inside. \
                 Refusing to start. This is ext4 with a 128-byte inode; `mkfs.ext4 \
                 -I 256` or larger, btrfs and xfs all record nanoseconds. See \
                 DESIGN.md §8z-bis.",
                args.mount.display()
            );
            detach_or_say_why(&args.mount);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "hydrationd: could not find out whether {} records sub-second mtimes \
                 ({e}); refusing rather than assuming it does, because the worker's \
                 record of what it has already written rests on that",
                args.mount.display()
            );
            detach_or_say_why(&args.mount);
            std::process::exit(1);
        }
    }

    let stream = match remote::connect_checked(&args.socket, args.peer_uid) {
        Ok(s) => s,
        Err(e) => {
            // Refusing to start is the right answer. Marking the mount with
            // nobody able to fetch content would make every dehydrated file
            // unreadable, which is worse than not starting.
            eprintln!(
                "hydrationd: cannot reach the sync daemon at {}: {e}",
                args.socket.display()
            );
            // Leaving without taking the mount down is how a deployment ends up
            // serving zeros, and it is the ordinary case rather than an exotic
            // one: `RequiresMountsFor=` puts the mount up as a *precondition* of
            // starting this service, so between boot and the user's session
            // there is a mount full of placeholders and no process able to
            // answer for it. Every restart re-opened that window.
            //
            // The shutdown path further down does this after a mark has existed.
            // Here nothing was ever marked, which does not make the files any
            // safer — it makes them unprotected without even a group open.
            detach_or_say_why(&args.mount);
            std::process::exit(1);
        }
    };

    // Read before the fork, because after it the child needs it and the parent
    // has no reason to ask again. The pid is needed so the change reporter can
    // ignore the sync daemon's own writes — reporting them as local edits
    // would upload every placeholder it lays down straight back.
    let watched_pid = remote::peer_cred(&stream).map(|c| c.0).unwrap_or(0);

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

        // The sync daemon's pid, in a cell rather than a number: the daemon is
        // a user unit that restarts, the fetch path reconnects when it does,
        // and each reconnect stores the new pid here so the change filter
        // below keeps matching the process it is meant to ignore.
        let peer_pid = std::sync::Arc::new(std::sync::atomic::AtomicI32::new(watched_pid));

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
            vec![unsafe { libc::getpid() }],
            Some(std::sync::Arc::clone(&peer_pid)),
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

        // Reconnecting, because the peer is a user unit and restarting it is
        // routine. Before this, its restart cost the mount: the helper's
        // fetches failed on the dead socket until the worker gave up and the
        // supervisor detached everything — measured on 2026-08-12, five
        // minutes from `systemctl --user restart` to teardown. The uid check
        // re-runs on every reconnect; see `remote` for why that is sufficient
        // and what an impostor costs.
        let fetch = SocketFetch::reconnecting(conn, &args.mount, &args.socket, args.peer_uid)
            .with_peer_pid(peer_pid);
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

    // Denying until the mount has gone quiet, and then leaving either way.
    //
    // "Not forever" was always the stated intent here — a process that never
    // exits is one systemd never restarts, and the whole point of detaching above
    // was to reach a state the unit can recover from. The first version expressed
    // it with a quiet window alone, which does not achieve it: the window slides,
    // so any reader that keeps touching the mount keeps this process alive, and
    // on 2026-08-12 two thumbnail workers kept it alive for 23 minutes while the
    // unit reported `active` and the mount stayed down. The cap is what makes the
    // intent true. See `supervisor::DENY_DRAIN_CAP` and `probes/denyloop.c`.
    match drain_denying(&group, DENY_DRAIN_QUIET, DENY_DRAIN_CAP)? {
        Drained::Quiet { denied } => {
            eprintln!(
                "hydrationd: nothing left in flight after {} denial(s); exiting so the \
                 unit can restart",
                denied
            );
        }
        Drained::StillBusy {
            denied,
            still_hammering,
        } => {
            // Said at this length because the alternative is someone finding a
            // detached mount and 500 million denials with nothing to explain
            // either. Exiting here lets those readers see zeros; staying would
            // keep every reader on the machine broken instead, with no recovery.
            eprintln!(
                "hydrationd: still being accessed after {}s and {} denial(s) — leaving anyway \
                 so the unit can restart. Readers still holding descriptors on the detached \
                 mount will now read zeros; nothing new can reach it. Last seen asking: {:?}",
                DENY_DRAIN_CAP.as_secs(),
                denied,
                still_hammering
            );
        }
    }
    std::process::exit(if stalled { 75 } else { 1 });
}

//! The hydration loop, and the fork that makes it fail closed.

use crate::fanotify::{self, Group};
use crate::placeholder;
use crate::policy::{cgroup_of, Decision, DenialLog, Policy};
use crate::supervisor::{allow, deny, take_over, InFlight};
use hydration_protocol::FileId;
use std::io;
use std::path::{Path, PathBuf};

/// Where content comes from.
///
/// The privileged helper does not know and must not care. It hands over an
/// identity and a size and receives bytes; whoever implements this is the one
/// holding the credentials, and they are on the other side of a socket in the
/// real daemon.
pub trait Fetch: Send {
    fn fetch(&mut self, file: FileId, size: u64) -> io::Result<Vec<u8>>;
}

/// Resolve the file an event refers to.
///
/// The event fd is the only handle we get, and it is authoritative: it names the
/// inode the kernel is asking about, which is exactly what the privilege rule in
/// §6b wants. Reading a path out of it is for logging and for the mark calls,
/// never for deciding *what* to write.
fn path_of(event_fd: i32) -> io::Result<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{event_fd}"))
}

/// Outcome of handling one event, for tests and for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handled {
    Hydrated {
        bytes: u64,
    },
    /// A placeholder with no name and no content. Allowed without fetching,
    /// because there is nothing to fetch.
    Empty,
    /// Already had content: nothing to do but let it through.
    AlreadyPresent,
    Denied {
        rule: String,
    },
    Failed {
        reason: String,
    },
}

/// A [`Fetch`] you can give up on.
///
/// §6a-bis, first requirement: **the worker must have a per-event deadline.** A
/// `Fetch` is client code talking to a network, and it may never return. If the
/// worker waits inside it, the pre-content event goes unanswered — and a process
/// blocked in one cannot be killed by a signal, so every later operation on the
/// mount blocks too and nothing recovers on its own. A slow cloud must not be
/// able to lock a filesystem.
///
/// The deadline cannot be enforced by asking implementors to respect one; that
/// is the kind of rule this framework exists to stop needing. So the fetch runs
/// on its own thread and the worker waits on a channel instead. When the wait
/// expires the worker answers `EIO` and moves on, and the abandoned fetch is
/// left to finish or not — its reply is discarded either way.
///
/// The thread is created after `spawn_split`'s `fork`, never before: forking a
/// process that already has threads gives the child one thread and any locks the
/// others held, which is its own class of hang.
struct Timed {
    req: std::sync::mpsc::Sender<(u64, FileId, u64)>,
    rep: std::sync::mpsc::Receiver<(u64, io::Result<Vec<u8>>)>,
    seq: u64,
    /// Consecutive deadlines missed. A single slow object is not a verdict on
    /// the fetcher; a run of them is.
    missed: u32,
    /// When the run started, so an unresponsive fetcher is bounded in time and
    /// not only in count.
    since: Option<std::time::Instant>,
}

/// After this many consecutive misses the fetcher is treated as wedged and no
/// longer waited on, so each event costs a denial rather than a full timeout.
/// Denying promptly is the fail-closed answer; making every reader wait out the
/// deadline first would be the same outage, slower.
const WEDGED_AFTER: u32 = 3;

/// Whether this error means the socket is gone rather than the request refused.
fn is_connection_lost(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::NotConnected
    )
}

/// How long a fetcher may stay unresponsive before the unit gives up on itself.
///
/// §6a-bis's third requirement, reached by the other road. A worker that denies
/// promptly is not stuck, so the supervisor's stall watch will never fire — the
/// mount would go on serving instant `EIO` forever, healthily, which is an
/// outage that looks like a working system. Past this point the worker stops,
/// the supervisor takes over, and the mount comes down so the unit can restart.
pub const WEDGED_LIMIT: std::time::Duration = std::time::Duration::from_secs(300);

impl Timed {
    fn new<F: Fetch + 'static>(mut fetch: F) -> Self {
        let (req_tx, req_rx) = std::sync::mpsc::channel::<(u64, FileId, u64)>();
        let (rep_tx, rep_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            while let Ok((seq, file, size)) = req_rx.recv() {
                // A send failure means the worker is gone; there is nobody left
                // to answer for, so stop rather than fetching into the void.
                if rep_tx.send((seq, fetch.fetch(file, size))).is_err() {
                    return;
                }
            }
        });
        Self {
            req: req_tx,
            rep: rep_rx,
            seq: 0,
            missed: 0,
            since: None,
        }
    }

    fn wedged(&self) -> bool {
        self.missed >= WEDGED_AFTER
    }

    /// How long it has been unresponsive, if it is.
    fn wedged_for(&self) -> std::time::Duration {
        match self.since {
            Some(t) if self.wedged() => t.elapsed(),
            _ => std::time::Duration::ZERO,
        }
    }

    fn missed_one(&mut self) {
        self.missed += 1;
        self.since.get_or_insert_with(std::time::Instant::now);
    }

    fn answered(&mut self) {
        self.missed = 0;
        self.since = None;
    }

    fn fetch(&mut self, file: FileId, size: u64, within: std::time::Duration) -> io::Result<Vec<u8>> {
        if self.wedged() {
            // Abandoned fetches keep running, and a reply from one is proof the
            // fetcher is alive again. Draining for it here is what keeps this
            // from being a one-way door: the short-circuit below skips the send,
            // so without this nothing could ever arrive, nothing could reset the
            // counter, and three missed deadlines would turn the mount into
            // instant `EIO` for good — served by two healthy-looking processes,
            // with nothing to tear anything down. That is the state §6a-bis says
            // must not persist, reached quietly.
            let mut recovered = false;
            while self.rep.try_recv().is_ok() {
                recovered = true;
            }
            if recovered {
                self.answered();
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("fetcher unresponsive after {WEDGED_AFTER} consecutive deadlines"),
                ));
            }
        }
        self.seq += 1;
        let want = self.seq;
        if self.req.send((want, file, size)).is_err() {
            return Err(io::Error::other("the fetch thread is gone"));
        }

        // Replies from abandoned fetches are still in the channel and are not
        // answers to this question — matching on the sequence number is what
        // keeps a late reply from being delivered as the wrong file's content,
        // which would be silent corruption rather than a visible failure.
        let deadline = std::time::Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                self.missed_one();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("fetch exceeded {within:?}"),
                ));
            }
            match self.rep.recv_timeout(left) {
                Ok((got, r)) if got == want => {
                    // A dead peer fails *instantly*, not slowly, so counting
                    // only missed deadlines would never notice one. The helper
                    // connects out once and has no reconnect path, so a routine
                    // client restart — an upgrade, `Restart=on-failure`, a
                    // logout that clears the runtime directory along with the
                    // socket — would otherwise leave this worker serving instant
                    // EIO forever, under two units that both look healthy.
                    //
                    // Only connection-terminal errors count. A per-file refusal
                    // ("no cloud id for this inode") is an ordinary answer and
                    // must not bring the mount down.
                    match &r {
                        Err(e) if is_connection_lost(e) => self.missed_one(),
                        _ => self.answered(),
                    }
                    return r;
                }
                Ok(_) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    self.missed_one();
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("fetch exceeded {within:?}"),
                    ));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::other("the fetch thread stopped"))
                }
            }
        }
    }
}

pub struct Worker<F: Fetch> {
    group: Group,
    fetch: Timed,
    policy: Policy,
    pub log: DenialLog,
    in_flight: InFlight,
    /// How long any one event may take before the reader is told `EIO`.
    ///
    /// Bounded, and bounded low: this is not a network timeout but the longest a
    /// filesystem operation anywhere on the mount may be stalled by us. §6a-bis.
    event_deadline: std::time::Duration,
    /// So a denial count is announced when it changes rather than every loop.
    reported_denials: usize,
    _fetch: std::marker::PhantomData<F>,
}

/// A read must not be held longer than a user would wait before assuming the
/// machine is broken. Overridable, because a client with large objects and a
/// slow link may reasonably choose differently — but never unbounded.
pub const DEFAULT_EVENT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

impl<F: Fetch + 'static> Worker<F> {
    pub fn new(group: Group, fetch: F, policy: Policy, in_flight: InFlight) -> Self {
        Self::with_deadline(group, fetch, policy, in_flight, DEFAULT_EVENT_DEADLINE)
    }

    pub fn with_deadline(
        group: Group,
        fetch: F,
        policy: Policy,
        in_flight: InFlight,
        event_deadline: std::time::Duration,
    ) -> Self {
        Self {
            group,
            fetch: Timed::new(fetch),
            policy,
            log: DenialLog::default(),
            in_flight,
            event_deadline,
            reported_denials: 0,
            _fetch: std::marker::PhantomData,
        }
    }

    /// True once the fetcher has missed enough deadlines to be treated as
    /// unresponsive. The mount is still answered — with `EIO` — but the unit
    /// cannot recover on its own from here, and §6a-bis says it must come down.
    pub fn fetcher_wedged(&self) -> bool {
        self.fetch.wedged()
    }

    /// The fetcher has been unresponsive long enough that this unit cannot
    /// recover on its own, and should stop rather than serve denials forever.
    pub fn should_give_up(&self) -> bool {
        self.fetch.wedged_for() >= WEDGED_LIMIT
    }

    /// Handle one event, start to finish, and answer it.
    ///
    /// Answering is not optional and not deferrable: a pre-content event holds a
    /// reader inside `read()`, so every path out of this function ends in either
    /// an allow or a deny. The only way a reader hangs is if this function does
    /// not return, which is what [`InFlight`] exists to survive.
    pub fn handle(&mut self, ev: &fanotify::Event) -> Handled {
        let fd = ev.fd;
        if fd < 0 {
            return Handled::Failed {
                reason: "event carried no fd".into(),
            };
        }

        // Published before anything that can block, so a supervisor can answer
        // for us if we die between here and the response.
        self.in_flight.holding(fd);
        let outcome = self.decide_and_fill(ev);

        if std::env::var_os("HYDRATIOND_TRACE").is_some() {
            eprintln!(
                "[worker] {} -> {outcome:?}",
                path_of(fd)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| format!("fd {fd}"))
            );
        }
        let r = match &outcome {
            Handled::Hydrated { .. } | Handled::AlreadyPresent | Handled::Empty => {
                allow(&self.group, fd)
            }
            Handled::Denied { .. } | Handled::Failed { .. } => deny(&self.group, fd),
        };
        self.in_flight.released();
        unsafe { libc::close(fd) };

        if let Err(e) = r {
            return Handled::Failed {
                reason: format!("could not answer the event: {e}"),
            };
        }
        outcome
    }

    fn decide_and_fill(&mut self, ev: &fanotify::Event) -> Handled {
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(ev.fd) };

        // Everything the decision needs comes from the descriptor, not from a
        // name.
        //
        // The path is still resolved, because an ignore mark and a denial log
        // entry both need one — but it is no longer what the answer depends on.
        // A name is a weaker handle than it looks: it can change between
        // resolving it and using it, and a placeholder that someone unlinked
        // while holding it open has no name at all. The path-first version of
        // this function refused that read with EIO, which fails safe but still
        // fails: the content was fetchable the whole time.
        let path = path_of(ev.fd).ok();

        match placeholder::has_mark_fd(borrowed) {
            Ok(false) => {
                // Content is already there. Suppress future events for it —
                // this is the zero-cost claim in §2.4, and without it every
                // read of every hydrated file pays a round trip forever.
                //
                // Except when the file does not look like it has content. A
                // sized file occupying no disk is either genuinely sparse or a
                // placeholder whose mark was removed, and the helper cannot tell
                // which: `user.hydration.dehydrated` is owner-writable, so a
                // same-uid process can strip it and make this branch serve the
                // hole as though it were content.
                //
                // That is not a new capability — the same process could write
                // zeros over the file directly — but the ignore mark would make
                // it *permanent* and unobservable, surviving every later read
                // with no further involvement. Declining to install it bounds
                // the damage to the reads that actually happen while the mark is
                // missing, so restoring the mark restores the file. The price is
                // a round trip per read of a genuinely sparse hydrated file,
                // which is rare and is the safe direction to be wrong in.
                //
                // It is a limit, not a fix, and it does not reach small files:
                // btrfs stores those inline, so a stripped small placeholder
                // still reports blocks and still gets the mark. See §6b for why
                // the underlying hole cannot be closed without taking placeholder
                // creation back across the privilege boundary.
                if let Some(p) = &path {
                    if self.looks_stripped(ev.fd) {
                        // The reader's cgroup is deliberately not looked up: the
                        // pidfd is consumed by the policy check further down,
                        // and who read it is not the point. What is worth
                        // recording is that a file in this state was served.
                        self.log.record(
                            "-",
                            "sized file occupying no disk; not suppressing future events",
                            Some(p),
                        );
                    } else {
                        let _ = self.group.ignore(p);
                    }
                }
                return Handled::AlreadyPresent;
            }
            Ok(true) => {}
            Err(e) => {
                return Handled::Failed {
                    reason: format!("could not read the placeholder mark: {e}"),
                }
            }
        }

        // A marked placeholder that has neither a name nor any content.
        //
        // This is how a placeholder gets created at all. The unprivileged daemon
        // builds one on an `O_TMPFILE` inode and links it in complete; sizing it
        // fires a pre-content event (measured — `probes/tmpfile.c`) that only
        // this process can answer, and answering it the ordinary way is
        // impossible because an anonymous inode has no cloud object yet.
        //
        // What makes allowing it safe is not that the daemon says so. It is that
        // the file is empty at the moment the event fires: the event precedes
        // the truncate, so there are no bytes here that a reader could be served
        // instead of real content. Allowing an empty file is not a shortcut past
        // hydration — it is what hydrating an empty file would do.
        //
        // The first version of this rule trusted a `user.hydration.building`
        // xattr instead, and that was exploitable: any process with the file's
        // uid can set it, so an attacker could mark a real placeholder, let a
        // reader block on it, unlink it, and have the helper serve zeros. The
        // discriminator has to be a property of the file, not a claim about it.
        if let Some(outcome) = self.nothing_to_serve(ev.fd) {
            return outcome;
        }

        let cgroup = ev.pidfd.and_then(|pfd| {
            let c = cgroup_of(pfd).ok();
            unsafe { libc::close(pfd) };
            c
        });

        if let Decision::Deny { rule } = self.policy.decide(cgroup.as_deref()) {
            self.log
                .record(cgroup.as_deref().unwrap_or("?"), &rule, path.as_deref());
            return Handled::Denied { rule };
        }

        let (id, size) = match placeholder::id_and_size_fd(borrowed) {
            Ok(v) => v,
            Err(e) => {
                return Handled::Failed {
                    reason: format!("could not stat the event fd: {e}"),
                }
            }
        };

        let content = match self.fetch.fetch(id, size, self.event_deadline) {
            Ok(c) => c,
            Err(e) => {
                return Handled::Failed {
                    reason: format!("fetch failed: {e}"),
                }
            }
        };

        // Written through the event fd, never by re-opening the path. A write to
        // a freshly opened file inside the marked mount fires another
        // pre-content event, and the only process that could answer it is this
        // one — which is about to be blocked inside the write. The helper
        // deadlocks against itself and the reader waits forever.
        //
        // The whole object or nothing (§5.7): a refusal leaves the placeholder
        // exactly as it was found.
        match placeholder::hydrate_fd(borrowed, &content, size) {
            Ok(()) => {
                // The mark is cleared inside `hydrate_fd`, in the same operation
                // that wrote the content — one owner, so the two cannot disagree.
                //
                // No path, no ignore mark: an unlinked file has no name to mark
                // and will not be opened again anyway.
                if let Some(p) = &path {
                    let _ = self.group.ignore(p);
                }
                Handled::Hydrated { bytes: size }
            }
            Err(e) => Handled::Failed {
                reason: format!("hydration refused: {e}"),
            },
        }
    }

    /// A file that claims a size but occupies no disk.
    ///
    /// Ambiguous by construction — a legitimately sparse hydrated file looks
    /// exactly like a placeholder someone stripped the mark from — so this is
    /// only ever used to withhold an optimisation, never to decide an answer.
    fn looks_stripped(&self, fd: i32) -> bool {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } < 0 {
            return false;
        }
        st.st_size > 0 && st.st_blocks == 0
    }

    /// `Some(Empty)` when there is provably nothing to serve.
    ///
    /// Both conditions are properties the kernel reports, not assertions anyone
    /// makes, which is the entire point:
    ///
    /// - `st_size == 0` — no bytes exist, so no reader can receive the wrong
    ///   ones. This is what carries the safety argument.
    /// - `st_nlink == 0` — no name, so nothing can even reach it. Not required
    ///   for safety; it keeps the rule to the case that needs it, so a named
    ///   empty placeholder still takes the ordinary path and has its mark
    ///   cleared properly.
    fn nothing_to_serve(&self, fd: i32) -> Option<Handled> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } < 0 {
            return None;
        }
        (st.st_nlink == 0 && st.st_size == 0).then_some(Handled::Empty)
    }

    /// Run until the deadline, answering everything that arrives.
    pub fn run(&mut self, until: std::time::Instant) -> io::Result<Vec<Handled>> {
        if std::env::var_os("HYDRATIOND_TRACE").is_some() {
            eprintln!("[worker] loop start, group fd={}", self.group.as_raw());
        }
        let mut seen = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];

        while std::time::Instant::now() < until {
            // §6c requires the denial log to be *visible*. A count kept in
            // memory and never shown is the same failure as everything else
            // here: something the user would want to know, known and not said.
            // Reported when it changes, so a quiet system stays quiet and a
            // backup sweep being refused announces itself.
            let denials = self.log.entries().len();
            if denials != self.reported_denials {
                self.reported_denials = denials;
                eprintln!(
                    "[worker] hydration denied {denials} time(s) so far: {:?}",
                    self.log.summary()
                );
            }

            // Stop rather than go on denying. Every reader has been answered —
            // the loop only reaches here between events — so nothing is left
            // hanging, and the supervisor takes the mount down from here.
            if self.should_give_up() {
                eprintln!(
                    "[worker] the fetcher has been unresponsive for {}s; stopping so the \
                     mount comes down rather than serving EIO indefinitely",
                    WEDGED_LIMIT.as_secs()
                );
                break;
            }
            let mut pfd = libc::pollfd {
                fd: self.group.as_raw(),
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut pfd, 1, 200) };
            if n <= 0 {
                continue;
            }
            let len = self.group.read_events(&mut buf)?;
            if std::env::var_os("HYDRATIOND_TRACE").is_some() {
                eprintln!("[worker] read {len} bytes of events");
            }
            for ev in fanotify::events(&buf, len) {
                seen.push(self.handle(&ev));
            }
        }
        Ok(seen)
    }
}

/// Start the helper: mark the mount, fork, and never let a reader see zeros.
///
/// Returns in the parent only. The child runs `worker` and exits.
///
/// # Safety of the fork
///
/// The child is created before any thread is spawned and does nothing between
/// `fork` and its own loop but run code in this crate, so the usual
/// async-signal-safety concerns do not apply. That ordering is load-bearing: a
/// multi-threaded fork here would be a bug, not a style question.
pub fn spawn_split<F: Fetch + 'static>(
    mount: &Path,
    fetch: F,
    policy: Policy,
    worker_deadline: std::time::Duration,
) -> io::Result<SplitHandle> {
    let group = Group::new_pre_content()?;
    group.mark_mount(mount)?;
    let in_flight = InFlight::new();
    // Shared before the fork, so both halves address the same page.
    let worker_view = in_flight.share();

    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }

    if child == 0 {
        // Worker.
        let until = std::time::Instant::now() + worker_deadline;
        let mut w = Worker::new(group, fetch, policy, worker_view);
        let _ = w.run(until);
        // Deliberately _exit: no destructors, no flushing a parent's buffers.
        unsafe { libc::_exit(0) };
    }

    Ok(SplitHandle {
        group,
        in_flight,
        worker: child,
    })
}

/// The supervisor's half.
pub struct SplitHandle {
    group: Group,
    in_flight: InFlight,
    worker: i32,
}

impl SplitHandle {
    pub fn worker_pid(&self) -> i32 {
        self.worker
    }

    /// Watch the worker, then answer whatever it left stranded and deny
    /// everything from then on.
    ///
    /// This is the whole reason the process is split. Without it, killing the
    /// worker turns every dehydrated file into a source of zeros — measured, and
    /// worse than the FUSE client this replaces.
    ///
    /// It watches **progress**, not just liveness, which §6a-bis added after a
    /// hung worker wedged the mount several times during development. A worker
    /// that has died is recoverable: the supervisor still holds the group and
    /// denies. A worker that is *alive and stuck* holding an event is not, and
    /// it is worse — the reader it is holding cannot be killed by a signal, so
    /// every later operation on the mount blocks behind it and "restart the
    /// daemon" is not an available answer.
    pub fn supervise(&self, until: std::time::Instant) -> io::Result<SuperviseReport> {
        self.supervise_with_stall(until, DEFAULT_STALL)
    }

    /// As [`supervise`](Self::supervise), with the stall window given explicitly.
    pub fn supervise_with_stall(
        &self,
        until: std::time::Instant,
        stall_after: std::time::Duration,
    ) -> io::Result<SuperviseReport> {
        let mut status = 0i32;
        let mut stalled = false;
        let mut beat = self.in_flight.progress();
        let mut moved = std::time::Instant::now();

        loop {
            if unsafe { libc::waitpid(self.worker, &mut status, libc::WNOHANG) } == self.worker {
                break;
            }
            let now = self.in_flight.progress();
            if now != beat {
                beat = now;
                moved = std::time::Instant::now();
            }
            // Only a worker that is *holding something* can be stalling. An idle
            // worker makes no progress either, and treating that as a fault
            // would tear the mount down every time nobody is reading.
            if self.in_flight.current().is_some() && moved.elapsed() >= stall_after {
                stalled = true;
                break;
            }
            if std::time::Instant::now() >= until {
                return Ok(SuperviseReport {
                    worker_signal: None,
                    stranded_answered: None,
                    denied_after: 0,
                    stalled: false,
                });
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        if stalled {
            // Order matters, and it is the one thing §6a-bis is really about.
            // Signal first: a worker stuck in a network fetch dies here and its
            // event is then answered below. If it does *not* die, it is stuck
            // inside a pre-content event of its own making — the trap in
            // §6a-ter — and no signal will ever reach it. Answering the stranded
            // event is what releases it, so that comes second rather than first.
            unsafe { libc::kill(self.worker, libc::SIGKILL) };
            let grace = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while std::time::Instant::now() < grace {
                if unsafe { libc::waitpid(self.worker, &mut status, libc::WNOHANG) } == self.worker {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }

        let mut stranded = None;
        take_over(&self.group, &self.in_flight, |fd| stranded = Some(fd))?;

        if stalled {
            // Reap whatever the answer above freed. Not fatal if it is still
            // there: the group is ours, every event gets EIO, and the unit is
            // coming down regardless.
            unsafe { libc::waitpid(self.worker, &mut status, libc::WNOHANG) };
        }

        // From here on the group still exists, so events keep arriving — and
        // every one of them gets EIO rather than being allowed through to a
        // file with no content in it.
        let mut denied = 0usize;
        let mut buf = vec![0u8; 64 * 1024];
        while std::time::Instant::now() < until {
            let mut pfd = libc::pollfd {
                fd: self.group.as_raw(),
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
                continue;
            }
            let len = self.group.read_events(&mut buf)?;
            for ev in fanotify::events(&buf, len) {
                if ev.fd >= 0 {
                    let _ = deny(&self.group, ev.fd);
                    unsafe { libc::close(ev.fd) };
                    denied += 1;
                }
            }
        }

        Ok(SuperviseReport {
            worker_signal: if libc::WIFSIGNALED(status) {
                Some(libc::WTERMSIG(status))
            } else {
                None
            },
            stranded_answered: stranded,
            denied_after: denied,
            stalled,
        })
    }
}

/// How long a worker may hold one event without answering anything before the
/// supervisor stops believing it will.
///
/// Comfortably longer than [`DEFAULT_EVENT_DEADLINE`], so a worker that is
/// merely waiting out a slow fetch is never mistaken for a stuck one — the
/// deadline should fire first and let the worker answer `EIO` itself.
pub const DEFAULT_STALL: std::time::Duration = std::time::Duration::from_secs(90);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperviseReport {
    /// The signal that killed the worker, if one did.
    pub worker_signal: Option<i32>,
    /// The event fd the worker died holding, which the supervisor answered on
    /// its behalf. `None` means it died between events.
    pub stranded_answered: Option<i32>,
    pub denied_after: usize,
    /// The worker was alive but had stopped answering. §6a-bis: this is the
    /// unrecoverable case, and the mount has to come down — the binary turns it
    /// into a non-zero exit so `BindsTo=` tears the mount unit down with it.
    pub stalled: bool,
}

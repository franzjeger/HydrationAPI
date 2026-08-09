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
    /// Deliver the object by writing it into `dest`, chunk by chunk.
    ///
    /// `dest` is called with `(bytes, offset)` as they arrive and `progress`
    /// after each one. Streaming rather than returning a `Vec` is what lifts the
    /// size ceiling from "whatever fits in one deadline" to "whatever the
    /// transfer cap allows" — and what stops a root process from allocating an
    /// object's worth of memory per read (§8d).
    fn fetch_into(
        &mut self,
        file: FileId,
        size: u64,
        dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        progress: &mut dyn FnMut(u64),
    ) -> io::Result<()>;
}

/// The simple case: a fetcher that has the whole object in hand.
///
/// Streaming is what the framework needs from a real provider, but plenty of
/// callers — tests, and any source that is already local — have the bytes
/// already. Implementing this gives them [`Fetch`] for free, and keeps the
/// interesting trait honest about what it is for.
pub trait FetchWhole: Send {
    fn fetch(&mut self, file: FileId, size: u64) -> io::Result<Vec<u8>>;
}

impl<T: FetchWhole> Fetch for T {
    fn fetch_into(
        &mut self,
        file: FileId,
        size: u64,
        dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        progress: &mut dyn FnMut(u64),
    ) -> io::Result<()> {
        let body = self.fetch(file, size)?;
        // Delivered in chunks even though it is all here, so that a caller which
        // swaps a local source for a network one changes nothing about how the
        // worker sees it.
        let mut off = 0u64;
        for part in body.chunks(hydration_protocol::MAX_CHUNK as usize) {
            dest(part, off)?;
            off += part.len() as u64;
            progress(off);
        }
        // A short body is the provider's failure, not a partial success (§5.7),
        // and answering the event with less than it demanded would hand the
        // reader zeros (§8d).
        if off != size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("delivered {off} of {size} bytes"),
            ));
        }
        Ok(())
    }
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
    /// A transfer that started and was given up on — too slow, or too large to
    /// hold a filesystem operation open for.
    ///
    /// Distinct from `Failed` for the same reason `Denied` is: "a 4 GB object
    /// was abandoned at 900 MB" is a capacity fact the user needs, and it is
    /// indistinguishable from a provider fault otherwise.
    Abandoned { reason: String },
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
/// What the fetch thread tells the worker while a transfer runs.
enum Step {
    /// Bytes landed. Carries the running total, for the log and for the cap.
    Progress(u64),
    /// Every promised byte arrived.
    Done,
    /// It will not complete.
    Failed(io::Error),
}

/// A [`Fetch`] you can give up on, streamed.
///
/// §6a-bis's first requirement, extended to transfers that legitimately take
/// minutes. A `Fetch` is client code talking to a network and may never return;
/// if the worker waits inside it the pre-content event goes unanswered, and a
/// process blocked in one cannot be killed by a signal, so every later operation
/// on the mount blocks too.
///
/// The deadline cannot be enforced by asking implementors to respect one. So the
/// fetch runs on its own thread and the worker waits on a channel — but now it
/// waits *repeatedly*, once per chunk, which is what lets a slow-but-progressing
/// transfer continue while a stopped one is still cut off promptly.
///
/// Three limits, and they answer different questions:
///
/// - **first byte** — is this service answering at all?
/// - **stall** — has it stopped part way?
/// - **total** — is this object simply too big to be worth blocking a filesystem
///   operation for? Unbounded total is not defensible: the reader is inside
///   `read()` the whole time and cannot be signalled away, so "no cap" means a
///   user can have an unkillable process for hours. The cap is chosen from how
///   long a filesystem operation may block, not from how big a file may be.
struct Timed {
    req: std::sync::mpsc::Sender<Job>,
    rep: std::sync::mpsc::Receiver<(u64, Step)>,
    seq: u64,
    missed: u32,
    since: Option<std::time::Instant>,
}

struct Job {
    seq: u64,
    file: FileId,
    size: u64,
    fd: i32,
}

/// After this many consecutive first-byte misses the fetcher is treated as
/// unresponsive and no longer waited on, so each event costs a denial rather
/// than a full timeout.
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
/// §6a-bis's third requirement reached by another road: a worker that denies
/// promptly is not stuck, so the supervisor's stall watch never fires and the
/// mount would serve instant `EIO` forever, healthily.
pub const WEDGED_LIMIT: std::time::Duration = std::time::Duration::from_secs(300);

impl Timed {
    fn new<F: Fetch + 'static>(mut fetch: F) -> Self {
        let (req_tx, req_rx) = std::sync::mpsc::channel::<Job>();
        let (rep_tx, rep_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            while let Ok(job) = req_rx.recv() {
                let tx = rep_tx.clone();
                let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(job.fd) };
                let mut wrote = |buf: &[u8], off: u64| -> io::Result<()> {
                    placeholder::write_at(borrowed, buf, off)
                };
                let mut tick = |total: u64| {
                    let _ = tx.send((job.seq, Step::Progress(total)));
                };
                let outcome = fetch.fetch_into(job.file, job.size, &mut wrote, &mut tick);
                let step = match outcome {
                    Ok(()) => Step::Done,
                    Err(e) => Step::Failed(e),
                };
                if rep_tx.send((job.seq, step)).is_err() {
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

    /// Run one transfer into `fd`, calling `alive` once per wait so the caller
    /// can prove to the supervisor that it is still in control of its own loop.
    ///
    /// Deliberately not a byte counter: a heartbeat that moves with the network
    /// lets a provider dribbling one byte per stall-window hold the mount for
    /// what is arithmetically forever. This one moves at a rate the *worker*
    /// controls, and the worker is the thing that decides when patience runs out.
    fn run(
        &mut self,
        file: FileId,
        size: u64,
        fd: i32,
        limits: Limits,
        alive: &mut dyn FnMut(),
    ) -> Result<u64, TransferError> {
        if self.wedged() {
            // Abandoned transfers keep running, and anything from one is proof
            // of life. Draining for it here is what keeps this from being a
            // one-way door.
            let mut recovered = false;
            while self.rep.try_recv().is_ok() {
                recovered = true;
            }
            if recovered {
                self.answered();
            } else {
                return Err(TransferError::Unresponsive);
            }
        }

        self.seq += 1;
        let want = self.seq;
        if self
            .req
            .send(Job {
                seq: want,
                file,
                size,
                fd,
            })
            .is_err()
        {
            return Err(TransferError::Gone);
        }

        let began = std::time::Instant::now();
        let mut deadline = began + limits.first_byte;
        let mut moved = 0u64;
        loop {
            alive();
            if began.elapsed() > limits.total {
                self.missed_one();
                return Err(TransferError::TooLong { got: moved, size });
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                self.missed_one();
                return Err(if moved == 0 {
                    TransferError::NoFirstByte
                } else {
                    TransferError::Stalled { got: moved, size }
                });
            }
            match self.rep.recv_timeout(left.min(HEARTBEAT)) {
                Ok((got, _)) if got != want => continue,
                Ok((_, Step::Progress(total))) => {
                    if moved == 0 {
                        // The first byte is the evidence that matters: it says
                        // the service is alive. A transfer that produced bytes
                        // and then stalled is a fact about the object, not about
                        // the fetcher, and must not count towards wedged.
                        self.answered();
                    }
                    moved = total;
                    deadline = std::time::Instant::now() + limits.stall;
                }
                Ok((_, Step::Done)) => {
                    self.answered();
                    return Ok(moved);
                }
                Ok((_, Step::Failed(e))) => {
                    if is_connection_lost(&e) {
                        self.missed_one();
                    } else if moved > 0 {
                        self.answered();
                    }
                    return Err(TransferError::Provider(e));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(TransferError::Gone)
                }
            }
        }
    }
}

/// How often the worker proves it is alive while waiting on a transfer.
const HEARTBEAT: std::time::Duration = std::time::Duration::from_millis(500);

/// What bounds a transfer.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// How long the service has to say anything at all.
    pub first_byte: std::time::Duration,
    /// How long it may go without saying anything more.
    pub stall: std::time::Duration,
    /// The longest a filesystem operation may be blocked by us, whatever the
    /// object's size. Not optional: the reader cannot be signalled away.
    pub total: std::time::Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            first_byte: std::time::Duration::from_secs(30),
            stall: std::time::Duration::from_secs(60),
            total: std::time::Duration::from_secs(600),
        }
    }
}

#[derive(Debug)]
enum TransferError {
    NoFirstByte,
    Stalled { got: u64, size: u64 },
    TooLong { got: u64, size: u64 },
    Unresponsive,
    Gone,
    Provider(io::Error),
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoFirstByte => write!(f, "the provider sent nothing"),
            Self::Stalled { got, size } => write!(f, "stalled at {got} of {size} bytes"),
            Self::TooLong { got, size } => {
                write!(f, "abandoned at {got} of {size} bytes: too long to hold a read")
            }
            Self::Unresponsive => write!(f, "fetcher unresponsive"),
            Self::Gone => write!(f, "the fetch thread is gone"),
            Self::Provider(e) => write!(f, "{e}"),
        }
    }
}

pub struct Worker<F: Fetch> {
    group: Group,
    fetch: Timed,
    policy: Policy,
    pub log: DenialLog,
    in_flight: InFlight,
    /// What bounds a transfer: first byte, stall, and total. §6a-bis.
    limits: Limits,
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
        Self::with_limits(group, fetch, policy, in_flight, Limits::default())
    }

    pub fn with_deadline(
        group: Group,
        fetch: F,
        policy: Policy,
        in_flight: InFlight,
        first_byte: std::time::Duration,
    ) -> Self {
        Self::with_limits(
            group,
            fetch,
            policy,
            in_flight,
            Limits {
                first_byte,
                stall: first_byte,
                total: first_byte * 20,
            },
        )
    }

    pub fn with_limits(
        group: Group,
        fetch: F,
        policy: Policy,
        in_flight: InFlight,
        limits: Limits,
    ) -> Self {
        Self {
            group,
            fetch: Timed::new(fetch),
            policy,
            log: DenialLog::default(),
            in_flight,
            limits,
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
            Handled::Denied { .. } | Handled::Failed { .. } | Handled::Abandoned { .. } => {
                deny(&self.group, fd)
            }
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

        // Residue from a transfer that was cut off mid-stream.
        //
        // A marked file that occupies disk cannot exist between transfers, but
        // it is exactly what a crash during one leaves — and the supervisor
        // cannot clean it up, because it holds the event fd's *number* and not
        // the descriptor, so it can answer but not punch. The next transfer is
        // therefore the only place it can be done.
        match placeholder::clear_residue(borrowed, size) {
            Ok(true) => eprintln!("[worker] cleared residue from an interrupted transfer"),
            Ok(false) => {}
            Err(e) => {
                return Handled::Failed {
                    reason: format!("could not clear an interrupted transfer: {e}"),
                }
            }
        }

        // Written through the event fd as the bytes arrive, never by re-opening
        // the path. A write to a freshly opened file inside the marked mount
        // fires another pre-content event, and the only process that could
        // answer it is this one — which is about to be blocked inside the write.
        //
        // Measured (`probes/stream.c`): these partial writes fire no events of
        // their own, and no bystander can observe the half-filled file, because
        // their own event queues behind the one being served. That is what makes
        // filling incrementally safe rather than merely convenient.
        let limits = self.limits;
        let in_flight = self.in_flight.clone();
        let mut alive = move || in_flight.working();
        let outcome = self.fetch.run(id, size, ev.fd, limits, &mut alive);

        match outcome {
            Ok(_) => match placeholder::finish_hydration(borrowed, size) {
                Ok(()) => {
                    // The mark is cleared inside `finish_hydration`, in the same
                    // operation that fsynced the content — one owner, so the two
                    // cannot disagree.
                    //
                    // No path, no ignore mark: an unlinked file has no name to
                    // mark and will not be opened again anyway.
                    if let Some(p) = &path {
                        let _ = self.group.ignore(p);
                    }
                    Handled::Hydrated { bytes: size }
                }
                Err(e) => {
                    let _ = placeholder::abandon(borrowed, size);
                    Handled::Failed {
                        reason: format!("hydration refused: {e}"),
                    }
                }
            },
            Err(e) => {
                // The whole object or nothing (§5.7). Whatever landed is punched
                // back out, so the placeholder is exactly as it was found — and
                // the reader gets an error rather than the part that arrived,
                // because answering `FAN_ALLOW` with less than the event asked
                // for hands them zeros in silence (§8d).
                let _ = placeholder::abandon(borrowed, size);
                let abandoned = matches!(
                    e,
                    TransferError::TooLong { .. } | TransferError::Stalled { .. }
                );
                let reason = format!("{e}");
                if abandoned {
                    self.log.record("-", "transfer abandoned", path.as_deref());
                    Handled::Abandoned { reason }
                } else {
                    Handled::Failed { reason }
                }
            }
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
        // Either counter moving is proof of life.
        //
        // `progress` only moves when an event is fully answered, and a
        // legitimate streaming transfer can hold one for minutes — so watching
        // it alone would tear the mount down mid-download. `liveness` moves once
        // per pass of the worker's own wait loop, at a rate the worker controls
        // rather than the network.
        let mut beat = (self.in_flight.progress(), self.in_flight.liveness());
        let mut moved = std::time::Instant::now();

        loop {
            if unsafe { libc::waitpid(self.worker, &mut status, libc::WNOHANG) } == self.worker {
                break;
            }
            let now = (self.in_flight.progress(), self.in_flight.liveness());
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
    /// unrecoverable case, and the mount has to come down. The binary detaches
    /// it itself and then exits non-zero, in that order — exiting first would
    /// close the group, and a marked mount with no group fails *open*.
    pub stalled: bool,
}

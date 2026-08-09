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

pub struct Worker<F: Fetch> {
    group: Group,
    fetch: F,
    policy: Policy,
    pub log: DenialLog,
    in_flight: InFlight,
}

impl<F: Fetch> Worker<F> {
    pub fn new(group: Group, fetch: F, policy: Policy, in_flight: InFlight) -> Self {
        Self {
            group,
            fetch,
            policy,
            log: DenialLog::default(),
            in_flight,
        }
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

        let content = match self.fetch.fetch(id, size) {
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
pub fn spawn_split<F: Fetch>(
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

    /// Wait for the worker, then answer whatever it left stranded and deny
    /// everything from then on.
    ///
    /// This is the whole reason the process is split. Without it, killing the
    /// worker turns every dehydrated file into a source of zeros — measured, and
    /// worse than the FUSE client this replaces.
    pub fn supervise(&self, until: std::time::Instant) -> io::Result<SuperviseReport> {
        let mut status = 0i32;
        unsafe { libc::waitpid(self.worker, &mut status, 0) };

        let mut stranded = None;
        take_over(&self.group, &self.in_flight, |fd| stranded = Some(fd))?;

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
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuperviseReport {
    /// The signal that killed the worker, if one did.
    pub worker_signal: Option<i32>,
    /// The event fd the worker died holding, which the supervisor answered on
    /// its behalf. `None` means it died between events.
    pub stranded_answered: Option<i32>,
    pub denied_after: usize,
}

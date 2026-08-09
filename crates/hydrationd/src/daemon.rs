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
            Handled::Hydrated { .. } | Handled::AlreadyPresent => allow(&self.group, fd),
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
        let path = match path_of(ev.fd) {
            Ok(p) => p,
            Err(e) => {
                return Handled::Failed {
                    reason: format!("could not resolve the event fd: {e}"),
                }
            }
        };

        match placeholder::is_dehydrated(&path) {
            Ok(false) => {
                // Content is already there. Suppress future events for it —
                // this is the zero-cost claim in §2.4, and without it every
                // read of every hydrated file pays a round trip forever.
                let _ = self.group.ignore(&path);
                return Handled::AlreadyPresent;
            }
            Ok(true) => {}
            Err(e) => {
                return Handled::Failed {
                    reason: format!("could not stat {}: {e}", path.display()),
                }
            }
        }

        let cgroup = ev.pidfd.and_then(|pfd| {
            let c = cgroup_of(pfd).ok();
            unsafe { libc::close(pfd) };
            c
        });

        if let Decision::Deny { rule } = self.policy.decide(cgroup.as_deref()) {
            self.log
                .record(cgroup.as_deref().unwrap_or("?"), &rule, Some(&path));
            return Handled::Denied { rule };
        }

        let (id, size) = match (placeholder::id_of(&path), std::fs::metadata(&path)) {
            (Ok(id), Ok(md)) => (id, md.len()),
            _ => {
                return Handled::Failed {
                    reason: format!("could not read {}", path.display()),
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
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(ev.fd) };
        match placeholder::hydrate_fd(borrowed, &content, size) {
            Ok(()) => {
                // The mark and the content change together. Clearing it after
                // the write and before the ignore mark means a reader arriving
                // in between still sees a file that is intercepted and full.
                let _ = placeholder::mark_dehydrated(&path, false);
                let _ = self.group.ignore(&path);
                Handled::Hydrated { bytes: size }
            }
            Err(e) => Handled::Failed {
                reason: format!("hydration refused: {e}"),
            },
        }
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

//! The supervisor/worker split that makes hydration fail closed.
//!
//! Bare fanotify fails *open*: kill the daemon and a dehydrated placeholder
//! reads back as zeros with exit 0. That is silent data corruption, and worse
//! than the FUSE client this replaces, which at least reports `ENOTCONN`.
//! Measured, in `probes/watchdog.c`.
//!
//! The fix is structural rather than careful coding. The fanotify group lives as
//! long as *any* descriptor references it, so the process is split in two before
//! anything can go wrong:
//!
//! ```text
//! super  ── fanotify_init() + mark
//!    │       fork()
//!    ├── worker    hydrates; publishes the event it is holding
//!    └── super     holds its copy of the fd, otherwise idle
//!                  on worker death: answers the stranded event, then denies
//! ```
//!
//! Two failure modes, both measured, both closed:
//!
//! * Worker dies between events → the supervisor still holds the group, and
//!   denies with `EIO`. The reader gets an error, not zeros.
//! * Worker dies *holding* an event it had already dequeued → that event is
//!   gone from the queue and the supervisor never sees it, so the reader hangs
//!   forever. Closed by the worker publishing the event fd it is holding: a
//!   response is matched by fd number within the group, so the supervisor can
//!   answer for a worker that is no longer alive.
//!
//! What is *not* closed: both processes dying at once. Nothing inside this
//! process can cover that, which is why §6.4a puts the sync directory on its own
//! mount and §8 requires the unit to tear it down.

use crate::fanotify::{self, Group};
use std::io;
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long the teardown drain waits for silence before deciding nothing is left
/// waiting on it.
pub const DENY_DRAIN_QUIET: Duration = Duration::from_secs(10);

/// The longest the teardown drain will run, however busy it is.
///
/// This is not a tidiness limit, it is the whole reason the drain terminates.
/// The quiet window is a *sliding* one — every event that arrives pushes it out
/// again — so on its own it makes termination a property of the rest of the
/// machine rather than of this process. Measured, `probes/denyloop.c`: a reader
/// that treats `EIO` as transient and comes straight back holds the window open
/// at ~333,000 denials per second indefinitely.
///
/// That is not a hypothetical about badly written software. On 2026-08-12 this
/// deployment sat mount-down for 23 minutes because two KDE thumbnail workers
/// were faulting on placeholders; the supervisor answered on the order of 500
/// million denials and never saw a quiet 10 seconds, so it never exited,
/// `Restart=always` never fired, `RequiresMountsFor=` never remounted, and the
/// unit stayed `active` throughout. Fail-closed had become fail-down-forever,
/// which is worse than the failure the design was avoiding: an outage that
/// reports itself as healthy.
///
/// Six times the quiet window. Long enough that a real backlog of in-flight
/// readers is answered rather than abandoned, short enough that recovery is
/// prompt — and recovery is the point, because a detached mount serves nobody.
pub const DENY_DRAIN_CAP: Duration = Duration::from_secs(60);

/// The two words the halves share. Laid out explicitly because it is mapped, not
/// allocated, and both processes have to agree on where each field lives.
#[repr(C)]
struct Shared {
    /// The event fd the worker is currently holding, or -1.
    slot: AtomicI32,
    _pad: u32,
    /// Incremented every time the worker passes through its own wait loop.
    ///
    /// Deliberately not a byte counter. A heartbeat that moves with the network
    /// makes the supervisor's verdict depend on the network, and the supervisor
    /// is the one component that must have no opinion about it — a provider
    /// dribbling one byte per stall window would otherwise hold the mount for
    /// what is arithmetically forever. This moves at a rate the *worker*
    /// controls, so a worker stuck in an uninterruptible write or deadlocked on
    /// its own pre-content event stops bumping it, which is exactly the state
    /// that must be caught.
    working: AtomicU64,
    /// Incremented every time the worker finishes answering an event.
    ///
    /// A counter rather than a timestamp, so the shared page needs no clock and
    /// the supervisor's judgement is "did this move" rather than "is this recent
    /// enough" — which cannot be fooled by a clock stepping.
    beat: AtomicU64,
}

/// Process-local reference-counted owner of the `MAP_SHARED` page.
///
/// Wrapping the `MAP_SHARED` VMA inside `Arc<SharedMapping>` combines both
/// properties cleanly:
/// 1. Within any single process, cloning and dropping `InFlight` in arbitrary
///    order is 100% memory-safe — `munmap` runs only when the last `Arc` in
///    that process drops.
/// 2. Across `fork()`, both processes inherit mappings backed by the same
///    physical `MAP_SHARED` kernel page, while `munmap` in one process never
///    unmaps the other process's virtual mapping.
#[derive(Debug)]
struct SharedMapping {
    ptr: *mut Shared,
}

// SAFETY: `ptr` addresses an anonymous `MAP_SHARED` kernel page accessed
// exclusively via `AtomicI32` / `AtomicU64`, and stays mapped until `Drop`.
unsafe impl Send for SharedMapping {}
// SAFETY: All reads and writes to `*ptr` go through lock-free atomics.
unsafe impl Sync for SharedMapping {}

impl Drop for SharedMapping {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` was returned by `libc::mmap` with `size_of::<Shared>()`
        // and `Arc` guarantees no in-process references remain when `drop` runs.
        unsafe {
            libc::munmap(
                self.ptr as *mut libc::c_void,
                std::mem::size_of::<Shared>(),
            );
        }
    }
}

/// Where the worker records the event it currently holds.
///
/// A `MAP_SHARED` anonymous mapping, established *before* the fork. This has to
/// be genuinely shared memory: an `Arc<AtomicI32>` looks like it would work and
/// does not, because `fork` gives the child a copy-on-write private page. The
/// worker's writes would land in its own copy, the supervisor would read -1
/// forever, and the stranded event would go unanswered — which presents as the
/// reader hanging, with nothing in any log to say why.
#[derive(Clone, Debug)]
pub struct InFlight {
    mapping: Arc<SharedMapping>,
}

impl Default for InFlight {
    fn default() -> Self {
        Self::new()
    }
}

impl InFlight {
    pub fn new() -> Self {
        let len = std::mem::size_of::<Shared>();
        // SAFETY: Anonymous `MAP_SHARED` mapping with no file descriptor; kernel
        // chooses a page-aligned address and zero-initializes the page.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert!(
            p != libc::MAP_FAILED,
            "could not map the in-flight slot: {}",
            std::io::Error::last_os_error()
        );
        let ptr = p as *mut Shared;
        // SAFETY: `ptr` is page-aligned (exceeding `Shared`'s 8-byte alignment),
        // valid for `size_of::<Shared>()` bytes, and uniquely owned before return.
        // Relaxed initialization suffices because `fork` or thread spawn provides
        // the happens-before barrier to any concurrent reader.
        unsafe {
            (*ptr).slot.store(-1, Ordering::Relaxed);
            (*ptr).beat.store(0, Ordering::Relaxed);
            (*ptr).working.store(0, Ordering::Relaxed);
        }
        Self {
            mapping: Arc::new(SharedMapping { ptr }),
        }
    }

    #[inline]
    fn shared(&self) -> &Shared {
        // SAFETY: `self.mapping` keeps the `MAP_SHARED` page mapped for `&self`'s
        // lifetime, and `Shared` contains only atomic fields.
        unsafe { &*self.mapping.ptr }
    }

    /// A handle onto the same slot, for the other side of the fork.
    pub fn share(&self) -> Self {
        self.clone()
    }

    /// Called by the worker before anything that can block: a network fetch, a
    /// lock, a write to a socket the other end may never read.
    ///
    /// Bumps `working` *before* publishing `slot` with Release ordering: after
    /// an idle stretch exceeding `DEFAULT_STALL`, a supervisor polling between
    /// `holding(fd)` and the first transfer chunk must see fresh liveness rather
    /// than mistaking prior idle silence for a 90-second stall.
    pub fn holding(&self, fd: i32) {
        let s = self.shared();
        // AcqRel/Release ensures the liveness bump is visible to any supervisor
        // Acquire load that observes `slot != -1`.
        s.working.fetch_add(1, Ordering::AcqRel);
        s.slot.store(fd, Ordering::Release);
    }

    /// Called by the worker once the event has been answered.
    ///
    /// Bumps the progress counter as well as clearing the slot, and in that
    /// order: the supervisor's test is "holding something, and the counter has
    /// not moved", so clearing first would let a worker that answers steadily
    /// look momentarily stalled.
    pub fn released(&self) {
        let s = self.shared();
        // Release ensures `beat` increment is visible before `slot` clears to -1.
        s.beat.fetch_add(1, Ordering::AcqRel);
        s.slot.store(-1, Ordering::Release);
    }

    pub fn current(&self) -> Option<i32> {
        // Acquire pairs with Release stores in `holding` and `released`.
        match self.shared().slot.load(Ordering::Acquire) {
            -1 => None,
            fd => Some(fd),
        }
    }

    /// Called once per pass of the worker's wait loop during a long transfer.
    ///
    /// A transfer that legitimately takes minutes would otherwise look exactly
    /// like a hung worker — `progress()` frozen, an event held — and the mount
    /// would be torn down mid-download.
    pub fn working(&self) {
        // Release pairs with supervisor Acquire load in `liveness()`.
        self.shared().working.fetch_add(1, Ordering::Release);
    }

    /// The worker's own liveness, independent of whether anything completed.
    pub fn liveness(&self) -> u64 {
        // Acquire pairs with `working()` / `holding()`.
        self.shared().working.load(Ordering::Acquire)
    }

    /// How many events the worker has answered.
    ///
    /// Only ever compared with itself. §6a-bis: the supervisor has to watch
    /// *progress*, because a worker that is alive and stuck is worse than one
    /// that is dead — a process blocked in a pre-content event cannot be killed
    /// by a signal, so nothing recovers on its own.
    pub fn progress(&self) -> u64 {
        // Acquire pairs with `released()`.
        self.shared().beat.load(Ordering::Acquire)
    }
}

/// What the supervisor does once the worker is gone.
///
/// Everything is denied with `EIO`, including anything the worker was holding.
/// A denial is the honest answer: the component that could produce content is
/// not running, and the alternative -- letting the read through -- is zeros.
pub fn take_over(
    group: &Group,
    in_flight: &InFlight,
    mut on_event: impl FnMut(i32),
) -> io::Result<()> {
    // The event the worker died holding is no longer in the queue, so it will
    // never come back from read(). It has to be answered by number or the
    // reader waits forever.
    if let Some(stranded) = in_flight.current() {
        on_event(stranded);
        group.respond_raw(stranded, fanotify::deny_with(libc::EIO))?;
    }
    Ok(())
}

/// Deny one event with `EIO`.
pub fn deny(group: &Group, event_fd: i32) -> io::Result<()> {
    group.respond_raw(event_fd, fanotify::deny_with(libc::EIO))
}

/// Why the teardown drain stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Drained {
    /// Nothing arrived for the quiet window. Everything that was in flight has
    /// been answered, and exiting now strands nobody.
    Quiet { denied: u64 },
    /// The cap expired with events still arriving.
    ///
    /// Exiting closes the group, and a mount with no group fails *open*, so the
    /// readers still hammering will get the zeros a placeholder is made of. That
    /// is a real cost and it is chosen deliberately: the mount is already
    /// detached, so nothing *new* can reach it, and the alternative is a process
    /// that never exits and a deployment that never recovers. `still_hammering`
    /// carries the pids so the log can name them instead of leaving the next
    /// person to work it out from `/proc` during an outage.
    StillBusy {
        denied: u64,
        still_hammering: Vec<i32>,
    },
}

/// Answer everything with `EIO` until the mount goes quiet, or until `cap`.
///
/// Extracted from `main` so it can be tested at all: the loop it replaces was
/// inline in `bin/hydrationd.rs`, which meant the one property that mattered —
/// that it terminates — had no test and turned out to be false.
///
/// Three things here are deliberate and were each wrong in the version this
/// replaces:
///
/// * **The cap.** See [`DENY_DRAIN_CAP`]. Without it the loop does not terminate.
/// * **`revents` is checked.** `poll` reports `POLLERR`, `POLLHUP` and `POLLNVAL`
///   whether or not they were requested, and the old loop took any non-zero
///   return as traffic. An error condition on the group fd therefore reset the
///   quiet window just as effectively as a real event, so a broken group fd was
///   indistinguishable from a busy mount.
/// * **The window only resets for events actually answered.** A wakeup that
///   decodes to nothing is not traffic, and treating it as such was a second way
///   to hold the window open with no reader involved at all.
pub fn drain_denying(group: &Group, quiet: Duration, cap: Duration) -> io::Result<Drained> {
    let mut buf = vec![0u8; 64 * 1024];
    let started = Instant::now();
    let mut quiet_since = Instant::now();
    let mut denied = 0u64;
    // Bounded on purpose: this runs while the machine is in trouble, and an
    // unbounded set keyed by a pid a storm controls is a memory leak with extra
    // steps. Eight names is plenty to point at a culprit.
    let mut hammering: Vec<i32> = Vec::new();

    loop {
        if quiet_since.elapsed() >= quiet {
            return Ok(Drained::Quiet { denied });
        }
        if started.elapsed() >= cap {
            return Ok(Drained::StillBusy {
                denied,
                still_hammering: hammering,
            });
        }
        let mut pfd = libc::pollfd {
            fd: group.as_raw(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut pfd, 1, 500) } <= 0 {
            continue;
        }
        if pfd.revents & libc::POLLIN == 0 {
            // An error or hangup on the group fd. Not traffic, so the quiet
            // window is left alone and the loop can still finish.
            continue;
        }
        // A failure here is not a reason to abandon the mount mid-drain, and it
        // must not reset the window either, or a persistently failing read would
        // hold the loop open until the cap for no reason.
        let len = match group.read_events(&mut buf) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let mut answered_any = false;
        for ev in crate::fanotify::events(&buf, len) {
            if ev.fd < 0 {
                continue;
            }
            if deny(group, ev.fd).is_ok() {
                denied += 1;
                answered_any = true;
            }
            unsafe { libc::close(ev.fd) };
            if ev.pid != 0 && hammering.len() < 8 && !hammering.contains(&ev.pid) {
                hammering.push(ev.pid);
            }
        }
        if answered_any {
            quiet_since = Instant::now();
        }
    }
}

/// Allow one event: the content is in place.
pub fn allow(group: &Group, event_fd: i32) -> io::Result<()> {
    group.respond_raw(event_fd, fanotify::FAN_ALLOW)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_flight_is_empty_until_the_worker_says_otherwise() {
        let f = InFlight::new();
        assert_eq!(f.current(), None);
        f.holding(7);
        assert_eq!(f.current(), Some(7));
        f.released();
        assert_eq!(f.current(), None);
    }

    #[test]
    fn a_clone_sees_the_same_slot() {
        // The supervisor's view has to be the worker's view, or it will answer
        // the wrong fd -- or none.
        let a = InFlight::new();
        let b = a.clone();
        a.holding(11);
        assert_eq!(b.current(), Some(11));
    }

    #[test]
    fn dropping_original_before_clone_is_sound_and_holding_bumps_liveness() {
        let a = InFlight::new();
        let b = a.clone();
        let before = b.liveness();
        drop(a);
        // Previously `drop(a)` unmapped the shared page while `b` stayed live (UB/SIGSEGV).
        b.holding(19);
        assert_eq!(b.current(), Some(19));
        assert!(
            b.liveness() > before,
            "holding(fd) must advance liveness so waking after >90s idle never trips stall kill"
        );
        b.released();
        assert_eq!(b.current(), None);
    }

    /// The test the previous implementation passed while being wrong.
    ///
    /// `Arc<AtomicI32>` satisfies every same-process assertion above and fails
    /// here, because `fork` hands the child a copy-on-write private page. The
    /// supervisor then reads -1 forever and never answers the stranded event,
    /// which presents as a reader hanging with nothing to explain it. Sharing
    /// across a fork is the entire requirement, so it is the thing to assert.
    #[test]
    fn the_slot_is_visible_across_a_fork() {
        let parent = InFlight::new();
        let child_view = parent.share();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            child_view.holding(4242);
            unsafe { libc::_exit(0) };
        }

        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(
            parent.current(),
            Some(4242),
            "the parent cannot see what the child recorded — the slot is not \
             actually shared, so a worker that dies holding an event leaves the \
             reader hanging"
        );
    }
}

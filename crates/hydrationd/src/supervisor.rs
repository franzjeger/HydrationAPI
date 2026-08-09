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

/// The two words the halves share. Laid out explicitly because it is mapped, not
/// allocated, and both processes have to agree on where each field lives.
#[repr(C)]
struct Shared {
    /// The event fd the worker is currently holding, or -1.
    slot: AtomicI32,
    _pad: u32,
    /// Incremented every time the worker finishes answering an event.
    ///
    /// A counter rather than a timestamp, so the shared page needs no clock and
    /// the supervisor's judgement is "did this move" rather than "is this recent
    /// enough" — which cannot be fooled by a clock stepping.
    beat: AtomicU64,
}

/// Where the worker records the event it currently holds.
///
/// A `MAP_SHARED` anonymous mapping, established *before* the fork. This has to
/// be genuinely shared memory: an `Arc<AtomicI32>` looks like it would work and
/// does not, because `fork` gives the child a copy-on-write private page. The
/// worker's writes would land in its own copy, the supervisor would read -1
/// forever, and the stranded event would go unanswered — which presents as the
/// reader hanging, with nothing in any log to say why.
///
/// That is not a hypothetical: it is how this was first written, and the
/// integration test caught it.
#[derive(Debug)]
pub struct InFlight {
    /// Points into the shared mapping. Cloned by value across `fork`, which is
    /// exactly what we want: both processes address the same page.
    shared: *mut Shared,
    /// Only the process that created the mapping unmaps it.
    owner: bool,
}

// The pointer addresses a shared mapping whose lifetime outlives the fork, and
// every access is atomic.
unsafe impl Send for InFlight {}
unsafe impl Sync for InFlight {}

impl Default for InFlight {
    fn default() -> Self {
        Self::new()
    }
}

impl InFlight {
    pub fn new() -> Self {
        let len = std::mem::size_of::<Shared>();
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
        let shared = p as *mut Shared;
        unsafe {
            (*shared).slot.store(-1, Ordering::SeqCst);
            (*shared).beat.store(0, Ordering::SeqCst);
        }
        Self {
            shared,
            owner: true,
        }
    }

    /// A handle onto the same slot, for the other side of the fork.
    pub fn share(&self) -> Self {
        Self {
            shared: self.shared,
            owner: false,
        }
    }

    /// Called by the worker before anything that can block: a network fetch, a
    /// lock, a write to a socket the other end may never read.
    pub fn holding(&self, fd: i32) {
        unsafe { (*self.shared).slot.store(fd, Ordering::SeqCst) };
    }

    /// Called by the worker once the event has been answered.
    ///
    /// Bumps the progress counter as well as clearing the slot, and in that
    /// order: the supervisor's test is "holding something, and the counter has
    /// not moved", so clearing first would let a worker that answers steadily
    /// look momentarily stalled.
    pub fn released(&self) {
        unsafe {
            (*self.shared).beat.fetch_add(1, Ordering::SeqCst);
            (*self.shared).slot.store(-1, Ordering::SeqCst);
        }
    }

    pub fn current(&self) -> Option<i32> {
        match unsafe { (*self.shared).slot.load(Ordering::SeqCst) } {
            -1 => None,
            fd => Some(fd),
        }
    }

    /// How many events the worker has answered.
    ///
    /// Only ever compared with itself. §6a-bis: the supervisor has to watch
    /// *progress*, because a worker that is alive and stuck is worse than one
    /// that is dead — a process blocked in a pre-content event cannot be killed
    /// by a signal, so nothing recovers on its own.
    pub fn progress(&self) -> u64 {
        unsafe { (*self.shared).beat.load(Ordering::SeqCst) }
    }
}

impl Clone for InFlight {
    fn clone(&self) -> Self {
        self.share()
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        if self.owner {
            unsafe {
                libc::munmap(
                    self.shared as *mut libc::c_void,
                    std::mem::size_of::<Shared>(),
                )
            };
        }
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

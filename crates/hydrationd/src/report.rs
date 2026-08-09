//! Reporting local changes without putting the event loop behind a socket.
//!
//! Change detection has to reach the unprivileged daemon, and the only channel
//! is the socket the worker already owns. Sending from the worker's event loop
//! is the obvious arrangement and it is a trap: an `AF_UNIX` stream accepts
//! about 278 short messages on a default `SO_SNDBUF` before the sender blocks —
//! the kernel charges a whole skb per small send, not the payload — and a worker
//! blocked in `write()` stops answering pre-content events.
//!
//! That is §6a-bis reached by a road the supervisor cannot see. Its stall watch
//! fires on *holding an event without progress*, and a worker blocked between
//! events holds nothing, so it is classified as idle forever while every reader
//! on the mount hangs. Mount looks healthy; nothing recovers.
//!
//! So the send never happens on the event loop:
//!
//! ```text
//!   drainer  ── reads the notify group, folds each event into a dirty set
//!                 never blocks on anything but a mutex
//!   sender   ── swaps the set out, writes one batched line
//!                 may block; blocks only itself, while the set keeps absorbing
//!   worker   ── answers pre-content events, touches neither
//! ```
//!
//! Folding into a set rather than a queue is not an optimisation bolted on: it
//! is the same coalescing the kernel already does. Measured on this mount,
//! 10,000 alternating writes to two files produced two events, with `MODIFY` and
//! `CLOSE_WRITE` merged per object. The set continues that past the kernel's
//! 16384-object cliff, and its size is bounded by the number of files on the
//! mount rather than by how much writing happens.
//!
//! Nothing is dropped, so nothing is silently lost — but the channel is still
//! not authoritative, and callers must not treat silence as "nothing changed".
//! See [`hydration_protocol::FromHelper::Resync`].

use crate::watch::{Change, Watcher};
use hydration_protocol::transport::Notifier;
use hydration_protocol::{FileId, FromHelper};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Files written since the last send, and what happened to them.
#[derive(Debug, Default)]
pub struct Dirty {
    files: HashMap<FileId, bool>,
    /// The kernel dropped events; the daemon has to walk instead.
    lost: bool,
}

impl Dirty {
    fn note(&mut self, file: FileId, what: Change) {
        // `Closed` is the stronger fact — a writable handle went away, which is
        // the moment the upload rules want to start a quiet period from — so it
        // wins over a bare `Modified` for the same inode.
        let closed = self.files.entry(file).or_insert(false);
        *closed |= what == Change::Closed;
    }

    fn take(&mut self) -> (Vec<FileId>, bool) {
        let files = self.files.drain().map(|(f, _)| f).collect();
        (files, std::mem::take(&mut self.lost))
    }
}

/// Both threads, running until the connection breaks.
///
/// Spawned by the worker *after* `fork`. A thread that exists before a fork
/// leaves the child holding any lock it was in the middle of, which is its own
/// class of hang and one this project has no appetite for.
pub struct Reporter {
    dirty: Arc<Mutex<Dirty>>,
}

impl Reporter {
    /// `ignore_pids` must include every process that writes hydrated content,
    /// or each hydration is reported as a local edit and uploaded straight back.
    pub fn spawn(
        mount: &std::path::Path,
        ignore_pids: Vec<i32>,
        notifier: Notifier,
        batch_every: Duration,
    ) -> std::io::Result<Self> {
        let dirty = Arc::new(Mutex::new(Dirty::default()));

        let mut watcher = Watcher::new(mount, ignore_pids)?;
        let drain = Arc::clone(&dirty);
        std::thread::spawn(move || loop {
            match watcher.poll(Duration::from_millis(200)) {
                Ok(seen) => {
                    let lost = watcher.take_overflow();
                    if seen.is_empty() && !lost {
                        continue;
                    }
                    // The only lock this thread ever waits on, held for the
                    // length of a few hash inserts. Everything that could block
                    // for longer is the sender's problem.
                    let Ok(mut d) = drain.lock() else { return };
                    d.lost |= lost;
                    for o in seen {
                        d.note(o.file, o.what);
                    }
                }
                // A watcher that cannot read has nothing left to contribute, and
                // spinning on the error would burn a core. The daemon still has
                // its periodic walk, which is what makes this survivable.
                Err(_) => return,
            }
        });

        let send = Arc::clone(&dirty);
        std::thread::spawn(move || loop {
            std::thread::sleep(batch_every);
            let (files, lost) = {
                let Ok(mut d) = send.lock() else { return };
                d.take()
            };
            // Resync first. It says "what follows is incomplete", and a daemon
            // that acted on the batch before hearing that would believe it had
            // the whole story for a moment.
            if lost && notifier.send(&FromHelper::Resync).is_err() {
                return;
            }
            if !files.is_empty() && notifier.send(&FromHelper::Changed { files }).is_err() {
                return;
            }
        });

        Ok(Self { dirty })
    }

    /// How many distinct files are waiting to be reported. For status, and for
    /// tests that need to observe the fold rather than the socket.
    pub fn pending(&self) -> usize {
        self.dirty.lock().map(|d| d.files.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(ino: u64) -> FileId {
        FileId { fsid: 1, ino }
    }

    /// The fold is the whole reason this is a set. A long write produces
    /// thousands of events for one file; sending one line each is what puts the
    /// event loop behind a socket.
    #[test]
    fn many_events_for_one_file_become_one_entry() {
        let mut d = Dirty::default();
        for _ in 0..10_000 {
            d.note(id(7), Change::Modified);
        }
        d.note(id(8), Change::Modified);
        assert_eq!(d.files.len(), 2);
        let (files, lost) = d.take();
        assert_eq!(files.len(), 2);
        assert!(!lost);
        assert_eq!(d.files.len(), 0, "taking did not clear the set");
    }

    /// `Closed` is the stronger fact and must survive a later `Modified` for the
    /// same file — the upload rules start their quiet period from it.
    #[test]
    fn a_close_is_not_lost_behind_a_later_modify() {
        let mut d = Dirty::default();
        d.note(id(1), Change::Closed);
        d.note(id(1), Change::Modified);
        assert_eq!(d.files.get(&id(1)), Some(&true));
    }

    #[test]
    fn an_overflow_is_reported_once_and_then_cleared() {
        let mut d = Dirty::default();
        d.lost = true;
        assert!(d.take().1);
        assert!(!d.take().1, "the same overflow was reported twice");
    }
}

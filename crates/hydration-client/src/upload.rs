//! Getting local changes back to the cloud, without the races.
//!
//! Every rule in this module is one of the bugs from DESIGN.md §5, and most of
//! them were shipped and then fixed by hand in a real client. The point of
//! putting them here is that a cloud client using this framework cannot get them
//! wrong, because it is never asked to.
//!
//! Four rules, in the order they were learned:
//!
//! 1. **Upload when the file goes quiet, not when it closes.** An atomic save
//!    closes a temp file it is about to rename away; a scratch file is written
//!    and deleted seconds later; an editor saving ten times starts ten uploads
//!    that collide. Waiting removes all three at the source instead of
//!    recovering from them afterwards.
//! 2. **An upload is addressed by inode, never by a captured name.** The name is
//!    resolved at the moment the bytes are sent. Capturing it when the job was
//!    queued is what put a file in the cloud under
//!    `README.md.tmp.194149.5089d5eff10a`.
//! 3. **A missing local file is a positive statement.** It means the delete is
//!    the newer intention and wins — including deleting the remote object the
//!    upload has just this moment created. Reading it as "no fresh data" and
//!    falling back to a stale in-memory copy is how a deleted file came back.
//! 4. **The pending count includes edits still waiting out the debounce.** With
//!    a 15-minute window the waiting kind is the common one, and omitting it
//!    shows "everything synced" over work that has not left the machine.

use crate::store::Store;
use crate::Provider;
use hydration_protocol::FileId;
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::time::Duration;

/// Time, so the races can be tested without sleeping through them.
///
/// The bugs this module exists to prevent only appear at specific interleavings.
/// A test that waits for a real 900-second debounce would not be run, and a test
/// that shortens it to 50ms tests a different thing and passes for the wrong
/// reason.
pub trait Clock: Send {
    fn now(&self) -> Duration;
}

/// Wall clock, measured from process start.
pub struct SystemClock(std::time::Instant);

impl Default for SystemClock {
    fn default() -> Self {
        Self(std::time::Instant::now())
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

/// A clock the test moves by hand.
#[derive(Debug, Default, Clone)]
pub struct TestClock(std::sync::Arc<std::sync::atomic::AtomicU64>);

impl TestClock {
    pub fn advance(&self, by: Duration) {
        self.0
            .fetch_add(by.as_millis() as u64, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Duration {
        Duration::from_millis(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// What the cloud gave back for an upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uploaded {
    pub cloud_id: String,
    pub etag: Option<String>,
}

/// Uploading and deleting, the half only the client knows how to do.
pub trait Sink: Send {
    /// Send this file's current content. `existing` is the cloud ID if the
    /// object is already known, so the client can make the write conditional.
    ///
    /// Takes a path resolved *now*, not a name captured when the job was queued.
    fn upload(&mut self, path: &std::path::Path, existing: Option<&str>) -> io::Result<Uploaded>;
    fn remove(&mut self, cloud_id: &str) -> io::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Waiting {
    /// When the debounce expires. Pushed out by every further write.
    due: Duration,
}

/// What happened to one upload, for tests and for the status the user sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Sent {
        cloud_id: String,
    },
    /// The file was gone by the time the bytes were due. The delete is the newer
    /// intention, so nothing was uploaded and any remote copy was removed.
    DeletedInstead,
    /// The file is gone and was never in the cloud: nothing to do at all.
    NothingToDo,
    Failed(String),
}

pub struct Queue<C: Clock> {
    waiting: HashMap<FileId, Waiting>,
    /// Uploads that have started. Counted as unsent, because they are.
    in_flight: usize,
    debounce: Duration,
    clock: C,
}

impl<C: Clock> Queue<C> {
    pub fn new(debounce: Duration, clock: C) -> Self {
        Self {
            waiting: HashMap::new(),
            in_flight: 0,
            debounce,
            clock,
        }
    }

    /// The file changed. Start or extend its quiet period.
    ///
    /// Rewriting pushes the deadline out rather than queueing a second upload —
    /// ten saves become one, and the two uploads that used to collide on the way
    /// out never both exist.
    pub fn touch(&mut self, file: FileId) {
        let due = self.clock.now() + self.debounce;
        self.waiting.insert(file, Waiting { due });
    }

    /// The file was deleted. Drop any waiting edit rather than racing it.
    ///
    /// Returns whether there was one, which the caller needs in order to
    /// distinguish "cancelled a pending upload" from "nothing was queued".
    pub fn cancel(&mut self, file: &FileId) -> bool {
        self.waiting.remove(file).is_some()
    }

    /// Bring every deadline forward. Used at shutdown.
    ///
    /// An edit lives only on this machine until it uploads, so a restart inside
    /// the window would take that work with it. Draining first is not politeness,
    /// it is the difference between a delay and a loss.
    pub fn flush_now(&mut self) {
        let now = self.clock.now();
        for w in self.waiting.values_mut() {
            w.due = now;
        }
    }

    /// Files whose quiet period has expired.
    pub fn due(&self) -> Vec<FileId> {
        let now = self.clock.now();
        let mut due: Vec<FileId> = self
            .waiting
            .iter()
            .filter(|(_, w)| w.due <= now)
            .map(|(f, _)| *f)
            .collect();
        // Deterministic order, so a failure is reproducible.
        due.sort_by_key(|f| (f.fsid, f.ino));
        due
    }

    /// Everything not yet in the cloud: waiting *and* in flight.
    ///
    /// The one number the user is asked to trust. Counting only what has started
    /// would show "synced" over a fifteen-minute queue.
    pub fn pending(&self) -> usize {
        self.waiting.len() + self.in_flight
    }

    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// Run one upload, start to finish, applying rules 2 and 3.
    pub fn run_one<S: Sink>(&mut self, file: FileId, store: &mut Store, sink: &mut S) -> Outcome {
        self.waiting.remove(&file);
        self.in_flight += 1;
        let outcome = Self::send(file, store, sink);
        self.in_flight -= 1;
        outcome
    }

    fn send<S: Sink>(file: FileId, store: &mut Store, sink: &mut S) -> Outcome {
        // Rule 2: the name is resolved here, not when the job was queued. By now
        // an atomic save has already renamed the temp file into place, so this
        // is the name the file actually has.
        let Some(entry) = store.lookup(&file) else {
            // Rule 3, before anything was sent: the file is gone. Nothing to
            // upload, and nothing was created that needs removing.
            return Outcome::NothingToDo;
        };
        let path: PathBuf = entry.path.clone();
        let existing = entry.cloud_id.clone();

        let uploaded = match sink.upload(&path, existing.as_deref()) {
            Ok(u) => u,
            Err(e) => return Outcome::Failed(e.to_string()),
        };

        // Rule 3, after the bytes went out: the file was deleted while this was
        // in flight. Absence is a decision, not missing information — so the
        // object that has just come into existence in the cloud has to go.
        //
        // The bug this replaces read the same absence as "I have no fresh data"
        // and uploaded its stale in-memory copy anyway, which put a deleted file
        // back complete with its contents.
        if store.lookup(&file).is_none() {
            if let Err(e) = sink.remove(&uploaded.cloud_id) {
                return Outcome::Failed(format!(
                    "the file was deleted mid-upload and the remote copy could not \
                     be removed: {e}"
                ));
            }
            return Outcome::DeletedInstead;
        }

        // The identity never changed: this writes one attribute onto a file that
        // has had the same inode since it was created.
        if let Err(e) = store.adopt_cloud_id(&path, &uploaded.cloud_id, uploaded.etag.as_deref()) {
            return Outcome::Failed(format!("could not record the cloud id: {e}"));
        }
        Outcome::Sent {
            cloud_id: uploaded.cloud_id,
        }
    }
}

/// A [`Sink`] that keeps a client's `Provider` and its upload side together.
pub struct ProviderSink<P>(pub P);

impl<P: Provider + Sink> Sink for ProviderSink<P> {
    fn upload(&mut self, path: &std::path::Path, existing: Option<&str>) -> io::Result<Uploaded> {
        self.0.upload(path, existing)
    }
    fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
        self.0.remove(cloud_id)
    }
}

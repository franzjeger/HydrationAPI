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

/// What the framework already knows about the object a local file came from.
///
/// Two facts, and a conditional write needs both: the id says *which* object,
/// the tag says *which version of it this edit is based on*. Passing only the
/// id — which is all this interface used to carry — left the provider with no
/// precondition to offer, so every update to an object that already existed was
/// refused rather than written blind. Measured on a live account: the tag was on
/// the file the whole time, in `user.hydration.etag`, read by `Store::lookup`
/// and then dropped at this boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Known<'a> {
    pub cloud_id: &'a str,
    /// The tag recorded for the version this edit is based on.
    ///
    /// `None` is a real state, not a gap: a file whose lineage was lost with an
    /// atomic save has no record of what it was based on, and a provider whose
    /// tags are not preconditions has nothing to offer either. What to do about
    /// it belongs to the provider, which is the half that knows what its service
    /// accepts.
    pub tag: Option<&'a str>,
}

/// How many times a repeated failure doubles its wait before the cap takes over.
const RETRY_DOUBLINGS: u32 = 8;

/// The longest a failing upload waits between attempts.
///
/// A conflict that needs a person is not resolved by asking sooner, and one that
/// resolves itself — a service having a bad minute, a lock that clears — does so
/// well inside this. The file stays visibly unsent the whole time, which is the
/// thing the user is actually owed.
const RETRY_CEILING: Duration = Duration::from_secs(900);

/// How long a file must go untouched before it is sent.
///
/// Rule 1 is what this exists for: an atomic save closes a temp file it is about
/// to rename away, a scratch file is written and deleted seconds later, and an
/// editor saving ten times would start ten uploads that collide. Waiting removes
/// all three at the source. Ten seconds covers a save burst — those are
/// milliseconds apart — and covers a large file arriving by copy, because every
/// write pushes the deadline out again and the timer only starts when the
/// writing stops.
///
/// It used to be fifteen minutes, with no reasoning written down anywhere,
/// because it was not a decision this project made: it was carried over from the
/// FUSE client this replaces, where it was working around that design's own
/// problems. Inheriting a number along with the code that needed it is how a
/// constant outlives its argument.
///
/// What it cost is not subtle. Measured on a live account on 2026-08-13: a
/// six-byte file created in the sync folder had not reached the cloud a quarter
/// of an hour later, and its owner concluded uploads did not work — which was a
/// fair reading of the evidence, and was not what was wrong.
///
/// The price of the shorter window is real and small: an editor that autosaves
/// every minute now produces an upload a minute instead of one every fifteen.
/// That is what a sync client is for. The window that is too long does not save
/// traffic, it only delays it, and it delays the one thing the user is watching
/// for.
pub const QUIET_PERIOD: Duration = Duration::from_secs(10);

/// Uploading and deleting, the half only the client knows how to do.
pub trait Sink: Send {
    /// Send this file's current content. `existing` is what the framework knows
    /// about the object already, so the client can make the write conditional.
    ///
    /// Takes a path resolved *now*, not a name captured when the job was queued.
    fn upload(
        &mut self,
        path: &std::path::Path,
        existing: Option<Known<'_>>,
    ) -> io::Result<Uploaded>;

    /// Move or rename an existing cloud object to match its local path.
    ///
    /// This is a distinct operation from uploading content. An implementation
    /// which addresses an update by object id can successfully send the bytes
    /// while leaving the object under its old name forever; the next delta pass
    /// then moves the local file back. Keeping the operation explicit prevents
    /// a content-only sink from presenting that loop as successful sync.
    fn move_item(
        &mut self,
        _from: &std::path::Path,
        _to: &std::path::Path,
        _existing: Known<'_>,
    ) -> io::Result<Uploaded> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this cloud provider cannot move or rename objects",
        ))
    }

    /// Create a cloud folder for a directory created locally.
    ///
    /// Without this operation an empty directory can never sync, so a sink
    /// with only file upload and delete is not a complete two-way contract.
    fn create_folder(&mut self, _path: &std::path::Path) -> io::Result<Uploaded> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this cloud provider cannot create folders",
        ))
    }

    /// Remove a folder after the provider has proved that doing so is not an
    /// implicit recursive delete.
    ///
    /// Kept separate from [`Sink::remove_known`]: deleting a file removes one
    /// object, while deleting a non-empty folder removes an unbounded subtree.
    /// A provider must require the recorded identity and metadata version,
    /// check its service-specific empty-folder condition, and bind the delete
    /// to the version observed by that check.
    fn remove_folder(&mut self, _existing: Known<'_>) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this cloud provider cannot safely remove folders",
        ))
    }

    /// Remove an object whose identity and base version are both known.
    ///
    /// The default preserves the older id-only contract for providers which do
    /// not support conditional deletion. Providers with a usable version token
    /// should override this and refuse a stale delete rather than erasing work
    /// from another device.
    fn remove_known(&mut self, existing: Known<'_>) -> io::Result<()> {
        self.remove(existing.cloud_id)
    }

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
    /// Uploads that have started. Counted as unsent, because they are — and
    /// named rather than counted, because eviction has to be able to ask
    /// *which* file is being sent, not just how many.
    in_flight: std::collections::HashSet<FileId>,
    debounce: Duration,
    /// Consecutive failures per file, for the backoff. Not in `waiting`: that
    /// entry is removed by `begin` before the attempt whose outcome sets this.
    failures: HashMap<FileId, u32>,
    clock: C,
}

impl<C: Clock> Queue<C> {
    pub fn new(debounce: Duration, clock: C) -> Self {
        Self {
            waiting: HashMap::new(),
            failures: HashMap::new(),
            in_flight: std::collections::HashSet::new(),
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
        // A real edit clears the failure history: whatever the last attempt
        // could not send, this is different content, and it deserves the
        // ordinary quiet period rather than the penalty the old bytes earned.
        self.failures.remove(&file);
        self.waiting.insert(file, Waiting { due });
    }

    /// Send failed. Come back later, and later again if it keeps failing.
    ///
    /// A failure has to be re-queued — `begin` took the file out, and without
    /// this it is simply gone until the next resync walk, which on a stable
    /// system is days. But re-queuing it at the quiet period's cadence means a
    /// file that *cannot* be sent is attempted every ten seconds forever, which
    /// is a denial of service aimed at the user's own tenant and the surest way
    /// to be throttled.
    ///
    /// Doubling from the quiet period, capped. The cap matters more than the
    /// curve: a conflict that needs a person is not resolved by asking sooner,
    /// and one that resolves itself does so within minutes.
    pub fn failed(&mut self, file: FileId) {
        // Held outside `waiting`, because `begin` removes that entry before the
        // attempt runs and the outcome is only known afterwards. Keeping the
        // count there meant it reset on every attempt and the wait never grew,
        // which is the storm this exists to stop, wearing a fix.
        let failures = self.failures.entry(file).or_insert(0);
        *failures = failures.saturating_add(1);
        let failures = *failures;
        let backoff = self
            .debounce
            .saturating_mul(1u32 << failures.min(RETRY_DOUBLINGS))
            .min(RETRY_CEILING);
        let due = self.clock.now() + backoff;
        self.waiting.insert(file, Waiting { due });
    }

    /// The file went out. Forget what the old bytes could not do.
    pub fn sent(&mut self, file: FileId) {
        self.failures.remove(&file);
    }

    /// The file was deleted. Drop any waiting edit rather than racing it.
    ///
    /// Returns whether there was one, which the caller needs in order to
    /// distinguish "cancelled a pending upload" from "nothing was queued".
    pub fn cancel(&mut self, file: &FileId) -> bool {
        self.failures.remove(file);
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
        self.waiting.len() + self.in_flight.len()
    }

    /// Whether this file has an edit that has not been sent.
    ///
    /// Consulted by the delta pass: a waiting edit is newer than anything the
    /// cloud can say, and exists nowhere else.
    pub fn is_waiting(&self, file: &FileId) -> bool {
        self.waiting.contains_key(file)
    }

    pub fn waiting(&self) -> usize {
        self.waiting.len()
    }

    /// The files with an edit waiting, as of now.
    ///
    /// Exists so a delta pass can consult the queue without holding its lock.
    /// Holding it across the pass is worse than slow: the thread that receives
    /// change notifications blocks on the same lock, so no edit made *during*
    /// the pass can reach the queue — `is_waiting` becomes structurally false
    /// for exactly the edits most at risk of being overwritten by it.
    pub fn waiting_set(&self) -> std::collections::HashSet<FileId> {
        self.waiting.keys().copied().collect()
    }

    /// Whether this file is being sent right now.
    ///
    /// Eviction needs this as well as the waiting set: a file whose upload has
    /// already started is no longer *waiting*, and replacing it mid-transfer
    /// makes the delete-during-upload rule (§5.5) see the inode change and
    /// remove the object it had just created.
    pub fn sending_set(&self) -> std::collections::HashSet<FileId> {
        self.in_flight.clone()
    }

    /// Run one upload, start to finish, applying rules 2 and 3.
    pub fn run_one<S: Sink>(&mut self, file: FileId, store: &mut Store, sink: &mut S) -> Outcome {
        self.begin(file);
        let outcome = run_upload(file, store, sink);
        self.finish(file);
        outcome
    }

    /// Claim a due file for upload.
    ///
    /// Split out from [`Queue::run_one`] so a caller can hold the queue lock
    /// only long enough to claim the work, and not for the whole network round
    /// trip. Holding it across the upload would make every status query wait on
    /// the slowest transfer -- and the count is the one number the user is asked
    /// to trust, so it must not be the thing that stops responding.
    pub fn begin(&mut self, file: FileId) {
        self.waiting.remove(&file);
        self.in_flight.insert(file);
    }

    /// Release a claim taken by [`Queue::begin`].
    pub fn finish(&mut self, file: FileId) {
        self.in_flight.remove(&file);
    }
}

/// One upload, with rules 2 and 3 applied. See [`Queue::run_one`].
pub fn run_upload<S: Sink>(file: FileId, store: &mut Store, sink: &mut S) -> Outcome {
    {
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
        // Read from the file, not from anything this process happens to
        // remember. A provider's own memory of a tag only covers objects its
        // delta rounds have mentioned, and delta reports *changes* — so an
        // object that has not moved in the cloud since the daemon started is
        // never in it, and every update to a long-settled file was refused for
        // want of a precondition that was on disk the whole time.
        let based_on = entry.etag.clone();

        // Observed before the sink reads a byte, so the stamp written on success
        // can never describe content newer than what was sent.
        let sent_state = std::fs::metadata(&path).ok();

        let known = existing.as_deref().map(|cloud_id| Known {
            cloud_id,
            tag: based_on.as_deref(),
        });
        let uploaded = match sink.upload(&path, known) {
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
        // Renamed and deleted look identical from here, and they are not.
        //
        // `lookup` re-verifies the recorded path, so a file that moved during
        // the upload answers exactly like one that was removed. Treating both as
        // a deletion was survivable while only a user's `mv` could cause it; the
        // delta pass now renames files itself whenever an object moves in the
        // cloud, so the framework could reach here about its own rename and
        // delete the object it had just created — a real remote delete, which
        // every other device then applies.
        //
        // So it looks again, the same way the fetch path does before giving up.
        // A file found under a *different* name was renamed, and the object we
        // just created carries the wrong one — an atomic save is exactly this:
        // written as `x.tmp`, uploaded, renamed to `x` (§5.4). Sending it once
        // more under the name it now has is bounded, and it is the only answer
        // that leaves neither an orphaned object nor a wrongly named one.
        if store.lookup(&file).is_none() {
            if let Some(root) = store.root().map(|r| r.to_path_buf()) {
                let _ = store.scan(&root);
            }
            if let Some(moved) = store.lookup(&file) {
                if moved.path != path {
                    // Resent as a *create*, not as an update of the object we
                    // just made.
                    //
                    // Passing the existing id looks tidier and is wrong: to a
                    // provider that addresses an update by object id — Graph
                    // does — an update changes content and not the name, so the
                    // object keeps the temp name the create gave it. §5.4 says
                    // no upload succeeds under a name the file no longer has,
                    // and an atomic save is precisely this shape: written as
                    // `x.tmp`, uploaded, renamed to `x`. The reference provider
                    // happens to rename on update, which is why this only
                    // surfaced when a second one was written.
                    //
                    // Observed before the send, so an edit that lands during it
                    // leaves the file dirty and is sent again rather than being
                    // blessed as delivered.
                    let sent_state = std::fs::metadata(&moved.path).ok();
                    return match sink.upload(&moved.path, None) {
                        Ok(again) => {
                            // The object created under the old name is ours and
                            // holds nothing anyone wants. Removing it is the one
                            // deletion this path may issue, because it is the
                            // object this call created moments ago.
                            if again.cloud_id != uploaded.cloud_id {
                                if let Err(e) = sink.remove(&uploaded.cloud_id) {
                                    return Outcome::Failed(format!(
                                        "resent under the new name, but the object \
                                         created under the old one could not be \
                                         removed: {e}"
                                    ));
                                }
                            }
                            if let Err(e) = store.adopt_cloud_id(
                                &moved.path,
                                &again.cloud_id,
                                again.etag.as_deref(),
                            ) {
                                return Outcome::Failed(format!(
                                    "could not record the cloud id after a rename: {e}"
                                ));
                            }
                            if let Some(md) = &sent_state {
                                let _ = hydration_protocol::stamp::write_as(&moved.path, md);
                            }
                            Outcome::Sent {
                                cloud_id: again.cloud_id,
                            }
                        }
                        Err(e) => Outcome::Failed(format!(
                            "the file was renamed mid-upload and the resend failed: {e}"
                        )),
                    };
                }
            }
        }
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

        // The third moment the framework makes content clean, and the reason
        // this is not merely bookkeeping: without it, every file that has ever
        // been uploaded looks unstamped, and a resync walk would queue the whole
        // directory.
        //
        // Stamped from the state observed *before* the sink read the file, not
        // from the file as it is now. An upload takes time, and an edit that
        // landed during it is not covered by the bytes that went out — stamping
        // afterwards would bless that edit as sent, so it would never be
        // re-queued and the next remote change would destroy it. Stamping the
        // earlier state means the file simply reads as dirty and goes again,
        // which costs one redundant upload.
        if let Some(md) = &sent_state {
            let _ = hydration_protocol::stamp::write_as(&path, md);
        }

        Outcome::Sent {
            cloud_id: uploaded.cloud_id,
        }
    }
}

/// A [`Sink`] that keeps a client's `Provider` and its upload side together.
pub struct ProviderSink<P>(pub P);

impl<P: Provider + Sink> Sink for ProviderSink<P> {
    fn upload(
        &mut self,
        path: &std::path::Path,
        existing: Option<Known<'_>>,
    ) -> io::Result<Uploaded> {
        self.0.upload(path, existing)
    }
    fn move_item(
        &mut self,
        from: &std::path::Path,
        to: &std::path::Path,
        existing: Known<'_>,
    ) -> io::Result<Uploaded> {
        self.0.move_item(from, to, existing)
    }
    fn create_folder(&mut self, path: &std::path::Path) -> io::Result<Uploaded> {
        self.0.create_folder(path)
    }
    fn remove_known(&mut self, existing: Known<'_>) -> io::Result<()> {
        self.0.remove_known(existing)
    }
    fn remove_folder(&mut self, existing: Known<'_>) -> io::Result<()> {
        self.0.remove_folder(existing)
    }
    fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
        self.0.remove(cloud_id)
    }
}

//! The daemon's run loop, with the cloud left as a hole.
//!
//! Everything `hydration-sync` used to be, minus the one decision a client has
//! to make: which cloud. That arrives as a [`CloudAccess`], and the binary
//! becomes an argument parser that names one.
//!
//! # Why this end listens
//!
//! The socket direction is a security decision rather than a convenience.
//!
//! If the privileged helper accepted connections, any local process could
//! connect and impersonate the sync daemon — and the helper's whole job is to
//! write what it is told into the user's files. An impersonator would get to
//! choose the content of any placeholder.
//!
//! So the unprivileged side listens, on a socket only its owner can reach, and
//! the helper connects out and checks who it reached. The worst an impersonating
//! *listener* can do is serve content for files it already had access to.

use crate::delta::{self, Applied, Cursor, Discover};
use crate::evict_policy::{Clock, EvictionConfig, FreeSpace, RealClock, StatvfsSpace};
use crate::manifest::{BackupPolicy, Manifest};
use crate::place::TmpfilePlacer;
use crate::reclaim;
use crate::store::Store;
use crate::upload::{run_upload, Known, Outcome, Queue, Sink, SystemClock, Uploaded};
use crate::{Changes, Daemon, Provider};
use hydration_protocol::transport::DaemonConn;
use hydration_protocol::FileId;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Everything a client supplies, as one factory with three roles.
///
/// Three roles rather than one object because the daemon runs them on separate
/// threads: the fetch loop, the upload driver and the delta pass each get their
/// own instance and none of them shares a lock with the others. A provider whose
/// roles share state — a token cache, most obviously — must make that state
/// `Sync` and refresh it single-flight, because three instances *will* be alive
/// at once.
pub trait CloudAccess: Send + 'static {
    type Fetch: Provider;
    type Upload: Sink;
    type Changes: Discover;
    fn provider(&self) -> io::Result<Self::Fetch>;
    fn sink(&self) -> io::Result<Self::Upload>;
    fn discover(&self) -> io::Result<Self::Changes>;
    /// Checked once at startup so a missing credential is a startup failure
    /// rather than a surprise on the first read.
    fn preflight(&self) -> io::Result<()> {
        Ok(())
    }
}

/// What the daemon needs to know that is not about any particular cloud.
///
/// No cloud directory, no endpoint, no credential: those are the factory's
/// business, and a run loop that could name them would be a run loop only one
/// provider fits.
#[derive(Debug, Clone)]
pub struct Config {
    /// The sync directory.
    pub mount: PathBuf,
    /// Where the privileged helper connects in. The control socket is this path
    /// with its extension replaced by `.ctl`.
    pub socket: PathBuf,
    /// How long a file must sit still before it is sent.
    pub debounce: Duration,
    /// Auto-eviction policy, or `None` to leave it off — the default, byte-for-
    /// byte today's behaviour. When `Some`, a background thread dehydrates the
    /// least-recently-acquired unpinned files under disk pressure. Off unless the
    /// product turns it on, because auto-destroying local availability is a
    /// surprising default; the pin is the user's opt-out for a file it keeps.
    pub eviction: Option<crate::evict_policy::EvictionConfig>,
}

/// Hand out one role, without letting the factory itself become shared state.
///
/// The lock is held for exactly as long as it takes to build an instance and no
/// longer — the roles never see it. [`CloudAccess`] promises only `Send`, and a
/// mutex is what turns that into something three threads can each ask once.
fn role<C, T>(access: &Mutex<C>, make: impl FnOnce(&C) -> io::Result<T>) -> io::Result<T> {
    match access.lock() {
        Ok(a) => make(&a),
        // A thread died while building a role. Nothing else can be built from
        // this factory, and saying so beats blocking forever.
        Err(_) => Err(io::Error::other("the cloud access is poisoned")),
    }
}

/// Replace the local namespace watcher only after a complete watcher for the
/// path's current tree has been built.
///
/// A helper restart can detach and remount the sync root while this process
/// stays alive. Inotify watches belong to inodes, not path strings, so the old
/// watcher then remains perfectly valid while watching the hidden, detached
/// tree. Keeping it would make local renames and deletions disappear until the
/// next cloud delta restored the old namespace. Build first and swap second so
/// a transient failure leaves the previous (possibly still useful) watcher in
/// place rather than creating a wholly unwatched interval.
fn replace_removal_watch(
    root: &std::path::Path,
    watcher: &mut Option<crate::removals::Removals>,
) -> io::Result<usize> {
    let fresh = crate::removals::Removals::watch(root)?;
    let count = fresh.watched();
    *watcher = Some(fresh);
    Ok(count)
}

/// Local edits, from the helper into the upload queue.
///
/// Deliberately does almost nothing: this runs on the thread that answers
/// fetches, and a reader is blocked inside `read()` for every moment it spends
/// elsewhere. Touching the queue takes a lock the upload driver holds only for
/// bookkeeping, never across an upload.
struct QueueChanges {
    queue: Arc<Mutex<Queue<SystemClock>>>,
    resync: Arc<AtomicBool>,
    exposures: Arc<Mutex<Vec<String>>>,
}

impl Changes for QueueChanges {
    fn changed(&mut self, files: &[FileId]) {
        let Ok(mut q) = self.queue.lock() else { return };
        for f in files {
            q.touch(*f);
        }
    }

    fn exposed(&mut self, mounts: &[String]) {
        if let Ok(mut e) = self.exposures.lock() {
            *e = mounts.to_vec();
        }
    }

    fn resync(&mut self) {
        // The channel admitted it is incomplete. Walking is the only honest
        // recovery: the dropped events are gone, and nothing else will mention
        // those files again.
        self.resync.store(true, Ordering::SeqCst);
    }
}

/// What a resync walk found: what to send, and what it refused to.
///
/// Private, like the walk that returns it. The refusals travel out rather than
/// being printed in place so that the whole decision stays a function of the
/// directory and can be asserted on — the arm this replaces returned only the
/// files it queued, so what it wrongly queued was visible nowhere but in the
/// uploads that followed.
#[derive(Debug, Default, PartialEq, Eq)]
struct Resync {
    /// Files to queue for upload.
    send: Vec<FileId>,
    /// Placeholders that hold bytes. Never sent — see [`dirty_files`] — and
    /// carried out of the walk rather than dropped, because naming them is the
    /// only warning anyone gets before the helper discards them.
    holding: Vec<PathBuf>,
}

/// Everything in the sync directory the framework has not sent in its current
/// form.
///
/// Two kinds, and the second one took a review to see:
///
/// - **Dirty** — stamped, and no longer matching. An ordinary in-place edit that
///   nobody told us about.
/// - **Unstamped with content and no cloud id** — a file the framework has never
///   made clean. That covers a file the user simply created, and it also covers
///   the shape most editors actually use: write a temporary file, rename it over
///   the target. A rename replaces the inode, and the stamp lives on the inode,
///   so the replacement carries neither stamp nor cloud id. The event path
///   catches those; the resync walk exists precisely for when the event path
///   did not, and it was skipping the most common edit shape there is.
///
/// This does not queue the world, because everything the framework has placed,
/// hydrated or uploaded is stamped — so an unstamped file with content is, by
/// construction, one that has never been sent. It also retries uploads that
/// failed, which nothing else does.
///
/// # A placeholder is never unsent content, whatever its stamp says
///
/// The mark is checked once, above both kinds, because it is the same rule
/// twice and having it in only one arm was a bug. The `Unstamped` arm excluded
/// marked files from the start; the `Dirty` arm did not, and a placeholder is
/// `Dirty` in every state that matters:
///
/// - A transfer cut off mid-stream. The worker writes through the event fd and
///   settles what it wrote — `settle_range` for one range, `finish_hydration`
///   for the last of them; killed in between — which a machine-wide `pkill
///   hydrationd` did on a live mount on 2026-08-10 — it leaves a file that is
///   still marked, holds part of the object, and whose `pwrite` moved the mtime
///   out from under the placeholder's stamp.
/// - A transfer in progress right now, which looks identical from here.
/// - A punch of ours whose re-stamp failed. `dehydrate`, `evict` and `abandon`
///   all stamp with `let _ =`.
/// - `touch` on a placeholder: mtime moved, no content at all.
///
/// Queueing any of those calls `run_upload`, which resolves the path and reads
/// it — through the mount, which is the whole point. Every missing range fires
/// a pre-content event, the helper hydrates the entire object, and the upload
/// then sends the cloud a byte-identical copy of what it just served. A full
/// down-and-up cycle for a multi-gigabyte file, and a remote version bump every
/// other device has to apply.
///
/// # Why not send them, then, if a user's bytes might be in there
///
/// Because the upload path cannot carry them, and ranged fills did not change
/// that — they only changed which half of the argument does the work.
///
/// `run_upload` reads the file to send it, and that read is what the helper
/// answers. It asks `partial::Standing` first, and there are exactly two
/// answers. `Unknown` — no worker record vouches for what is on disk — punches
/// the file via `clear_residue` before a byte of it reaches the sink, so an edit
/// that reached a marked file unintercepted is destroyed by the read that was
/// meant to send it. `Ours` — the worker wrote those ranges itself and the file
/// has not moved since — keeps them, but they are the *cloud's* bytes by
/// construction, so there is nothing of the user's in them to rescue.
///
/// Either way the queue gains nothing and the read hydrates the rest of the
/// object. Note that `clear_residue` used to be unconditional and this argument
/// used to rest on that; ranged fills made a marked file holding bytes ordinary
/// (`daemon.rs`, the `Standing::Unknown` arm), and the conclusion survives the
/// premise being replaced.
///
/// Clearing the mark first is the one thing that would let those bytes out, and
/// it must never be done from here. A cut-off transfer holds a *prefix* of the
/// object with holes after it; unmarked, those holes read as legitimate zeros
/// and the upload writes them over the cloud object for every device. Nothing on
/// this side can tell that apart from a user's edit — which is exactly why
/// `clear_residue` does not try, and why `hydrationd`'s `looks_stripped` refuses
/// to install an ignore mark on a sized file occupying no disk. Guessing wrong
/// destroys the object; not guessing costs a log line.
///
/// So they are skipped, and the ones holding bytes are *named* — this walk is
/// the only thing that looks at every file, and after the next read the file is
/// quietly the cloud's copy again with nothing left to notice.
///
/// # Why `Clean` is the line, now that partial fills exist
///
/// The bytes question is asked with `holds_data` — `SEEK_DATA`, never
/// `st_blocks`, which reports the same count for an empty placeholder and a
/// filled one (§8z) — and it is asked only of a placeholder whose stamp already
/// disagrees. That gate began as an optimisation and is now the thing that keeps
/// the warning true.
///
/// It rested on "nothing in the framework writes into a marked file and
/// re-stamps it". `settle_range` does exactly that: it is how a ranged fill
/// records the part it has, and it stamps precisely so a resync walk does not
/// read the fill as the user's own edit. So a marked file that is `Clean` *and*
/// holds bytes is no longer impossible — it is the ordinary shape of a partially
/// hydrated file, and it is the framework's own content.
///
/// Warning about those would put a line in front of the user on every resync for
/// every file the helper is part-way through, which is how the line that matters
/// stops being read. `Clean` is what separates "the framework put these bytes
/// here and vouches for them" from "these bytes arrived some other way", and it
/// is the only signal on this side that does: `partial::Standing` lives in the
/// worker's memory and nothing on this side of the socket can consult it.
///
/// Measured before it was used (`probes/seekdata.c`, 7.1.6, btrfs and ext4):
/// `open` and `lseek(SEEK_DATA)` fire no pre-content event, while a `read` on
/// the same file fires one. Asking whether a placeholder holds bytes therefore
/// does not hydrate it — without which the diagnostic would be the harm.
fn dirty_files(root: &std::path::Path) -> io::Result<Resync> {
    use hydration_protocol::stamp::{self, State};
    use std::os::unix::fs::MetadataExt;

    let mut found = Resync::default();
    let ignore = crate::store::load_ignore(root);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)?.flatten() {
            let path = e.path();
            let Ok(md) = e.metadata() else { continue };
            // Sync-ignore: never queue a `.git/` file for resync — it is not
            // synced, and its constant churn would otherwise refill the queue.
            if path
                .strip_prefix(root)
                .is_ok_and(|rel| ignore.is_ignored(rel))
            {
                continue;
            }
            if md.is_dir() {
                stack.push(path);
                continue;
            }
            if !md.is_file()
                || path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(hydration_protocol::names::is_internal)
            {
                continue;
            }
            let state = stamp::state(&path);
            // Above both arms, not inside one. Neither kind may be a
            // placeholder, and a placeholder is `Dirty` far more often than it
            // is `Unstamped` — see this function's docs for what queueing one
            // costs and why sending it anyway does not save the bytes in it.
            if matches!(
                crate::store::get_xattr(&path, hydration_protocol::xattr::DEHYDRATED),
                Ok(Some(_))
            ) {
                // `unwrap_or(false)` says nothing rather than guessing. The
                // realistic error here is the file having been deleted between
                // `read_dir` and now, and a warning naming a file that no longer
                // exists is worse than no warning: §6c wants a log that is true
                // before it wants one that is complete.
                if !matches!(state, Ok(State::Clean))
                    && hydration_protocol::holds_data(&path).unwrap_or(false)
                {
                    found.holding.push(path);
                }
                continue;
            }
            let worth_sending = match state {
                Ok(State::Dirty) => true,
                Ok(State::Unstamped) => {
                    md.len() > 0
                        && !matches!(
                            crate::store::get_xattr(&path, crate::store::XATTR_ID),
                            Ok(Some(_))
                        )
                }
                _ => false,
            };
            if worth_sending {
                found.send.push(FileId {
                    fsid: md.dev(),
                    ino: md.ino(),
                });
            }
        }
    }
    Ok(found)
}

/// One `watch` line's worth of state: the three numbers a tray displays.
///
/// `PartialEq` *is* the contract's change test — a line goes out when this
/// tuple differs from the last one written to that connection, so equality here
/// is the definition of "nothing changed".
#[derive(Debug, Clone, PartialEq, Eq)]
struct WatchState {
    /// What [`Queue::pending`] returned: waiting and in flight.
    unsent: u64,
    /// The manifest's file count as of its last build — see [`control`] for why
    /// it is a stored number and not a fresh walk.
    excluded: u64,
    /// How many other mounts expose the sync files (§6.4a).
    exposures: u64,
    /// How many fetches are in flight right now — the count a tray shows as
    /// "downloading N". A live number, not a walk-derived one: it is the length
    /// of the set the fetch role is bumping, sampled each tick.
    downloading: u64,
    /// Whether a delta pass is applying right now — the tray's "indexing…". The
    /// `delta_busy` flag the pass raises around `apply_remembering`, sampled each
    /// tick; like `downloading` it is a live read off by at most one tick, which
    /// for a pass worth showing (a first sync, a large cloud change) is invisible,
    /// and a pass shorter than a tick was never going to be worth a line anyway.
    scanning: bool,
    /// The relative paths of uploads in flight right now — the tray's
    /// per-file "uploading" list. A live read, off by at most one tick, like
    /// `downloading`. Empty when nothing is being sent. Carried as a single
    /// whitespace-free token (each path escaped, paths joined by a space) so it
    /// is one value on the line rather than many.
    uploading: Vec<String>,
}

impl WatchState {
    /// The wire form, without the trailing newline.
    ///
    /// Key order is fixed and new keys may only ever be appended: a reader is
    /// told to ignore keys it does not recognise, and that promise is only
    /// worth having if the keys it does recognise stay where they were.
    /// `uploading` is the newest key, so it goes last: its value is a list of
    /// escaped paths, which is not `<u64>`, and a reader that predates it
    /// simply does not recognise the key and ignores it.
    fn line(&self) -> String {
        let uploading = self
            .uploading
            .iter()
            .map(|p| crate::wire::encode_path(p))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "unsent={} excluded={} exposures={} downloading={} scanning={} uploading={}",
            self.unsent,
            self.excluded,
            self.exposures,
            self.downloading,
            self.scanning as u8,
            uploading
        )
    }
}

/// The watch tuple as of this instant.
///
/// Each lock is taken for one length read and dropped before the next is
/// touched, and both are dropped before any socket sees a byte. The queue lock
/// in particular is the one the helper's change notifications take, and that
/// thread answers fetches — a reader would sit blocked inside `read()` for as
/// long as a status sample held it.
fn watch_state(
    queue: &Mutex<Queue<SystemClock>>,
    excluded: &AtomicU64,
    exposures: &Mutex<Vec<String>>,
    in_flight: &AtomicU64,
    scanning: bool,
    active_uploads: &Mutex<HashMap<FileId, String>>,
) -> WatchState {
    let unsent = queue.lock().unwrap().pending() as u64;
    let exposures = exposures.lock().unwrap().len() as u64;
    // Sorted, so the line is deterministic for a given set: the broadcast
    // compares whole lines, and a set that has not changed must not re-send
    // itself just because its insertion order moved.
    let mut uploading: Vec<String> = active_uploads.lock().unwrap().values().cloned().collect();
    uploading.sort();
    WatchState {
        unsent,
        excluded: excluded.load(Ordering::SeqCst),
        exposures,
        // Relaxed: a display counter with no ordering relationship to the other
        // fields, read a moment after the guards that move it, and off by at
        // most one in-flight fetch either way is invisible in a tray.
        downloading: in_flight.load(Ordering::Relaxed),
        // Passed in rather than read here: the one caller that samples it every
        // tick has `delta_busy` in scope, and the initial-connect caller has no
        // pass to report and hands `false` — corrected within a tick by the next
        // broadcast, the same freshness the other sampled fields carry.
        scanning,
        uploading,
    }
}

/// More live watchers than this and new ones are refused by closing them.
///
/// The registry has to be bounded because its entries outlive their moment on
/// the accept thread: a connect loop faster than the once-a-second cull could
/// otherwise walk the daemon into its fd limit, which is shared with the helper
/// connection and every hydration in flight. The legitimate population is a
/// tray and a D-Bus bridge; dozens is already generous.
const MAX_WATCHERS: usize = 32;

/// Every connection that asked to `watch`, and the last line each was told.
///
/// One registry served by one already-existing thread, rather than a thread per
/// connection. A watcher is long-lived *by design*, so the obvious
/// thread-per-connection shape hands anything that reconnects in a loop one
/// parked thread per attempt, and nothing on the accept side can tell that loop
/// from an enthusiastic tray. Here a reconnect costs one registry slot, dead
/// slots are reclaimed on every tick and every registration, and the daemon has
/// the same number of threads with thirty watchers as with none.
#[derive(Default)]
struct Watchers {
    conns: Mutex<Vec<Watcher>>,
}

struct Watcher {
    conn: UnixStream,
    last: WatchState,
}

/// Whether the peer end of this stream has gone away.
///
/// A zero-timeout poll asking for no events at all: `POLLHUP`, `POLLERR` and
/// `POLLNVAL` are reported whether or not they were requested, and they are the
/// only three of interest. `POLLIN` must *not* be in the mask — a watcher's
/// bytes are ignored rather than read, so "readable" means an unread buffer,
/// not a departure. Without this probe a watcher that disconnects during a
/// quiet stretch would sit in the registry forever: culling on write failure
/// alone needs the state to change first, and the normal state of a synced
/// drive is that it does not.
fn peer_gone(conn: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut p = libc::pollfd {
        fd: conn.as_raw_fd(),
        events: 0,
        revents: 0,
    };
    let rc = unsafe { libc::poll(&mut p, 1, 0) };
    rc > 0 && (p.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0
}

fn write_line(conn: &mut UnixStream, state: &WatchState) -> io::Result<()> {
    use std::io::Write;
    writeln!(conn, "{}", state.line())
}

impl Watchers {
    /// Take ownership of a connection whose peer asked to watch.
    ///
    /// The first state line is written here, synchronously, so that `watch` is
    /// answered immediately rather than on the next tick — the peer can read
    /// one line and then own nothing but a quiet socket. The state may move
    /// between this line and the registration becoming visible to a broadcast;
    /// that costs at most one extra line on the next tick, never a missed final
    /// state, because a broadcast compares against what each connection was
    /// actually told.
    fn adopt(&self, mut conn: UnixStream, state: WatchState) {
        let Ok(mut conns) = self.conns.lock() else {
            return;
        };
        // Reclaim before counting: the cap must measure live peers, not the
        // residue of a reconnect loop that already closed its last attempts.
        conns.retain(|w| !peer_gone(&w.conn));
        if conns.len() >= MAX_WATCHERS {
            // Dropping the stream closes it; EOF is the refusal. There is no
            // error line to send, because after `watch` the connection speaks
            // state lines and nothing else — a reader would have to parse the
            // apology as one.
            return;
        }
        // A watcher that stops draining must not park the thread every other
        // watcher's lines come from. The socket's send buffer absorbs
        // thousands of state lines before a write can block at all, so this
        // only ever fires on a peer that has plainly stopped reading — and
        // dropping it is then the answer, at worst costing the peer a torn
        // final line before the EOF that tells it to reconnect.
        let _ = conn.set_write_timeout(Some(Duration::from_secs(1)));
        // Write before taking ownership of `state`, so the move into the
        // registry entry is the last thing that touches it.
        if write_line(&mut conn, &state).is_ok() {
            conns.push(Watcher { conn, last: state });
        }
    }

    /// Tell every watcher whose last line differs, and drop the departed.
    ///
    /// An identical tuple is deliberately not re-sent: the verb exists so a
    /// tray can sleep instead of polling, and a repeated line is a wakeup that
    /// says nothing — the polling this replaces, moved one process over.
    fn broadcast(&self, state: WatchState) {
        let Ok(mut conns) = self.conns.lock() else {
            return;
        };
        conns.retain_mut(|w| {
            if peer_gone(&w.conn) {
                return false;
            }
            if w.last == state {
                return true;
            }
            if write_line(&mut w.conn, &state).is_err() {
                return false;
            }
            w.last = state.clone();
            true
        });
    }

    #[cfg(test)]
    fn live(&self) -> usize {
        self.conns.lock().unwrap().len()
    }
}

/// The user's own way in: a line-oriented socket only they can reach.
///
/// Eviction and status both have to be triggered by somebody, and the trigger
/// has to name a file. That is why §8 left it unwired — until placeholder
/// creation showed that turning a file back into a placeholder needs no
/// privilege at all, so the naming happens entirely on the unprivileged side and
/// §6b never comes into it.
///
/// It runs inside the daemon rather than as a separate command deliberately. A
/// standalone tool could evict a file the daemon is uploading right now, and the
/// upload's delete-during-upload rule would then see the inode change and remove
/// the object it had just created (§5.5). Only the process that owns the queue
/// can refuse that, so only it does the work.
///
/// Three verbs, one per line:
///
/// - `status` — one report per request, human-readable on purpose: it is what
///   `hydration-ctl status` shows a person, and its wording is not a machine
///   surface. Machines get `watch`.
/// - `evict <path>` — turn a file the cloud already holds back into a
///   placeholder.
/// - `pin <path>` / `unpin <path>` — keep a file or directory on device, so
///   eviction skips it (`pin`), or release it (`unpin`). A directory pin
///   protects everything under it. Both are pure `user.*` metadata writes: they
///   fire no pre-content event, need no privilege, and never reach the helper.
///   The reply is `pinned` / `unpinned`, or `error: <why>` for a path outside
///   the sync directory.
/// - `pending <dir>` — the dehydrated files under a directory, one relative
///   path per line (empty if none), for a caller about to hydrate each. Reads
///   no content: a directory walk and one `getxattr` per file, skipping the
///   framework's own names and not following symlinks.
/// - `watch` — one state line immediately, another every time the state
///   changes, and nothing else ever, until the peer disconnects. A state line
///   is `key=value` pairs joined by single spaces, newline-terminated,
///   currently `unsent=<u64> excluded=<u64> exposures=<u64> downloading=<u64> scanning=<0|1> uploading=<paths>`:
///   the upload queue's pending count, the manifest's file count as of its last
///   build, how many other mounts expose the sync files, how many fetches are in
///   flight right now, whether a delta pass is applying, and the relative paths
///   of uploads in flight right now (each escaped, space-joined, empty when
///   nothing is being sent). Keys stay in that order and new keys are only ever
///   appended, so a reader must ignore keys it does not recognise. An unchanged
///   tuple is never re-sent.
#[allow(clippy::too_many_arguments)]
fn control(
    socket: &std::path::Path,
    mount: PathBuf,
    queue: Arc<Mutex<Queue<SystemClock>>>,
    exposures: Arc<Mutex<Vec<String>>>,
    excluded: Arc<AtomicU64>,
    in_flight: Arc<AtomicU64>,
    active_uploads: Arc<Mutex<HashMap<FileId, String>>>,
    watchers: Arc<Watchers>,
) -> io::Result<()> {
    use std::io::{BufRead, BufReader, Write};

    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)?;
    // Owner-only. Everything reachable here the user could do by hand — these
    // are their files — so the socket is a convenience, not a privilege.
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))?;

    for conn in listener.incoming().flatten() {
        // A peer that connects and never speaks must not become the reason
        // nobody else can. Connections are handled on the accept thread, so
        // without this a single silent client parks the user's only status and
        // eviction channel indefinitely — and it is the channel they would
        // reach for to find out why nothing is responding.
        let _ = conn.set_read_timeout(Some(Duration::from_secs(10)));
        let reader = BufReader::new(match conn.try_clone() {
            Ok(c) => c,
            Err(_) => continue,
        });
        let mut out = conn;
        for line in reader.lines().map_while(Result::ok) {
            let (verb, arg) = line.trim().split_once(' ').unwrap_or((line.trim(), ""));
            let reply = match verb {
                "evict" => {
                    // The argument goes through unchanged. Trimming or joining
                    // it here would mean two places decide what a path means,
                    // and `reclaim` is the one that has to be right — it
                    // resolves through `safe_join` and then through the
                    // filesystem, so neither `..` nor a symlinked subdirectory
                    // can lead it out of the sync directory.
                    // Snapshotted, so the control socket never holds the queue
                    // across a directory walk.
                    let (waiting, sending) = {
                        let q = queue.lock().unwrap();
                        (q.waiting_set(), q.sending_set())
                    };
                    let mut store = Store::new();
                    let _ = store.scan(&mount);
                    match reclaim::reclaim(&mount, arg, &mut store, &waiting, &sending) {
                        Ok(Ok(r)) => format!("reclaimed {} bytes", r.bytes),
                        Ok(Err(why)) => format!("kept: {why:?}"),
                        Err(e) => format!("error: {e}"),
                    }
                }
                "pin" | "unpin" => {
                    // The same shape as evict — an untrusted path, confined by
                    // `reclaim::set_pin` through the same `safe_join` — but it
                    // touches no content: a pin is a `setxattr`/`removexattr`,
                    // which fires no pre-content event and needs no privilege, so
                    // nothing here crosses to the helper (§6b never comes into
                    // it). Unlike evict it accepts a directory, because a folder
                    // pin protects its subtree. A path that will not resolve
                    // inside the sync directory is an `error:` rather than a
                    // `kept:` — a pin keeps nothing back, it is a rejected
                    // request.
                    match reclaim::set_pin(&mount, arg, verb == "pin") {
                        Ok(Ok(())) => if verb == "pin" { "pinned" } else { "unpinned" }.to_string(),
                        Ok(Err(why)) => format!("error: {why:?}"),
                        Err(e) => format!("error: {e}"),
                    }
                }
                "pending" => {
                    // A content-free enumeration: the dehydrated files under a
                    // directory, one relative path per line, for a caller about
                    // to hydrate each in its own process — the reads must not
                    // happen here (§6a-ter). An empty list is a valid answer;
                    // `writeln!` below still sends a newline, so the client does
                    // not read the reply as dropped.
                    match reclaim::pending(&mount, arg) {
                        Ok(Ok(paths)) => paths.join("\n"),
                        Ok(Err(why)) => format!("error: {why:?}"),
                        Err(e) => format!("error: {e}"),
                    }
                }
                "status" => {
                    let pending = queue.lock().unwrap().pending();
                    let m = Manifest::build(&mount).unwrap_or_default();
                    // A fresh count was just paid for; publishing it costs
                    // nothing and spares watchers up to a whole status-thread
                    // period of staleness after an eviction.
                    excluded.store(m.len() as u64, Ordering::SeqCst);
                    let seen = exposures.lock().unwrap();
                    format!(
                        "{pending} unsent\n{}\n{}",
                        crate::manifest::status_line(BackupPolicy::Exclude, m.len()),
                        if seen.is_empty() {
                            "no other mount exposes these files".to_string()
                        } else {
                            format!(
                                "WARNING: {} other mount(s) bypass hydration: {seen:?}",
                                seen.len()
                            )
                        }
                    )
                }
                "watch" => {
                    // From here this connection is written to and never read —
                    // one state line now, another per change, nothing else —
                    // so it leaves the accept thread before the next
                    // `incoming()`. It joins a registry the status thread
                    // already serves once a second, rather than getting a
                    // thread of its own: a watcher is long-lived *by design*,
                    // so serving it here would park the user's only status and
                    // eviction channel for its whole lifetime — the exact
                    // condition the read timeout above exists to prevent,
                    // except that a watcher never times out on purpose — and
                    // thread-per-watcher would let a reconnect loop grow the
                    // daemon by one parked thread per attempt.
                    // `false`: this is the one-shot state a new watcher gets on
                    // connect, and control has no `delta_busy` in scope; the status
                    // thread's next tick corrects it if a pass is in fact running.
                    watchers.adopt(
                        out,
                        watch_state(
                            &queue,
                            &excluded,
                            &exposures,
                            &in_flight,
                            false,
                            &active_uploads,
                        ),
                    );
                    break;
                }
                "" => continue,
                other => format!("unknown command: {other}"),
            };
            if writeln!(out, "{reply}").is_err() {
                break;
            }
        }
    }
    Ok(())
}

/// One auto-eviction sweep: enumerate residents, plan under the current pressure,
/// and reclaim the plan — skipping anything the queue is uploading. Returns bytes
/// freed (a lower bound; `reclaim` measures each `st_blocks` delta).
///
/// The disk state (`available`/`total`), `now`, and the queue snapshot are read
/// by the caller and passed in, so this stays a testable unit: a test drives a
/// scratch mount, an explicit disk pressure, and an explicit `sending` set with
/// no thread, no statvfs, and no real clock. `reclaim` stays the sole authority —
/// a file that raced into the queue after the snapshot is still refused by its
/// live `UploadPending`/`ChangedSinceUpload` checks, which is why this loops
/// `reclaim` rather than trusting the enumerator's pre-filter.
fn plan_and_reclaim(
    mount: &std::path::Path,
    cfg: &EvictionConfig,
    available: u64,
    total: u64,
    now: u64,
    waiting: &HashSet<FileId>,
    sending: &HashSet<FileId>,
) -> io::Result<u64> {
    let (low, _) = cfg.marks(total);
    if available >= low {
        return Ok(0); // common path: no pressure, no walk beyond this.
    }
    let candidates = reclaim::evictable_candidates(mount)?;
    let plan = crate::evict_policy::plan(candidates, available, total, cfg, now);

    // One scanned Store reused across the batch — reclaim only uses it to forget
    // the swapped-out inode.
    let mut store = Store::new();
    let _ = store.scan(mount);

    let mut freed = 0u64;
    for rel in plan {
        // A refusal (raced upload, a fresh edit, a pin set mid-sweep) is a skip,
        // not a failure: the point of looping reclaim is that it re-checks.
        if let Ok(Ok(r)) = reclaim::reclaim(mount, &rel, &mut store, waiting, sending) {
            freed = freed.saturating_add(r.bytes);
        }
    }
    Ok(freed)
}

/// Run the daemon until the helper socket stops accepting.
///
/// Every thread below builds its own role from `access`. Nothing here knows what
/// a cloud is beyond the three traits, which is the whole point: swapping
/// `FolderCloud` for a real service changes this file not at all.
pub fn run<C: CloudAccess>(config: Config, access: C) -> io::Result<()> {
    // Before the credential, because this one costs nothing and the failure it
    // prevents is the worst one available.
    //
    // A sync root that is not its own mount can never be marked — §6.4a, a
    // directory mark delivers nothing — so every placeholder written into it is
    // a file that reads as zeros with no way to ever fix itself. Starting anyway
    // and materialising into the bare directory underneath a mount that has not
    // come up is not a corner case: it happened, and produced 145,711 files and
    // 102 GB of apparent size, all of it zero, indistinguishable from the real
    // thing to everything that read it.
    //
    // See `mount::is_mount_point` for why this is not an `st_dev` comparison.
    match crate::mount::is_mount_point(&config.mount) {
        Ok(true) => {}
        Ok(false) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is not a mount point; a sync root has to be its own mount \
                     or nothing can hydrate what is written into it, and every \
                     placeholder would read back as zeros",
                    config.mount.display()
                ),
            ))
        }
        Err(e) => {
            return Err(io::Error::new(
                e.kind(),
                format!(
                    "could not tell whether {} is a mount point ({e}); refusing \
                     rather than materialising into a directory that may not be one",
                    config.mount.display()
                ),
            ))
        }
    }

    // Asked once up front so a missing credential — or an unwritable cloud
    // directory — is a startup failure rather than a surprise on the first
    // fetch.
    access.preflight()?;

    // A crash between linking a new placeholder and renaming it over the old one
    // leaves a complete file under a scratch name. Nothing else would ever
    // remove it, and the user would see it in their sync folder forever.
    match TmpfilePlacer::sweep_scratch(&config.mount) {
        Ok(0) => {}
        Ok(n) => eprintln!("hydration-sync: swept {n} leftover scratch file(s)"),
        Err(e) => eprintln!("hydration-sync: could not sweep scratch files: {e}"),
    }
    let queue = Arc::new(Mutex::new(Queue::new(
        config.debounce,
        SystemClock::default(),
    )));
    let stop = Arc::new(AtomicBool::new(false));
    // Set when the helper says its change channel has a hole in it, so the
    // upload driver walks instead of trusting what it was told.
    let resync = Arc::new(AtomicBool::new(true));
    // Which helper incarnation currently owns the fanotify mark. A reconnect
    // may follow an ordinary socket restart, or it may follow the helper
    // detaching and remounting the sync root. The upload-side inotify watcher
    // cannot tell those cases apart and must be rebuilt for both: a watch on
    // the old vfsmount stays alive but sees none of the user's new namespace
    // operations.
    let helper_generation = Arc::new(AtomicU64::new(0));
    // Folder events produced by the delta applier are indistinguishable from
    // local mkdir/rename events at the inotify boundary. The upload side waits
    // until a whole delta batch has settled before deciding which directories
    // still have no cloud identity.
    let delta_busy = Arc::new(AtomicBool::new(false));
    let folder_refresh = Arc::new(AtomicBool::new(true));
    // Reported by the helper, shown by the status thread. §6.4a.
    let exposures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    // The manifest's file count as of its last build, for `watch`. A stored
    // number rather than a call, so telling a watcher the count never walks
    // the directory the manifest describes — the status thread walks it on its
    // own cadence anyway, and `status` refreshes the number for free whenever
    // it builds a manifest of its own.
    let excluded = Arc::new(AtomicU64::new(0));
    // Fetches in flight, shared between whichever Daemon currently holds the
    // helper connection (which bumps it) and the status thread (which reads it).
    // Created here, before either exists, so both see the same counter.
    let in_flight = Arc::new(AtomicU64::new(0));
    // The relative paths of uploads in flight right now, shared between the
    // upload driver (which adds a path when it claims a file and removes it
    // when the transfer ends) and the status thread (which reads it into the
    // watch line). Keyed by `FileId`, not by name, so a file that is re-queued
    // while a stale finish for its old inode lands cannot be removed by the
    // wrong event — the inode is the only address that is stable across a
    // rename, which is the same reason the queue itself is keyed by it.
    let active_uploads: Arc<Mutex<HashMap<FileId, String>>> = Arc::new(Mutex::new(HashMap::new()));
    // Everyone who asked to be told when the numbers above move.
    let watchers = Arc::new(Watchers::default());

    let _ = std::fs::remove_file(&config.socket);
    let listener = UnixListener::bind(&config.socket)?;
    // Owner-only. The helper checks the peer's uid from its side; this is the
    // half that stops anyone else reaching the content in the first place.
    std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o600))?;

    eprintln!(
        "hydration-sync: mount={} socket={} debounce={}s",
        config.mount.display(),
        config.socket.display(),
        config.debounce.as_secs()
    );

    // Behind a lock only so three threads can each ask it for an instance. The
    // instances themselves never touch it again.
    let access = Arc::new(Mutex::new(access));

    // Deletions the user made while the daemon was stopped, found now — before
    // the delta and manifest threads rewrite the journal they are detected in —
    // and withdrawn by the upload thread below once it has a sink. The walk it
    // costs happens once, at startup, on the tree it was going to scan anyway.
    // See `detect_offline_removals` for why absence across a whole root is not
    // read as a deletion.
    let offline_deletions = detect_offline_removals(&config.mount);
    if !offline_deletions.is_empty() {
        eprintln!(
            "hydration-sync: {} file(s) were deleted while the daemon was stopped; \
             withdrawing them from the cloud",
            offline_deletions.len()
        );
    }

    // The upload driver keeps its own store: a held upload must never block a
    // status query behind a shared lock.
    {
        let (
            q,
            stop,
            mount,
            access,
            resync,
            helper_gen,
            delta_busy,
            folder_refresh,
            tracked,
            folder_retry,
            au,
        ) = (
            Arc::clone(&queue),
            Arc::clone(&stop),
            config.mount.clone(),
            Arc::clone(&access),
            Arc::clone(&resync),
            Arc::clone(&helper_generation),
            Arc::clone(&delta_busy),
            Arc::clone(&folder_refresh),
            // The placeholder count, an always-current proxy for the tree size,
            // so a removal batch is measured against the whole and a wrong root's
            // total disappearance can be told from a folder's partial one.
            Arc::clone(&excluded),
            std::cmp::max(config.debounce, Duration::from_secs(1)),
            Arc::clone(&active_uploads),
        );
        std::thread::spawn(move || {
            // Same reasoning as the delta thread below: a queue that grows and
            // never drains is visible in the status line, but the reason is not,
            // and the reason is here.
            let mut sink = match role(&access, C::sink) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "hydration-sync: could not start the upload sink: {e}; \
                         nothing will be sent"
                    );
                    return;
                }
            };
            // Heal the past before watching the future. These were deleted while
            // this daemon was not running, detected at startup while the journal
            // still had them (see `detect_offline_removals`). `sink.remove` is
            // idempotent — a 404 for an object already gone is not an error — so
            // a candidate that overlaps something the online path also catches
            // costs nothing.
            for (path, cloud_id) in &offline_deletions {
                match sink.remove(cloud_id) {
                    Ok(()) => eprintln!(
                        "hydration-sync: {path} was deleted while the daemon was stopped; \
                         removed from the cloud"
                    ),
                    Err(e) => eprintln!(
                        "hydration-sync: {path} was deleted while the daemon was stopped, but \
                         the cloud copy could not be removed: {e}. It will return as a \
                         placeholder and can be deleted again."
                    ),
                }
            }

            // Reads the lineage record, never writes it. This scan runs only when
            // something is already due, which for a file saved atomically is a
            // debounce after its extended attributes went away — far too late to
            // learn anything from the file. What it needs is what the delta
            // pass's scan wrote down while they were still there.
            let mut store = Store::new().consulting();

            // Removals ride with the uploads because this thread already owns
            // the sink, and a second thread holding it would put every deletion
            // behind whatever transfer is running. It is also the right place in
            // meaning: sending a change and withdrawing one are the same
            // conversation with the service.
            //
            // A failure to start watching is survivable and is not silent. What
            // it costs is that local deletions stop reaching the cloud, which is
            // a sync that is behind rather than one that destroys anything.
            // Bridges the gap between an upload settling and the delta pass
            // writing it down. Cleared wholesale rather than aged: every entry
            // is superseded within a delta round, so the only thing a precise
            // eviction policy would buy is a more interesting way to be wrong.
            let mut recent: std::collections::HashMap<String, String> =
                std::collections::HashMap::new();
            let mut folders_pending = BTreeSet::new();
            let mut folders_committed = BTreeMap::new();
            let mut renames_pending = Vec::new();
            let mut folders_gone_pending = Vec::new();
            let mut folders_seeded = false;
            let mut next_folder_retry = std::time::Instant::now();
            // Capture the generation *before* the walk. On the live 26k-folder
            // tree the helper replaced the mount while this walk was in flight;
            // loading afterwards would have labelled that mixed, stale watcher
            // as current and no later reconnect would repair it.
            let mut watched_helper = helper_gen.load(Ordering::SeqCst);
            let mut next_watch_retry = std::time::Instant::now();
            let mut removals = match crate::removals::Removals::watch(&mount) {
                Ok(w) => {
                    eprintln!(
                        "hydration-sync: watching {} directories for deletions",
                        w.watched()
                    );
                    Some(w)
                }
                Err(e) => {
                    eprintln!(
                        "hydration-sync: cannot watch for deletions ({e}); files deleted \
                         here will stay in the cloud"
                    );
                    None
                }
            };
            while !stop.load(Ordering::SeqCst) {
                // Close the holes in the change channel by looking, rather than
                // by trusting that nothing was missed.
                //
                // Set at startup, whenever the helper reconnects, and whenever
                // it reports an overflow — three states in which edits happened
                // that produced no event anyone will ever see. The walk costs a
                // stat per file, and this thread already walks the tree before
                // every batch.
                if resync.swap(false, Ordering::SeqCst) {
                    match dirty_files(&mount) {
                        Ok(found) => {
                            if !found.send.is_empty() {
                                eprintln!(
                                    "hydration-sync: resync found {} file(s) changed with \
                                     no event",
                                    found.send.len()
                                );
                                let mut queue = q.lock().unwrap();
                                for f in found.send {
                                    queue.touch(f);
                                }
                            }
                            // Not a log detail, for the same reason §6.4a's
                            // exposure warning is not: these files hold bytes
                            // the framework will not send and the helper will
                            // discard, and after the next read there is nothing
                            // left to notice. This line is the only moment
                            // anyone can act on them.
                            if !found.holding.is_empty() {
                                eprintln!(
                                    "hydration-sync: WARNING — {} dehydrated file(s) hold \
                                     bytes and were not queued for upload:",
                                    found.holding.len()
                                );
                                for p in &found.holding {
                                    eprintln!("hydration-sync:   {}", p.display());
                                }
                                // No advice to copy the bytes out, because
                                // there is none to give: copying is a read,
                                // and the read is what punches them. Saying
                                // otherwise would be a diagnostic invented to
                                // round the sentence off, which is the one
                                // thing a log here may not do.
                                eprintln!(
                                    "hydration-sync:   A dehydrated file's content is the \
                                     cloud's to supply, so the framework never sends it: \
                                     reading one in order to upload it hydrates the whole \
                                     object and sends the cloud its own bytes back. Bytes \
                                     found in one are a transfer in progress, a transfer \
                                     that was cut off, or a write that reached the file \
                                     while nothing was intercepting — indistinguishable \
                                     from here, and the helper punches all three on the \
                                     next read and refetches the cloud's copy. Any read \
                                     of these files, including one taken to copy them \
                                     elsewhere, is that read."
                                );
                            }
                        }
                        Err(e) => eprintln!("hydration-sync: resync walk failed: {e}"),
                    }
                    if !delta_busy.load(Ordering::SeqCst) {
                        match unidentified_folders(&mount) {
                            Ok(found) => folders_pending.extend(found),
                            Err(e) => eprintln!("hydration-sync: folder resync walk failed: {e}"),
                        }
                    }
                }

                if !folders_seeded
                    && !delta_busy.load(Ordering::SeqCst)
                    && has_cloud_identity(&mount)
                {
                    match unidentified_folders(&mount) {
                        Ok(found) => {
                            folders_pending.extend(found);
                            folders_seeded = true;
                        }
                        Err(e) => eprintln!("hydration-sync: folder startup walk failed: {e}"),
                    }
                }

                let due = q.lock().unwrap().due();
                if !due.is_empty() {
                    let _ = store.scan(&mount);
                }
                for file in due {
                    q.lock().unwrap().begin(file);
                    // Captured before the send, because afterwards the file may
                    // already be gone — which is precisely the case this is for.
                    let sent_path = store
                        .lookup(&file)
                        .and_then(|e| crate::lineage::relative(&mount, &e.path));
                    // The tray's per-file "uploading" list: the path is present
                    // for the whole transfer and gone once it settles. A file
                    // that is gone by the time we resolve it is not listed —
                    // there is nothing to show for it either way.
                    if let Some(rel) = &sent_path {
                        au.lock().unwrap().insert(file, rel.clone());
                    }
                    let outcome = run_upload(file, &mut store, &mut sink);
                    // What this thread just created, so a file deleted before the
                    // delta pass next scans can still be withdrawn.
                    //
                    // Measured 2026-08-13: a file uploaded and deleted sixteen
                    // seconds later resolved to nothing, because the lineage
                    // record is written by the delta scan and that runs every
                    // thirty. The upload driver knew the object it had just made
                    // and told nobody.
                    if let (Outcome::Sent { cloud_id }, Some(rel)) = (&outcome, &sent_path) {
                        if recent.len() >= RECENT_SENDS {
                            recent.clear();
                        }
                        recent.insert(rel.clone(), cloud_id.clone());
                    }
                    {
                        let mut queue = q.lock().unwrap();
                        queue.finish(file);
                        // The transfer is over, so the tray's list loses it.
                        au.lock().unwrap().remove(&file);
                        // A failure has to go back in the queue.
                        //
                        // `begin` takes the file out and `finish` releases the
                        // claim; without this, a failed upload is simply gone —
                        // the resync walk would find it again, but that runs only
                        // at startup, on a helper reconnect, or after an event
                        // overflow, which on a stable system is days. An initial
                        // sync meeting a service that throttles would park most
                        // of its queue on the first refusal and not notice.
                        if matches!(outcome, Outcome::Failed(_)) {
                            queue.failed(file);
                        } else {
                            queue.sent(file);
                        }
                    }
                    eprintln!("hydration-sync: upload {file:?} -> {outcome:?}");
                }

                if let Some(w) = &mut removals {
                    if !delta_busy.load(Ordering::SeqCst)
                        && folder_refresh.swap(false, Ordering::SeqCst)
                    {
                        w.refresh_folders();
                    }
                    let local = w.take();
                    if w.lost_events() {
                        // Missed removals leave objects in the cloud the user
                        // deleted here. Behind, never destructive — but the user
                        // is entitled to know their deletion did not land.
                        eprintln!(
                            "hydration-sync: the deletion watch overflowed; some files \
                             deleted here will stay in the cloud until they are deleted \
                             again"
                        );
                        resync.store(true, Ordering::SeqCst);
                    }
                    folders_pending.extend(local.folders_created);
                    renames_pending.extend(local.renamed);
                    folders_gone_pending.extend(local.folders_gone);
                    if !local.gone.is_empty() {
                        let known = tracked.load(Ordering::SeqCst) as usize;
                        apply_removals(&mount, &local.gone, &recent, known, &mut sink);
                    }
                }
                let connected_helper = helper_gen.load(Ordering::SeqCst);
                if connected_helper != watched_helper
                    && std::time::Instant::now() >= next_watch_retry
                {
                    match replace_removal_watch(&mount, &mut removals) {
                        Ok(count) => {
                            eprintln!(
                                "hydration-sync: rebuilt the deletion/rename watch after helper \
                                 connection; watching {count} directories"
                            );
                            watched_helper = connected_helper;
                            // Folder identities captured by the old watcher name
                            // the old tree. The fresh walk recorded the current
                            // tree's identities, so no separate refresh is needed.
                            folder_refresh.store(false, Ordering::SeqCst);
                        }
                        Err(e) => {
                            eprintln!(
                                "hydration-sync: could not rebuild the deletion/rename watch \
                                 after helper connection ({e}); local namespace changes may stay \
                                 in the cloud until the retry"
                            );
                            // Keep the generation outstanding so a transient
                            // walk failure heals without requiring another
                            // helper restart, but bound both work and logs.
                            next_watch_retry =
                                std::time::Instant::now() + std::time::Duration::from_secs(5);
                        }
                    }
                }
                if !delta_busy.load(Ordering::SeqCst) {
                    if !renames_pending.is_empty() {
                        apply_renames(&mount, &renames_pending, &mut sink);
                        renames_pending.clear();
                    }
                    if !folders_gone_pending.is_empty() {
                        let known = tracked.load(Ordering::SeqCst) as usize;
                        apply_folder_removals(&mount, &folders_gone_pending, known, &mut sink);
                        folders_gone_pending.clear();
                    }
                    if !folders_pending.is_empty() && std::time::Instant::now() >= next_folder_retry
                    {
                        let created = apply_folder_creates(
                            &mount,
                            &mut folders_pending,
                            &mut folders_committed,
                            &mut sink,
                        );
                        if let Some(w) = &mut removals {
                            for (rel, uploaded) in created {
                                w.remember_folder(
                                    &rel,
                                    &uploaded.cloud_id,
                                    uploaded.etag.as_deref(),
                                );
                            }
                        }
                        next_folder_retry = std::time::Instant::now() + folder_retry;
                    }
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
    }

    // Bringing changes down. Separate from the upload driver on purpose: a held
    // upload must not delay a delta pass, and a delta pass must not sit on the
    // queue lock while it walks the sync directory.
    //
    // The placer builds each placeholder on an anonymous inode and links it in
    // complete, so nothing here needs the privileged helper — see `place.rs`.
    // The privileged half is never sent a destination, which is what makes §6b
    // structural rather than a rule someone has to remember.
    {
        let (q, stop, mount, access, delta_busy, folder_refresh) = (
            Arc::clone(&queue),
            Arc::clone(&stop),
            config.mount.clone(),
            Arc::clone(&access),
            Arc::clone(&delta_busy),
            Arc::clone(&folder_refresh),
        );
        std::thread::spawn(move || {
            // Leaving quietly here is indistinguishable, from outside, from a
            // drive with nothing on it: the status thread keeps printing "0
            // unsent", no placeholder ever appears, and the state directory
            // stays empty. The only thread that could have said why is the one
            // that just died. A live Graph account produced exactly that.
            let mut cloud = match role(&access, C::discover) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!(
                        "hydration-sync: could not start the delta feed: {e}; \
                         no delta pass will run"
                    );
                    return;
                }
            };
            // Opened when the mount is confirmed, dropped when it goes away, and
            // opened again only when a mount is back. Not once for the life of
            // the thread: the placer pins the root it was opened on, so one that
            // outlived its mount would keep writing into a filesystem nobody can
            // reach — safe, and pointless. `None` means "no mount right now",
            // which is the same state the thread starts in.
            let mut placer: Option<TmpfilePlacer> = None;
            // What the last completed pass was applied to. A round whose batch
            // and whose tree are both unchanged would do exactly nothing, and
            // this is how it finds that out for the price of the walk it was
            // going to do anyway.
            let mut applied_to: Option<delta::Fingerprint> = None;
            // The maintaining side. `delta::apply` scans every round, which is
            // the only regular walk this daemon does, and it happens while files
            // still carry their own identity — so it is the one place that can
            // write down what an atomic save is about to destroy.
            let mut store = Store::new().remembering();
            // Forced on the first turn, so the record exists from startup rather
            // than five minutes into it.
            let mut walked = std::time::Instant::now() - WALK_EVERY;
            let mut cursor = Cursor::default();
            // Set when a pass deliberately left something for a later one.
            //
            // Without it the *next* pass undoes the decision: a delta feed with
            // nothing new returns an empty batch, and the empty-batch arm below
            // advanced the cursor unconditionally — so the refusal that was
            // held back on purpose was consumed by silence, and the service
            // never mentions those objects again.
            let mut unfinished = false;
            // Said once, not once a round: a mount that is gone stays gone until
            // someone acts, and five seconds of the same line is a log nobody
            // reads any of.
            let mut complained = false;
            while !stop.load(Ordering::SeqCst) {
                // Two questions, and they are not the same one.
                //
                // "Is there a mount here at all" is what `is_mount_point`
                // answers, and it is the right question exactly once per
                // incarnation: a sync root that is a plain directory can never
                // be marked (§6.4a), so opening a placer on one would be
                // arranging the original failure. It cannot answer the other
                // question — a mount that was detached and replaced is still *a*
                // mount — which is why it is asked here, where a new placer is
                // about to be opened, and not inside the pass.
                //
                // "Is it still the mount we started on" is the placer's own, via
                // the unique mount id it captured at open time, and `apply` asks
                // it per change. See `place.rs` for why that one cannot be
                // carried by a path check.
                if placer.is_none() {
                    let opened = match crate::mount::is_mount_point(&mount) {
                        Ok(true) => TmpfilePlacer::new(&mount).map_err(|e| {
                            format!("could not open the sync root {} ({e})", mount.display())
                        }),
                        Ok(false) => Err(format!(
                            "{} is not a mount point — nothing will be applied until it \
                             is back, because placeholders written into the bare \
                             directory would read as zeros",
                            mount.display()
                        )),
                        Err(e) => Err(format!(
                            "cannot tell whether {} is a mount point ({e}) — holding off \
                             rather than writing into a directory that may not be one",
                            mount.display()
                        )),
                    };
                    match opened {
                        Ok(p) => {
                            if complained {
                                eprintln!(
                                    "hydration-sync: {} is a mount again; resuming",
                                    mount.display()
                                );
                            }
                            complained = false;
                            placer = Some(p);
                        }
                        Err(why) => {
                            if !complained {
                                complained = true;
                                eprintln!("hydration-sync: {why}");
                            }
                            std::thread::sleep(Duration::from_secs(5));
                            continue;
                        }
                    }
                }
                let Some(placer_ref) = placer.as_mut() else {
                    unreachable!("a placer was just opened or the round was skipped")
                };
                match cloud.changes(&cursor) {
                    Ok((changes, next)) if !changes.is_empty() => {
                        // Snapshotted, then released — not held across the pass.
                        //
                        // The lock is the same one the change-notification
                        // thread takes, so holding it here would stop any edit
                        // made during the pass from ever reaching the queue,
                        // and `apply` would then find those exact files
                        // unprotected. The snapshot can go stale, which is what
                        // the stamp check inside `apply` is for.
                        let waiting = q.lock().unwrap().waiting_set();
                        delta_busy.store(true, Ordering::SeqCst);
                        let applied = delta::apply_remembering(
                            &mount,
                            &changes,
                            &mut store,
                            &waiting,
                            placer_ref,
                            &mut applied_to,
                        );
                        folder_refresh.store(true, Ordering::SeqCst);
                        delta_busy.store(false, Ordering::SeqCst);
                        // The cursor moves only past a pass that finished.
                        //
                        // A delta service does not replay a consumed change, so
                        // advancing past a pass that refused something means the
                        // refusal is permanent however transient its cause —
                        // two objects swapping paths refuse each other on one
                        // pass and would succeed on the next, if there were one.
                        // A pass that stopped because the mount went away is not
                        // an incident. `hydrationd` detaches it on purpose when
                        // it fails closed, so this is the client meeting a
                        // deliberate act — reported plainly, with the counts of
                        // what did land, and then the placer is dropped so the
                        // next round has to find a mount before it opens
                        // another. Cursor stays put: what was not applied has
                        // not been seen.
                        let lost_the_mount = matches!(&applied, Ok(a) if a.stopped.is_some());
                        if let Ok(a) = &applied {
                            if let Some(why) = &a.stopped {
                                eprintln!(
                                    "hydration-sync: delta pass stopped after {} of {} \
                                     changes: {why}; not advancing",
                                    a.created + a.updated + a.removed,
                                    changes.len()
                                );
                            }
                        }
                        match &applied {
                            Ok(a) if a.retryable => {
                                unfinished = true;
                                // Already explained above when it was the mount;
                                // saying it twice in different words reads as two
                                // separate problems.
                                if !lost_the_mount {
                                    eprintln!(
                                        "hydration-sync: delta pass incomplete ({} \
                                         deferred); not advancing",
                                        a.failed.len()
                                    );
                                }
                            }
                            Ok(_) => {
                                unfinished = false;
                                cursor = next;
                            }
                            Err(_) => unfinished = true,
                        }
                        if lost_the_mount {
                            placer = None;
                        }
                        match applied {
                            Ok(a) if a != Applied::default() => {
                                eprintln!(
                                    "hydration-sync: delta +{} ~{} -{} moved {} \
                                     kept-local {} failed {}",
                                    a.created,
                                    a.updated,
                                    a.removed,
                                    a.moved,
                                    a.kept_local.len(),
                                    a.failed.len()
                                );
                                // Not a log line among log lines: these are the
                                // changes the framework deliberately refused to
                                // apply because local work would have been lost,
                                // and they are what a conflict UI is for.
                                for k in &a.kept_local {
                                    eprintln!(
                                        "hydration-sync:   kept local copy of {}: {}",
                                        k.path, k.why
                                    );
                                }
                                // With the cause, because without it these lines
                                // are indistinguishable from each other: a
                                // permission error on the sync root and a path
                                // the cloud was never allowed to name printed
                                // the same sentence, and the difference had to
                                // be found by bisecting the daemon.
                                for f in &a.failed {
                                    eprintln!(
                                        "hydration-sync:   could not apply {}: {}",
                                        f.path, f.why
                                    );
                                }
                            }
                            Ok(_) => {}
                            Err(e) => eprintln!("hydration-sync: delta pass failed: {e}"),
                        }
                    }
                    // Nothing new. Only meaningful if the last pass finished:
                    // silence must not be read as permission to move past work
                    // that was deliberately deferred.
                    Ok((_, next)) if !unfinished => cursor = next,
                    Ok(_) => {}
                    Err(e) => eprintln!("hydration-sync: could not list the cloud: {e}"),
                }
                // The lineage record is written by this store's scan, and
                // `delta::apply` no longer scans on a round that has nothing to
                // apply. So the walk gets a cadence of its own: often enough
                // that a file's identity is written down well before an atomic
                // save can destroy it, and rare enough that a quiet tree of
                // 167,890 files costs nothing to keep quiet.
                //
                // Five seconds of polling and five minutes of walking are
                // different jobs and were only ever the same number by accident.
                if walked.elapsed() >= WALK_EVERY {
                    if let Err(e) = store.scan(&mount) {
                        eprintln!("hydration-sync: could not walk the sync root: {e}");
                    }
                    walked = std::time::Instant::now();
                }
                std::thread::sleep(POLL_EVERY);
            }
        });
    }

    // The user's way in. §8 item 10's trigger, and the status surface item 11
    // asked for.
    {
        let ctl = config.socket.with_extension("ctl");
        let (mount, q, ex, exc, inf, au, ws) = (
            config.mount.clone(),
            Arc::clone(&queue),
            Arc::clone(&exposures),
            Arc::clone(&excluded),
            Arc::clone(&in_flight),
            Arc::clone(&active_uploads),
            Arc::clone(&watchers),
        );
        eprintln!("hydration-sync: control socket at {}", ctl.display());
        std::thread::spawn(move || {
            if let Err(e) = control(&ctl, mount, q, ex, exc, inf, au, ws) {
                eprintln!("hydration-sync: control socket unavailable: {e}");
            }
        });
    }

    // Auto-eviction, only when the product turned it on. The thread does not even
    // exist while the policy is off, so an "off" daemon never wakes to sample a
    // disk it will never act on — "off" is off, not merely idle.
    if let Some(evict_cfg) = config.eviction {
        let (mount, stop, delta_busy, queue) = (
            config.mount.clone(),
            Arc::clone(&stop),
            Arc::clone(&delta_busy),
            Arc::clone(&queue),
        );
        std::thread::spawn(move || {
            let free = StatvfsSpace {
                mount: mount.clone(),
            };
            let clock = RealClock;
            let interval = evict_cfg.min_interval_secs.max(1);
            while !stop.load(Ordering::SeqCst) {
                // The interval in one-second slices, so `stop` is prompt.
                for _ in 0..interval {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
                // Never fight a delta pass materialising placeholders over the
                // same tree, exactly as the upload thread gates its writes.
                if delta_busy.load(Ordering::SeqCst) {
                    continue;
                }
                // Cheap unless something is happening: one `statvfs`, and only
                // below the low mark do we walk and evict. P1 measured `f_bavail`
                // coarse and lagging a delete until the commit, so the sweep sizes
                // its batch by `reclaim`'s block-accurate bytes and this re-read
                // only re-arms the trigger on the next tick.
                let (Ok(available), Ok(total)) = (free.available(), free.total()) else {
                    continue;
                };
                let (low, _) = evict_cfg.marks(total);
                if available >= low {
                    continue;
                }
                // Snapshot the queue as the evict verb does — lock only long
                // enough to copy the two sets, never across the walk.
                let (waiting, sending) = {
                    let q = queue.lock().unwrap();
                    (q.waiting_set(), q.sending_set())
                };
                match plan_and_reclaim(
                    &mount,
                    &evict_cfg,
                    available,
                    total,
                    clock.now_secs(),
                    &waiting,
                    &sending,
                ) {
                    Ok(freed) if freed > 0 => {
                        eprintln!("hydration-sync: auto-eviction freed {freed} bytes")
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("hydration-sync: auto-eviction sweep failed: {e}"),
                }
            }
        });
    }

    // Status, the manifest that makes a backup honest — and the `watch`
    // broadcasts, which ride this thread rather than getting one of their own.
    {
        let (q, stop, mount, exposures, excluded, in_flight, delta_busy, au, watchers) = (
            Arc::clone(&queue),
            Arc::clone(&stop),
            config.mount.clone(),
            Arc::clone(&exposures),
            Arc::clone(&excluded),
            Arc::clone(&in_flight),
            Arc::clone(&delta_busy),
            Arc::clone(&active_uploads),
            Arc::clone(&watchers),
        );
        std::thread::spawn(move || {
            // The walk keeps its thirty-second cadence; only the sleep is
            // sliced finer. Watchers are told on a one-second sample, not per
            // change notification, because two of the three numbers they are
            // told are only ever as fresh as somebody's walk or sample anyway:
            // notifying per change would mean either a directory walk per
            // event — a stat storm under a burst of saves — or a line about a
            // count that has not been recomputed. Sampling the cheap two (a
            // queue length under its mutex, a vector length) and reusing this
            // thread's walk for the third puts a tray within a second of the
            // number that actually moves, for one extra wakeup a second in a
            // process whose upload driver already wakes five times a second.
            // Once every five minutes, not once every thirty seconds.
            //
            // `manifest::refresh` walks the whole sync root reading extended
            // attributes, then renders and writes the result. On the measured
            // account that is 167,890 files and a 43 MB file, and at the old
            // cadence it was the single most expensive thing this daemon did:
            // one thread pinned at essentially a full core, permanently, on a
            // tree where nothing was changing. Measured 2026-08-13 — 99 seconds
            // of CPU in 120 seconds of wall clock, all of it here.
            //
            // The manifest exists for §6d: it tells someone restoring a backup
            // which files were not in it. Backups run daily. Nothing about that
            // wants a thirty-second refresh, and the count it also feeds to the
            // tray moves when the user's files move, which is not every half
            // minute either.
            //
            // The right fix is one walk shared with the delta pass's, instead of
            // two threads walking the same tree on different clocks. That is a
            // larger change than this, and this is the one that stops the
            // machine getting warm.
            const TICKS_PER_MANIFEST: u32 = 300;
            let mut tick = 0;
            while !stop.load(Ordering::SeqCst) {
                if tick == 0 {
                    if let Ok(m) = Manifest::build(&mount) {
                        let _ = m.write(&mount);
                        // The count `watch` hands out, from the walk that was
                        // happening regardless.
                        excluded.store(m.len() as u64, Ordering::SeqCst);
                        // §6d: the count goes where "everything synced" goes, not
                        // into a log file nobody opens. This is a daemon, so the log
                        // is what it has — a UI would show the same sentence.
                        eprintln!(
                            "hydration-sync: {} unsent, {}",
                            q.lock().unwrap().pending(),
                            crate::manifest::status_line(BackupPolicy::Exclude, m.len())
                        );
                        // §6.4a. Not a log detail: another mount over the same files
                        // bypasses hydration entirely, and anything reading through
                        // it gets the zeros a placeholder is made of. The framework
                        // cannot prevent it, so the one thing it owes the user is
                        // that it never happens quietly.
                        let seen = exposures.lock().unwrap();
                        if !seen.is_empty() {
                            eprintln!(
                                "hydration-sync: WARNING — {} other mount(s) expose these files \
                                 and bypass hydration: {:?}",
                                seen.len(),
                                *seen
                            );
                        }
                    }
                }
                tick = (tick + 1) % TICKS_PER_MANIFEST;
                watchers.broadcast(watch_state(
                    &q,
                    &excluded,
                    &exposures,
                    &in_flight,
                    delta_busy.load(Ordering::SeqCst),
                    &au,
                ));
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }

    for conn in listener.incoming() {
        let conn = conn?;
        // One helper at a time. A second connection means something unexpected
        // is talking to us, and serving both would be worse than serving
        // neither.
        //
        // A fresh fetch role per connection, because a fresh `Daemon` per
        // connection is what re-scans the sync directory — the helper may have
        // been restarted, and the index it had is a snapshot of a moment that
        // has passed.
        let provider = role(&access, C::provider)?;
        match Daemon::new(provider, &config.mount) {
            Ok(mut daemon) => {
                eprintln!("hydration-sync: helper connected");
                // Every new connection is a resync point. The helper may have
                // been restarted, and anything edited while it was gone produced
                // no event at all.
                helper_generation.fetch_add(1, Ordering::SeqCst);
                resync.store(true, Ordering::SeqCst);
                daemon.on_change(Box::new(QueueChanges {
                    queue: Arc::clone(&queue),
                    resync: Arc::clone(&resync),
                    exposures: Arc::clone(&exposures),
                }));
                // Bump the shared counter, so this connection's fetches show up
                // in the same "downloading" number the status thread broadcasts.
                daemon.track_fetches(Arc::clone(&in_flight));
                let mut c = DaemonConn::new(conn)?;
                if let Err(e) = daemon.serve(&mut c) {
                    eprintln!("hydration-sync: helper connection ended: {e}");
                } else {
                    eprintln!("hydration-sync: helper disconnected");
                }
            }
            Err(_) => eprintln!("hydration-sync: could not open the cloud directory"),
        }
    }
    Ok(())
}

/// The most removals one batch may carry out before it stops and asks.
///
/// The catastrophic shape — an unmounted or rebuilt sync root read as "the user
/// deleted everything" — cannot arise here at all, and that is the point of
/// watching for events rather than inferring from absence: an unmounted root
/// produces no events, because its watches went with it.
///
/// What is left is an ordinary `rm -rf` of a large folder, which is a real thing
/// a user may mean. So this is a pause, not a refusal on principle: the batch is
/// declined, it is said plainly what would have been removed, and the files stay
/// in the cloud. The floor matters as much as any ratio would — a hundred
/// removals is a folder, and a folder is exactly the thing somebody deletes on
/// purpose.
/// How often the cloud is asked whether anything changed.
///
/// Every round costs a reconciliation of the whole batch against the tree, and
/// the batch is the whole listing — PROVIDER.md:103 requires a provider's quiet
/// round to carry it rather than be `(vec![], new_cursor)`, because that shape
/// once consumed a refusal that had been deliberately held back. So the price of
/// a round is set by the drive's size, not by how much changed, and the only
/// lever left is how often it is paid.
///
/// Five seconds was never argued for anywhere. Measured on a live account on
/// 2026-08-13, on 167,890 files, it cost 40% of a core in perpetuity to keep
/// asking a quiet drive the same question. Thirty seconds is what the walk
/// beside it already used, is well inside what anyone notices for a change made
/// on another device, and costs a sixth as much.
///
/// A change made *here* does not wait for this: local edits are seen by the
/// helper's watch and uploaded on their own quiet period, and local deletions by
/// the inotify watch in `crate::removals`. This interval only bounds how stale
/// the *other* direction can be.
const POLL_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

/// How often the sync root is walked when the cloud reports nothing.
///
/// The walk is what keeps the lineage record current — see `crate::lineage` for
/// what that costs to be without — and it is the most expensive thing this
/// daemon does: a stat and two extended attributes per file, 167,890 of them on
/// the measured account. It used to happen on every delta round, eight seconds
/// apart, and cost 48% of a core in perpetuity.
///
/// Five minutes bounds that to something unmeasurable while leaving the record
/// far fresher than the failure it guards against needs: a file has to be
/// uploaded and then saved atomically inside one window to slip through, and
/// even then the content reconciliation in the Graph sink recovers it.
const WALK_EVERY: std::time::Duration = std::time::Duration::from_secs(300);

/// The floor on how many objects one batch may withdraw from the cloud before
/// it is refused and the user asked, whatever the size of the tree.
///
/// The ratio below is the part that matters for trees; the floor only keeps a
/// small account able to delete a handful without a fight.
const REMOVAL_FLOOR: usize = 64;

/// A batch larger than a tree's-worth over this is refused.
///
/// `known / 10`, so a tenth of the tree. This is `guard_blast_radius`'s shape,
/// deliberately, because it defends the same thing from the other side: a wrong
/// or rebuilt root makes *everything* "gone", and everything is far more than a
/// tenth, so it is refused — while a real folder, thousands of files that are
/// still a small fraction of a large account, is let through. The flat cap this
/// replaces refused a folder of more than a hundred files outright, so a
/// non-empty tree could not be deleted at all on any account big enough to have
/// one.
const REMOVAL_RATIO: usize = 10;

/// The most one removal batch may withdraw, given the tree it is part of.
///
/// A whole-root disappearance is above it and a contained subtree is below it,
/// which is the one distinction the flat cap could not make. See
/// [`REMOVAL_FLOOR`] and [`REMOVAL_RATIO`], and `guard_blast_radius`, whose
/// shape this is.
fn removal_ceiling(known: usize) -> usize {
    std::cmp::max(REMOVAL_FLOOR, known / REMOVAL_RATIO)
}

/// How many just-sent objects the upload driver remembers for the removal path.
///
/// Only has to outlive one delta round, after which the lineage record carries
/// the same fact durably. Generous enough that an initial sync's worth of sends
/// does not evict the one file the user is about to delete.
const RECENT_SENDS: usize = 4096;

/// What the framework knows about the object that used to be at a path.
///
/// Two registers, because the framework keeps the two halves of its tree in
/// different places: `.hydration-lineage` records files that hold content, and
/// §6d's manifest records the ones that do not. A deleted placeholder is the
/// commonest deletion there is — it is how somebody clears out files they never
/// opened — so covering only the first would be covering the rarer half.
struct Registers {
    lineage: crate::lineage::Lineage,
    /// Parsed from the manifest on first miss and kept until it changes. It is
    /// tens of megabytes on a large account, so it is not re-read per batch, and
    /// it is not read at all unless a deletion actually needs it.
    manifest: Option<(
        std::time::SystemTime,
        std::collections::HashMap<String, crate::lineage::Record>,
    )>,
}

impl Registers {
    fn load(root: &std::path::Path) -> Self {
        Self {
            lineage: crate::lineage::Lineage::load(root),
            manifest: None,
        }
    }

    fn record(&mut self, root: &std::path::Path, rel: &str) -> Option<crate::lineage::Record> {
        if let Some(r) = self.lineage.get(rel) {
            return Some(r.clone());
        }
        self.manifest(root)?.get(rel).cloned()
    }

    fn manifest(
        &mut self,
        root: &std::path::Path,
    ) -> Option<&std::collections::HashMap<String, crate::lineage::Record>> {
        let path = root.join(hydration_protocol::names::MANIFEST);
        let stamp = std::fs::metadata(&path).ok()?.modified().ok()?;
        let stale = self.manifest.as_ref().is_none_or(|(at, _)| *at != stamp);
        if stale {
            let raw = std::fs::read_to_string(&path).ok()?;
            let mut by_path = std::collections::HashMap::new();
            for line in raw.lines() {
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                let mut f = line.split('\t');
                if let (Some(p), Some(id), Some(_size), Some(tag)) =
                    (f.next(), f.next(), f.next(), f.next())
                {
                    if !p.is_empty() && !id.is_empty() {
                        by_path.insert(
                            p.to_string(),
                            crate::lineage::Record {
                                cloud_id: id.to_string(),
                                tag: (tag != "-").then(|| tag.to_string()),
                            },
                        );
                    }
                }
            }
            self.manifest = Some((stamp, by_path));
        }
        self.manifest.as_ref().map(|(_, m)| m)
    }
}

/// Deletions made while the daemon was not running.
///
/// The inotify watch in `removals` sees only what happens while it is open. A
/// file deleted while the daemon was stopped is invisible to it: at the next
/// start the file is simply absent, and absence alone is the one signal the
/// whole removal design refuses to act on — a file is absent because the user
/// deleted it, because the delta pass has not placed it, or because the sync
/// root is empty, unmounted, or wrong, and acting on the last of those empties
/// the account.
///
/// So this does not act on absence. It acts on the *difference* between what the
/// framework wrote down as present and what is present now. The record is the
/// persistent presence journal — the manifest (placeholders) and the lineage
/// (hydrated files) together, both keyed by path and carrying a cloud id.
///
/// Both live inside the sync root, and that co-location is the safety. A rebuilt
/// or empty or wrong root carries neither file, so the journal is empty and the
/// difference is nothing. The catastrophic shape — every file "missing" because
/// the subvolume did not mount — cannot arise, for the same reason
/// `empty_mount_never_deletes` holds: the record of what was here is gone with
/// the files it described. The mount check in [`run`] is a second line, refusing
/// to start at all when the root is not a mount.
///
/// Run once, synchronously, before any thread starts: the first delta scan and
/// the first manifest write both rewrite the journal within seconds, and this
/// has to read what the *last* run left. The result is carried into the upload
/// thread, which owns the sink and withdraws each object once it is built.
///
/// Two guards beyond the co-location:
///   * an object still on disk under a *different* path moved rather than
///     vanished, and is not withdrawn — an offline `mv` inside the root;
///   * a disappearance larger than [`removal_ceiling`] of the journal is refused
///     whole and said out loud. The ceiling is proportional — a tenth of the
///     tree, floored — so a deleted folder, thousands of files that are still a
///     small fraction of a large account, is withdrawn, while a wrong or
///     unmounted root, where *everything* is gone, is not. A flat cap could not
///     tell those apart, and so a non-empty folder could not be deleted offline
///     at all on any account big enough to have one.
fn detect_offline_removals(root: &std::path::Path) -> Vec<(String, String)> {
    // The presence journal, both halves, co-located in the sync root.
    let mut journal: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for (path, (cloud_id, _tag)) in crate::manifest::entries(root) {
        journal.insert(path, cloud_id);
    }
    for (path, record) in crate::lineage::Lineage::load(root).entries() {
        journal.insert(path.to_string(), record.cloud_id.clone());
    }
    // SAFETY-CRITICAL — the sync-ignore transition. Last run's journal was
    // written before the ignore was switched on, so it still records every
    // `.git/` path the old client uploaded (measured: 1,292 of them carry a
    // recoverable cloud id). Without this line, the first start after the switch
    // reads them all as offline deletions — the scan no longer records ignored
    // paths, so they look "gone" — and, being under the removal ceiling, silently
    // withdraws 1,292 real objects from the cloud. Dropping them from the journal
    // here makes an ignored path unable to be a withdrawal candidate at all,
    // whatever the present-scan sees. Going forward the lineage self-cleans
    // (ignored paths stop being scanned/recorded); this covers the one-time
    // read of a journal that predates the switch.
    let ignore = crate::store::load_ignore(root);
    journal.retain(|path, _| !ignore.is_ignored(std::path::Path::new(path)));
    if journal.is_empty() {
        return Vec::new();
    }
    // The tree the disappearance is measured against — the whole of what the
    // last run recorded. A deleted folder is a fraction of it; a wrong root is
    // all of it.
    let known = journal.len();

    // What is here now, and which objects sit on any path, so an offline move is
    // not read as a deletion.
    let (present, on_disk) = scan_present(root);

    let mut gone: Vec<(String, String)> = journal
        .into_iter()
        .filter(|(path, _)| !present.contains(path))
        .filter(|(_, cloud_id)| !on_disk.contains(cloud_id))
        .collect();
    gone.sort();

    let ceiling = removal_ceiling(known);
    if gone.len() > ceiling {
        eprintln!(
            "hydration-sync: {} of {known} files recorded here are gone since the daemon last \
             ran — more than the {ceiling} it will withdraw from the cloud without being asked, \
             which is the shape of a wrong or unmounted root rather than a deleted folder. \
             Nothing was removed; they are still in the cloud and will return as placeholders. \
             If you deleted them on purpose, delete them again with the daemon running. First \
             few: {}",
            gone.len(),
            gone.iter()
                .take(5)
                .map(|(p, _)| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return Vec::new();
    }
    gone
}

/// Walk the sync root once: which relative paths hold a file, and which cloud
/// ids sit on any of them. Framework files are skipped, as everywhere.
fn scan_present(
    root: &std::path::Path,
) -> (
    std::collections::HashSet<String>,
    std::collections::HashSet<String>,
) {
    let mut present = std::collections::HashSet::new();
    let mut on_disk = std::collections::HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(md) = entry.metadata() else {
                continue;
            };
            if md.is_dir() {
                stack.push(path);
                continue;
            }
            if !md.is_file()
                || path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(hydration_protocol::names::is_internal)
            {
                continue;
            }
            if let Some(rel) = crate::lineage::relative(root, &path) {
                present.insert(rel);
            }
            if let Ok(Some(bytes)) = crate::store::get_xattr(&path, crate::store::XATTR_ID) {
                if let Ok(id) = String::from_utf8(bytes) {
                    on_disk.insert(id);
                }
            }
        }
    }
    (present, on_disk)
}

#[derive(Debug)]
struct CommittedFolder {
    uploaded: Uploaded,
    dev: u64,
    ino: u64,
}

fn has_cloud_identity(path: &std::path::Path) -> bool {
    matches!(
        crate::store::get_xattr(path, crate::store::XATTR_ID),
        Ok(Some(raw)) if !raw.is_empty()
    )
}

/// Find directories which are not yet attached to a cloud object.
///
/// This is the recovery path for daemon restarts and inotify overflow. The
/// caller processes the returned paths shallowest-first, because a child can
/// only be created after its parent has a stable identity.
fn unidentified_folders(root: &std::path::Path) -> io::Result<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    let ignore = crate::store::load_ignore(root);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if !kind.is_dir() {
                continue;
            }
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(hydration_protocol::names::is_internal)
            {
                continue;
            }
            // Sync-ignore: skip the whole subtree, before pushing or queueing it.
            // This closes a real upload-side leak: a `.git` dir has leaf `.git`
            // (is_internal false), so without this it is descended and every
            // `.git/refs/...` is queued as a cloud folder-create.
            if path
                .strip_prefix(root)
                .is_ok_and(|rel| ignore.is_ignored(rel))
            {
                continue;
            }
            stack.push(path.clone());
            if has_cloud_identity(&path) {
                continue;
            }
            if let Ok(rel) = path.strip_prefix(root) {
                if let Some(rel) = rel.to_str() {
                    found.insert(rel.to_string());
                }
            }
        }
    }
    Ok(found)
}

/// Create pending local directories without ever retrying a Graph create that
/// has already committed. If recording the returned identity fails, the
/// committed result stays in memory and only the local xattr write is retried.
fn apply_folder_creates<S: Sink>(
    root: &std::path::Path,
    pending: &mut BTreeSet<String>,
    committed: &mut BTreeMap<String, CommittedFolder>,
    sink: &mut S,
) -> Vec<(String, Uploaded)> {
    use std::os::unix::fs::MetadataExt;

    let mut recorded = Vec::new();
    let ignore = crate::store::load_ignore(root);
    let mut paths: Vec<_> = pending.iter().cloned().collect();
    paths.sort_by_key(|path| (path.matches('/').count(), path.clone()));
    for rel in paths {
        // Sync-ignore: never create an ignored folder in the cloud.
        // unidentified_folders already prunes these before they reach `pending`;
        // this is belt-and-braces, and it drops the stale entry so it does not
        // sit in `pending` forever.
        if ignore.is_ignored(std::path::Path::new(&rel)) {
            pending.remove(&rel);
            committed.remove(&rel);
            continue;
        }
        let path = root.join(&rel);
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            pending.remove(&rel);
            committed.remove(&rel);
            continue;
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            pending.remove(&rel);
            committed.remove(&rel);
            continue;
        }
        if has_cloud_identity(&path) {
            pending.remove(&rel);
            committed.remove(&rel);
            continue;
        }

        if let Some(done) = committed.get(&rel) {
            if metadata.dev() != done.dev || metadata.ino() != done.ino {
                let known = Known {
                    cloud_id: &done.uploaded.cloud_id,
                    tag: done.uploaded.etag.as_deref(),
                };
                match sink.remove_known(known) {
                    Ok(()) => {
                        committed.remove(&rel);
                    }
                    Err(e) => eprintln!(
                        "hydration-sync: folder {rel} changed inode after its cloud create; \
                         could not conditionally withdraw the orphaned object: {e}"
                    ),
                }
                continue;
            }
            let mut store = Store::new();
            match store.adopt_cloud_id(
                &path,
                &done.uploaded.cloud_id,
                done.uploaded.etag.as_deref(),
            ) {
                Ok(()) => {
                    recorded.push((rel.clone(), done.uploaded.clone()));
                    pending.remove(&rel);
                    committed.remove(&rel);
                }
                Err(e) => eprintln!(
                    "hydration-sync: created folder {rel} in the cloud, but could not record \
                     its returned identity locally; recording will be retried: {e}"
                ),
            }
            continue;
        }

        let Some(parent) = path.parent() else {
            pending.remove(&rel);
            continue;
        };
        if !has_cloud_identity(parent) {
            continue;
        }
        match sink.create_folder(&path) {
            Ok(uploaded) => {
                committed.insert(
                    rel.clone(),
                    CommittedFolder {
                        uploaded,
                        dev: metadata.dev(),
                        ino: metadata.ino(),
                    },
                );
                // Recording is intentionally a separate step through the
                // committed arm, so a failed xattr write can never repeat the
                // already-successful remote create.
                let Some(done) = committed.get(&rel) else {
                    continue;
                };
                let mut store = Store::new();
                match store.adopt_cloud_id(
                    &path,
                    &done.uploaded.cloud_id,
                    done.uploaded.etag.as_deref(),
                ) {
                    Ok(()) => {
                        eprintln!("hydration-sync: created folder {rel} in the cloud");
                        recorded.push((rel.clone(), done.uploaded.clone()));
                        pending.remove(&rel);
                        committed.remove(&rel);
                    }
                    Err(e) => eprintln!(
                        "hydration-sync: created folder {rel} in the cloud, but could not record \
                         its returned identity locally; recording will be retried: {e}"
                    ),
                }
            }
            Err(e) => eprintln!(
                "hydration-sync: local folder {rel} could not be created in the cloud; \
                 it remains queued: {e}"
            ),
        }
    }
    recorded
}

/// Carry a local identity-preserving rename to the cloud.
///
/// A genuine filesystem rename keeps the inode and its cloud xattrs. An atomic
/// save does not: the temporary inode takes the destination name without the
/// replaced object's identity. That distinction lets this avoid both failure
/// modes — moving a cloud object for an editor's scratch name, and uploading
/// content successfully while leaving a real rename under its old cloud name.
fn apply_renames<S: Sink>(
    root: &std::path::Path,
    renamed: &[crate::removals::Renamed],
    sink: &mut S,
) {
    let ignore = crate::store::load_ignore(root);
    for item in renamed {
        let internal = |path: &str| {
            std::path::Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(hydration_protocol::names::is_internal)
        };
        // Sync-ignore beside is_internal: a rename touching an ignored path is
        // not carried to the cloud — a `.git/` file renamed under its own repo
        // is not a namespace move the cloud should hear about.
        if internal(&item.from)
            || internal(&item.to)
            || ignore.is_ignored(std::path::Path::new(&item.from))
            || ignore.is_ignored(std::path::Path::new(&item.to))
        {
            continue;
        }

        let target = root.join(&item.to);
        let Some(cloud_id) = crate::store::get_xattr(&target, crate::store::XATTR_ID)
            .ok()
            .flatten()
            .and_then(|raw| String::from_utf8(raw).ok())
        else {
            // This is normally an atomic save. Its content path uses the
            // lineage record to update the existing object conditionally; it
            // is not a namespace move from the temporary name.
            eprintln!(
                "hydration-sync: {} became {} without carrying a cloud identity; \
                 treating it as replacement content, not a cloud rename",
                item.from, item.to
            );
            continue;
        };
        let tag = crate::store::get_xattr(&target, crate::store::XATTR_ETAG)
            .ok()
            .flatten()
            .and_then(|raw| String::from_utf8(raw).ok());
        let known = Known {
            cloud_id: &cloud_id,
            tag: tag.as_deref(),
        };
        match sink.move_item(&root.join(&item.from), &target, known) {
            Ok(uploaded) => {
                let mut store = Store::new();
                match store.adopt_cloud_id(&target, &uploaded.cloud_id, uploaded.etag.as_deref()) {
                    Ok(()) => eprintln!(
                        "hydration-sync: renamed {} to {} in the cloud",
                        item.from, item.to
                    ),
                    Err(e) => eprintln!(
                        "hydration-sync: renamed {} to {} in the cloud, but could not record \
                         the returned identity on the local object: {e}",
                        item.from, item.to
                    ),
                }
            }
            Err(e) => eprintln!(
                "hydration-sync: {} became {}, but the cloud object could not be renamed: \
                 {e}. The next delta pass may restore the cloud name locally.",
                item.from, item.to
            ),
        }
    }
}

/// Withdraw from the cloud the files that went away here.
///
/// Called only with names the kernel reported as removed — never with an
/// absence. `removals` explains at length why that distinction is the whole
/// design and not a nicety.
fn apply_removals<S: Sink>(
    root: &std::path::Path,
    gone: &[crate::removals::Gone],
    recent: &std::collections::HashMap<String, String>,
    known: usize,
    sink: &mut S,
) {
    let ceiling = removal_ceiling(known);
    if gone.len() > ceiling {
        eprintln!(
            "hydration-sync: {} files were deleted here at once, which is more than the \
             {ceiling} this will remove from the cloud without being asked (a tenth of the \
             {known} it is tracking). Nothing was removed; the files are still in the cloud \
             and will come back on the next delta pass. First few: {}",
            gone.len(),
            gone.iter()
                .take(5)
                .map(|g| g.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return;
    }

    let mut registers = Registers::load(root);
    let ignore = crate::store::load_ignore(root);
    for g in gone {
        // Sync-ignore: a local `rm -rf .git` must not withdraw the cloud copies.
        // An ignored path that was uploaded once still has a recoverable cloud
        // id (measured: nearly all of them do), so without this the deletion
        // would delete the cloud object. Ignore is prospective and sync-only —
        // it leaves what is already in the cloud alone.
        if ignore.is_ignored(std::path::Path::new(&g.path)) {
            continue;
        }
        let how = if g.moved_out {
            "moved out of"
        } else {
            "deleted from"
        };
        let recent_id = recent.get(g.path.as_str());
        let recorded = recent_id
            .is_none()
            .then(|| registers.record(root, &g.path))
            .flatten();
        let Some(cloud_id) = recent_id
            .cloned()
            .or_else(|| recorded.as_ref().map(|known| known.cloud_id.clone()))
        else {
            // Not an error. A file created here and never uploaded has no object
            // to withdraw, and that is the ordinary case for scratch files.
            eprintln!(
                "hydration-sync: {} was {how} the sync folder; nothing to remove, the \
                 cloud has no record of it",
                g.path
            );
            continue;
        };
        let removed = match recorded.as_ref() {
            Some(known) => sink.remove_known(Known {
                cloud_id: &known.cloud_id,
                tag: known.tag.as_deref(),
            }),
            None => sink.remove(&cloud_id),
        };
        match removed {
            Ok(()) => eprintln!(
                "hydration-sync: {} was {how} the sync folder; removed from the cloud",
                g.path
            ),
            // Left alone rather than retried. The next delta pass will bring the
            // object back down as a placeholder, which is visible and correct —
            // the file is in the cloud, so it should be here. Retrying a removal
            // in a loop is how one failure becomes a deletion nobody asked for.
            Err(e) => eprintln!(
                "hydration-sync: {} was {how} the sync folder, but the cloud copy could \
                 not be removed: {e}. It will come back on the next delta pass.",
                g.path
            ),
        }
    }
}

/// Withdraw directories only through the provider's explicit empty-folder
/// contract. A generic object delete is intentionally unavailable here.
fn apply_folder_removals<S: Sink>(
    root: &std::path::Path,
    gone: &[crate::removals::FolderGone],
    known: usize,
    sink: &mut S,
) {
    let ignore = crate::store::load_ignore(root);
    let ceiling = removal_ceiling(known);
    if gone.len() > ceiling {
        eprintln!(
            "hydration-sync: {} folders were deleted here at once, which is more than the \
             {ceiling} this will remove from the cloud without being asked (a tenth of the \
             {known} it is tracking). Nothing was removed; first few: {}",
            gone.len(),
            gone.iter()
                .take(5)
                .map(|folder| folder.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        return;
    }

    let mut ordered: Vec<_> = gone.iter().collect();
    ordered.sort_by_key(|folder| {
        (
            std::cmp::Reverse(folder.path.matches('/').count()),
            folder.path.as_str(),
        )
    });
    for folder in ordered {
        // Sync-ignore: a deleted `.git/` folder must not withdraw its cloud
        // copy. Prospective and sync-only — leave what is already in the cloud.
        if ignore.is_ignored(std::path::Path::new(&folder.path)) {
            continue;
        }
        let how = if folder.moved_out {
            "moved out of"
        } else {
            "deleted from"
        };
        let Some(record) = &folder.record else {
            eprintln!(
                "hydration-sync: folder {} was {how} the sync folder without a recorded \
                 cloud identity; no cloud object was deleted",
                folder.path
            );
            continue;
        };
        let Some(tag) = record.etag.as_deref() else {
            eprintln!(
                "hydration-sync: folder {} was {how} the sync folder, but its cloud metadata \
                 version was unknown; refusing a blind recursive delete",
                folder.path
            );
            continue;
        };
        match sink.remove_folder(Known {
            cloud_id: &record.cloud_id,
            tag: Some(tag),
        }) {
            Ok(()) => eprintln!(
                "hydration-sync: folder {} was {how} the sync folder; removed the proven-empty \
                 cloud folder",
                folder.path
            ),
            Err(e) => eprintln!(
                "hydration-sync: folder {} was {how} the sync folder, but the cloud folder \
                 was left untouched: {e}. It will come back on the next delta pass.",
                folder.path
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store;
    use hydration_protocol::stamp::{self, State};
    use hydration_protocol::{holds_data, xattr};
    use std::path::Path;

    /// Not `/tmp`: every one of these needs user extended attributes and real
    /// sparseness, and tmpfs has neither in the form this measures.
    /// `HYDRATION_TEST_DIR` points it at whichever filesystem is under test.
    ///
    /// `CARGO_TARGET_TMPDIR` is not available to a unit test inside the library
    /// — cargo only sets it for integration tests — so the fallback is spelled
    /// out from the manifest directory, as in `place.rs`.
    fn scratch(name: &str) -> PathBuf {
        test_scratch::scratch(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
            &format!("resync-walk/{name}"),
        )
    }

    /// Move a file's mtime to a fixed, distant instant.
    ///
    /// Not decoration. The kernel stamps mtime from a coarse clock — a write
    /// microseconds after `stamp::write` can land on the same nanosecond value,
    /// and the file then reads `Clean`. A test built that way asserts that a
    /// placeholder is not queued while being unable to fail, because the state
    /// it claims to set up never existed. Every test here sets the mtime
    /// explicitly and then asserts the state it meant to create.
    fn set_mtime(path: &Path, secs: i64) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [
            libc::timespec {
                tv_sec: secs,
                tv_nsec: 0,
            },
            libc::timespec {
                tv_sec: secs,
                tv_nsec: 0,
            },
        ];
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(rc, 0, "could not set mtime: {}", io::Error::last_os_error());
    }

    /// A placeholder as the framework leaves one: sized, empty, marked, stamped.
    fn placeholder(dir: &Path, name: &str, size: u64) -> PathBuf {
        let p = dir.join(name);
        let f = std::fs::File::create(&p).unwrap();
        f.set_len(size).unwrap();
        drop(f);
        store::set_xattr(&p, xattr::DEHYDRATED, b"1").unwrap();
        store::set_xattr(&p, store::XATTR_ID, b"cloud-1").unwrap();
        stamp::write(&p).unwrap();
        assert_eq!(stamp::state(&p).unwrap(), State::Clean);
        assert!(
            !holds_data(&p).unwrap(),
            "a fresh placeholder holds nothing"
        );
        p
    }

    /// Write into a placeholder's hole without changing its size, the way the
    /// worker's `write_at` does — and the way a process writing to a file the
    /// helper is not intercepting does.
    fn fill_range(path: &Path, len: usize) {
        use std::os::unix::fs::FileExt;
        let f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        f.write_all_at(&vec![b'x'; len], 0).unwrap();
    }

    /// The reported defect: a fill that was interrupted between the `pwrite` and
    /// the stamp `finish_hydration` writes.
    ///
    /// A `pkill hydrationd` mid-transfer leaves exactly this on a live mount —
    /// still marked, holding part of the object, and `Dirty` because the write
    /// moved the mtime the placeholder's stamp describes. Queued, `run_upload`
    /// reads it through the mount, every hole fires a pre-content event, the
    /// whole object is hydrated, and the cloud is sent a byte-identical copy of
    /// what it just served.
    #[test]
    fn an_interrupted_fill_is_not_queued_for_upload() {
        let dir = scratch("interrupted-fill");
        let p = placeholder(&dir, "big.iso", 1 << 20);
        fill_range(&p, 4096);
        set_mtime(&p, 1_700_000_000);

        // The state the test claims to have built, asserted rather than assumed.
        assert_eq!(stamp::state(&p).unwrap(), State::Dirty);
        assert!(holds_data(&p).unwrap(), "the interrupted fill left bytes");

        let found = dirty_files(&dir).unwrap();
        assert_eq!(found.send, Vec::new(), "a placeholder must not be uploaded");
        assert_eq!(found.holding, vec![p], "and must not be dropped in silence");
    }

    /// The same shape, arrived at from the other direction: bytes that are the
    /// user's, in a file that is still marked because nothing intercepted the
    /// write.
    ///
    /// Indistinguishable from the case above by anything on this side, which is
    /// the point. Queueing it would not save the bytes — `run_upload` reads the
    /// file to send it, and that read is what makes the helper punch — so the
    /// only thing left to do with them is say where they are.
    #[test]
    fn a_write_into_a_marked_file_is_named_rather_than_sent() {
        let dir = scratch("unintercepted-write");
        let p = placeholder(&dir, "notes.txt", 8192);
        fill_range(&p, 512);
        set_mtime(&p, 1_700_000_100);
        assert_eq!(stamp::state(&p).unwrap(), State::Dirty);

        let found = dirty_files(&dir).unwrap();
        assert_eq!(found.send, Vec::new());
        assert_eq!(found.holding, vec![p]);
    }

    /// A placeholder whose mtime moved and whose content did not.
    ///
    /// `touch` does this, and so does a punch of ours whose `let _ =` re-stamp
    /// failed. It is `Dirty` and it holds nothing, so there are no bytes to lose
    /// and nothing to warn about — reporting it would put a line in front of the
    /// user on every resync that they must learn to ignore, which is how the
    /// line that matters stops being read.
    #[test]
    fn a_touched_placeholder_is_skipped_without_a_warning() {
        let dir = scratch("touched");
        let p = placeholder(&dir, "held.bin", 1 << 20);
        set_mtime(&p, 1_700_000_200);
        assert_eq!(stamp::state(&p).unwrap(), State::Dirty);
        assert!(!holds_data(&p).unwrap());

        let found = dirty_files(&dir).unwrap();
        assert_eq!(found.send, Vec::new());
        assert_eq!(found.holding, Vec::<PathBuf>::new());
    }

    /// The ordinary placeholder, which is most of the sync directory.
    #[test]
    fn a_clean_placeholder_is_neither_sent_nor_reported() {
        let dir = scratch("clean");
        placeholder(&dir, "quiet.bin", 1 << 20);

        let found = dirty_files(&dir).unwrap();
        assert_eq!(found, Resync::default());
    }

    /// A partially hydrated file: marked, holding bytes, and `Clean`.
    ///
    /// This state did not exist when the walk was written — `clear_residue` was
    /// unconditional and a marked file holding bytes could not survive between
    /// transfers. Ranged fills made it ordinary: `settle_range` writes a range
    /// into a still-marked file and stamps it, so the file holds the cloud's
    /// bytes and reads `Clean`.
    ///
    /// It must be silent. Not because there is nothing there — there is — but
    /// because those bytes are the framework's own and the helper is part-way
    /// through putting them there. Warning would name every file being hydrated,
    /// on every resync, in the same sentence used for bytes that are about to be
    /// punched; the honest line and the routine one would be identical and the
    /// user would learn to skip both.
    ///
    /// The `Clean` gate is what holds this, and it is the only signal available:
    /// `partial::Standing` lives in the worker's memory, on the far side of the
    /// socket. Removing the gate — or "fixing" the stale premise that once
    /// justified it — turns the warning into noise, so it is pinned here.
    #[test]
    fn a_partially_hydrated_file_is_not_reported_as_holding_bytes() {
        let dir = scratch("partial-fill");
        let p = placeholder(&dir, "half.iso", 1 << 20);

        // What `settle_range` leaves: bytes in the hole, mark untouched, and a
        // stamp describing the file as it now stands.
        fill_range(&p, 4096);
        stamp::write(&p).unwrap();

        assert_eq!(
            stamp::state(&p).unwrap(),
            State::Clean,
            "a settled range leaves the file Clean, which is what the gate reads"
        );
        assert!(holds_data(&p).unwrap(), "and it really does hold bytes");
        assert!(
            store::get_xattr(&p, xattr::DEHYDRATED).unwrap().is_some(),
            "and it is still a placeholder"
        );

        let found = dirty_files(&dir).unwrap();
        assert_eq!(found, Resync::default(), "a partial fill is not news");
    }

    /// The reason the `Dirty` arm exists, and it still has to work: an in-place
    /// edit of a hydrated file, which no event mentioned.
    #[test]
    fn an_edited_file_is_still_queued() {
        let dir = scratch("edited");
        let p = dir.join("report.txt");
        std::fs::write(&p, b"first").unwrap();
        store::set_xattr(&p, store::XATTR_ID, b"cloud-2").unwrap();
        stamp::write(&p).unwrap();
        std::fs::write(&p, b"second, and longer").unwrap();
        set_mtime(&p, 1_700_000_300);
        assert_eq!(stamp::state(&p).unwrap(), State::Dirty);

        let found = dirty_files(&dir).unwrap();
        let md = std::fs::metadata(&p).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            found.send,
            vec![FileId {
                fsid: md.dev(),
                ino: md.ino()
            }]
        );
        assert_eq!(found.holding, Vec::<PathBuf>::new());
    }

    /// The other arm, unchanged: an editor's write-and-rename leaves an inode
    /// carrying neither stamp nor cloud id.
    #[test]
    fn an_unstamped_file_with_content_is_still_queued() {
        let dir = scratch("unstamped");
        let p = dir.join("saved.txt");
        std::fs::write(&p, b"written by an editor").unwrap();

        let found = dirty_files(&dir).unwrap();
        assert_eq!(found.send.len(), 1);
        assert_eq!(found.holding, Vec::<PathBuf>::new());
    }

    #[derive(Default)]
    struct FolderSink {
        created: Vec<PathBuf>,
    }

    impl Sink for FolderSink {
        fn upload(&mut self, _path: &Path, _existing: Option<Known<'_>>) -> io::Result<Uploaded> {
            unreachable!("this sink only records folder creates")
        }

        fn create_folder(&mut self, path: &Path) -> io::Result<Uploaded> {
            self.created.push(path.to_path_buf());
            let name = path.file_name().unwrap().to_string_lossy();
            Ok(Uploaded {
                cloud_id: format!("cloud-{name}"),
                etag: Some(format!("et:version-{name}")),
            })
        }

        fn remove(&mut self, _cloud_id: &str) -> io::Result<()> {
            unreachable!("this sink only records folder creates")
        }
    }

    #[test]
    fn local_folder_create_is_parent_first_and_records_returned_identity() {
        let dir = scratch("folder-create-parent-first");
        store::set_xattr(&dir, store::XATTR_ID, b"cloud-root").unwrap();
        std::fs::create_dir_all(dir.join("Projects/New")).unwrap();
        let mut pending = unidentified_folders(&dir).unwrap();
        let mut committed = BTreeMap::new();
        let mut sink = FolderSink::default();

        apply_folder_creates(&dir, &mut pending, &mut committed, &mut sink);

        assert_eq!(
            sink.created,
            [dir.join("Projects"), dir.join("Projects/New")],
            "a child was sent before its parent's returned cloud identity was recorded"
        );
        assert!(pending.is_empty());
        assert!(committed.is_empty());
        assert_eq!(
            store::get_xattr(&dir.join("Projects"), store::XATTR_ID)
                .unwrap()
                .unwrap(),
            b"cloud-Projects"
        );
        assert_eq!(
            store::get_xattr(&dir.join("Projects/New"), store::XATTR_ETAG)
                .unwrap()
                .unwrap(),
            b"et:version-New"
        );
    }

    #[derive(Default)]
    struct RenameSink {
        moves: Vec<(PathBuf, PathBuf, String, Option<String>)>,
    }

    impl Sink for RenameSink {
        fn upload(
            &mut self,
            _path: &Path,
            _existing: Option<Known<'_>>,
        ) -> io::Result<crate::upload::Uploaded> {
            unreachable!("this sink only records namespace operations")
        }

        fn move_item(
            &mut self,
            from: &Path,
            to: &Path,
            existing: Known<'_>,
        ) -> io::Result<crate::upload::Uploaded> {
            self.moves.push((
                from.to_path_buf(),
                to.to_path_buf(),
                existing.cloud_id.to_string(),
                existing.tag.map(str::to_string),
            ));
            Ok(crate::upload::Uploaded {
                cloud_id: existing.cloud_id.to_string(),
                etag: Some("ctag-after-rename".into()),
            })
        }

        fn remove(&mut self, _cloud_id: &str) -> io::Result<()> {
            unreachable!("this sink only records namespace operations")
        }
    }

    #[test]
    fn identity_preserving_local_rename_uses_the_namespace_operation() {
        let dir = scratch("rename-cloud");
        let target = dir.join("after.txt");
        std::fs::write(&target, b"same bytes").unwrap();
        store::set_xattr(&target, store::XATTR_ID, b"cloud-rename").unwrap();
        store::set_xattr(&target, store::XATTR_ETAG, b"ctag-before").unwrap();
        let mut sink = RenameSink::default();

        apply_renames(
            &dir,
            &[crate::removals::Renamed {
                from: "before.txt".into(),
                to: "after.txt".into(),
                is_dir: false,
            }],
            &mut sink,
        );

        assert_eq!(
            sink.moves,
            [(
                dir.join("before.txt"),
                target.clone(),
                "cloud-rename".into(),
                Some("ctag-before".into()),
            )]
        );
        assert_eq!(
            store::get_xattr(&target, store::XATTR_ETAG)
                .unwrap()
                .unwrap(),
            b"ctag-after-rename"
        );
    }

    #[test]
    fn identity_preserving_folder_rename_uses_the_same_guarded_namespace_operation() {
        let dir = scratch("rename-folder-cloud");
        let target = dir.join("after");
        std::fs::create_dir(&target).unwrap();
        store::set_xattr(&target, store::XATTR_ID, b"cloud-folder").unwrap();
        store::set_xattr(&target, store::XATTR_ETAG, b"et:folder-before").unwrap();
        let mut sink = RenameSink::default();

        apply_renames(
            &dir,
            &[crate::removals::Renamed {
                from: "before".into(),
                to: "after".into(),
                is_dir: true,
            }],
            &mut sink,
        );

        assert_eq!(
            sink.moves,
            [(
                dir.join("before"),
                target,
                "cloud-folder".into(),
                Some("et:folder-before".into()),
            )]
        );
    }

    #[test]
    fn rebuilding_the_namespace_watch_after_root_replacement_observes_the_new_tree() {
        let dir = scratch("rewatch-replaced-root");
        std::fs::create_dir(dir.join("from")).unwrap();
        std::fs::create_dir(dir.join("destination")).unwrap();
        let stale = crate::removals::Removals::watch(&dir).unwrap();

        // Model hydrationd's fail-closed detach followed by systemd mounting a
        // new incarnation at the same path. The old inotify descriptor remains
        // valid and quiet on `detached`; only a rebuilt watcher can see changes
        // below the path named by `dir` now.
        let detached = dir.with_extension("detached");
        let _ = std::fs::remove_dir_all(&detached);
        std::fs::rename(&dir, &detached).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::create_dir(dir.join("from")).unwrap();
        std::fs::create_dir(dir.join("destination")).unwrap();

        let mut watcher = Some(stale);
        assert_eq!(replace_removal_watch(&dir, &mut watcher).unwrap(), 3);
        std::fs::rename(dir.join("from"), dir.join("destination/from")).unwrap();
        std::thread::sleep(Duration::from_millis(120));

        let batch = watcher.as_mut().unwrap().take();
        assert_eq!(
            batch.renamed,
            [crate::removals::Renamed {
                from: "from".into(),
                to: "destination/from".into(),
                is_dir: true,
            }],
            "the replacement watcher stayed attached to the detached tree"
        );
        std::fs::remove_dir_all(detached).unwrap();
    }

    #[test]
    fn atomic_replacement_without_identity_is_not_a_cloud_rename() {
        let dir = scratch("replace-not-rename");
        std::fs::write(dir.join("doc.txt"), b"new inode").unwrap();
        let mut sink = RenameSink::default();

        apply_renames(
            &dir,
            &[crate::removals::Renamed {
                from: "doc.txt.tmp".into(),
                to: "doc.txt".into(),
                is_dir: false,
            }],
            &mut sink,
        );

        assert!(sink.moves.is_empty());
    }

    #[derive(Default)]
    struct DeleteSink {
        known: Vec<(String, Option<String>)>,
        folders: Vec<(String, Option<String>)>,
        plain: Vec<String>,
    }

    impl Sink for DeleteSink {
        fn upload(
            &mut self,
            _path: &Path,
            _existing: Option<Known<'_>>,
        ) -> io::Result<crate::upload::Uploaded> {
            unreachable!("this sink only records deletion")
        }

        fn remove_known(&mut self, existing: Known<'_>) -> io::Result<()> {
            self.known.push((
                existing.cloud_id.to_string(),
                existing.tag.map(str::to_string),
            ));
            Ok(())
        }

        fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
            self.plain.push(cloud_id.to_string());
            Ok(())
        }

        fn remove_folder(&mut self, existing: Known<'_>) -> io::Result<()> {
            self.folders.push((
                existing.cloud_id.to_string(),
                existing.tag.map(str::to_string),
            ));
            Ok(())
        }
    }

    #[test]
    fn deleting_a_placeholder_preserves_its_manifest_precondition() {
        let dir = scratch("delete-manifest-tag");
        crate::manifest::Manifest {
            entries: vec![crate::manifest::Entry {
                path: "gone.txt".into(),
                cloud_id: "drive|cloud-delete".into(),
                size: 9,
                etag: Some("ct:c:{G},9".into()),
            }],
            unrecoverable: vec![],
        }
        .write(&dir)
        .unwrap();
        let mut sink = DeleteSink::default();

        apply_removals(
            &dir,
            &[crate::removals::Gone {
                path: "gone.txt".into(),
                moved_out: false,
            }],
            &std::collections::HashMap::new(),
            0,
            &mut sink,
        );

        assert_eq!(
            sink.known,
            [("drive|cloud-delete".into(), Some("ct:c:{G},9".into()))]
        );
        assert!(sink.plain.is_empty());
    }

    #[test]
    fn folder_deletes_are_versioned_and_deepest_first() {
        let mut sink = DeleteSink::default();
        apply_folder_removals(
            std::path::Path::new("/no/such/root"),
            &[
                crate::removals::FolderGone {
                    path: "Work".into(),
                    moved_out: false,
                    record: Some(crate::removals::FolderRecord {
                        cloud_id: "drive|parent".into(),
                        etag: Some("et:parent-1".into()),
                    }),
                },
                crate::removals::FolderGone {
                    path: "Work/Empty".into(),
                    moved_out: false,
                    record: Some(crate::removals::FolderRecord {
                        cloud_id: "drive|child".into(),
                        etag: Some("et:child-1".into()),
                    }),
                },
            ],
            0,
            &mut sink,
        );

        assert_eq!(
            sink.folders,
            [
                ("drive|child".into(), Some("et:child-1".into())),
                ("drive|parent".into(), Some("et:parent-1".into())),
            ]
        );
        assert!(sink.known.is_empty());
        assert!(sink.plain.is_empty());
    }

    #[test]
    fn folder_delete_without_both_identity_and_version_never_reaches_the_sink() {
        let mut sink = DeleteSink::default();
        apply_folder_removals(
            std::path::Path::new("/no/such/root"),
            &[
                crate::removals::FolderGone {
                    path: "local-only".into(),
                    moved_out: false,
                    record: None,
                },
                crate::removals::FolderGone {
                    path: "unversioned".into(),
                    moved_out: false,
                    record: Some(crate::removals::FolderRecord {
                        cloud_id: "drive|folder".into(),
                        etag: None,
                    }),
                },
            ],
            0,
            &mut sink,
        );

        assert!(sink.folders.is_empty());
        assert!(sink.known.is_empty());
        assert!(sink.plain.is_empty());
    }

    #[test]
    fn an_oversized_folder_delete_batch_is_all_or_nothing() {
        // One over the floor, with nothing tracked, so the ceiling is the floor.
        let gone: Vec<_> = (0..=REMOVAL_FLOOR)
            .map(|index| crate::removals::FolderGone {
                path: format!("folder-{index}"),
                moved_out: false,
                record: Some(crate::removals::FolderRecord {
                    cloud_id: format!("drive|folder-{index}"),
                    etag: Some(format!("et:folder-{index}")),
                }),
            })
            .collect();
        let mut sink = DeleteSink::default();

        apply_folder_removals(std::path::Path::new("/no/such/root"), &gone, 0, &mut sink);

        assert!(sink.folders.is_empty());
        assert!(sink.known.is_empty());
        assert!(sink.plain.is_empty());
    }

    /// A scratch directory whose *canonical* path is used, because these tests
    /// bind sockets in it. A socket path has a 108-byte ceiling (`sun_path`),
    /// and the uncanonicalized fallback — manifest dir plus `../../target` —
    /// is long enough to cross it on a deep checkout. Short test names, same
    /// reason.
    fn ctl_scratch(name: &str) -> PathBuf {
        let d = test_scratch::scratch(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
            &format!("control-socket/{name}"),
        );
        d.canonicalize().unwrap_or(d)
    }

    fn state(unsent: u64, excluded: u64, exposures: u64) -> WatchState {
        WatchState {
            unsent,
            excluded,
            exposures,
            downloading: 0,
            scanning: false,
            uploading: Vec::new(),
        }
    }

    /// The regression `watch` invites, and the reason it is not served on the
    /// accept thread: a watcher is long-lived and silent *by design*, and the
    /// old shape held each connection there until its read timed out — so one
    /// watcher would park `status` and `evict`, the user's only channel, for
    /// ten seconds per reconnect, forever.
    #[test]
    fn a_watcher_does_not_park_status_or_evict() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;

        let dir = ctl_scratch("no-park");
        let mount = dir.join("m");
        std::fs::create_dir_all(&mount).unwrap();
        let sock = dir.join("ctl");

        let queue = Arc::new(Mutex::new(Queue::new(
            Duration::from_secs(900),
            SystemClock::default(),
        )));
        let exposures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let excluded = Arc::new(AtomicU64::new(7));
        let watchers = Arc::new(Watchers::default());
        {
            let (s, m, q, e, x, inf, au, w) = (
                sock.clone(),
                mount.clone(),
                Arc::clone(&queue),
                Arc::clone(&exposures),
                Arc::clone(&excluded),
                Arc::new(AtomicU64::new(0)),
                Arc::new(Mutex::new(HashMap::new())),
                Arc::clone(&watchers),
            );
            std::thread::spawn(move || control(&s, m, q, e, x, inf, au, w));
        }
        // The listener comes up on another thread; connecting retries until it
        // has. Deadlines are generous because the test machines run gates
        // concurrently, and a tight deadline measures the machine, not the
        // code.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let connect = |what: &str| -> UnixStream {
            loop {
                match UnixStream::connect(&sock) {
                    Ok(c) => {
                        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        return c;
                    }
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("could not connect for {what}: {e}"),
                }
            }
        };

        let mut watcher = connect("watch");
        writeln!(watcher, "watch").unwrap();
        let mut first = String::new();
        BufReader::new(watcher.try_clone().unwrap())
            .read_line(&mut first)
            .expect("watch was not answered with an immediate state line");
        assert_eq!(
            first,
            "unsent=0 excluded=7 exposures=0 downloading=0 scanning=0 uploading=\n"
        );

        // The watcher stays connected and says nothing more. Both other verbs
        // must still be answered on fresh connections, inside the read timeout
        // — with the watcher parked on the accept thread they would not be.
        let mut status = connect("status");
        writeln!(status, "status").unwrap();
        let mut line = String::new();
        BufReader::new(status)
            .read_line(&mut line)
            .expect("status went unanswered while a watcher was connected");
        assert_eq!(line, "0 unsent\n");

        let mut evict = connect("evict");
        writeln!(evict, "evict no-such-file").unwrap();
        let mut line = String::new();
        BufReader::new(evict)
            .read_line(&mut line)
            .expect("evict went unanswered while a watcher was connected");
        assert!(
            !line.trim().is_empty(),
            "evict must answer something, even a refusal"
        );
    }

    /// `pin`/`unpin` over the socket: a file round-trips (the xattr appears and
    /// goes away), a directory can be pinned — the folder half of "Keep on
    /// Device", which `evict` deliberately refuses — and a path that escapes the
    /// sync directory is an `error:`, confined exactly like `evict`.
    #[test]
    fn pin_unpin_and_directories_over_the_socket() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixStream;

        let dir = ctl_scratch("pin-socket");
        let mount = dir.join("m");
        std::fs::create_dir_all(&mount).unwrap();
        let file = mount.join("keep.txt");
        std::fs::write(&file, b"content").unwrap();
        let sub = mount.join("keep-dir");
        std::fs::create_dir_all(&sub).unwrap();
        let sock = dir.join("ctl");

        let queue = Arc::new(Mutex::new(Queue::new(
            Duration::from_secs(900),
            SystemClock::default(),
        )));
        let exposures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let excluded = Arc::new(AtomicU64::new(0));
        let watchers = Arc::new(Watchers::default());
        {
            let (s, m, q, e, x, inf, au, w) = (
                sock.clone(),
                mount.clone(),
                Arc::clone(&queue),
                Arc::clone(&exposures),
                Arc::clone(&excluded),
                Arc::new(AtomicU64::new(0)),
                Arc::new(Mutex::new(HashMap::new())),
                Arc::clone(&watchers),
            );
            std::thread::spawn(move || control(&s, m, q, e, x, inf, au, w));
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let ask = |line: &str| -> String {
            let c = loop {
                match UnixStream::connect(&sock) {
                    Ok(c) => {
                        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        break c;
                    }
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("could not connect: {e}"),
                }
            };
            writeln!(&c, "{line}").unwrap();
            let mut reply = String::new();
            BufReader::new(c).read_line(&mut reply).expect("no reply");
            reply.trim().to_string()
        };

        // A file round-trips: the mark appears, then goes away.
        assert_eq!(ask("pin keep.txt"), "pinned");
        assert!(
            crate::store::is_pinned(&file).unwrap(),
            "the pin did not land"
        );
        assert_eq!(ask("unpin keep.txt"), "unpinned");
        assert!(
            !crate::store::is_pinned(&file).unwrap(),
            "the pin did not clear"
        );

        // A directory can be pinned — evict cannot touch one.
        assert_eq!(ask("pin keep-dir"), "pinned");
        assert!(
            crate::store::is_pinned(&sub).unwrap(),
            "a directory pin did not land"
        );

        // Confined exactly like evict: an escape is refused, not obeyed.
        assert!(
            ask("pin ../../etc/passwd").starts_with("error:"),
            "pin obeyed a path outside the sync directory"
        );
    }

    /// `pending <dir>` lists the dehydrated files under a directory over the
    /// socket, one relative path per line — the multi-line reply the folder
    /// hydrate path reads whole. An empty subtree comes back empty, not as a
    /// dropped connection.
    #[test]
    fn pending_lists_dehydrated_files_over_the_socket() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;

        let dir = ctl_scratch("pending-socket");
        let mount = dir.join("m");
        let tree = mount.join("tree");
        std::fs::create_dir_all(&tree).unwrap();
        // The mark is what `pending` reads; two marked files and one plain one.
        for name in ["a.bin", "b.bin"] {
            let p = tree.join(name);
            std::fs::write(&p, b"").unwrap();
            crate::store::set_xattr(&p, hydration_protocol::xattr::DEHYDRATED, b"1").unwrap();
        }
        std::fs::write(tree.join("resident.txt"), b"here").unwrap();
        let empty = mount.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let sock = dir.join("ctl");

        let queue = Arc::new(Mutex::new(Queue::new(
            Duration::from_secs(900),
            SystemClock::default(),
        )));
        let exposures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let excluded = Arc::new(AtomicU64::new(0));
        let watchers = Arc::new(Watchers::default());
        {
            let (s, m, q, e, x, inf, au, w) = (
                sock.clone(),
                mount.clone(),
                Arc::clone(&queue),
                Arc::clone(&exposures),
                Arc::clone(&excluded),
                Arc::new(AtomicU64::new(0)),
                Arc::new(Mutex::new(HashMap::new())),
                Arc::clone(&watchers),
            );
            std::thread::spawn(move || control(&s, m, q, e, x, inf, au, w));
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        // Reads the *whole* reply, not one line — a `pending` answer is
        // multi-line — by shutting down the write half first, exactly as the
        // product's control_request does.
        let ask = |line: &str| -> String {
            let mut c = loop {
                match UnixStream::connect(&sock) {
                    Ok(c) => {
                        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                        break c;
                    }
                    Err(_) if std::time::Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(e) => panic!("could not connect: {e}"),
                }
            };
            writeln!(c, "{line}").unwrap();
            c.shutdown(std::net::Shutdown::Write).unwrap();
            let mut reply = String::new();
            c.read_to_string(&mut reply).unwrap();
            reply.trim_end_matches('\n').to_string()
        };

        let mut lines: Vec<String> = ask("pending tree")
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        lines.sort();
        assert_eq!(
            lines,
            vec!["tree/a.bin".to_string(), "tree/b.bin".to_string()]
        );

        assert_eq!(ask("pending empty"), "", "an empty subtree lists nothing");
    }

    /// A pressure sweep evicts an evictable resident and — the safety line —
    /// leaves alone a file the queue is uploading. The `sending` snapshot is how
    /// the delete-during-upload hazard is closed: replacing an in-flight file's
    /// inode would make the upload delete the object it just created.
    #[test]
    fn a_sweep_evicts_a_resident_but_skips_an_uploading_file() {
        use std::os::unix::fs::MetadataExt;
        let dir = ctl_scratch("evict-sweep");
        let mount = dir.join("m");
        std::fs::create_dir_all(&mount).unwrap();

        let synced = |name: &str, body: &[u8]| -> (std::path::PathBuf, FileId) {
            let p = mount.join(name);
            std::fs::write(&p, body).unwrap();
            crate::store::set_xattr(&p, crate::store::XATTR_ID, b"cloud-1").unwrap();
            hydration_protocol::stamp::write(&p).unwrap();
            let md = std::fs::metadata(&p).unwrap();
            (
                p,
                FileId {
                    fsid: md.dev(),
                    ino: md.ino(),
                },
            )
        };
        let (a, _) = synced("a.bin", &vec![b'a'; 8192]);
        let (b, b_id) = synced("b.bin", &vec![b'b'; 8192]);

        // The point of this test is that reclaim — not plan — is what spares the
        // file being uploaded, so plan must want BOTH files: if it stops after
        // one, the outcome turns on which of a and b sorts first, and that order
        // is not stable. plan ranks by recency (hydrated_at, mtime fallback), and
        // on ext4 with a 128-byte inode mtime has only second granularity — the
        // nanosecond fields live past the 128th byte — so a.bin and b.bin written
        // back to back tie, and the tie falls through to readdir hash order, which
        // is per-filesystem-instance. Measured: one CI ext4-128 runner yielded b
        // first, so plan (which stops at the high mark) selected only b, reclaim
        // refused it, and nothing was evicted; the same test passed on btrfs, xfs,
        // ext4-512, and other ext4-128 instances where a happened to sort first.
        //
        // The fix is to make plan genuinely want both, as the test always claimed:
        // high = min(total, high_abs) must exceed what these two ~8 KiB files can
        // free, so a large `total` (below) leaves high at high_abs = 1 MiB, far
        // above ~16 KiB. plan then selects both regardless of order, and reclaim
        // is left to refuse b. low stays 100 (min(total, low_abs)), so available 0
        // is still under pressure.
        let cfg = crate::evict_policy::EvictionConfig {
            low_pct: 100,
            low_abs: 100,
            high_pct: 100,
            high_abs: 1_000_000,
            grace_secs: 0,
            sweep_cap: 1_000_000,
            min_interval_secs: 0,
        };
        let sending: HashSet<FileId> = std::iter::once(b_id).collect();
        // available 0 < low 100 -> under pressure; total huge so high = high_abs.
        let freed = plan_and_reclaim(
            &mount,
            &cfg,
            0,
            10_000_000,
            10_000,
            &HashSet::new(),
            &sending,
        )
        .unwrap();

        let dehydrated = |p: &std::path::Path| {
            crate::store::get_xattr(p, hydration_protocol::xattr::DEHYDRATED)
                .unwrap()
                .is_some()
        };
        assert!(dehydrated(&a), "the evictable resident was not dehydrated");
        assert!(!dehydrated(&b), "a file being uploaded was evicted");
        assert!(freed > 0, "the sweep reported no bytes freed");
    }

    /// Above the low mark there is no pressure, so the sweep is a single
    /// `statvfs`-shaped no-op: it evicts nothing and does not even walk. This is
    /// the common path, and the idempotence a second sweep at target must have.
    #[test]
    fn a_sweep_without_pressure_evicts_nothing() {
        let dir = ctl_scratch("no-pressure");
        let mount = dir.join("m");
        std::fs::create_dir_all(&mount).unwrap();
        let p = mount.join("resident.bin");
        std::fs::write(&p, vec![b'r'; 8192]).unwrap();
        crate::store::set_xattr(&p, crate::store::XATTR_ID, b"cloud-1").unwrap();
        hydration_protocol::stamp::write(&p).unwrap();

        // default_pressure: with total 1000, low = min(10% = 100, 10 GiB) = 100.
        let cfg = crate::evict_policy::EvictionConfig::default_pressure();
        let freed = plan_and_reclaim(
            &mount,
            &cfg,
            500,
            1000,
            10_000,
            &HashSet::new(),
            &HashSet::new(),
        )
        .unwrap();

        assert_eq!(freed, 0, "freed bytes without pressure");
        assert!(
            crate::store::get_xattr(&p, hydration_protocol::xattr::DEHYDRATED)
                .unwrap()
                .is_none(),
            "a file was evicted without pressure"
        );
    }

    /// The contract's quietest clause: an unchanged tuple emits nothing. A
    /// line that repeats the last line is a wakeup that says nothing — the
    /// polling this verb exists to remove, moved one process over.
    #[test]
    fn an_unchanged_state_emits_no_line() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixStream;

        let (ours, theirs) = UnixStream::pair().unwrap();
        theirs
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut peer = BufReader::new(theirs);

        let watchers = Watchers::default();
        watchers.adopt(ours, state(3, 1, 0));

        let mut line = String::new();
        peer.read_line(&mut line).unwrap();
        assert_eq!(
            line,
            "unsent=3 excluded=1 exposures=0 downloading=0 scanning=0 uploading=\n"
        );

        // The same tuple, twice. `broadcast` writes synchronously, so had a
        // line been written it would already be in our buffer — the timeout
        // below can only fire in the correct case, it cannot save a buggy
        // build by racing it.
        watchers.broadcast(state(3, 1, 0));
        watchers.broadcast(state(3, 1, 0));
        line.clear();
        let err = peer
            .read_line(&mut line)
            .expect_err("an identical state was re-broadcast");
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "expected silence, got: {err}"
        );

        // And the moment one number moves, exactly one line, keys in order.
        watchers.broadcast(state(2, 1, 0));
        line.clear();
        peer.read_line(&mut line).unwrap();
        assert_eq!(
            line,
            "unsent=2 excluded=1 exposures=0 downloading=0 scanning=0 uploading=\n"
        );
    }

    /// A watcher that hangs up during a quiet stretch must be noticed without
    /// a state change. Culling on write failure alone needs the state to move
    /// first, and "nothing changed for an hour" is the normal state of a
    /// synced drive — a reconnecting tray would otherwise grow the registry by
    /// one dead entry per attempt until something happened to change a number.
    #[test]
    fn a_departed_watcher_is_culled_without_a_state_change() {
        use std::os::unix::net::UnixStream;

        let (ours, theirs) = UnixStream::pair().unwrap();
        let watchers = Watchers::default();
        watchers.adopt(ours, state(0, 0, 0));
        assert_eq!(watchers.live(), 1);

        drop(theirs);
        // The state has not changed, so no write will fail: only the hangup
        // probe can notice the departure.
        watchers.broadcast(state(0, 0, 0));
        assert_eq!(watchers.live(), 0);
    }

    /// The registry is a bound, not a leak: a connection past the cap is
    /// closed, and closed is observable as an immediate EOF rather than a
    /// hang or a half-protocol.
    #[test]
    fn a_watcher_beyond_the_cap_is_refused_with_eof() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::net::UnixStream;

        let watchers = Watchers::default();
        // Held open, so the cap is measuring live peers and not exercising
        // the registration-time cull.
        let mut peers = Vec::new();
        for _ in 0..MAX_WATCHERS {
            let (ours, theirs) = UnixStream::pair().unwrap();
            watchers.adopt(ours, state(0, 0, 0));
            peers.push(theirs);
        }
        assert_eq!(watchers.live(), MAX_WATCHERS);

        let (ours, theirs) = UnixStream::pair().unwrap();
        watchers.adopt(ours, state(0, 0, 0));
        assert_eq!(watchers.live(), MAX_WATCHERS, "the cap must hold");

        theirs
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut line = String::new();
        let n = BufReader::new(theirs).read_line(&mut line).unwrap();
        assert_eq!(n, 0, "a refused watcher must see EOF, got {line:?}");
        drop(peers);
    }

    // ---- offline deletion reconciliation --------------------------------

    fn write_manifest(root: &Path, entries: &[(&str, &str)]) {
        let mut s = String::from("# path\tcloud-id\tsize\tetag\n");
        for (p, id) in entries {
            s.push_str(&format!("{p}\t{id}\t10\t-\n"));
        }
        std::fs::write(root.join(hydration_protocol::names::MANIFEST), s).unwrap();
    }

    fn write_lineage(root: &Path, entries: &[(&str, &str)]) {
        let mut s = String::from("# path\tcloud-id\tetag\n");
        for (p, id) in entries {
            s.push_str(&format!("{p}\t{id}\n"));
        }
        std::fs::write(root.join(hydration_protocol::names::LINEAGE), s).unwrap();
    }

    /// A file present on disk, carrying the cloud id the journal knows it by.
    fn place(root: &Path, rel: &str, cloud_id: &str) {
        let abs = root.join(rel);
        if let Some(parent) = abs.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&abs, b"x").unwrap();
        store::set_xattr(&abs, store::XATTR_ID, cloud_id.as_bytes()).unwrap();
    }

    fn candidate_paths(root: &Path) -> Vec<String> {
        let mut v: Vec<String> = detect_offline_removals(root)
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        v.sort();
        v
    }

    /// The whole point: a file the journal recorded and that is gone now is a
    /// deletion the daemon slept through, and it is found. Both halves of the
    /// journal — a placeholder in the manifest, a hydrated file in the lineage —
    /// are covered.
    #[test]
    fn a_file_deleted_while_the_daemon_was_stopped_is_detected() {
        let root = scratch("offline/detected");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_manifest(&root, &[("kept.pdf", "idK"), ("gone.pdf", "idG")]);
        write_lineage(
            &root,
            &[("Work/kept.txt", "idKH"), ("Work/gone.txt", "idGH")],
        );
        place(&root, "kept.pdf", "idK");
        place(&root, "Work/kept.txt", "idKH");
        // gone.pdf and Work/gone.txt are deleted: recorded, not on disk.

        assert_eq!(
            candidate_paths(&root),
            vec!["Work/gone.txt".to_string(), "gone.pdf".to_string()],
            "a deletion made while the daemon was stopped was not detected"
        );
    }

    /// The safety the whole design turns on: a root with no journal produces no
    /// candidates, whatever is or is not on disk.
    ///
    /// This is the shape of a subvolume that did not mount, or a rebuilt one, or
    /// simply the wrong directory. The record of what was here lives here, so
    /// when the files are gone the record is gone with them, and the difference
    /// is nothing. Files are placed to prove the candidates come from the
    /// journal and never from the disk — an empty journal over a full tree is
    /// still empty.
    #[test]
    fn a_root_with_no_journal_deletes_nothing() {
        let root = scratch("offline/no-journal");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        place(&root, "a.txt", "idA");
        place(&root, "b.txt", "idB");
        assert!(
            detect_offline_removals(&root).is_empty(),
            "a root with no journal produced deletion candidates — the empty-mount \
             catastrophe, arrived at offline"
        );
    }

    /// An offline `mv` inside the sync root is not a deletion.
    ///
    /// The old path is gone from disk, so by absence it looks deleted. But the
    /// object is still here under its new name — the same cloud id sits on the
    /// moved file — so nothing is withdrawn.
    #[test]
    fn an_offline_move_is_not_a_deletion() {
        let root = scratch("offline/moved");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_manifest(&root, &[("old/a.txt", "idA")]);
        place(&root, "new/a.txt", "idA"); // moved: same object, new path

        assert!(
            detect_offline_removals(&root).is_empty(),
            "a file moved while the daemon was stopped was withdrawn from the cloud as \
             though it had been deleted"
        );
    }

    #[test]
    fn a_file_still_present_is_not_a_candidate() {
        let root = scratch("offline/present");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_manifest(&root, &[("a.txt", "idA")]);
        place(&root, "a.txt", "idA");
        assert!(detect_offline_removals(&root).is_empty());
    }

    /// The highest-risk test in the sync-ignore feature: enabling the ignore must
    /// withdraw nothing offline. Last run's journal — written before the switch —
    /// still records every `.git/` path the old client uploaded (measured on the
    /// live account: 1,292 with a recoverable cloud id). On the first start after
    /// the switch the scan stops recording them, so by absence they look deleted,
    /// and withdrawing them would delete real objects from the cloud.
    /// `journal.retain` drops ignored paths before the gone-set is computed, so
    /// not one becomes a candidate — while an ordinary offline deletion beside
    /// them still is, proving the guard is selective, not "delete nothing".
    #[test]
    fn enabling_ignore_withdraws_nothing_offline() {
        let root = scratch("offline/ignore-transition");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        write_manifest(
            &root,
            &[
                ("Projects/Aurora/.git/index", "id1"),
                ("Projects/Aurora/.git/HEAD", "id2"),
                ("Projects/Aurora/.git/refs/heads/main", "id3"),
                ("a/b/.git/config", "id4"),
                ("submodule/.git", "id5"), // a gitlink file
                ("Documents/report.txt", "idReal"),
            ],
        );
        // Nothing is placed on disk, so every journal path looks gone. Without the
        // retain, the .git/ paths would all be withdrawal candidates.
        let gone: Vec<String> = detect_offline_removals(&root)
            .into_iter()
            .map(|(p, _)| p)
            .collect();
        assert_eq!(
            gone,
            vec!["Documents/report.txt".to_string()],
            "a .git/ path was an offline withdrawal candidate — the transition would \
             mass-delete the user's cloud objects"
        );
    }

    /// The folder-create leak, closed. A `.git` directory has leaf `.git`
    /// (is_internal false), so before the sync-ignore it was descended and every
    /// `.git/refs/...` was queued as a cloud folder-create. It must not be now.
    #[test]
    fn unidentified_folders_does_not_descend_git() {
        let root = ctl_scratch("unidentified-git");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("repo/.git/refs/heads")).unwrap();
        std::fs::create_dir_all(root.join("Projects/NewThing")).unwrap();

        let found = unidentified_folders(&root).unwrap();
        assert!(
            found.iter().any(|p| p == "Projects/NewThing"),
            "an ordinary new folder must be a folder-create candidate: {found:?}"
        );
        assert!(
            !found.iter().any(|p| p.contains(".git")),
            "a .git subtree was queued as cloud folder-creates (the leak): {found:?}"
        );
    }

    /// A whole-root disappearance is refused: everything gone is a wrong or
    /// unmounted root, never a deleted folder.
    ///
    /// The whole journal is gone here, which is above the ceiling however large
    /// the tree — the one shape that must never be propagated unasked.
    #[test]
    fn a_whole_root_disappearance_is_refused() {
        let root = scratch("offline/whole-root");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let entries: Vec<(String, String)> = (0..REMOVAL_FLOOR * 2)
            .map(|i| (format!("f{i}.txt"), format!("id{i}")))
            .collect();
        let refs: Vec<(&str, &str)> = entries
            .iter()
            .map(|(p, i)| (p.as_str(), i.as_str()))
            .collect();
        write_manifest(&root, &refs);
        // Nothing placed: every recorded file is gone. That is the catastrophe
        // shape, and it is refused whatever the tree size.
        assert!(
            detect_offline_removals(&root).is_empty(),
            "a whole-root disappearance was withdrawn without being asked"
        );
    }

    /// The point of the proportional guard: a non-empty folder — many more files
    /// than the old flat cap — is withdrawn, because it is a small fraction of
    /// the tree rather than the whole of it.
    ///
    /// A two-thousand-file journal with a hundred and fifty gone under one
    /// folder: past the hundred the flat cap refused, but under a tenth of the
    /// tree, so the deletion propagates.
    #[test]
    fn a_large_folder_that_is_a_small_fraction_is_withdrawn() {
        let root = scratch("offline/large-folder");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let mut journal: Vec<(String, String)> = Vec::new();
        // 1850 files elsewhere, all present.
        for i in 0..1850 {
            journal.push((format!("Other/f{i}.txt"), format!("keep{i}")));
        }
        // 150 files under one folder, all deleted — more than the old cap of 100,
        // but a fifteenth of the 2000-file tree.
        for i in 0..150 {
            journal.push((format!("Photos/2024/p{i}.jpg"), format!("gone{i}")));
        }
        let refs: Vec<(&str, &str)> = journal
            .iter()
            .map(|(p, i)| (p.as_str(), i.as_str()))
            .collect();
        write_manifest(&root, &refs);
        // Place only the 1850 that were kept.
        for i in 0..1850 {
            place(&root, &format!("Other/f{i}.txt"), &format!("keep{i}"));
        }

        let candidates = detect_offline_removals(&root);
        assert_eq!(
            candidates.len(),
            150,
            "a 150-file folder, a fifteenth of a 2000-file tree, was not withdrawn — the flat \
             cap that refused it is exactly what makes deleting a non-empty folder impossible"
        );
        assert!(
            candidates
                .iter()
                .all(|(p, _)| p.starts_with("Photos/2024/")),
            "the withdrawal reached outside the deleted folder"
        );
    }
}

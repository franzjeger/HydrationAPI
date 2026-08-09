//! The unprivileged sync daemon.
//!
//! Holds the credentials, talks to the cloud, runs the upload queue, keeps the
//! backup manifest. Has no capabilities and does not need any.
//!
//! ```text
//! hydration-sync --mount ~/OneDrive --cloud ~/.local/share/hydration/cloud
//! ```
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

use hydration_client::delta::{self, Applied, Cursor, Discover};
use hydration_client::manifest::{BackupPolicy, Manifest};
use hydration_client::place::TmpfilePlacer;
use hydration_client::providers::FolderCloud;
use hydration_client::reclaim;
use hydration_client::store::Store;
use hydration_client::upload::{run_upload, Outcome, Queue, SystemClock};
use hydration_client::{Changes, Daemon};
use hydration_protocol::transport::DaemonConn;
use hydration_protocol::FileId;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Args {
    mount: PathBuf,
    cloud: PathBuf,
    socket: PathBuf,
    debounce: Duration,
}

fn usage() -> ! {
    eprintln!(
        "usage: hydration-sync --mount <dir> [--cloud <dir>] [--socket <path>] \
         [--debounce-secs <n>]"
    );
    std::process::exit(2)
}

fn parse() -> Args {
    let mut mount = None;
    let mut cloud = None;
    let mut socket = None;
    let mut debounce = Duration::from_secs(900);
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--mount" => mount = it.next().map(PathBuf::from),
            "--cloud" => cloud = it.next().map(PathBuf::from),
            "--socket" => socket = it.next().map(PathBuf::from),
            "--debounce-secs" => {
                debounce = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .map(Duration::from_secs)
                    .unwrap_or_else(|| usage())
            }
            "-h" | "--help" => usage(),
            _ => usage(),
        }
    }
    let mount = mount.unwrap_or_else(|| usage());
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    Args {
        cloud: cloud.unwrap_or_else(|| home.join(".local/share/hydration/cloud")),
        socket: socket.unwrap_or_else(default_socket),
        mount,
        debounce,
    }
}

/// `$XDG_RUNTIME_DIR` when there is one: it is user-owned, mode 0700, and wiped
/// at logout, which is exactly the lifetime this socket should have.
fn default_socket() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("hydration-sync.sock")
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
fn dirty_files(root: &std::path::Path) -> io::Result<Vec<FileId>> {
    use hydration_protocol::stamp::{self, State};
    use std::os::unix::fs::MetadataExt;

    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)?.flatten() {
            let path = e.path();
            let Ok(md) = e.metadata() else { continue };
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
            let worth_sending = match stamp::state(&path) {
                Ok(State::Dirty) => true,
                Ok(State::Unstamped) => {
                    // A placeholder is never "unsent content" — it has no
                    // content — and reading one to upload it would hydrate the
                    // very file we are trying to leave alone.
                    md.len() > 0
                        && !matches!(
                            hydration_client::store::get_xattr(
                                &path,
                                hydration_protocol::xattr::DEHYDRATED
                            ),
                            Ok(Some(_))
                        )
                        && !matches!(
                            hydration_client::store::get_xattr(
                                &path,
                                hydration_client::store::XATTR_ID
                            ),
                            Ok(Some(_))
                        )
                }
                _ => false,
            };
            if worth_sending {
                out.push(FileId {
                    fsid: md.dev(),
                    ino: md.ino(),
                });
            }
        }
    }
    Ok(out)
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
fn control(
    socket: &std::path::Path,
    mount: PathBuf,
    queue: Arc<Mutex<Queue<SystemClock>>>,
    exposures: Arc<Mutex<Vec<String>>>,
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
                "status" => {
                    let pending = queue.lock().unwrap().pending();
                    let m = Manifest::build(&mount).unwrap_or_default();
                    let seen = exposures.lock().unwrap();
                    format!(
                        "{pending} unsent\n{}\n{}",
                        hydration_client::manifest::status_line(BackupPolicy::Exclude, m.len()),
                        if seen.is_empty() {
                            "no other mount exposes these files".to_string()
                        } else {
                            format!("WARNING: {} other mount(s) bypass hydration: {seen:?}", seen.len())
                        }
                    )
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

fn main() -> io::Result<()> {
    let args = parse();
    if !args.mount.is_dir() {
        eprintln!(
            "hydration-sync: {} is not a directory",
            args.mount.display()
        );
        std::process::exit(1);
    }

    // Opened once up front so a missing or unwritable cloud directory is a
    // startup failure rather than a surprise on the first fetch.
    FolderCloud::open(&args.cloud)?;

    // A crash between linking a new placeholder and renaming it over the old one
    // leaves a complete file under a scratch name. Nothing else would ever
    // remove it, and the user would see it in their sync folder forever.
    match TmpfilePlacer::sweep_scratch(&args.mount) {
        Ok(0) => {}
        Ok(n) => eprintln!("hydration-sync: swept {n} leftover scratch file(s)"),
        Err(e) => eprintln!("hydration-sync: could not sweep scratch files: {e}"),
    }
    let queue = Arc::new(Mutex::new(Queue::new(
        args.debounce,
        SystemClock::default(),
    )));
    let stop = Arc::new(AtomicBool::new(false));
    // Set when the helper says its change channel has a hole in it, so the
    // upload driver walks instead of trusting what it was told.
    let resync = Arc::new(AtomicBool::new(true));
    // Reported by the helper, shown by the status thread. §6.4a.
    let exposures: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    // Unix socket paths are capped at roughly 108 bytes by the kernel, which is
    // short enough to hit with an ordinary XDG_RUNTIME_DIR under a long home.
    // The raw error ("path must be shorter than SUN_LEN") says nothing about
    // what to do, so say it here.
    if args.socket.as_os_str().len() > 100 {
        eprintln!(
            "hydration-sync: socket path is {} bytes; the kernel limit is about 108. \
             Pass a shorter --socket.",
            args.socket.as_os_str().len()
        );
        std::process::exit(1);
    }
    let _ = std::fs::remove_file(&args.socket);
    let listener = UnixListener::bind(&args.socket)?;
    // Owner-only. The helper checks the peer's uid from its side; this is the
    // half that stops anyone else reaching the content in the first place.
    std::fs::set_permissions(&args.socket, std::fs::Permissions::from_mode(0o600))?;

    eprintln!(
        "hydration-sync: mount={} cloud={} socket={} debounce={}s",
        args.mount.display(),
        args.cloud.display(),
        args.socket.display(),
        args.debounce.as_secs()
    );

    // The upload driver keeps its own store: a held upload must never block a
    // status query behind a shared lock.
    {
        let (q, stop, mount, clouddir, resync) = (
            Arc::clone(&queue),
            Arc::clone(&stop),
            args.mount.clone(),
            args.cloud.clone(),
            Arc::clone(&resync),
        );
        std::thread::spawn(move || {
            let Ok(sink) = FolderCloud::open(&clouddir) else {
                return;
            };
            // Rooted, so an upload from a subdirectory records its path and not
            // just its name — otherwise the next delta pass moves the file to
            // the sync root.
            let mut sink = sink.rooted_at(&mount);
            let mut store = Store::new();
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
                        Ok(found) if !found.is_empty() => {
                            eprintln!(
                                "hydration-sync: resync found {} file(s) changed with no event",
                                found.len()
                            );
                            let mut queue = q.lock().unwrap();
                            for f in found {
                                queue.touch(f);
                            }
                        }
                        Ok(_) => {}
                        Err(e) => eprintln!("hydration-sync: resync walk failed: {e}"),
                    }
                }

                let due = q.lock().unwrap().due();
                if !due.is_empty() {
                    let _ = store.scan(&mount);
                }
                for file in due {
                    q.lock().unwrap().begin(file);
                    let outcome = run_upload(file, &mut store, &mut sink);
                    {
                        let mut queue = q.lock().unwrap();
                        queue.finish(file);
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
                            queue.touch(file);
                        }
                    }
                    eprintln!("hydration-sync: upload {file:?} -> {outcome:?}");
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
        let (q, stop, mount, clouddir) = (
            Arc::clone(&queue),
            Arc::clone(&stop),
            args.mount.clone(),
            args.cloud.clone(),
        );
        std::thread::spawn(move || {
            let Ok(mut cloud) = FolderCloud::open(&clouddir) else {
                return;
            };
            let mut placer = TmpfilePlacer::new(&mount);
            let mut store = Store::new();
            let mut cursor = Cursor::default();
            // Set when a pass deliberately left something for a later one.
            //
            // Without it the *next* pass undoes the decision: a delta feed with
            // nothing new returns an empty batch, and the empty-batch arm below
            // advanced the cursor unconditionally — so the refusal that was
            // held back on purpose was consumed by silence, and the service
            // never mentions those objects again.
            let mut unfinished = false;
            while !stop.load(Ordering::SeqCst) {
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
                        let applied =
                            delta::apply(&mount, &changes, &mut store, &waiting, &mut placer);
                        // The cursor moves only past a pass that finished.
                        //
                        // A delta service does not replay a consumed change, so
                        // advancing past a pass that refused something means the
                        // refusal is permanent however transient its cause —
                        // two objects swapping paths refuse each other on one
                        // pass and would succeed on the next, if there were one.
                        match &applied {
                            Ok(a) if a.retryable => {
                                unfinished = true;
                                eprintln!(
                                    "hydration-sync: delta pass incomplete ({} deferred); \
                                     not advancing",
                                    a.failed.len()
                                );
                            }
                            Ok(_) => {
                                unfinished = false;
                                cursor = next;
                            }
                            Err(_) => unfinished = true,
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
                                for p in &a.kept_local {
                                    eprintln!("hydration-sync:   kept local copy of {p}");
                                }
                                for p in &a.failed {
                                    eprintln!("hydration-sync:   could not apply {p}");
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
                std::thread::sleep(Duration::from_secs(5));
            }
        });
    }

    // The user's way in. §8 item 10's trigger, and the status surface item 11
    // asked for.
    {
        let ctl = args.socket.with_extension("ctl");
        let (mount, q, ex) = (
            args.mount.clone(),
            Arc::clone(&queue),
            Arc::clone(&exposures),
        );
        eprintln!("hydration-sync: control socket at {}", ctl.display());
        std::thread::spawn(move || {
            if let Err(e) = control(&ctl, mount, q, ex) {
                eprintln!("hydration-sync: control socket unavailable: {e}");
            }
        });
    }

    // Status, and the manifest that makes a backup honest.
    {
        let (q, stop, mount, exposures) = (
            Arc::clone(&queue),
            Arc::clone(&stop),
            args.mount.clone(),
            Arc::clone(&exposures),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if let Ok(m) = Manifest::build(&mount) {
                    let _ = m.write(&mount);
                    // §6d: the count goes where "everything synced" goes, not
                    // into a log file nobody opens. This is a daemon, so the log
                    // is what it has — a UI would show the same sentence.
                    eprintln!(
                        "hydration-sync: {} unsent, {}",
                        q.lock().unwrap().pending(),
                        hydration_client::manifest::status_line(BackupPolicy::Exclude, m.len())
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
                std::thread::sleep(Duration::from_secs(30));
            }
        });
    }

    for conn in listener.incoming() {
        let conn = conn?;
        // One helper at a time. A second connection means something unexpected
        // is talking to us, and serving both would be worse than serving
        // neither.
        let mount = args.mount.clone();
        let clouddir = args.cloud.clone();
        match (
            FolderCloud::open(&clouddir),
            Daemon::new(FolderCloud::open(&clouddir)?, &mount),
        ) {
            (Ok(_), Ok(mut daemon)) => {
                eprintln!("hydration-sync: helper connected");
                // Every new connection is a resync point. The helper may have
                // been restarted, and anything edited while it was gone produced
                // no event at all.
                resync.store(true, Ordering::SeqCst);
                daemon.on_change(Box::new(QueueChanges {
                    queue: Arc::clone(&queue),
                    resync: Arc::clone(&resync),
                    exposures: Arc::clone(&exposures),
                }));
                let mut c = DaemonConn::new(conn)?;
                if let Err(e) = daemon.serve(&mut c) {
                    eprintln!("hydration-sync: helper connection ended: {e}");
                } else {
                    eprintln!("hydration-sync: helper disconnected");
                }
            }
            _ => eprintln!("hydration-sync: could not open the cloud directory"),
        }
    }
    Ok(())
}

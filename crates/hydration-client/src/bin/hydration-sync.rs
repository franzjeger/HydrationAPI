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
use hydration_client::store::Store;
use hydration_client::upload::{run_upload, Queue, SystemClock};
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
}

impl Changes for QueueChanges {
    fn changed(&mut self, files: &[FileId]) {
        let Ok(mut q) = self.queue.lock() else { return };
        for f in files {
            q.touch(*f);
        }
    }

    fn resync(&mut self) {
        // The channel admitted it is incomplete. Walking is the only honest
        // recovery: the dropped events are gone, and nothing else will mention
        // those files again.
        self.resync.store(true, Ordering::SeqCst);
    }
}

/// Everything in the sync directory that no longer looks the way the framework
/// left it.
///
/// Deliberately not "everything with a cloud id", and deliberately not
/// "everything": a file the framework has never written is the user's own and is
/// left to change detection, or it would be queued for upload on every resync
/// forever. Only files that were once clean and are no longer count.
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
            if matches!(stamp::state(&path), Ok(State::Dirty)) {
                out.push(FileId {
                    fsid: md.dev(),
                    ino: md.ino(),
                });
            }
        }
    }
    Ok(out)
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
            let Ok(mut sink) = FolderCloud::open(&clouddir) else {
                return;
            };
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
                    q.lock().unwrap().finish();
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
            while !stop.load(Ordering::SeqCst) {
                match cloud.changes(&cursor) {
                    Ok((changes, next)) if !changes.is_empty() => {
                        cursor = next;
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
                        match applied {
                            Ok(a) if a != Applied::default() => {
                                eprintln!(
                                    "hydration-sync: delta +{} ~{} -{} kept-local {} failed {}",
                                    a.created,
                                    a.updated,
                                    a.removed,
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
                    Ok((_, next)) => cursor = next,
                    Err(e) => eprintln!("hydration-sync: could not list the cloud: {e}"),
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        });
    }

    // Status, and the manifest that makes a backup honest.
    {
        let (q, stop, mount) = (Arc::clone(&queue), Arc::clone(&stop), args.mount.clone());
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

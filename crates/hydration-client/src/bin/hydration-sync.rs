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

use hydration_client::manifest::{BackupPolicy, Manifest};
use hydration_client::providers::FolderCloud;
use hydration_client::store::Store;
use hydration_client::upload::{run_upload, Queue, SystemClock};
use hydration_client::Daemon;
use hydration_protocol::transport::DaemonConn;
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
    let queue = Arc::new(Mutex::new(Queue::new(
        args.debounce,
        SystemClock::default(),
    )));
    let stop = Arc::new(AtomicBool::new(false));

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
        let (q, stop, mount, clouddir) = (
            Arc::clone(&queue),
            Arc::clone(&stop),
            args.mount.clone(),
            args.cloud.clone(),
        );
        std::thread::spawn(move || {
            let Ok(mut sink) = FolderCloud::open(&clouddir) else {
                return;
            };
            let mut store = Store::new();
            while !stop.load(Ordering::SeqCst) {
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

//! The unprivileged sync daemon.
//!
//! Holds the credentials, talks to the cloud, runs the upload queue, keeps the
//! backup manifest. Has no capabilities and does not need any.
//!
//! ```text
//! hydration-sync --mount ~/OneDrive --cloud ~/.local/share/hydration/cloud
//! ```
//!
//! There is almost nothing here. The run loop lives in
//! [`hydration_client::daemon_loop`], which knows about clouds only through
//! [`hydration_client::CloudAccess`] — so this file is the one place that says
//! *which* cloud, and a client with a real service writes its own version of
//! exactly this much. The socket direction, and why this end is the one that
//! listens, is documented there.

use hydration_client::daemon_loop::{self, Config};
use hydration_client::providers::FolderAccess;
use std::io;
use std::path::PathBuf;
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
    let mut debounce = hydration_client::upload::QUIET_PERIOD;
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

    // Unix socket paths are capped at roughly 108 bytes by the kernel, which is
    // short enough to hit with an ordinary XDG_RUNTIME_DIR under a long home.
    // The raw error ("path must be shorter than SUN_LEN") says nothing about
    // what to do, so say it here — where `--socket` is a thing that exists.
    if args.socket.as_os_str().len() > 100 {
        eprintln!(
            "hydration-sync: socket path is {} bytes; the kernel limit is about 108. \
             Pass a shorter --socket.",
            args.socket.as_os_str().len()
        );
        std::process::exit(1);
    }

    // The one decision this binary makes. Everything below the line is the same
    // for a folder, for Graph, for anything.
    let access = FolderAccess::new(&args.cloud, &args.mount);
    eprintln!("hydration-sync: cloud={}", args.cloud.display());

    daemon_loop::run(
        Config {
            mount: args.mount,
            socket: args.socket,
            debounce: args.debounce,
            eviction: None,
        },
        access,
    )
}

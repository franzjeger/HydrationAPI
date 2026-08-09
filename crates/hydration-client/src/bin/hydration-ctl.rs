//! Talking to a running sync daemon.
//!
//! ```text
//! hydration-ctl status
//! hydration-ctl evict Documents/big-video.mp4
//! ```
//!
//! Everything here is done *by the daemon*, not by this process, and that is the
//! point rather than an implementation detail. A standalone tool could evict a
//! file the daemon is uploading right now, and the delete-during-upload rule
//! (§5.5) would then see the inode change and remove the object it had just
//! created. Only the process that owns the upload queue can refuse that.
//!
//! It needs no privilege. Turning a file back into a placeholder is done by
//! building the replacement on an anonymous inode and swapping it in, which the
//! unprivileged side can do on its own — so the privileged helper is never asked
//! to accept a path, and §6b holds without anyone having to remember it (§6b,
//! §6a-ter).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

fn usage() -> ! {
    eprintln!(
        "usage: hydration-ctl [--socket <path>] <status | evict <relative-path>>\n\
         \n\
         Paths are relative to the sync directory. `evict` gives back the disk a\n\
         file occupies, keeping it readable — reading it fetches the content again.\n\
         It refuses any file the cloud does not already have, so nothing that\n\
         exists only on this machine can be thrown away."
    );
    std::process::exit(2)
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mut socket = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
        .join("hydration-sync.ctl");

    let mut words: Vec<String> = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next().map(Into::into).unwrap_or_else(|| usage()),
            "-h" | "--help" => usage(),
            _ => words.push(a),
        }
    }
    if words.is_empty() {
        usage();
    }

    let mut conn = match UnixStream::connect(&socket) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "hydration-ctl: no sync daemon at {} ({e})\n\
                 Is hydration-sync running? Pass --socket if it uses another path.",
                socket.display()
            );
            std::process::exit(1);
        }
    };
    writeln!(conn, "{}", words.join(" "))?;
    conn.flush()?;

    // One command, one reply — but a reply may be several lines, and the daemon
    // keeps the connection open for more, so read until it goes quiet rather
    // than until EOF.
    conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    let reader = BufReader::new(conn);
    let mut said_anything = false;
    for line in reader.lines() {
        match line {
            Ok(l) => {
                println!("{l}");
                said_anything = true;
            }
            Err(_) => break,
        }
    }
    if !said_anything {
        eprintln!("hydration-ctl: the daemon closed without answering");
        std::process::exit(1);
    }
    Ok(())
}

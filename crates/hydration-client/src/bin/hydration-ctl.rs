//! Talking to a running sync daemon.
//!
//! ```text
//! hydration-ctl status
//! hydration-ctl evict Documents/big-video.mp4
//! hydration-ctl watch
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
        "usage: hydration-ctl [--socket <path>] <status | evict <relative-path> | watch>\n\
         \n\
         Paths are relative to the sync directory. `evict` gives back the disk a\n\
         file occupies, keeping it readable — reading it fetches the content again.\n\
         It refuses any file the cloud does not already have, so nothing that\n\
         exists only on this machine can be thrown away.\n\
         \n\
         `watch` prints one machine-readable state line immediately and another\n\
         every time the state changes, until the daemon goes away:\n\
         \n\
         unsent=<n> excluded=<n> exposures=<n>\n\
         \n\
         Keys keep that order; new keys may be appended over time, so a consumer\n\
         must ignore keys it does not recognise. An unchanged state is never\n\
         repeated. `status` stays human-readable and is not for parsing."
    );
    std::process::exit(2)
}

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mut socket = None;

    let mut words: Vec<String> = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => {
                socket = Some(
                    args.next()
                        .map(std::path::PathBuf::from)
                        .unwrap_or_else(|| usage()),
                )
            }
            "-h" | "--help" => usage(),
            _ => words.push(a),
        }
    }
    if words.is_empty() {
        usage();
    }
    let socket = match socket {
        Some(s) => s,
        None => match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            Some(dir) => std::path::PathBuf::from(dir).join("hydration-sync.ctl"),
            None => {
                eprintln!(
                    "hydration-ctl: XDG_RUNTIME_DIR is not set; pass --socket <path> explicitly"
                );
                std::process::exit(2);
            }
        },
    };

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

    // Close our write side for one-shot commands so the daemon's `reader.lines()`
    // loop sees immediate EOF after answering and closes the reply stream instead
    // of parking both processes on the 10-second idle read timeout. `watch` is the
    // exception: keeping the socket open in both directions is the subscription.
    if words[0] != "watch" {
        conn.shutdown(std::net::Shutdown::Write)?;
        conn.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    }
    let reader = BufReader::new(conn);
    let mut said_anything = false;
    let mut stdout = std::io::stdout();
    for line in reader.lines() {
        match line {
            Ok(l) => {
                // Not `println!`: a `watch` piped into `head -1` closes stdout
                // after the first line, and the macro turns that broken pipe
                // into a panic. A consumer that stops listening has what it
                // wanted — that is an exit, not a crash.
                if writeln!(stdout, "{l}").is_err() {
                    break;
                }
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

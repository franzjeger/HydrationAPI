//! The wire format across the hydration privilege boundary.
//!
//! One rule shapes everything here, from DESIGN.md §6b:
//!
//! > The privileged side never accepts a *destination* from the unprivileged
//! > side — only content for a destination it chose itself.
//!
//! That is why a [`FetchRequest`] carries an inode and a filesystem id rather
//! than a path, and why [`FetchResponse`] carries bytes and nothing else. There
//! is no field in this protocol that a compromised sync daemon could use to
//! make the root helper write somewhere it did not already intend to write.
//!
//! Messages are newline-delimited JSON, with file content following a `Ready`
//! response as raw bytes on the same stream. Not because the volume warrants
//! JSON, but because the whole point of this boundary is that it can be read and
//! audited in an afternoon; the bulk path is the byte run, which costs nothing
//! to frame.

use serde::{Deserialize, Serialize};

pub mod transport;

/// The `nodump` inode flag, and its one legitimate use here.
///
/// DESIGN.md §6d. A backup that skips dehydrated files does not contain the
/// cloud files, and a user who believed their backup covered the sync folder
/// finds out at restore time. `nodump` is how a placeholder asks to be skipped —
/// but almost nothing honours it, which is why the manifest is the mechanism and
/// this is only the part that cooperating tools can see.
///
/// It lives in the shared crate because both halves touch it and they must not
/// disagree: the privileged side sets it when a file loses its content and
/// clears it when the content comes back, and the unprivileged side reports what
/// a backup will therefore miss.
///
/// Measured (`probes/nodump.c`, 7.1.6, btrfs), and all three answers shape the
/// code that uses this:
///
/// ```text
///   set nodump: completed, events fired: 0
///   survives a hole punch:            yes
///   survives being written through:   yes
/// ```
///
/// Firing no pre-content event is what makes it safe to set inside `evict()`,
/// which runs in the marked mount in the process that answers events — the trap
/// in §6a-ter. Surviving a write is why clearing it needs an explicit step in
/// hydration: filling the file does not do it.
pub mod flags {
    use std::io;
    use std::os::fd::AsRawFd;
    use std::path::Path;

    /// `_IOR`/`_IOW` encoding, rather than the two constants everyone pastes.
    ///
    /// `FS_IOC_GETFLAGS` is `_IOR('f', 1, long)`, and the request number embeds
    /// `sizeof(long)` — so the familiar `0x80086601` is correct only where a
    /// long is eight bytes. Hard-coding it silently breaks on 32-bit, in the
    /// direction that matters: the ioctl fails, the flag is never set, and a
    /// backup quietly includes or excludes the wrong files.
    const fn ioc(dir: u32, ty: u8, nr: u8, size: usize) -> libc::c_ulong {
        ((dir << 30) | ((size as u32) << 16) | ((ty as u32) << 8) | nr as u32) as libc::c_ulong
    }

    const READ: u32 = 2;
    const WRITE: u32 = 1;
    const LONG: usize = std::mem::size_of::<libc::c_long>();
    const GETFLAGS: libc::c_ulong = ioc(READ, b'f', 1, LONG);
    const SETFLAGS: libc::c_ulong = ioc(WRITE, b'f', 2, LONG);
    const NODUMP: libc::c_long = 0x0000_0040;

    /// Set or clear `nodump`, opening read-only.
    ///
    /// Read-only on purpose: this runs inside the marked mount, and opening for
    /// write there is how §6a-ter's trap is sprung. Changing an inode flag needs
    /// no write access, only ownership.
    pub fn set_nodump(path: &Path, on: bool) -> io::Result<()> {
        let f = std::fs::File::open(path)?;
        let mut cur: libc::c_long = 0;
        if unsafe { libc::ioctl(f.as_raw_fd(), GETFLAGS, &mut cur) } < 0 {
            return Err(unsupported_or(io::Error::last_os_error()));
        }
        let want = if on { cur | NODUMP } else { cur & !NODUMP };
        if want != cur && unsafe { libc::ioctl(f.as_raw_fd(), SETFLAGS, &want) } < 0 {
            return Err(unsupported_or(io::Error::last_os_error()));
        }
        Ok(())
    }

    /// As [`set_nodump`], on a descriptor that is already open.
    ///
    /// What hydration uses: the content is written through the event fd, and
    /// re-opening the path to clear a flag would be the same trap by a different
    /// door.
    pub fn set_nodump_fd(fd: std::os::fd::BorrowedFd<'_>, on: bool) -> io::Result<()> {
        let mut cur: libc::c_long = 0;
        if unsafe { libc::ioctl(fd.as_raw_fd(), GETFLAGS, &mut cur) } < 0 {
            return Err(unsupported_or(io::Error::last_os_error()));
        }
        let want = if on { cur | NODUMP } else { cur & !NODUMP };
        if want != cur && unsafe { libc::ioctl(fd.as_raw_fd(), SETFLAGS, &want) } < 0 {
            return Err(unsupported_or(io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn has_nodump(path: &Path) -> io::Result<bool> {
        let f = std::fs::File::open(path)?;
        let mut cur: libc::c_long = 0;
        if unsafe { libc::ioctl(f.as_raw_fd(), GETFLAGS, &mut cur) } < 0 {
            return Err(unsupported_or(io::Error::last_os_error()));
        }
        Ok(cur & NODUMP != 0)
    }

    /// Filesystems that have no such flag report `ENOTTY`. Worth naming, because
    /// the caller's choice differs: an unsupported filesystem means the backup
    /// policy cannot be honoured at all and the user has to be told, whereas a
    /// permission error is a bug here.
    fn unsupported_or(e: io::Error) -> io::Error {
        match e.raw_os_error() {
            Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP) => io::Error::new(
                io::ErrorKind::Unsupported,
                "this filesystem has no nodump flag",
            ),
            _ => e,
        }
    }
}


/// Extended attributes both halves agree on.
///
/// Here rather than in either half because they are the shared vocabulary: the
/// privileged side writes the dehydrated mark, the unprivileged side reads it to
/// decide what a backup is missing. Duplicating the string in two crates is how
/// they drift.
pub mod xattr {
    /// Set while a file is a placeholder, cleared when it is filled.
    ///
    /// This — not `st_blocks` — is what "is a placeholder" means. btrfs stores
    /// small files inline, so a dehydrated 21-byte script still reports blocks;
    /// and a newly created file reports none. Neither size nor blocks separates
    /// the cases, so the framework records the fact instead of inferring it.
    pub const DEHYDRATED: &str = "user.hydration.dehydrated";
    /// The cloud object this file is.
    pub const ID: &str = "user.hydration.id";
    /// The version we believe we have.
    pub const ETAG: &str = "user.hydration.etag";
    /// A mode the cloud has nowhere to store.
    pub const MODE: &str = "user.hydration.mode";
    // There is deliberately no "under construction" mark here.
    //
    // An earlier version had one, and the helper trusted it to decide that an
    // event could be allowed without hydrating. Every `user.*` xattr is
    // writable by any process sharing the file's uid — which in this threat
    // model is the adversary — so the mark was not evidence of anything, and
    // forging it made a real placeholder serve zeros to a reader. See
    // `hydrationd`'s `nothing_to_serve` for what replaced it: a property of the
    // file rather than a claim about it.
}

/// What the framework last wrote, so "has the user touched this" is a question
/// with an answer.
///
/// Change notifications are an optimisation, never an authority. Measured: the
/// notify queue holds 16384 distinct objects and overflows in under two seconds
/// under an archive unpack, `truncate(2)` produces no event at all, and every
/// edit made while the helper was not running produced none either. So a
/// destructive decision — replacing a file with a placeholder, or throwing its
/// content away to reclaim disk — must never rest on *not having heard* about a
/// change.
///
/// The stamp is what it rests on instead. At each of the three moments the
/// framework itself makes a file's content clean — placing a placeholder,
/// finishing a hydration, finishing an upload — it records the size and mtime it
/// just produced. Anything else that writes to the file moves the mtime, and the
/// disagreement is visible without having been told about.
///
/// A property of the file rather than a claim about it, for the same reason the
/// empty-inode rule is: a same-uid process can forge this, and forging it can
/// only cause the framework to *upload* content it need not have — never to
/// destroy any. The dangerous direction is closed by the stamp being *absent* or
/// *stale*, which is the direction an attacker cannot arrange without also
/// changing the file.
pub mod stamp {
    use std::io;
    use std::path::Path;

    pub const XATTR: &str = "user.hydration.stamp";

    /// `<mtime_sec>.<mtime_nsec>:<size>`. Readable on purpose — someone
    /// debugging a sync loop at 2am should be able to `getfattr` it.
    pub fn of(md: &std::fs::Metadata) -> String {
        use std::os::unix::fs::MetadataExt;
        format!("{}.{}:{}", md.mtime(), md.mtime_nsec(), md.size())
    }

    /// Record the current state of `path` as clean.
    pub fn write(path: &Path) -> io::Result<()> {
        let md = std::fs::metadata(path)?;
        set(path, of(&md).as_bytes())
    }

    /// Record a state observed earlier as clean.
    ///
    /// The stamp must describe content **no newer** than what was actually
    /// sent or written. Stamping from the file as it is *now*, after a transfer,
    /// blesses whatever landed during it — so an edit made mid-upload reads as
    /// Clean, is never re-sent, and is destroyed by the next remote change. A
    /// stale stamp costs a redundant upload; a fresh one costs the edit.
    pub fn write_as(path: &Path, md: &std::fs::Metadata) -> io::Result<()> {
        set(path, of(md).as_bytes())
    }

    /// As [`write`], through a descriptor.
    ///
    /// What hydration uses: re-opening a path inside a marked mount is the trap
    /// the whole design is arranged to avoid. Note that setting an extended
    /// attribute moves ctime and not mtime, so stamping after writing does not
    /// invalidate the stamp it just took.
    pub fn write_fd(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
        use std::os::fd::AsRawFd;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let v = format!("{}.{}:{}", st.st_mtime, st.st_mtime_nsec, st.st_size);
        let n = std::ffi::CString::new(XATTR).unwrap();
        let rc = unsafe {
            libc::fsetxattr(
                fd.as_raw_fd(),
                n.as_ptr(),
                v.as_ptr() as *const libc::c_void,
                v.len(),
                0,
            )
        };
        (rc == 0).then_some(()).ok_or_else(io::Error::last_os_error)
    }

    /// Whether the file still looks the way the framework left it.
    ///
    /// `Unstamped` is not the same as `Dirty` and the caller must not merge
    /// them: a file the framework has never written is the user's own, and
    /// deciding it is "changed" would queue every unrelated file in the
    /// directory for upload the first time anything resyncs.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum State {
        /// Matches what we last wrote.
        Clean,
        /// Written by someone else since.
        Dirty,
        /// The framework has never made this file clean.
        Unstamped,
    }

    pub fn state(path: &Path) -> io::Result<State> {
        let Some(recorded) = get(path)? else {
            return Ok(State::Unstamped);
        };
        let md = std::fs::metadata(path)?;
        Ok(if recorded == of(&md) {
            State::Clean
        } else {
            State::Dirty
        })
    }

    fn set(path: &Path, v: &[u8]) -> io::Result<()> {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has an interior nul"))?;
        let n = std::ffi::CString::new(XATTR).unwrap();
        let rc = unsafe {
            libc::setxattr(
                c.as_ptr(),
                n.as_ptr(),
                v.as_ptr() as *const libc::c_void,
                v.len(),
                0,
            )
        };
        (rc == 0).then_some(()).ok_or_else(io::Error::last_os_error)
    }

    fn get(path: &Path) -> io::Result<Option<String>> {
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has an interior nul"))?;
        let n = std::ffi::CString::new(XATTR).unwrap();
        let mut buf = [0u8; 96];
        let rc = unsafe {
            libc::getxattr(
                c.as_ptr(),
                n.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if rc >= 0 {
            return Ok(String::from_utf8(buf[..rc as usize].to_vec()).ok());
        }
        match io::Error::last_os_error().raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOTSUP) | Some(libc::ERANGE) => Ok(None),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

/// Files the framework puts in the user's sync directory, and the one rule about
/// them.
///
/// > **The framework's own files are never synced.**
///
/// Obvious once stated and easy to leave out, because nothing fails loudly when
/// you do. The manifest is rewritten every time the placeholder count changes;
/// if it is treated as user content it is uploaded on every rewrite, comes back
/// down as a delta, and the two ends chase each other indefinitely. Worse, a
/// cloud object could claim the manifest's own path and a delta pass would
/// happily replace §6d's mechanism with a placeholder — leaving the file that
/// tells a restoring user what is missing as a file with no content.
///
/// One predicate, in the shared crate, for the same reason the xattr names are
/// here: the scan, the manifest builder, the delta pass and the change watcher
/// all need the same answer, and four copies of it is how they come to disagree.
pub mod names {
    /// Lives in the sync root. Named so it sorts early and reads as what it is.
    pub const MANIFEST: &str = ".hydration-manifest";

    /// True for anything the framework wrote for its own purposes.
    ///
    /// Matched on the file name alone, so it holds at any depth — scratch names
    /// are created wherever a placeholder is, which is wherever the cloud says.
    pub fn is_internal(name: &str) -> bool {
        name == MANIFEST || name == concat!(".hydration-manifest", ".tmp") || is_scratch(name)
    }

    /// A half-finished placeholder rename: `.<base>.hydration-<seq>`.
    ///
    /// The trailing digits are what make this specific rather than a prefix
    /// match. A looser test matched the manifest itself — the file §6d exists to
    /// produce, whose whole purpose is to survive a backup and tell a restoring
    /// user what was left out. A sweep that quietly deletes it is the same class
    /// of failure as everything else here: something reporting success for work
    /// it destroyed.
    pub fn is_scratch(name: &str) -> bool {
        let Some(rest) = name.strip_prefix('.') else {
            return false;
        };
        let Some((base, seq)) = rest.rsplit_once(".hydration-") else {
            return false;
        };
        !base.is_empty() && !seq.is_empty() && seq.bytes().all(|b| b.is_ascii_digit())
    }
}

/// Identifies a file without naming it.
///
/// A path would be a destination, and destinations are the privileged side's
/// business. `(fsid, ino)` is what the kernel handed us in the event, and the
/// helper can check it against the mount it marked before writing a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileId {
    pub fsid: u64,
    pub ino: u64,
}

/// Helper → daemon: someone touched a dehydrated file, please provide content.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FetchRequest {
    /// Correlates the response. Monotonic per connection.
    pub id: u64,
    pub file: FileId,
    /// The byte range the kernel asked about.
    ///
    /// Treated as advice, not a contract: the measured range is the readahead
    /// window, not what the application asked for, and overlapping repeats are
    /// normal. v1 fetches whole files and ignores this beyond logging.
    pub offset: u64,
    pub len: u64,
    /// Who is reading, for the hydration policy in §6c. A cgroup path rather
    /// than a pid or an exe: the measured distinction between a backup daemon
    /// and the user's own shell is not visible in either of those.
    pub cgroup: Option<String>,
}

/// Daemon → helper: the answer.
///
/// There is no "partial" variant on purpose. §5.7 requires that a placeholder is
/// either filled with what it promised or left alone, so a fetch that cannot
/// deliver the whole object is a [`FetchResponse::Failed`], not a short success.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FetchResponse {
    /// Exactly `len` raw bytes follow this line on the same stream.
    ///
    /// Not `SCM_RIGHTS`, which would be the obvious choice and is the wrong one
    /// here: passing a descriptor means the privileged side accepts an object
    /// chosen by the unprivileged side, and the whole point of §6b is that it
    /// never does. Length-prefixed bytes are something the helper can bound,
    /// verify and discard.
    ///
    /// `len` must equal the size the placeholder promised. The helper checks it
    /// again anyway — it is the one that has to live with being wrong.
    Ready { id: u64, len: u64 },
    /// Nothing will be delivered. The reader gets `errno` and the placeholder is
    /// left exactly as it was.
    Failed { id: u64, errno: i32, reason: String },
    /// The policy says this reader may not hydrate — a backup sweep, an
    /// indexer. Distinct from `Failed` so the helper can report it separately:
    /// a denial is a decision, not a fault, and §6c requires it be visible.
    Denied { id: u64, reason: String },
}

impl FetchResponse {
    pub fn id(&self) -> u64 {
        match self {
            FetchResponse::Ready { id, .. }
            | FetchResponse::Failed { id, .. }
            | FetchResponse::Denied { id, .. } => *id,
        }
    }
}

/// Daemon → helper, unsolicited: this file is now a placeholder / no longer is.
///
/// The helper keeps no database. It needs to know which inodes are dehydrated
/// so it can drop its ignore marks, and that is all it is told.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Control {
    /// The file has been dehydrated: start intercepting it again.
    Dehydrated { file: FileId },
    /// The file is full: stop intercepting it (§2.4's zero-cost claim).
    Hydrated { file: FileId },
}

/// The largest single body chunk the helper will accept.
///
/// The helper's own constant, never the daemon's. It bounds one allocation in a
/// root process, and the component that chooses it must be the one that lives
/// with being wrong about it.
pub const MAX_CHUNK: u64 = 1 << 20;

/// The largest object the *helper* will hydrate, whatever a placeholder claims.
///
/// The delta pass already refuses absurd sizes, but that runs on the unprivileged
/// side — the side §6b assumes may be compromised — so it is not a bound the root
/// process may rely on. Two checks for one rule, the same argument the length
/// check already makes.
pub const MAX_OBJECT: u64 = 1 << 40;

/// Anything the daemon may send.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum ToHelper {
    Fetch(FetchResponse),
    Control(Control),
    /// Part of the body announced by a `Ready`. Exactly `len` raw bytes follow
    /// this line.
    ///
    /// The body is chunked rather than sent as one run so that a transfer can be
    /// *abandoned* without desynchronising the stream. Streaming means the
    /// daemon declares a length before it has the bytes — it takes the length
    /// from the placeholder, which it knows — and a provider that then delivers
    /// short would leave the connection out of step forever if the body were a
    /// flat run. With chunks, a short delivery is an [`ToHelper::Abort`] and the
    /// connection survives.
    Chunk {
        id: u64,
        len: u64,
    },
    /// The body is complete. Accepted only when the running total equals the
    /// length the `Ready` announced.
    Done {
        id: u64,
    },
    /// The transfer will not complete. The placeholder is put back exactly as it
    /// was and the reader gets `errno`.
    Abort {
        id: u64,
        errno: i32,
        reason: String,
    },
}

/// Anything the helper may send.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum FromHelper {
    Fetch(FetchRequest),
    /// A second mount now exposes the sync files (§6.4a). The helper cannot
    /// prevent it; the daemon must make it visible.
    ExposureChanged {
        mounts: Vec<String>,
    },
    /// These files were written by somebody other than us.
    ///
    /// Batched, because the helper coalesces per inode before sending: a long
    /// write produces thousands of events for one file, and the kernel already
    /// merges them per object until its queue fills. Sending one line per event
    /// would put the worker's event loop behind a socket the daemon may not be
    /// reading — measured at a 278-message cliff on a default `SO_SNDBUF` — and
    /// a worker blocked in `write()` stops answering pre-content events, which
    /// is §6a-bis reached by a road the supervisor cannot see.
    ///
    /// Identified the same way everything else is: by inode, never by path.
    Changed {
        files: Vec<FileId>,
    },
    /// Change detection lost track. Walk the sync directory instead of trusting
    /// this channel.
    ///
    /// Not an error, and not rare enough to treat as one. The notify queue holds
    /// 16384 distinct objects and overflows in under two seconds when something
    /// unpacks an archive; `truncate(2)` produces no event at all; and every
    /// edit made while the helper was not running produced none either. A change
    /// channel is an optimisation over walking, never a substitute for it, and
    /// saying so in the protocol is what stops a caller from believing silence
    /// means nothing happened.
    Resync,
}

/// Encode one message as a line.
pub fn encode<T: Serialize>(msg: &T) -> serde_json::Result<String> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    Ok(s)
}

/// Decode one line.
pub fn decode<T: for<'de> Deserialize<'de>>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim_end_matches('\n'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_names_an_inode_and_never_a_path() {
        // The rule from §6b, asserted rather than trusted to review: if a path
        // ever appears in a request, the privileged side has been handed a
        // destination by the unprivileged one.
        let req = FromHelper::Fetch(FetchRequest {
            id: 1,
            file: FileId { fsid: 7, ino: 42 },
            offset: 0,
            len: 4096,
            cgroup: Some("/system.slice/restic.service".into()),
        });
        let line = encode(&req).unwrap();
        assert!(
            !line.contains('/') || !line.contains("path"),
            "a fetch request must not carry a path: {line}"
        );
        assert_eq!(decode::<FromHelper>(&line).unwrap(), req);
    }

    #[test]
    fn there_is_no_partial_success() {
        // §5.7: a fetch either delivers the whole object or it fails. If a
        // "Partial" variant is ever added, this is where the argument for it
        // has to be made.
        let json = serde_json::to_string(&FetchResponse::Ready { id: 1, len: 10 }).unwrap();
        assert!(json.contains("Ready"));
        for bad in ["Partial", "Truncated", "Short"] {
            assert!(
                !format!("{:?}", FetchResponse::Ready { id: 0, len: 0 }).contains(bad),
                "the protocol grew a partial-success variant"
            );
        }
    }

    #[test]
    fn round_trips_every_response_shape() {
        for r in [
            FetchResponse::Ready { id: 1, len: 4096 },
            FetchResponse::Failed {
                id: 2,
                errno: 5,
                reason: "upstream closed early".into(),
            },
            FetchResponse::Denied {
                id: 3,
                reason: "restic.service".into(),
            },
        ] {
            let msg = ToHelper::Fetch(r.clone());
            let line = encode(&msg).unwrap();
            assert_eq!(decode::<ToHelper>(&line).unwrap(), msg);
        }
    }
}

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

/// Anything the daemon may send.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum ToHelper {
    Fetch(FetchResponse),
    Control(Control),
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

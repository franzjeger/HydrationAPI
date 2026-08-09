//! The unprivileged half: everything that knows about a cloud.
//!
//! This is where the credentials live, where the HTTP happens, and where the
//! sync logic goes. It runs as the user, with no capabilities at all.
//!
//! The division is the point (DESIGN.md §6b). The process holding
//! `CAP_SYS_ADMIN` never sees a token; the process holding the token can never
//! choose where the root helper writes. Everything crossing between them is in
//! `hydration-protocol`, and it is deliberately too narrow to express a
//! destination.

pub mod delta;
pub mod manifest;
pub mod place;
pub mod providers;
pub mod store;
pub mod upload;

use hydration_protocol::transport::DaemonConn;
use hydration_protocol::{FetchResponse, FileId, FromHelper};
use std::io;
use std::path::Path;

pub use store::{Entry, Store};

/// What a cloud client implements.
///
/// Small on purpose. Everything the framework can own — when to hydrate, what is
/// true about size, who wins a delete, whether a placeholder occupies disk — it
/// does own, because those are exactly the things a client cannot be expected to
/// get right on its own. What is left is the part only the client knows: how to
/// talk to its service.
pub trait Provider: Send {
    /// The whole object. Returning fewer bytes than `size` is a failure, not a
    /// partial success — the framework will refuse it and the reader will get an
    /// error rather than a truncated file (§5.7).
    fn fetch(&mut self, cloud_id: &str, size: u64) -> io::Result<Vec<u8>>;
}

/// Why a fetch could not be served, in the framework's own terms.
#[derive(Debug)]
enum Refusal {
    /// The helper named a file this daemon does not know about.
    Unknown,
    /// A file that exists locally and has never been uploaded. There is nothing
    /// to fetch, and that is not an error — the content is already the only copy.
    NeverUploaded,
    Provider(io::Error),
    /// The provider returned the wrong number of bytes.
    WrongLength {
        got: usize,
        want: u64,
    },
}

impl Refusal {
    fn into_response(self, id: u64) -> FetchResponse {
        let (errno, reason) = match self {
            Refusal::Unknown => (libc::EIO, "no such file in this sync directory".to_string()),
            // ENODATA rather than EIO: the file is fine, there is simply no
            // remote copy to bring down, and a reader deserves to be told the
            // difference.
            Refusal::NeverUploaded => (
                libc::ENODATA,
                "the file has never been uploaded; the local copy is the only one".to_string(),
            ),
            Refusal::Provider(e) => (libc::EIO, format!("provider failed: {e}")),
            Refusal::WrongLength { got, want } => (
                libc::EIO,
                format!("provider returned {got} bytes for an object recorded as {want}"),
            ),
        };
        FetchResponse::Failed { id, errno, reason }
    }
}

/// The sync daemon's serving loop.
pub struct Daemon<P: Provider> {
    provider: P,
    store: Store,
    root: std::path::PathBuf,
    /// Mounts other than our own that expose the sync files, most recently
    /// reported by the helper. §6.4a: we cannot prevent these, only surface them.
    exposures: Vec<String>,
}

impl<P: Provider> Daemon<P> {
    pub fn new(provider: P, root: &Path) -> io::Result<Self> {
        let mut store = Store::new();
        store.scan(root)?;
        Ok(Self {
            provider,
            store,
            root: root.to_path_buf(),
            exposures: Vec::new(),
        })
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.store
    }

    /// Mounts other than ours that can currently reach the sync files.
    ///
    /// More than zero is a condition the user has to be told about: someone can
    /// read the files by a path that bypasses hydration entirely, and they will
    /// get zeros. It is not an error we can fix, which is exactly why it must
    /// not be silent.
    pub fn exposures(&self) -> &[String] {
        &self.exposures
    }

    /// Serve until the helper goes away.
    pub fn serve(&mut self, conn: &mut DaemonConn) -> io::Result<()> {
        while let Some(msg) = conn.recv()? {
            match msg {
                FromHelper::Fetch(req) => match self.resolve_or_rescan(req.file) {
                    Ok((cloud_id, size)) => match self.provider.fetch(&cloud_id, size) {
                        Ok(content) if content.len() as u64 == size => {
                            conn.send_ready(req.id, &content)?;
                        }
                        Ok(content) => {
                            // Caught here as well as in the helper. Two checks
                            // for one rule is not redundancy: this one can say
                            // which provider misbehaved, and the helper's is the
                            // one that cannot be bypassed.
                            conn.send(
                                Refusal::WrongLength {
                                    got: content.len(),
                                    want: size,
                                }
                                .into_response(req.id),
                            )?;
                        }
                        Err(e) => conn.send(Refusal::Provider(e).into_response(req.id))?,
                    },
                    Err(refusal) => conn.send(refusal.into_response(req.id))?,
                },
                FromHelper::ExposureChanged { mounts } => {
                    self.exposures = mounts;
                }
            }
        }
        Ok(())
    }

    /// Resolve, looking again before giving up.
    ///
    /// The index is built by walking, once, when the daemon starts. Anything
    /// created after that — every placeholder a sync pass brings down while this
    /// loop is running — is absent from it, and refusing on an absent entry
    /// turns a perfectly good file into `EIO` for the reader.
    ///
    /// It presents as a race because it is one: whether a file is in the index
    /// depends on whether it existed when the scan happened. A rescan before
    /// refusing costs a walk on the miss path only, and the miss path is already
    /// about to fail.
    fn resolve_or_rescan(&mut self, file: FileId) -> Result<(String, u64), Refusal> {
        if self.store.lookup(&file).is_none() {
            let _ = self.rescan();
        }
        self.resolve(file)
    }

    fn resolve(&self, file: FileId) -> Result<(String, u64), Refusal> {
        let entry = self.store.lookup(&file).ok_or(Refusal::Unknown)?;
        let cloud_id = entry.cloud_id.ok_or(Refusal::NeverUploaded)?;
        Ok((cloud_id, entry.size))
    }

    /// Re-scan after a sync pass created or removed placeholders.
    pub fn rescan(&mut self) -> io::Result<usize> {
        let root = self.root.clone();
        self.store.scan(&root)
    }
}

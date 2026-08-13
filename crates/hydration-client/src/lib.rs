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

pub mod daemon_loop;
pub mod delta;
pub mod lineage;
pub mod manifest;
pub mod mount;
pub mod namespace;
pub mod place;
pub mod providers;
pub mod reclaim;
pub mod store;
pub mod upload;

use hydration_protocol::transport::{Body, DaemonConn};
use hydration_protocol::{FetchResponse, FileId, FromHelper, Span};
use std::io;
use std::path::Path;

pub use daemon_loop::CloudAccess;
pub use store::{Entry, Store};

/// What a cloud client implements.
///
/// Small on purpose. Everything the framework can own — when to hydrate, what is
/// true about size, who wins a delete, whether a placeholder occupies disk — it
/// does own, because those are exactly the things a client cannot be expected to
/// get right on its own. What is left is the part only the client knows: how to
/// talk to its service.
pub trait Provider: Send {
    /// Write `span` of the object into `out`.
    ///
    /// Streamed rather than returned, because the previous shape — hand back a
    /// `Vec` — made the object's size the memory cost *and* required the whole
    /// transfer to finish inside one deadline. An object larger than a few
    /// seconds of bandwidth was unservable, and its failure took the mount with
    /// it (§8d).
    ///
    /// `span` is what a reader actually demanded, and it is usually far smaller
    /// than the object: opening a 2.77 GiB archive to look at its header is a
    /// 4096-byte demand (§8d-bis). Serving the whole object instead is not a
    /// harmless over-delivery — [`Body`] refuses the extra bytes, and before it
    /// did, the transfer could not finish inside the deadlines and the read
    /// failed.
    ///
    /// [`Body`] holds the promise made on the wire and will not let it be
    /// broken: writing past the span's length fails at that byte, and finishing
    /// short is an abort rather than a truncation. So the whole of a correct
    /// implementation is usually
    ///
    /// ```ignore
    /// fn fetch(&mut self, id: &str, _size: u64, _tag: Option<&str>, span: Span, out: &mut Body<'_>) -> io::Result<()> {
    ///     let mut body = self.http.get(self.url(id))
    ///         .header("range", format!("bytes={}-{}", span.offset, span.end() - 1))
    ///         .send()?;
    ///     std::io::copy(&mut body, out)?;
    ///     Ok(())
    /// }
    /// ```
    ///
    /// A service with no ranged reads can still implement this by fetching the
    /// object and writing only the span out of it — correct, and no worse than
    /// what every fetch did before ranges existed.
    ///
    /// Returning `Err` abandons the transfer; the placeholder is put back
    /// exactly as it was and the reader gets an error rather than a short file
    /// (§5.7).
    ///
    /// `size` is the whole object's size even when `span` is a slice of it, and
    /// `content_tag` is the exact version marker recorded when the placeholder
    /// was installed. Providers whose tag format is a content hash must verify
    /// it before returning success **when the span is the whole object**
    /// (`span.is_whole(size)`); a range cannot be checked against a whole-object
    /// hash, and pretending otherwise would be a verification that never runs.
    /// Opaque version tags may be ignored here.
    fn fetch(
        &mut self,
        cloud_id: &str,
        size: u64,
        content_tag: Option<&str>,
        span: Span,
        out: &mut Body<'_>,
    ) -> io::Result<()>;
}

/// Why a fetch could not be served, in the framework's own terms.
#[derive(Debug)]
enum Refusal {
    /// The helper named a file this daemon does not know about.
    Unknown,
    /// A file that exists locally and has never been uploaded. There is nothing
    /// to fetch, and that is not an error — the content is already the only copy.
    NeverUploaded,
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
    changes: Option<Box<dyn Changes>>,
}

/// What to do about a local edit the helper noticed.
///
/// A trait rather than a channel, so the daemon loop hands the change over and
/// returns to reading immediately. Implementations must not block: this runs on
/// the thread that answers fetches, and a reader is waiting inside `read()` for
/// every moment it spends elsewhere.
pub trait Changes: Send {
    /// These inodes were written by someone other than the framework.
    fn changed(&mut self, files: &[FileId]);
    /// The change channel has a hole in it; walk the directory instead.
    fn resync(&mut self);
    /// Other mounts now expose the sync files (§6.4a).
    ///
    /// Defaulted, because a client that does nothing with it still works — but
    /// §6.4a is explicit that the framework cannot prevent this and therefore
    /// owes the user visibility, so a client that leaves it defaulted is
    /// choosing not to tell them.
    fn exposed(&mut self, _mounts: &[String]) {}
}

impl<P: Provider> Daemon<P> {
    pub fn new(provider: P, root: &Path) -> io::Result<Self> {
        let mut store = Store::new();
        store.scan(root)?;
        Ok(Self {
            provider,
            store,
            root: root.to_path_buf(),
            changes: None,
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

    /// Where local changes go once the helper reports them.
    ///
    /// Injected rather than owned, because the queue belongs to the upload
    /// driver and this loop must never wait on its lock: a fetch reply that
    /// queued behind an upload's bookkeeping would hold a reader inside `read()`
    /// for no reason.
    pub fn on_change(&mut self, sink: Box<dyn Changes>) {
        self.changes = Some(sink);
    }

    /// Serve until the helper goes away.
    pub fn serve(&mut self, conn: &mut DaemonConn) -> io::Result<()> {
        while let Some(msg) = conn.recv()? {
            match msg {
                FromHelper::Fetch(req) => match self.resolve_or_rescan(req.file) {
                    Ok((cloud_id, size, content_tag)) => {
                        let span = Span::new(req.offset, req.len);
                        // A request that runs off the end of what we believe the
                        // object to be is refused rather than clamped.
                        //
                        // The two sides can genuinely disagree — the helper reads
                        // the placeholder's current length, this index was built
                        // by a walk that may predate a resize — and silently
                        // serving a shorter range would answer the event with
                        // less than it demanded, which hands the reader zeros
                        // (§8d). An error puts the disagreement in front of
                        // somebody instead.
                        if span.end() > size {
                            conn.send(FetchResponse::Failed {
                                id: req.id,
                                errno: libc::EIO,
                                reason: format!(
                                    "asked for {}..{} of an object this daemon has as {size} bytes",
                                    span.offset,
                                    span.end()
                                ),
                            })?;
                            continue;
                        }
                        // The length is declared from the span the helper asked
                        // for — never from something the provider has yet to
                        // deliver. `Body` then holds it to that.
                        let mut body = conn.begin(req.id, span.len)?;
                        match self.provider.fetch(
                            &cloud_id,
                            size,
                            content_tag.as_deref(),
                            span,
                            &mut body,
                        ) {
                            Ok(()) => {
                                // A short delivery becomes an abort here rather
                                // than a truncated file; `finish` sends it and
                                // reports the error.
                                if let Err(e) = body.finish() {
                                    eprintln!("hydration: {cloud_id} ended short: {e}");
                                }
                            }
                            Err(e) => {
                                let _ = body.abort(libc::EIO, &format!("{e}"));
                            }
                        }
                    }
                    Err(refusal) => conn.send(refusal.into_response(req.id))?,
                },
                FromHelper::ExposureChanged { mounts } => {
                    if let Some(sink) = self.changes.as_mut() {
                        sink.exposed(&mounts);
                    }
                    self.exposures = mounts;
                }
                FromHelper::Changed { files } => {
                    if let Some(sink) = self.changes.as_mut() {
                        sink.changed(&files);
                    }
                }
                FromHelper::Resync => {
                    // Not an error. The helper is saying its change channel has
                    // a hole in it, which is a normal state — the notify queue
                    // overflows in seconds under an unpack — and the only honest
                    // recovery is to look at the directory rather than believe
                    // the channel.
                    if let Some(sink) = self.changes.as_mut() {
                        sink.resync();
                    }
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
    fn resolve_or_rescan(
        &mut self,
        file: FileId,
    ) -> Result<(String, u64, Option<String>), Refusal> {
        if self.store.lookup(&file).is_none() {
            let _ = self.rescan();
        }
        self.resolve(file)
    }

    fn resolve(&self, file: FileId) -> Result<(String, u64, Option<String>), Refusal> {
        let entry = self.store.lookup(&file).ok_or(Refusal::Unknown)?;
        let cloud_id = entry.cloud_id.ok_or(Refusal::NeverUploaded)?;
        Ok((cloud_id, entry.size, entry.etag))
    }

    /// Re-scan after a sync pass created or removed placeholders.
    pub fn rescan(&mut self) -> io::Result<usize> {
        let root = self.root.clone();
        self.store.scan(&root)
    }
}

//! Production wiring for the unprivileged OneDrive process.

use crate::auth::{AuthConfig, Clock, CredentialStore, RefreshToken, TokenCache};
use crate::{
    CloudId, DriveScope, GraphDiscover, GraphHttp, GraphSink, GraphTokens, Method, PersistedState,
    Request, Sleeper, StateStore, TagSource, TokenBlob, Transport, TreeBlob,
};
use hydration_client::{CloudAccess, Provider};
use hydration_protocol::transport::Body;
use hydration_protocol::Span;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub type SharedCredentialStore = Arc<dyn CredentialStore>;
pub type SharedTokenCache =
    Arc<TokenCache<Arc<GraphTokens>, MonotonicClock, SharedCredentialStore>>;

#[derive(Clone)]
pub struct FileCredentialStore {
    path: PathBuf,
}
impl FileCredentialStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}
impl CredentialStore for FileCredentialStore {
    fn load(&self) -> io::Result<Option<RefreshToken>> {
        match fs::read_to_string(&self.path) {
            Ok(s) if !s.is_empty() => Ok(Some(RefreshToken::new(s))),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the credential file is empty",
            )),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn save(&self, refresh: &RefreshToken) -> io::Result<()> {
        atomic_private_write(&self.path, refresh.expose_for_storage().as_bytes())
    }
}

#[derive(Clone)]
pub struct FileStateStore {
    dir: PathBuf,
}
impl FileStateStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }
}
impl StateStore for FileStateStore {
    fn load(&mut self) -> io::Result<Option<PersistedState>> {
        let tree = read_optional(self.dir.join("tree.json"))?.map(TreeBlob::from_bytes);
        let token = read_optional(self.dir.join("token.json"))?
            .map(|b| TokenBlob::from_bytes(&b))
            .transpose()?;
        if tree.is_none() && token.is_none() {
            Ok(None)
        } else {
            Ok(Some(PersistedState::raw(tree, token)))
        }
    }
    fn save_tree(&mut self, tree: &TreeBlob) -> io::Result<()> {
        atomic_private_write(&self.dir.join("tree.json"), tree.as_bytes())
    }
    fn save_token(&mut self, token: &TokenBlob) -> io::Result<()> {
        atomic_private_write(&self.dir.join("token.json"), &token.as_bytes())
    }
}

fn read_optional(path: PathBuf) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "storage path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    let tmp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    OpenOptions::new().read(true).open(parent)?.sync_all()
}

#[derive(Clone, Copy, Default)]
pub struct MonotonicClock;
impl Clock for MonotonicClock {
    fn now(&self) -> Duration {
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed()
    }
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration)
    }
}

#[derive(Clone, Copy, Default)]
pub struct SystemSleeper;
impl Sleeper for SystemSleeper {
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration)
    }
}

pub struct GraphProvider {
    http: GraphHttp<SharedTokenCache>,
    /// Windows of read-ahead on parallel connections; see [`Prefetcher`].
    prefetch: Prefetcher,
    /// Where the last ranged window this provider served ended, so the next
    /// request can be recognised as the continuation it is. The whole of the
    /// sequential-walk detection: a hydration reads windows back to back, a
    /// random access starts where nothing ended.
    last_window: Option<(String, u64)>,
}

/// A window's identity in the prefetch ledger: object, offset, length.
type WindowKey = (String, u64, u64);

/// What the prefetch pool holds: windows being fetched, windows fetched.
struct PrefetchState {
    inflight: std::collections::HashSet<WindowKey>,
    done: std::collections::HashMap<WindowKey, io::Result<Vec<u8>>>,
}

/// Windows of read-ahead, fetched on parallel connections while the current
/// one is served.
///
/// A sequential hydration was a strict alternation: fetch a window from the
/// service, hand it to the helper, wait for the reader to demand the next.
/// Instrumented 2026-08-25 on a 700 Mbit line, the local half of an 8 MiB
/// window costs under a millisecond — the whole ~400 ms window is *one TCP
/// stream to the content host*, which tops out around 20 MB/s however fast
/// the line. No amount of overlap within one stream can beat that ceiling;
/// only breadth can. So the pool runs [`PREFETCH_DEPTH`] workers, each with
/// its own transport (same shared token source, its own connection pool and
/// remembered content location), and the walk keeps that many upcoming
/// windows in flight — the per-stream ceiling times the pool is the
/// throughput.
///
/// The prediction is only ever the next contiguous windows of a recognised
/// sequential walk; a miss strands at most what is in flight, and the
/// ledger is capped ([`Prefetcher::hint`]) so the memory ceiling is a few
/// windows, not a file. Windows of any other object are abandoned the
/// moment the walk moves on ([`Prefetcher::take`]).
///
/// Correctness is unchanged from the inline path it shadows: ranged windows
/// carry no per-range integrity today (the whole-object hash arms in
/// [`Provider::fetch`] never touch this), a prefetched window is served only
/// on an exact `(cloud_id, span)` match, and any error is discarded so the
/// read falls back to the inline fetch and *its* verdict. A worker that
/// stalls past [`PREFETCH_PATIENCE`] is likewise abandoned for the inline
/// path rather than holding a reader against the helper's first-byte
/// budget.
struct Prefetcher {
    jobs: std::sync::mpsc::Sender<(String, Span, u64)>,
    state: Arc<(std::sync::Mutex<PrefetchState>, std::sync::Condvar)>,
}

/// How many windows ahead the walk keeps in flight, and the size of the
/// worker pool that carries them. Four: the measured per-stream ceiling
/// (~20 MB/s) times four is just above a 700 Mbit line, the widest
/// deployment measured, and the ledger cap makes the worst-case memory a
/// known handful of windows.
const PREFETCH_DEPTH: usize = 4;

/// How long [`Prefetcher::take`] waits for a matching fetch already in
/// flight before abandoning it for the inline path. Far under the helper's
/// `FIRST_BYTE_BUDGET` (30 s), so a stalled worker costs a duplicate window
/// download, never a failed read.
const PREFETCH_PATIENCE: Duration = Duration::from_secs(10);

/// Windows larger than this are not prefetched: the slot is also the memory
/// ceiling, and a reader demanding outsized spans is not the sequential
/// hydration this exists for.
const PREFETCH_CEILING: u64 = 16 * 1024 * 1024;

impl Prefetcher {
    /// `make_fetch` is called once per worker, on this thread, so each worker
    /// owns its own transport and nothing is shared but the token source.
    fn new<F>(workers: usize, make_fetch: impl Fn() -> F) -> Self
    where
        F: FnMut(&str, Span, u64) -> io::Result<Vec<u8>> + Send + 'static,
    {
        let (jobs, queue) = std::sync::mpsc::channel::<(String, Span, u64)>();
        let queue = Arc::new(std::sync::Mutex::new(queue));
        let state = Arc::new((
            std::sync::Mutex::new(PrefetchState {
                inflight: std::collections::HashSet::new(),
                done: std::collections::HashMap::new(),
            }),
            std::sync::Condvar::new(),
        ));
        // The workers end when the provider drops its sender; a fetch role is
        // one connection's lifetime, so this is bounded the same way.
        for _ in 0..workers {
            let queue = Arc::clone(&queue);
            let shared = Arc::clone(&state);
            let mut fetch = make_fetch();
            std::thread::spawn(move || loop {
                let job = queue.lock().unwrap().recv();
                let Ok((cloud_id, span, total)) = job else {
                    return;
                };
                let bytes = fetch(&cloud_id, span, total);
                let key = (cloud_id, span.offset, span.len);
                let (state, woken) = &*shared;
                let mut ledger = state.lock().unwrap();
                // A window abandoned while it was being fetched — the walk
                // moved to another object — is dropped, not recorded: its
                // entry left `inflight` and nothing is waiting for it.
                if ledger.inflight.remove(&key) {
                    ledger.done.insert(key, bytes);
                }
                woken.notify_all();
            });
        }
        Self { jobs, state }
    }

    /// Ask for `span` to be fetched in the background. Dropped without a
    /// trace when it is already in the ledger, larger than the ceiling, or
    /// the ledger is full — the walk will hint it again if it still matters.
    fn hint(&self, cloud_id: &str, span: Span, total: u64) {
        if span.len > PREFETCH_CEILING {
            return;
        }
        let key = (cloud_id.to_owned(), span.offset, span.len);
        let (state, _) = &*self.state;
        let mut ledger = state.lock().unwrap();
        if ledger.inflight.contains(&key) || ledger.done.contains_key(&key) {
            return;
        }
        // The ledger is the memory bound: in flight plus fetched, never more
        // than a couple of strides beyond the pool.
        if ledger.inflight.len() + ledger.done.len() >= PREFETCH_DEPTH + 2 {
            return;
        }
        ledger.inflight.insert(key.clone());
        drop(ledger);
        // A send can only fail if every worker died; the key then sits in
        // `inflight` until the walk moves to another object, and every read
        // takes the inline path — degraded, never wrong.
        let _ = self.jobs.send((key.0, span, total));
    }

    /// The prefetched bytes for exactly `(cloud_id, span)`, waiting briefly
    /// for a matching fetch in flight. Asking also abandons every window of
    /// every *other* object — the walk has spoken about where it is.
    fn take(&self, cloud_id: &str, span: Span) -> Option<Vec<u8>> {
        let key = (cloud_id.to_owned(), span.offset, span.len);
        let (state, woken) = &*self.state;
        let mut ledger = state.lock().unwrap();
        ledger.done.retain(|(id, _, _), _| id == cloud_id);
        ledger.inflight.retain(|(id, _, _)| id == cloud_id);
        let deadline = Instant::now() + PREFETCH_PATIENCE;
        loop {
            if let Some(bytes) = ledger.done.remove(&key) {
                // An error is discarded rather than returned: the inline
                // path retries with its own transport and its verdict is the
                // one the reader was always owed.
                return bytes.ok();
            }
            if !ledger.inflight.contains(&key) {
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (next, _timeout) = woken.wait_timeout(ledger, deadline - now).unwrap();
            ledger = next;
        }
    }
}

/// The window a sequential walk will demand next, if any: contiguous, the
/// same length the reader has been asking for, clipped at the object's end.
fn next_window(span: Span, size: u64) -> Option<Span> {
    let end = span.end();
    if end >= size {
        return None;
    }
    Some(Span::new(end, span.len.min(size - end)))
}

impl GraphProvider {
    /// QuickXor for the exact cTag the placeholder promises, when Graph has one.
    ///
    /// The persisted tag remains the concurrency/version token used by uploads.
    /// Integrity is read independently at hydration time, so choosing a usable
    /// `if-match` no longer silently gives up the hash Graph also carries.
    fn quickxor_for(
        &mut self,
        key: &crate::ObjectKey,
        expected_version: &str,
    ) -> io::Result<Option<String>> {
        let reply = self
            .http
            .send(&Request::new(Method::Get, crate::item_metadata_url(key)))?;
        if !(200..300).contains(&reply.status) {
            return Err(io::Error::other(format!(
                "the object's integrity metadata was refused with HTTP {}",
                reply.status
            )));
        }
        let item: crate::DriveItem = serde_json::from_slice(&reply.body).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the object's integrity metadata was malformed",
            )
        })?;
        quickxor_for_version(expected_version, &item)
    }
}

/// Separate a version precondition from a content-integrity value.
///
/// Kept outside the HTTP method so the judgment is testable without a token or
/// a socket. A metadata read for a newer cTag must never be used to bless bytes
/// for the older placeholder: that would hydrate a version and size the local
/// namespace has not applied yet.
fn quickxor_for_version(
    expected_version: &str,
    item: &crate::DriveItem,
) -> io::Result<Option<String>> {
    let body = item.body();
    let current = crate::content_tag(&body, TagSource::CTag).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "the object's metadata carried no cTag",
        )
    })?;
    if current != expected_version {
        return Err(io::Error::other(
            "the object changed after this placeholder was installed; waiting for delta",
        ));
    }
    Ok(body
        .hashes
        .and_then(|hashes| hashes.quick_xor_hash.as_deref())
        .map(str::to_string))
}

impl Provider for GraphProvider {
    fn fetch(
        &mut self,
        cloud_id: &str,
        size: u64,
        content_tag: Option<&str>,
        span: Span,
        out: &mut Body<'_>,
    ) -> io::Result<()> {
        let key = CloudId::parse(cloud_id)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Graph cloud id"))?;
        // QuickXorHash is a hash of the *object*. A range cannot be checked
        // against it — there is no per-range digest in Graph to check against
        // either — so the verification runs when the reader demanded the whole
        // object and is skipped, visibly, when it did not.
        //
        // Not a loophole someone could ride: nothing chooses the span except the
        // kernel reporting what a reader asked for, and a partially filled file
        // keeps its placeholder mark, so no range is ever promoted to "this file
        // is hydrated" without every other range having arrived. What is
        // genuinely lost is that a service corrupting one range of a large file
        // is no longer caught by the tag, only by whatever the reader makes of
        // the bytes. That is the price of not fetching 2.77 GiB to answer a
        // 4 KiB read, and it is recorded here rather than left to be discovered.
        match content_tag.and_then(|tag| tag.strip_prefix("qx:")) {
            Some(expected) if span.is_whole(size) => {
                let mut verified = crate::QuickXorWriter::new(out);
                self.http.download_span(&key, span, size, &mut verified)?;
                verified.verify(expected)
            }
            _ if span.is_whole(size) && content_tag.is_some_and(|tag| tag.starts_with("ct:")) => {
                let expected_version = content_tag.unwrap();
                match self.quickxor_for(&key, expected_version)? {
                    Some(expected) => {
                        let mut verified = crate::QuickXorWriter::new(out);
                        self.http.download_span(&key, span, size, &mut verified)?;
                        // No closing metadata read in this arm. The read above
                        // proved the cTag current and named the hash of exactly
                        // that version, so matching bytes *are* that version's
                        // content: a concurrent change with different content
                        // fails the hash, and a newer version with identical
                        // content is byte-identical — there is no second fact
                        // for a second read to establish, only a Graph round
                        // trip to pay on every small-file hydration (measured
                        // 2026-08-25: the closing read was a third of the
                        // ~450 ms a sequential bulk pull paid per file). The
                        // hashless arm below keeps its closing read: with no
                        // hash, the cTag bracket is the only integrity there
                        // is, and there it is load-bearing.
                        verified.verify(&expected)
                    }
                    // Not every Graph-backed library reports hashes. The cTag
                    // is checked on both sides of the download so a same-sized
                    // edit cannot slip through between metadata and content.
                    // TLS and the service remain the byte-integrity boundary
                    // for that drive.
                    None => {
                        self.http.download_span(&key, span, size, out)?;
                        self.quickxor_for(&key, expected_version)?;
                        Ok(())
                    }
                }
            }
            _ => {
                // A whole span without a usable tag keeps the plain inline
                // road; everything below is for the ranged windows of a
                // sequential walk.
                if span.is_whole(size) {
                    return self.http.download_span(&key, span, size, out);
                }
                let sequential = span.offset == 0
                    || self
                        .last_window
                        .as_ref()
                        .is_some_and(|(id, end)| id == cloud_id && *end == span.offset);
                self.last_window = Some((cloud_id.to_owned(), span.end()));
                if !sequential {
                    // A window that starts where nothing ended is random
                    // access; predicting its successor would be a guess paid
                    // for in whole windows of bandwidth.
                    return self.http.download_span(&key, span, size, out);
                }
                // Take before hinting: the take is what clears this window
                // from the ledger, so the hints below can top it back up to
                // depth — from then on the pool is always PREFETCH_DEPTH
                // windows ahead of the reader.
                let window = self.prefetch.take(cloud_id, span);
                let mut upcoming = next_window(span, size);
                for _ in 0..PREFETCH_DEPTH {
                    let Some(next) = upcoming else { break };
                    self.prefetch.hint(cloud_id, next, size);
                    upcoming = next_window(next, size);
                }
                match window {
                    Some(bytes) => out.write_all(&bytes),
                    None => self.http.download_span(&key, span, size, out),
                }
            }
        }
    }
}

pub struct GraphAccess {
    scope: DriveScope,
    root: PathBuf,
    state_dir: PathBuf,
    tags: TagSource,
    cache: SharedTokenCache,
}
impl GraphAccess {
    pub fn new(
        scope: DriveScope,
        root: impl Into<PathBuf>,
        state_dir: impl Into<PathBuf>,
        credential: impl Into<PathBuf>,
        config: AuthConfig,
        tags: TagSource,
    ) -> Self {
        let store: SharedCredentialStore = Arc::new(FileCredentialStore::new(credential));
        let cache = Arc::new(TokenCache::new(
            config,
            Arc::new(GraphTokens::new()),
            MonotonicClock,
            store,
        ));
        Self::with_token_cache(scope, root, state_dir, tags, cache)
    }

    /// Build every role around a cache the product shell already owns.
    ///
    /// Enrollment and account discovery happen before the daemon knows its
    /// drive scope. Accepting that same cache here prevents the product from
    /// constructing a second refresh-token authority after sign-in.
    pub fn with_token_cache(
        scope: DriveScope,
        root: impl Into<PathBuf>,
        state_dir: impl Into<PathBuf>,
        tags: TagSource,
        cache: SharedTokenCache,
    ) -> Self {
        Self {
            scope,
            root: root.into(),
            state_dir: state_dir.into(),
            tags,
            cache,
        }
    }
    pub fn shared_token_cache(&self) -> SharedTokenCache {
        Arc::clone(&self.cache)
    }

    /// The tag source every tag on this drive was actually written with.
    ///
    /// The constructor takes one, and the persisted tree pins one, and until
    /// this existed nothing made the two agree. Measured on a live account on
    /// 2026-08-13: the tree was pinned to `CTag`, every extended attribute on
    /// disk held a `ct:` value, and the product passed `QuickXor`. The mapper
    /// followed the pin and the sink followed the argument, so
    /// `GraphSink::precondition` returned `None` on its first line — a drive
    /// whose tags are hashes has nothing Graph accepts as a precondition — and
    /// every update to an object that already existed was refused. No amount of
    /// carrying the right tag to the sink could have helped: it was not looking
    /// at the tag.
    ///
    /// The pin wins because it is not a preference. It is the record of what the
    /// values on disk *are*, and `delta::is_current` compares them byte for
    /// byte. The constructor's value is what to pin when there is nothing
    /// pinned yet, which is the first round against a new account and the only
    /// moment the choice is still open.
    ///
    /// Said out loud when they disagree. The argument is a caller's belief about
    /// this drive, and a caller that is wrong about it should hear so once
    /// rather than have it quietly corrected forever.
    fn tags_in_force(&self) -> TagSource {
        let pinned = FileStateStore::new(&self.state_dir)
            .load()
            .ok()
            .flatten()
            .and_then(|state| state.tree().map(|t| t.tag_source()))
            .and_then(Result::ok);
        match pinned {
            Some(pin) if pin != self.tags => {
                eprintln!(
                    "hydration-graph: this drive's tags are pinned to {pin:?} and the \
                     caller asked for {:?}; using {pin:?}, which is what every tag \
                     already written here is. An upload cannot be made conditional on \
                     a tag of a shape the drive does not use.",
                    self.tags
                );
                pin
            }
            Some(pin) => pin,
            None => self.tags,
        }
    }
}
impl CloudAccess for GraphAccess {
    type Fetch = GraphProvider;
    type Upload = GraphSink<GraphHttp<SharedTokenCache>, SystemSleeper>;
    type Changes = GraphDiscover<GraphHttp<SharedTokenCache>, FileStateStore, SystemSleeper>;
    fn provider(&self) -> io::Result<Self::Fetch> {
        // Each worker gets its own transport: same shared token source, its
        // own connection pool and remembered content location. The pool is
        // the point — one stream's throughput ceiling is what it exists to
        // multiply — so nothing about a connection may be shared.
        let cache = Arc::clone(&self.cache);
        Ok(GraphProvider {
            http: GraphHttp::new(Arc::clone(&self.cache)),
            prefetch: Prefetcher::new(PREFETCH_DEPTH, move || {
                let mut http = GraphHttp::new(Arc::clone(&cache));
                move |cloud_id: &str, span: Span, total: u64| {
                    let key = CloudId::parse(cloud_id).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid Graph cloud id")
                    })?;
                    let mut window = Vec::with_capacity(span.len.min(PREFETCH_CEILING) as usize);
                    http.download_span(&key, span, total, &mut window)?;
                    Ok(window)
                }
            }),
            last_window: None,
        })
    }
    fn sink(&self) -> io::Result<Self::Upload> {
        Ok(GraphSink::new(
            self.scope.clone(),
            &self.root,
            self.tags_in_force(),
            GraphHttp::new(Arc::clone(&self.cache)),
            SystemSleeper,
        ))
    }
    fn discover(&self) -> io::Result<Self::Changes> {
        Ok(GraphDiscover::new(
            self.scope.clone(),
            GraphHttp::new(Arc::clone(&self.cache)),
            FileStateStore::new(&self.state_dir),
            SystemSleeper,
        ))
    }
    fn preflight(&self) -> io::Result<()> {
        if self.cache.is_signed_in() || self.cache.resume()? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "no stored OneDrive credential; device-code sign-in is still required",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydration_client::CloudAccess;
    use std::sync::Mutex;

    #[test]
    fn the_next_window_is_contiguous_same_sized_and_clipped_at_the_end() {
        // Mid-object: the same stride, starting where this one ended.
        assert_eq!(next_window(Span::new(0, 8), 32), Some(Span::new(8, 8)));
        // The last full window's successor is the remainder, not a promise
        // past the end.
        assert_eq!(next_window(Span::new(16, 8), 30), Some(Span::new(24, 6)));
        // At the end there is nothing to predict.
        assert_eq!(next_window(Span::new(24, 8), 32), None);
    }

    fn counting_prefetcher(workers: usize) -> (Prefetcher, Arc<Mutex<Vec<(String, Span)>>>) {
        let fetched = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&fetched);
        let prefetch = Prefetcher::new(workers, move || {
            let log = Arc::clone(&log);
            move |cloud_id: &str, span: Span, _total: u64| {
                log.lock().unwrap().push((cloud_id.to_owned(), span));
                Ok(vec![7u8; span.len as usize])
            }
        });
        (prefetch, fetched)
    }

    #[test]
    fn a_prefetched_window_is_served_once_and_only_for_its_exact_span() {
        let (prefetch, fetched) = counting_prefetcher(2);
        prefetch.hint("obj", Span::new(8, 8), 32);
        prefetch.hint("obj", Span::new(16, 8), 32);
        // Duplicate hints of a window already in the ledger are dropped.
        prefetch.hint("obj", Span::new(8, 8), 32);
        // The exact windows come back, and taking one removes it.
        assert_eq!(prefetch.take("obj", Span::new(8, 8)), Some(vec![7u8; 8]));
        assert_eq!(prefetch.take("obj", Span::new(8, 8)), None);
        assert_eq!(prefetch.take("obj", Span::new(16, 8)), Some(vec![7u8; 8]));
        let mut log = fetched.lock().unwrap().clone();
        log.sort_by_key(|(_, s)| s.offset);
        assert_eq!(
            log,
            [
                ("obj".to_owned(), Span::new(8, 8)),
                ("obj".to_owned(), Span::new(16, 8)),
            ]
        );
    }

    #[test]
    fn asking_about_one_object_abandons_every_other_objects_windows() {
        let (prefetch, _) = counting_prefetcher(1);
        prefetch.hint("obj", Span::new(0, 4), 16);
        // Wait until fetched, then walk to a different object: the ledger
        // forgets obj entirely.
        assert_eq!(prefetch.take("obj", Span::new(0, 4)), Some(vec![7u8; 4]));
        prefetch.hint("obj", Span::new(4, 4), 16);
        assert_eq!(prefetch.take("obj", Span::new(4, 4)), Some(vec![7u8; 4]));
        // Plant a finished window, then ask about another object.
        prefetch.hint("obj", Span::new(8, 4), 16);
        assert_eq!(prefetch.take("obj", Span::new(8, 4)), Some(vec![7u8; 4]));
        prefetch.hint("obj", Span::new(12, 4), 16);
        // Ensure it is Done, deterministically, by taking-and-replanting:
        // the ledger is reachable from the test, so plant directly instead.
        let (state, _) = &*prefetch.state;
        state.lock().unwrap().done.insert(
            ("obj".to_owned(), 12, 4),
            Ok(vec![7u8; 4]),
        );
        assert_eq!(prefetch.take("other", Span::new(0, 4)), None);
        let ledger = state.lock().unwrap();
        assert!(
            !ledger.done.contains_key(&("obj".to_owned(), 12, 4)),
            "windows of an abandoned object must not linger in memory"
        );
    }

    #[test]
    fn a_failed_prefetch_is_discarded_so_the_inline_path_decides() {
        let prefetch = Prefetcher::new(1, || {
            |_: &str, _: Span, _: u64| Err(io::Error::other("injected"))
        });
        prefetch.hint("obj", Span::new(0, 4), 8);
        assert_eq!(prefetch.take("obj", Span::new(0, 4)), None);
    }

    #[test]
    fn the_ledger_is_bounded_and_oversized_windows_are_never_hinted() {
        // No workers drain the queue, so every accepted hint stays in the
        // ledger — which is exactly how its bound becomes observable.
        let prefetch = Prefetcher::new(0, || |_: &str, _: Span, _: u64| Ok(Vec::new()));
        for i in 0..(PREFETCH_DEPTH as u64 + 5) {
            prefetch.hint("obj", Span::new(i * 8, 8), 1 << 30);
        }
        let (state, _) = &*prefetch.state;
        assert_eq!(
            state.lock().unwrap().inflight.len(),
            PREFETCH_DEPTH + 2,
            "the ledger stops accepting at its cap"
        );
        // A window past the ceiling is never hinted at all — the ledger is
        // also the memory bound.
        let prefetch = Prefetcher::new(0, || |_: &str, _: Span, _: u64| Ok(Vec::new()));
        prefetch.hint("obj", Span::new(0, PREFETCH_CEILING + 1), PREFETCH_CEILING * 2);
        let (state, _) = &*prefetch.state;
        assert!(state.lock().unwrap().inflight.is_empty());
    }

    #[derive(Default)]
    struct MemoryCredentialStore(Mutex<Option<String>>);

    impl CredentialStore for MemoryCredentialStore {
        fn load(&self) -> io::Result<Option<RefreshToken>> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .as_ref()
                .map(|value| RefreshToken::new(value.clone())))
        }

        fn save(&self, refresh: &RefreshToken) -> io::Result<()> {
            *self.0.lock().unwrap() = Some(refresh.expose_for_storage().to_owned());
            Ok(())
        }
    }

    fn access(dir: &Path) -> GraphAccess {
        GraphAccess::new(
            DriveScope::primary(crate::DriveId::parse("drive").unwrap()),
            dir.join("mount"),
            dir.join("state"),
            dir.join("refresh-token"),
            AuthConfig::public_client("client").with_scopes(["Files.ReadWrite.All"]),
            TagSource::CTag,
        )
    }

    /// A drive's tags are what is already written on it, not what a caller
    /// believes.
    ///
    /// Measured on a live account on 2026-08-13. The persisted tree was pinned
    /// to `CTag`, every `user.hydration.etag` on disk held a `ct:` value, and
    /// the product passed `QuickXor`. The mapper followed the pin and the sink
    /// followed the argument, so `GraphSink::precondition` refused on its first
    /// line — a drive whose tags are hashes has nothing Graph accepts as an
    /// `if-match` — and no update to an object that already existed had ever
    /// succeeded. Six files sat unsent for hours with the tag they needed in
    /// their own extended attributes.
    ///
    /// One value, supplied twice, with nothing checking they agreed.
    #[test]
    fn the_sink_follows_the_tag_source_the_drive_is_pinned_to() {
        let d = tempfile::tempdir().unwrap();
        let state = d.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let drive = crate::DriveId::parse("drive").unwrap();
        FileStateStore::new(&state)
            .save_tree(&TreeBlob::encode(&drive, TagSource::CTag, &[]))
            .unwrap();

        let access = GraphAccess::with_token_cache(
            DriveScope::primary(drive),
            d.path().join("mount"),
            &state,
            // What the product passed, and what the drive is not.
            TagSource::QuickXor,
            access(d.path()).shared_token_cache(),
        );

        assert_eq!(
            access.tags_in_force(),
            TagSource::CTag,
            "the sink would judge this drive's cTags as though they were hashes, \
             and refuse every update to a file that already exists"
        );
    }

    /// And before there is a tree, the caller's value is the one that gets
    /// pinned — which is the only moment the choice is still open.
    #[test]
    fn with_nothing_pinned_yet_the_callers_choice_stands() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(access(d.path()).tags_in_force(), TagSource::CTag);
    }

    #[test]
    fn roles_share_exactly_one_token_cache() {
        let d = tempfile::tempdir().unwrap();
        let a = access(d.path());
        let cache = a.shared_token_cache();
        assert_eq!(Arc::strong_count(&cache), 2);
        let _fetch = a.provider().unwrap();
        let _upload = a.sink().unwrap();
        let _discover = a.discover().unwrap();
        // The fetch role counts once for its own transport and once per
        // prefetch worker — all clones of this same cache, which is the
        // fact under test.
        assert_eq!(Arc::strong_count(&cache), 5 + PREFETCH_DEPTH);
    }

    #[test]
    fn injected_cache_is_the_cache_every_role_shares() {
        let d = tempfile::tempdir().unwrap();
        let original = access(d.path());
        let cache = original.shared_token_cache();
        let access = GraphAccess::with_token_cache(
            DriveScope::primary(crate::DriveId::parse("drive").unwrap()),
            d.path().join("mount"),
            d.path().join("state"),
            TagSource::CTag,
            Arc::clone(&cache),
        );
        drop(original);
        let _fetch = access.provider().unwrap();
        let _upload = access.sink().unwrap();
        let _discover = access.discover().unwrap();
        // Same arithmetic as above: the fetch role's prefetch workers each
        // hold a clone of the one shared cache.
        assert_eq!(Arc::strong_count(&cache), 5 + PREFETCH_DEPTH);
    }

    #[test]
    fn injected_credential_backend_is_not_tied_to_files() {
        let d = tempfile::tempdir().unwrap();
        let store: SharedCredentialStore = Arc::new(MemoryCredentialStore::default());
        store.save(&RefreshToken::new("refresh")).unwrap();
        let cache: SharedTokenCache = Arc::new(TokenCache::new(
            AuthConfig::public_client("client"),
            Arc::new(GraphTokens::new()),
            MonotonicClock,
            store,
        ));
        let access = GraphAccess::with_token_cache(
            DriveScope::primary(crate::DriveId::parse("drive").unwrap()),
            d.path().join("mount"),
            d.path().join("state"),
            TagSource::CTag,
            cache,
        );
        access.preflight().unwrap();
        assert!(access.shared_token_cache().is_signed_in());
    }

    #[test]
    fn preflight_fails_closed_without_a_credential() {
        let d = tempfile::tempdir().unwrap();
        let err = access(d.path()).preflight().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn preflight_loads_a_stored_credential_without_network() {
        let d = tempfile::tempdir().unwrap();
        let a = access(d.path());
        FileCredentialStore::new(d.path().join("refresh-token"))
            .save(&RefreshToken::new("refresh"))
            .unwrap();
        a.preflight().unwrap();
        assert!(a.shared_token_cache().is_signed_in());
    }

    fn quickxor(bytes: &[u8]) -> String {
        let mut out = Vec::new();
        let mut writer = crate::QuickXorWriter::new(&mut out);
        writer.write_all(bytes).unwrap();
        let expected = crate::base64_20(&{
            let mut digest = writer.digest;
            for (slot, byte) in digest[12..].iter_mut().zip(writer.length.to_le_bytes()) {
                *slot ^= byte;
            }
            digest
        });
        writer.verify(&expected).unwrap();
        assert_eq!(out, bytes);
        expected
    }

    #[test]
    fn quickxor_matches_microsoft_algorithm_vectors() {
        assert_eq!(quickxor(b""), "AAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert_eq!(quickxor(b"hello world"), "aCgDG9jwBhDc4Q1yawMZAAAAAAA=");
        assert_eq!(
            quickxor(&(0_u8..=255).collect::<Vec<_>>()),
            "QkGEfSisZcA7k+FCh71r2dbCayY="
        );
    }

    fn item_with_tags(ctag: &str, quickxor: Option<&str>) -> crate::DriveItem {
        let hashes = quickxor
            .map(|hash| serde_json::json!({"quickXorHash": hash}))
            .unwrap_or_else(|| serde_json::json!({}));
        serde_json::from_value(serde_json::json!({
            "id": "01A",
            "name": "report.txt",
            "size": 11,
            "cTag": ctag,
            "file": {"hashes": hashes}
        }))
        .unwrap()
    }

    #[test]
    fn a_ctag_version_and_its_quickxor_are_independent_facts() {
        let item = item_with_tags("c:{G},2", Some("aCgDG9jwBhDc4Q1yawMZAAAAAAA="));
        assert_eq!(
            quickxor_for_version("ct:c:{G},2", &item)
                .unwrap()
                .as_deref(),
            Some("aCgDG9jwBhDc4Q1yawMZAAAAAAA=")
        );
    }

    #[test]
    fn integrity_from_a_newer_version_cannot_bless_an_old_placeholder() {
        let item = item_with_tags("c:{G},3", Some("aCgDG9jwBhDc4Q1yawMZAAAAAAA="));
        let err = quickxor_for_version("ct:c:{G},2", &item).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        assert!(err.to_string().contains("changed"));
    }

    #[test]
    fn a_drive_without_quickxor_keeps_ctag_as_its_version_boundary() {
        let item = item_with_tags("c:{G},2", None);
        assert_eq!(quickxor_for_version("ct:c:{G},2", &item).unwrap(), None);
    }

    #[test]
    fn quickxor_is_chunk_independent_and_fails_closed() {
        let bytes = (0_u8..=255).cycle().take(100_003).collect::<Vec<_>>();
        let expected = quickxor(&bytes);
        let mut out = Vec::new();
        let mut writer = crate::QuickXorWriter::new(&mut out);
        for chunk in bytes.chunks(7919) {
            writer.write_all(chunk).unwrap();
        }
        writer.verify(&expected).unwrap();
        assert_eq!(out, bytes);

        let mut writer = crate::QuickXorWriter::new(Vec::new());
        writer.write_all(b"tampered").unwrap();
        let err = writer.verify("AAAAAAAAAAAAAAAAAAAAAAAAAAA=").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!err.to_string().contains("AAAAAAAA"));
    }
}

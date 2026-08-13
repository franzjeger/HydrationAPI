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
                        verified.verify(&expected)?;
                        // Metadata and content are separate Graph requests. A
                        // matching hash proves the bytes, while this second
                        // version read proves they still belong to the cTag the
                        // placeholder names rather than a newer version with
                        // identical content.
                        self.quickxor_for(&key, expected_version)?;
                        Ok(())
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
            _ => self.http.download_span(&key, span, size, out),
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
        Ok(GraphProvider {
            http: GraphHttp::new(Arc::clone(&self.cache)),
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
        assert_eq!(Arc::strong_count(&cache), 5);
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
        assert_eq!(Arc::strong_count(&cache), 5);
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

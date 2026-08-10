//! Production wiring for the unprivileged OneDrive process.

use crate::auth::{AuthConfig, Clock, CredentialStore, RefreshToken, TokenCache};
use crate::{
    CloudId, DriveScope, GraphDiscover, GraphHttp, GraphSink, GraphTokens, Method, PersistedState,
    Request, Sleeper, StateStore, TagSource, TokenBlob, Transport, TreeBlob,
};
use hydration_client::{CloudAccess, Provider};
use hydration_protocol::transport::Body;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub type SharedTokenCache = Arc<TokenCache<Arc<GraphTokens>, MonotonicClock, FileCredentialStore>>;

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
impl Provider for GraphProvider {
    fn fetch(&mut self, cloud_id: &str, _size: u64, out: &mut Body<'_>) -> io::Result<()> {
        let key = CloudId::parse(cloud_id)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid Graph cloud id"))?;
        let url = format!(
            "https://graph.microsoft.com/v1.0/drives/{}/items/{}/content",
            key.drive().as_str(),
            key.item().as_str()
        );
        let reply = self.http.send(&Request::new(Method::Get, url))?;
        if !(200..300).contains(&reply.status) {
            return Err(io::Error::other(format!(
                "Graph content request returned HTTP {}",
                reply.status
            )));
        }
        out.write_all(&reply.body)
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
        let cache = Arc::new(TokenCache::new(
            config,
            Arc::new(GraphTokens::new()),
            MonotonicClock,
            FileCredentialStore::new(credential),
        ));
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
            self.tags,
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
        if self.cache.resume()? {
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
}

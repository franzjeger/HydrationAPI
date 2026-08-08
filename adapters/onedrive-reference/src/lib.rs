//! Runs the conformance suite against the OneDriveForLinux FUSE client.
//!
//! The suite states what a hydration framework must guarantee. This adapter is
//! the thing that lets it say something about a *real* client rather than a
//! model: a genuine FUSE mount, the real sync engine, a real SQLite database,
//! and a fake Graph API that the harness can steer.
//!
//! Two design notes worth stating, because both are places where an adapter can
//! quietly make a suite meaningless:
//!
//! * **Status comes from the client, not from this file.** `pending_uploads`
//!   asks the client's own queue. Computing it here from the fake cloud would
//!   test this adapter's bookkeeping and report it as the client's.
//! * **The upload window is held open by delaying the response, not by
//!   sleeping.** A `PUT` is in flight from the moment it reaches the server
//!   until its response returns, so a delayed response is a genuinely in-flight
//!   upload, and the race is arranged rather than hoped for.

use hydration_conformance::{CloudObject, CloudOp, FetchBehaviour, Harness};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use graph_client::{auth::TokenSet, AuthManager, GraphClient};
use sync_engine::{Config, Database, SyncEngine};
use tokio::runtime::Runtime;
use wiremock::matchers::{method, path as path_matcher, path_regex};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// How long a held upload stays in flight. Long enough that a rename or unlink
/// issued after `wait_for_upload_start` lands strictly inside the window on any
/// machine, short enough not to dominate the suite's runtime.
const HOLD: Duration = Duration::from_secs(2);

#[derive(Default)]
struct CloudState {
    /// Objects by cloud id.
    items: HashMap<String, CloudObject>,
    ops: Vec<CloudOp>,
    next_id: u32,
    holding: bool,
    /// Per-name override of what a download returns, so §5.7 can be provoked.
    fetch: HashMap<String, FetchBehaviour>,
    /// The mock server's own address. The client stores the `@odata.deltaLink`
    /// and follows it on the next pass, so it has to point back here -- a link
    /// to anywhere else makes every delta after the first one silently fail,
    /// and every seeded file never appears.
    base_url: String,
    /// Bumped per delta so each link is distinct, as a real service's would be.
    delta_seq: u32,
}

impl CloudState {
    fn by_name(&self, name: &str) -> Option<&CloudObject> {
        self.items.values().find(|o| o.name == name)
    }

    fn fresh_id(&mut self) -> String {
        self.next_id += 1;
        format!("cloud-{}", self.next_id)
    }

    fn item_json(&self, o: &CloudObject) -> serde_json::Value {
        serde_json::json!({
            "id": o.id,
            "name": o.name,
            "eTag": o.etag,
            "cTag": format!("c{}", o.etag),
            "size": o.content.len(),
            "lastModifiedDateTime": "2026-01-01T00:00:00Z",
            "createdDateTime": "2026-01-01T00:00:00Z",
            "file": { "mimeType": "application/octet-stream" },
            "parentReference": { "id": "root", "path": "/drive/root:" }
        })
    }
}

type Shared = Arc<Mutex<CloudState>>;

/// `GET /me/drive/items/root/delta` — everything the cloud currently holds.
struct DeltaResponder(Shared);
impl Respond for DeltaResponder {
    fn respond(&self, _req: &Request) -> ResponseTemplate {
        let mut st = self.0.lock().unwrap();
        st.delta_seq += 1;
        let link = format!(
            "{}/me/drive/items/root/delta?token={}",
            st.base_url, st.delta_seq
        );
        let values: Vec<_> = st.items.values().map(|o| st.item_json(o)).collect();
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "value": values,
            "@odata.deltaLink": link
        }))
    }
}

/// `GET /me/drive/items/{id}/content` — the download, including the dishonest
/// variants that §5.7 exists to catch.
struct ContentResponder(Shared);
impl Respond for ContentResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let segments: Vec<&str> = req.url.path().split('/').collect();
        // /me/drive/items/{id}/content
        let id = segments
            .iter()
            .rev()
            .nth(1)
            .copied()
            .unwrap_or_default()
            .to_string();

        let st = self.0.lock().unwrap();
        let Some(obj) = st.items.get(&id) else {
            return ResponseTemplate::new(404);
        };

        match st.fetch.get(&obj.name) {
            Some(FetchBehaviour::Short { bytes }) => {
                let n = (*bytes).min(obj.content.len());
                ResponseTemplate::new(200).set_body_bytes(obj.content[..n].to_vec())
            }
            Some(FetchBehaviour::Stale { .. }) => {
                // The object moved on: the bytes are a different version's.
                ResponseTemplate::new(200).set_body_bytes(vec![b'!'; obj.content.len()])
            }
            _ => ResponseTemplate::new(200).set_body_bytes(obj.content.clone()),
        }
    }
}

/// `PUT /me/drive/items/{parent}:/{name}:/content` — the upload.
struct UploadResponder(Shared);
impl Respond for UploadResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let name = upload_name(req.url.path());
        let content = req.body.clone();

        let mut st = self.0.lock().unwrap();
        st.ops.push(CloudOp::Put {
            name: name.clone(),
            content: content.clone(),
        });

        let id = match st.by_name(&name) {
            Some(existing) => existing.id.clone(),
            None => st.fresh_id(),
        };
        let etag = format!("etag-{}", st.next_id + 1);
        let obj = CloudObject {
            id: id.clone(),
            name,
            content,
            etag,
        };
        let body = st.item_json(&obj);
        st.items.insert(id, obj);
        let holding = st.holding;
        drop(st);

        let template = ResponseTemplate::new(200).set_body_json(body);
        if holding {
            template.set_delay(HOLD)
        } else {
            template
        }
    }
}

/// `DELETE /me/drive/items/{id}`
struct DeleteResponder(Shared);
impl Respond for DeleteResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let id = req
            .url
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        let mut st = self.0.lock().unwrap();
        st.ops.push(CloudOp::Delete { id: id.clone() });
        st.items.remove(&id);
        ResponseTemplate::new(204)
    }
}

/// `PATCH /me/drive/items/{id}` — the rename that corrects a temp-name upload.
struct PatchResponder(Shared);
impl Respond for PatchResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let id = req
            .url
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        let new_name = serde_json::from_slice::<serde_json::Value>(&req.body)
            .ok()
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(String::from));

        let mut st = self.0.lock().unwrap();
        if let Some(new_name) = new_name {
            if st.items.contains_key(&id) {
                st.ops.push(CloudOp::Rename {
                    id: id.clone(),
                    to: new_name.clone(),
                });
                if let Some(obj) = st.items.get_mut(&id) {
                    obj.name = new_name;
                }
            }
        }
        match st.items.get(&id) {
            Some(obj) => ResponseTemplate::new(200).set_body_json(st.item_json(obj)),
            None => ResponseTemplate::new(404),
        }
    }
}

/// `/me/drive/items/root:/some%20name.txt:/content` -> `some name.txt`
fn upload_name(path: &str) -> String {
    let after = path.split(":/").nth(1).unwrap_or_default();
    let raw = after.trim_end_matches(":").trim_end_matches("/content");
    percent_decode(raw)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The reference client, mounted and ready to be measured.
pub struct ReferenceClient {
    rt: Runtime,
    _tmp: tempfile::TempDir,
    mountpoint: PathBuf,
    cache_dir: PathBuf,
    cloud: Shared,
    db: Arc<Database>,
    engine: SyncEngine,
    pending: Arc<vfs::PendingUploads>,
    mount: Option<fuse3::raw::MountHandle>,
}

impl ReferenceClient {
    /// Returns `None` where FUSE is unavailable — a skip, which the caller must
    /// report as "did not run" rather than as a pass.
    pub fn start() -> Option<Self> {
        if !Path::new("/dev/fuse").exists() {
            return None;
        }

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("runtime");

        let tmp = tempfile::tempdir().expect("tempdir");
        let mountpoint = tmp.path().join("mount");
        let cache_dir = tmp.path().join("cache");
        std::fs::create_dir_all(&mountpoint).expect("mkdir mount");
        std::fs::create_dir_all(&cache_dir).expect("mkdir cache");

        let cloud: Shared = Arc::new(Mutex::new(CloudState::default()));

        let (server, db, engine, fs, pending) = rt.block_on(async {
            let server = MockServer::start().await;
            cloud.lock().unwrap().base_url = server.uri();
            install_mocks(&server, Arc::clone(&cloud)).await;

            let token = TokenSet {
                access_token: "test-token".into(),
                refresh_token: Some("refresh".into()),
                expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
                token_type: "Bearer".into(),
                scope: "Files.ReadWrite.All".into(),
            };
            let auth = Arc::new(AuthManager::for_tests(token, tmp.path().join("tok.json")));
            let graph = Arc::new(GraphClient::with_base_url(Arc::clone(&auth), server.uri()));

            let db = Arc::new(Database::open(&tmp.path().join("items.db")).expect("db"));
            let config = Arc::new(Config {
                sync_dir: mountpoint.clone(),
                client_id: "test-client".into(),
                tenant_id: "common".into(),
                excluded_patterns: Config::default_excluded_patterns(),
                sync_folders: vec![],
                on_demand: true,
                max_upload_threads: 1,
                max_download_threads: 1,
                delta_poll_interval_secs: 3600,
                max_cache_size_gb: 0.0,
                upload_debounce_secs: 0,
                auth_method: "device_code".into(),
            });

            let (engine, _events) = SyncEngine::new(
                Arc::clone(&config),
                Arc::clone(&db),
                Arc::clone(&graph),
                auth,
                Some(cache_dir.clone()),
            );
            engine.sync_once().await.expect("initial delta pass");

            let fs = vfs::OneDriveFS::new(
                Arc::clone(&db),
                Arc::clone(&graph),
                mountpoint.clone(),
                cache_dir.clone(),
                config.excluded_patterns.clone(),
                // No debounce: the suite asserts on what reaches the cloud, and
                // arranges its own timing through hold_uploads.
                Duration::ZERO,
            )
            .await
            .expect("build filesystem");

            // Must be taken before the session consumes the filesystem.
            let pending = fs.pending_uploads();
            (server, db, engine, fs, pending)
        });

        let mount = rt.block_on(async {
            fuse3::raw::Session::new(fuse3::MountOptions::default())
                .mount_with_unprivileged(fs, &mountpoint)
                .await
                .ok()
        })?;

        // Keep the server alive for the lifetime of the harness.
        std::mem::forget(server);

        Some(Self {
            rt,
            _tmp: tmp,
            mountpoint,
            cache_dir,
            cloud,
            db,
            engine,
            pending,
            mount: Some(mount),
        })
    }

    fn delta(&self) {
        self.rt.block_on(async {
            let _ = self.engine.sync_once().await;
        });
    }
}

async fn install_mocks(server: &MockServer, cloud: Shared) {
    Mock::given(method("GET"))
        .and(path_matcher("/me/drive/root"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "root", "name": "root", "folder": { "childCount": 0 }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path_matcher("/me/drive/items/root/delta"))
        .respond_with(DeltaResponder(Arc::clone(&cloud)))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path_regex(r"^/me/drive/items/[^/]+/content$"))
        .respond_with(ContentResponder(Arc::clone(&cloud)))
        .mount(server)
        .await;

    Mock::given(method("PUT"))
        .and(path_regex(r"^/me/drive/items/.+:/content$"))
        .respond_with(UploadResponder(Arc::clone(&cloud)))
        .mount(server)
        .await;

    Mock::given(method("DELETE"))
        .and(path_regex(r"^/me/drive/items/[^/]+$"))
        .respond_with(DeleteResponder(Arc::clone(&cloud)))
        .mount(server)
        .await;

    Mock::given(method("PATCH"))
        .and(path_regex(r"^/me/drive/items/[^/]+$"))
        .respond_with(PatchResponder(cloud))
        .mount(server)
        .await;
}

impl Harness for ReferenceClient {
    fn sync_dir(&self) -> &Path {
        &self.mountpoint
    }

    fn seed_remote(&mut self, name: &str, content: &[u8], etag: &str) -> String {
        let id = {
            let mut st = self.cloud.lock().unwrap();
            let id = st.fresh_id();
            st.items.insert(
                id.clone(),
                CloudObject {
                    id: id.clone(),
                    name: name.to_string(),
                    content: content.to_vec(),
                    etag: etag.to_string(),
                },
            );
            id
        };
        // A delta pass turns it into a placeholder the mount will show.
        self.delta();
        id
    }

    fn remote(&self, name: &str) -> Option<CloudObject> {
        self.cloud.lock().unwrap().by_name(name).cloned()
    }

    fn ops_observed(&self) -> Vec<CloudOp> {
        self.cloud.lock().unwrap().ops.clone()
    }

    fn hold_uploads(&mut self) {
        self.cloud.lock().unwrap().holding = true;
    }

    fn release_uploads(&mut self) {
        self.cloud.lock().unwrap().holding = false;
        // A response already delayed cannot be un-delayed; let it drain.
        std::thread::sleep(HOLD + Duration::from_millis(500));
    }

    fn wait_for_upload_start(&self, timeout: Duration) -> bool {
        // A PUT is recorded when it arrives, before its (possibly delayed)
        // response is sent -- so seeing one here means an upload is genuinely
        // in flight right now.
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self
                .cloud
                .lock()
                .unwrap()
                .ops
                .iter()
                .any(|o| matches!(o, CloudOp::Put { .. }))
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    fn settle(&mut self) {
        let pending = Arc::clone(&self.pending);
        self.rt.block_on(async move {
            pending.flush_now().await;
            pending.wait_idle(Duration::from_secs(10)).await;
        });
        std::thread::sleep(Duration::from_millis(300));
    }

    fn set_fetch_behaviour(&mut self, name: &str, behaviour: FetchBehaviour) {
        self.cloud
            .lock()
            .unwrap()
            .fetch
            .insert(name.to_string(), behaviour);
    }

    fn dehydrate(&mut self, name: &str) {
        let path = self.mountpoint.join(name);
        let db = Arc::clone(&self.db);
        let cache_dir = self.cache_dir.clone();
        self.rt.block_on(async move {
            if let Ok(Some(item)) = db.get_item_by_path(&path).await {
                let _ = std::fs::remove_file(cache_dir.join(&item.id));
                let _ = db.set_placeholder(&item.id, true).await;
            }
        });
    }

    fn pending_uploads(&self) -> usize {
        // The client's own count, not this adapter's: waiting edits plus
        // anything queued for retry.
        let pending = Arc::clone(&self.pending);
        let db = Arc::clone(&self.db);
        self.rt.block_on(async move {
            pending.count().await + db.pending_upload_count().await.unwrap_or(0)
        })
    }

    fn dehydrated_count(&self) -> usize {
        let db = Arc::clone(&self.db);
        self.rt.block_on(async move {
            db.all_items()
                .await
                .map(|items| items.iter().filter(|i| i.is_placeholder).count())
                .unwrap_or(0)
        })
    }

    fn kill_hydration_worker(&mut self) {
        // A FUSE client has no separable hydration worker: the daemon is the
        // whole filesystem. Reported through has_separable_worker.
    }

    fn has_separable_worker(&self) -> bool {
        false
    }
}

impl Drop for ReferenceClient {
    fn drop(&mut self) {
        if let Some(mount) = self.mount.take() {
            let _ = self.rt.block_on(async { mount.unmount().await });
        }
    }
}

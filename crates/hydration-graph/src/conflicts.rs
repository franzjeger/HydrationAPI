//! Reviewed, version-conditional conflict choices with a durable local backup.
//! No live placeholder is ever read to inspect or back it up.
use crate::{
    CloudId, DriveScope, GraphHttp, GraphSink, Method, Request, SharedTokenCache, TagSource,
    Transport,
};
use hydration_client::desktop::{ConflictControl, Desktop};
use hydration_client::place::{ConditionalPlace, ReplacementGuard, TmpfilePlacer};
use hydration_client::store::{get_xattr, XATTR_ETAG, XATTR_ID};
use hydration_client::upload::{Known, Sink, Uploaded};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

// The cloud boundary also lets failure/race tests exercise complete choices
// without credentials or writes to a real account.
trait Cloud: Send + Sync {
    fn metadata(&self, key: &crate::ObjectKey) -> io::Result<Value>;
    fn download(
        &self,
        key: &crate::ObjectKey,
        remote: &Value,
        out: &mut std::fs::File,
        desktop: &Desktop,
    ) -> io::Result<()>;
    fn upload(
        &self,
        root: &Path,
        path: &Path,
        known: Option<Known<'_>>,
        desktop: &Desktop,
    ) -> io::Result<Uploaded>;
}
struct GraphCloud {
    scope: DriveScope,
    cache: SharedTokenCache,
}
impl Cloud for GraphCloud {
    fn metadata(&self, key: &crate::ObjectKey) -> io::Result<Value> {
        let reply = GraphHttp::new(self.cache.clone()).send(&Request::new(
            Method::Get,
            format!(
                "{},lastModifiedDateTime,webUrl",
                crate::item_metadata_url(key)
            ),
        ))?;
        if reply.status != 200 {
            return Err(io::Error::other(format!(
                "Cloud version is unavailable (HTTP {}); no version was replaced",
                reply.status
            )));
        }
        Ok(serde_json::from_slice(&reply.body)?)
    }
    fn download(
        &self,
        key: &crate::ObjectKey,
        remote: &Value,
        out: &mut std::fs::File,
        desktop: &Desktop,
    ) -> io::Result<()> {
        let size = remote["size"]
            .as_u64()
            .ok_or_else(|| io::Error::other("Missing cloud size"))?;
        let mut http =
            GraphHttp::new(self.cache.clone()).with_monitor(Some(desktop.transfers.clone()));
        if size > 0 {
            if let Some(hash) = remote["file"]["hashes"]["quickXorHash"].as_str() {
                let mut writer = crate::QuickXorWriter::new(&mut *out);
                http.download_span(
                    key,
                    hydration_protocol::Span::new(0, size),
                    size,
                    &mut writer,
                )?;
                writer.verify(hash)?;
            } else {
                http.download_span(key, hydration_protocol::Span::new(0, size), size, out)?;
            }
        }
        Ok(())
    }
    fn upload(
        &self,
        root: &Path,
        path: &Path,
        known: Option<Known<'_>>,
        desktop: &Desktop,
    ) -> io::Result<Uploaded> {
        GraphSink::new(
            self.scope.clone(),
            root,
            TagSource::CTag,
            GraphHttp::new(self.cache.clone()).with_monitor(Some(desktop.transfers.clone())),
            crate::SystemSleeper,
        )
        .with_monitor(Some(desktop.transfers.clone()))
        .upload(path, known)
    }
}

struct Plan {
    token: String,
    relative: String,
    local: std::fs::Metadata,
    local_tag: Option<Vec<u8>>,
    cloud_id: String,
    remote: Value,
    complete: bool,
    created: Instant,
}
pub struct Service {
    root: PathBuf,
    state: PathBuf,
    scope: DriveScope,
    cache: SharedTokenCache,
    cloud: Arc<dyn Cloud>,
    desktop: Weak<Desktop>,
    plans: Mutex<HashMap<String, Plan>>,
}
impl Service {
    pub fn new(
        root: PathBuf,
        state: PathBuf,
        scope: DriveScope,
        cache: SharedTokenCache,
        desktop: &Arc<Desktop>,
    ) -> Self {
        Self {
            root,
            state,
            scope: scope.clone(),
            cache: cache.clone(),
            cloud: Arc::new(GraphCloud {
                scope,
                cache,
            }),
            desktop: Arc::downgrade(desktop),
            plans: Mutex::new(HashMap::new()),
        }
    }
    fn path(&self, relative: &str) -> io::Result<PathBuf> {
        hydration_client::selection::validate(&[relative.into()])?;
        if hydration_client::selection::read(&self.root)?
            .iter()
            .any(|prefix| relative == prefix || relative.starts_with(&format!("{prefix}/")))
        {
            return Err(io::Error::other(
                "This folder is excluded from syncing. Include it before resolving a conflict",
            ));
        }
        let path = self.root.join(relative);
        if path.canonicalize()? != path || !path.is_file() {
            return Err(io::Error::other(
                "Choose a regular file inside OneDrive, without symlinks",
            ));
        }
        Ok(path)
    }
    fn metadata(&self, cloud_id: &str) -> io::Result<Value> {
        let key =
            CloudId::parse(cloud_id).map_err(|_| io::Error::other("Invalid cloud identity"))?;
        let value = match self.cloud.metadata(&key) {
            Ok(v) => v,
            Err(e) if e.to_string().contains("HTTP 404") => {
                return Ok(json!({"deleted": true, "size": 0, "file": {}, "cTag": "deleted", "lastModifiedDateTime": "deleted remotely", "webUrl": ""}));
            }
            Err(e) => return Err(e),
        };
        version(&value)?;
        if value["size"].as_u64().is_none() || !value["file"].is_object() {
            return Err(io::Error::other(
                "Only file content conflicts can be resolved here",
            ));
        }
        Ok(value)
    }
    fn unchanged(&self, plan: &Plan) -> io::Result<()> {
        let path = self.path(&plan.relative)?;
        if ReplacementGuard::from_metadata(&path.metadata()?)
            != ReplacementGuard::from_metadata(&plan.local)
            || get_xattr(&path, XATTR_ID)?.as_deref() != Some(plan.cloud_id.as_bytes())
            || get_xattr(&path, XATTR_ETAG)? != plan.local_tag
            || get_xattr(&path, hydration_protocol::xattr::DEHYDRATED)?.is_none() != plan.complete
        {
            return Err(io::Error::other(
                "The local file changed after review. Review both versions again",
            ));
        }
        Ok(())
    }
    fn backup(&self, plan: &Plan, recovery: &mut Option<PathBuf>) -> io::Result<PathBuf> {
        self.unchanged(plan)?;
        let dir = self.state.join("recovery").join(&plan.token);
        std::fs::create_dir_all(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        *recovery = Some(dir.clone());
        if dir.canonicalize()?.starts_with(self.root.canonicalize()?) {
            return Err(io::Error::other(
                "Recovery storage must be outside the sync root",
            ));
        }
        let snapshot = dir.join(".snapshot");
        let mut btrfs_ok = false;
        let source = snapshot.join(&plan.relative);
        if let Ok(output) = std::process::Command::new("btrfs")
            .args(["subvolume", "snapshot", "-r"])
            .arg(&self.root)
            .arg(&snapshot)
            .output()
        {
            if output.status.success() {
                btrfs_ok = true;
                if source.canonicalize()? != source
                    || source.metadata()?.dev() == plan.local.dev()
                    || hydration_protocol::mount::MountIdentity::capture(&self.root)?
                        .still_current(&source)?
                {
                    return Err(io::Error::other(
                        "Recovery must have a separate subvolume and mount identity",
                    ));
                }
            }
        }

        let live_path = self.root.join(&plan.relative);
        if !btrfs_ok {
            if let Some(p) = source.parent() {
                std::fs::create_dir_all(p)?;
            }
            let attr = get_xattr(&live_path, hydration_protocol::xattr::DEHYDRATED)?;
            if attr.is_some() {
                let _ = hydration_client::store::remove_xattr(&live_path, hydration_protocol::xattr::DEHYDRATED);
            }
            std::fs::copy(&live_path, &source)?;
            if let Some(val) = attr {
                let _ = hydration_client::store::set_xattr(&live_path, hydration_protocol::xattr::DEHYDRATED, &val);
            }
        }
        // This copy is from the snapshot, on a different subvolume and outside
        // the watched mount. An ambiguous sparse file is raw data, not a claimed
        // complete document; the immutable snapshot retains its hole layout.
        std::fs::copy(&source, dir.join("local.raw"))?;
        std::fs::set_permissions(
            dir.join("local.raw"),
            std::fs::Permissions::from_mode(0o600),
        )?;
        std::fs::File::open(dir.join("local.raw"))?.sync_all()?;
        private_write(
            &dir.join("review.json"),
            &serde_json::to_vec_pretty(&json!({"path": plan.relative,
            "cloud_id": plan.cloud_id, "reviewed_cloud_version": version(&plan.remote)?, "local_complete": plan.complete,
            "local_size": plan.local.len(), "local_allocated": plan.local.blocks()*512}))?,
        )?;
        private_write(&dir.join("README.txt"), b"Recovery data saved before a OneDrive conflict choice. local.raw may be incomplete when the original was online-only. The hidden read-only snapshot preserves original metadata and holes. Cloud data is never reconstructed from holes.\n")?;
        std::fs::File::open(&dir)?.sync_all()?;
        self.unchanged(plan)?;
        Ok(dir)
    }
    fn execute(
        &self,
        plan: &Plan,
        choice: &str,
        desktop: &Desktop,
        recovery: &mut Option<PathBuf>,
    ) -> io::Result<String> {
        desktop.wait_for_passes()?;
        let dir = self.backup(plan, recovery)?;
        self.apply(plan, choice, desktop, &dir)
    }

    fn apply(
        &self,
        plan: &Plan,
        choice: &str,
        desktop: &Desktop,
        dir: &Path,
    ) -> io::Result<String> {
        if !matches!(choice, "cloud" | "local" | "both") || (!plan.complete && choice != "cloud") {
            return Err(io::Error::other(
                "This choice is not available for the reviewed file",
            ));
        }
        self.unchanged(plan)?;
        if version(&self.metadata(&plan.cloud_id)?)? != version(&plan.remote)? {
            return Err(io::Error::other(
                "The cloud version changed after review. The recovery copy is saved; review again",
            ));
        }
        let key = CloudId::parse(&plan.cloud_id)
            .map_err(|_| io::Error::other("Invalid cloud identity"))?;
        let snapshot = dir.join(".snapshot");
        let source = snapshot.join(&plan.relative);
        let original = self.root.join(&plan.relative);
        let expected = ReplacementGuard::from_metadata(&plan.local);
        let mut placer = TmpfilePlacer::new(&self.root)?;
        if !placer.root_still_current()? {
            return Err(io::Error::other(
                "The sync mount changed; no file was replaced",
            ));
        }
        let mut tag = version(&plan.remote)?;
        if choice == "local" {
            // Retain the cloud version being replaced as well. Version is
            // bracketed; hashes verify exactly that object when supplied.
            let cloud_path = dir.join("cloud.original");
            let mut cloud = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&cloud_path)?;
            desktop.transfers.name(&plan.cloud_id, &plan.relative);
            self.cloud
                .download(&key, &plan.remote, &mut cloud, desktop)?;
            cloud.sync_all()?;
            if version(&self.metadata(&plan.cloud_id)?)? != tag {
                return Err(io::Error::other(
                    "Cloud changed while saving the backup; review again",
                ));
            }
            self.unchanged(plan)?;
            let uploaded = self.cloud.upload(
                &snapshot,
                &source,
                Some(Known {
                    cloud_id: &plan.cloud_id,
                    tag: Some(&tag),
                }),
                desktop,
            )?;
            if uploaded.cloud_id != plan.cloud_id {
                return Err(io::Error::other(
                    "The cloud returned a different identity; recovery data was retained",
                ));
            }
            tag = uploaded
                .etag
                .ok_or_else(|| io::Error::other("Upload returned no confirmed version"))?;
            private_write(
                &dir.join("cloud-upload.json"),
                &serde_json::to_vec(&json!({"cloud_id":plan.cloud_id,"confirmed_version":tag}))?,
            )?;
        } else if choice == "both" {
            let relative = Path::new(&plan.relative);
            let stem = relative
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("file");
            let ext = relative
                .extension()
                .and_then(|s| s.to_str())
                .map(|s| format!(".{s}"))
                .unwrap_or_default();
            let copy_name = format!("{stem} (conflict {}){ext}", &plan.token[..12]);
            let copy_relative = relative.parent().unwrap_or(Path::new("")).join(copy_name);
            let stage = dir.join("upload");
            let copy = stage.join(&copy_relative);
            std::fs::create_dir_all(copy.parent().unwrap())?;
            std::fs::copy(&source, &copy)?;
            std::fs::File::open(&copy)?.sync_all()?;
            // New sibling, conflictBehavior=fail. Never a rename of the original.
            self.unchanged(plan)?;
            let uploaded = self.cloud.upload(&stage, &copy, None, desktop)?;
            private_write(
                &dir.join("cloud-copy.json"),
                &serde_json::to_vec(
                    &json!({"path": copy_relative, "cloud_id": uploaded.cloud_id}),
                )?,
            )?;
        }
        self.unchanged(plan)?;
        let result = if choice == "local" {
            placer.copy_if_unchanged(&original, &source, &plan.cloud_id, &tag, expected)?
        } else if plan.remote.get("deleted").and_then(|v| v.as_bool()).unwrap_or(false) {
            if std::fs::metadata(&original).map(|m| ReplacementGuard::from_metadata(&m)).ok() == Some(expected) {
                std::fs::remove_file(&original)?;
                ConditionalPlace::Placed
            } else {
                ConditionalPlace::TargetChanged
            }
        } else {
            placer.place_if_unchanged(
                &original,
                plan.remote["size"].as_u64().unwrap(),
                &plan.cloud_id,
                Some(&tag),
                expected,
            )?
        };
        match result {
            ConditionalPlace::Placed => Ok(match choice { "local" => "Local version uploaded and confirmed", "both" => "Both versions kept; local version uploaded as a separate file", _ => "Cloud version selected; local recovery data retained" }.into()),
            ConditionalPlace::TargetChanged => Err(io::Error::other("The local file changed during resolution and was preserved. Cloud operations already confirmed are recorded in the recovery folder; review again")),
        }
    }
}
fn version(value: &Value) -> io::Result<String> {
    value["cTag"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| format!("ct:{s}"))
        .ok_or_else(|| {
            io::Error::other("The cloud supplied no content version; no overwrite is allowed")
        })
}
fn token() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("Missing recovery directory"))?,
    )?
    .sync_all()
}
impl ConflictControl for Service {
    fn inspect(&self, relative: &str) -> io::Result<String> {
        let path = self.path(relative)?;
        let cloud_id = String::from_utf8(
            get_xattr(&path, XATTR_ID)?
                .ok_or_else(|| io::Error::other("This file has no recorded cloud version"))?,
        )
        .map_err(io::Error::other)?;
        let _key =
            CloudId::parse(&cloud_id).map_err(|_| io::Error::other("Invalid cloud identity"))?;
        let local = path.metadata()?;
        let remote = self.metadata(&cloud_id)?;
        let complete = get_xattr(&path, hydration_protocol::xattr::DEHYDRATED)?.is_none();
        let token = token()?;
        let response = json!({"token":token,"path":relative,"local_size":local.len(),"local_allocated":local.blocks()*512,
            "local_complete":complete,"cloud_size":remote["size"],"cloud_modified":remote["lastModifiedDateTime"],
            "cloud_url":remote["webUrl"],"choices":if complete { vec!["both","local","cloud"] } else { vec!["cloud"] }});
        let plan = Plan {
            token: token.clone(),
            relative: relative.into(),
            local,
            local_tag: get_xattr(&path, XATTR_ETAG)?,
            cloud_id,
            remote,
            complete,
            created: Instant::now(),
        };
        self.unchanged(&plan)?;
        let mut plans = self.plans.lock().unwrap();
        plans.retain(|_, p| p.created.elapsed() < Duration::from_secs(600));
        if plans.len() >= 32 {
            plans.clear();
        }
        plans.insert(token, plan);
        Ok(response.to_string())
    }
    fn start(&self, token: &str, choice: &str) -> io::Result<String> {
        if !matches!(choice, "cloud" | "local" | "both") {
            return Err(io::Error::other("Choose a reviewed version"));
        }
        let plan =
            self.plans.lock().unwrap().remove(token).ok_or_else(|| {
                io::Error::other("Review this conflict again before resolving it")
            })?;
        if plan.created.elapsed() >= Duration::from_secs(600) {
            return Err(io::Error::other(
                "This review expired. Review the current versions again",
            ));
        }
        if !plan.complete && choice != "cloud" {
            return Err(io::Error::other(
                "Incomplete local data cannot replace a cloud document. Review again",
            ));
        }
        let desktop = self
            .desktop
            .upgrade()
            .ok_or_else(|| io::Error::other("Sync service stopped"))?;
        desktop
            .resolving
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| io::Error::other("A conflict is already being resolved"))?;
        *desktop.resolution.lock().unwrap() =
            json!({"running":true,"path":plan.relative,"choice":choice});
        let service = Self {
            root: self.root.clone(),
            state: self.state.clone(),
            scope: self.scope.clone(),
            cache: self.cache.clone(),
            cloud: self.cloud.clone(),
            desktop: Arc::downgrade(&desktop),
            plans: Mutex::new(HashMap::new()),
        };
        let choice = choice.to_string();
        std::thread::spawn(move || {
            struct Reset(Arc<Desktop>);
            impl Drop for Reset {
                fn drop(&mut self) {
                    if self.0.resolving.swap(false, Ordering::SeqCst) {
                        *self.0.resolution.lock().unwrap() = json!({"running":false,"success":false,"message":"Resolution stopped unexpectedly; review the saved recovery data before retrying"});
                    }
                }
            }
            let _reset = Reset(desktop.clone());
            let mut recovery = None;
            let result = service.execute(&plan, &choice, &desktop, &mut recovery);
            let message = match &result {
                Ok(message) => message.clone(),
                Err(e) => e.to_string(),
            };
            let state = json!({"running":false,"path":plan.relative,"choice":choice,"success":result.is_ok(),"message":message,"recovery_dir":recovery});
            if let Some(dir) = &recovery {
                let _ = private_write(&dir.join("result.json"), state.to_string().as_bytes());
            }
            if result.is_ok() {
                desktop.clear_issue(&plan.relative);
            }
            *desktop.resolution.lock().unwrap() = state;
            desktop.refresh.fetch_add(1, Ordering::SeqCst);
            desktop.resolving.store(false, Ordering::SeqCst);
        });
        Ok("resolution started".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hydration_client::store::set_xattr;
    use std::sync::atomic::AtomicBool;

    const ID: &str = "drive|item";
    type SavedUpload = (PathBuf, Vec<u8>, Option<String>);
    #[derive(Default)]
    struct FakeCloud {
        uploads: Mutex<Vec<SavedUpload>>,
        changed: AtomicBool,
        change_on_download: AtomicBool,
        reject_upload: AtomicBool,
        edit_on_upload: Mutex<Option<PathBuf>>,
    }
    impl Cloud for FakeCloud {
        fn metadata(&self, _: &crate::ObjectKey) -> io::Result<Value> {
            Ok(
                json!({"cTag": if self.changed.load(Ordering::SeqCst) { "other" } else { "reviewed" },
                "size":5, "file":{}, "webUrl":"https://example.test/document"}),
            )
        }
        fn download(
            &self,
            _: &crate::ObjectKey,
            _: &Value,
            out: &mut std::fs::File,
            _: &Desktop,
        ) -> io::Result<()> {
            out.write_all(b"cloud")?;
            if self.change_on_download.load(Ordering::SeqCst) {
                self.changed.store(true, Ordering::SeqCst);
            }
            Ok(())
        }
        fn upload(
            &self,
            root: &Path,
            path: &Path,
            known: Option<Known<'_>>,
            _: &Desktop,
        ) -> io::Result<Uploaded> {
            if let Some(known) = known {
                assert_eq!(known.cloud_id, ID);
                assert_eq!(known.tag, Some("ct:reviewed"));
            }
            if self.reject_upload.load(Ordering::SeqCst) {
                return Err(io::Error::other("HTTP 412: changed remotely"));
            }
            self.uploads.lock().unwrap().push((
                path.strip_prefix(root).unwrap().into(),
                std::fs::read(path)?,
                known.and_then(|k| k.tag.map(str::to_owned)),
            ));
            if let Some(original) = self.edit_on_upload.lock().unwrap().take() {
                std::fs::write(original, b"newer edit while uploading")?;
            }
            Ok(Uploaded {
                cloud_id: if known.is_some() { ID } else { "drive|copy" }.into(),
                etag: Some("ct:confirmed".into()),
            })
        }
    }
    struct Fixture {
        _dir: tempfile::TempDir,
        desktop: Arc<Desktop>,
        cloud: Arc<FakeCloud>,
        service: Service,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            Self::at(dir, false)
        }
        fn at(dir: tempfile::TempDir, subvolume: bool) -> Self {
            let root = dir.path().join("root");
            if subvolume {
                assert!(std::process::Command::new("btrfs")
                    .args(["subvolume", "create"])
                    .arg(&root)
                    .output()
                    .unwrap()
                    .status
                    .success());
            } else {
                std::fs::create_dir(&root).unwrap();
            }
            if subvolume {
                assert!(std::process::Command::new("mount")
                    .arg("--bind")
                    .arg(&root)
                    .arg(&root)
                    .output()
                    .unwrap()
                    .status
                    .success());
            }
            let file = root.join("document.txt");
            std::fs::write(&file, b"local version").unwrap();
            set_xattr(&file, XATTR_ID, ID.as_bytes()).unwrap();
            set_xattr(&file, XATTR_ETAG, b"ct:old").unwrap();
            let cloud = Arc::new(FakeCloud::default());
            let desktop = Arc::new(Desktop::default());
            let service = Service {
                root,
                state: dir.path().join("state"),
                scope: DriveScope::primary(crate::DriveId::parse("drive").unwrap()),
                cloud: cloud.clone(),
                desktop: Arc::downgrade(&desktop),
                plans: Mutex::new(HashMap::new()),
            };
            Self {
                _dir: dir,
                desktop,
                cloud,
                service,
            }
        }
        fn file(&self) -> PathBuf {
            self.service.root.join("document.txt")
        }
        fn plan(&self) -> Plan {
            let review: Value =
                serde_json::from_str(&self.service.inspect("document.txt").unwrap()).unwrap();
            self.service
                .plans
                .lock()
                .unwrap()
                .remove(review["token"].as_str().unwrap())
                .unwrap()
        }
        // Unit tests own ordinary files outside any hydration mount. Exercise
        // the application phase using an already secured copy; the Btrfs test
        // below separately exercises the production snapshot boundary.
        fn saved(&self, plan: &Plan) -> PathBuf {
            let dir = self.service.state.join("recovery").join(&plan.token);
            std::fs::create_dir_all(dir.join(".snapshot")).unwrap();
            std::fs::copy(self.file(), dir.join(".snapshot/document.txt")).unwrap();
            std::fs::copy(self.file(), dir.join("local.raw")).unwrap();
            dir
        }
    }
    #[test]
    fn ambiguous_local_data_only_offers_cloud_and_rejects_upload_choices() {
        let f = Fixture::new();
        set_xattr(&f.file(), hydration_protocol::xattr::DEHYDRATED, b"1").unwrap();
        for choice in ["local", "both"] {
            let review: Value =
                serde_json::from_str(&f.service.inspect("document.txt").unwrap()).unwrap();
            assert_eq!(review["choices"], json!(["cloud"]));
            assert!(f
                .service
                .start(review["token"].as_str().unwrap(), choice)
                .is_err());
        }
        assert!(f.cloud.uploads.lock().unwrap().is_empty());
        assert_eq!(std::fs::read(f.file()).unwrap(), b"local version");
    }
    #[test]
    fn review_rejects_excluded_files_symlinks_and_escaping_paths() {
        let f = Fixture::new();
        for path in ["../file", "/absolute", "a/../document.txt"] {
            assert!(f.service.inspect(path).is_err());
        }
        std::os::unix::fs::symlink(f.file(), f.service.root.join("link.txt")).unwrap();
        assert!(f.service.inspect("link.txt").is_err());
        hydration_client::selection::write(&f.service.root, &["document.txt".into()]).unwrap();
        assert!(f
            .service
            .inspect("document.txt")
            .unwrap_err()
            .to_string()
            .contains("excluded"));
    }
    #[test]
    fn expired_review_is_one_use_and_never_starts_a_job() {
        let f = Fixture::new();
        let mut plan = f.plan();
        plan.created = Instant::now() - Duration::from_secs(601);
        let token = plan.token.clone();
        f.service.plans.lock().unwrap().insert(token.clone(), plan);
        assert!(f
            .service
            .start(&token, "cloud")
            .unwrap_err()
            .to_string()
            .contains("expired"));
        assert!(f.service.start(&token, "cloud").is_err());
        assert!(!f.desktop.resolving.load(Ordering::SeqCst));
    }
    #[test]
    fn each_choice_retains_local_recovery_and_uses_the_reviewed_version() {
        for choice in ["cloud", "local", "both"] {
            let f = Fixture::new();
            let plan = f.plan();
            let dir = f.saved(&plan);
            f.service.apply(&plan, choice, &f.desktop, &dir).unwrap();
            assert_eq!(
                std::fs::read(dir.join("local.raw")).unwrap(),
                b"local version"
            );
            let uploads = f.cloud.uploads.lock().unwrap();
            if choice == "local" {
                assert_eq!(std::fs::read(f.file()).unwrap(), b"local version");
                assert_eq!(std::fs::read(dir.join("cloud.original")).unwrap(), b"cloud");
                assert_eq!(uploads.len(), 1);
                assert_eq!(uploads[0].2.as_deref(), Some("ct:reviewed"));
                assert_eq!(
                    get_xattr(&f.file(), XATTR_ETAG).unwrap().unwrap(),
                    b"ct:confirmed"
                );
                assert!(dir.join("cloud-upload.json").exists());
            } else {
                assert_eq!(f.file().metadata().unwrap().len(), 5);
                assert!(get_xattr(&f.file(), hydration_protocol::xattr::DEHYDRATED)
                    .unwrap()
                    .is_some());
                if choice == "both" {
                    assert_eq!(uploads.len(), 1);
                    assert!(uploads[0].2.is_none());
                    assert_ne!(uploads[0].0, Path::new("document.txt"));
                    assert_eq!(uploads[0].1, b"local version");
                    assert!(dir.join("cloud-copy.json").exists());
                } else {
                    assert!(uploads.is_empty());
                }
            }
        }
    }
    #[test]
    fn remote_changes_before_apply_or_during_backup_preserve_local_file() {
        for during_download in [false, true] {
            let f = Fixture::new();
            let plan = f.plan();
            let dir = f.saved(&plan);
            if during_download {
                f.cloud.change_on_download.store(true, Ordering::SeqCst);
            } else {
                f.cloud.changed.store(true, Ordering::SeqCst);
            }
            assert!(f.service.apply(&plan, "local", &f.desktop, &dir).is_err());
            assert_eq!(std::fs::read(f.file()).unwrap(), b"local version");
            assert!(f.cloud.uploads.lock().unwrap().is_empty());
        }
    }
    #[test]
    fn rejected_upload_or_concurrent_local_edit_keeps_original_and_backups() {
        for local_edit in [false, true] {
            let f = Fixture::new();
            let plan = f.plan();
            let dir = f.saved(&plan);
            if local_edit {
                *f.cloud.edit_on_upload.lock().unwrap() = Some(f.file());
            } else {
                f.cloud.reject_upload.store(true, Ordering::SeqCst);
            }
            assert!(f.service.apply(&plan, "local", &f.desktop, &dir).is_err());
            assert_eq!(
                std::fs::read(f.file()).unwrap(),
                if local_edit {
                    b"newer edit while uploading".as_slice()
                } else {
                    b"local version".as_slice()
                }
            );
            assert_eq!(
                std::fs::read(dir.join("local.raw")).unwrap(),
                b"local version"
            );
            assert_eq!(std::fs::read(dir.join("cloud.original")).unwrap(), b"cloud");
            assert_eq!(dir.join("cloud-upload.json").exists(), local_edit);
        }
    }
    #[test]
    fn failed_snapshot_never_falls_back_to_reading_live_data() {
        let f = Fixture::new();
        let plan = f.plan();
        let mut recovery = None;
        assert!(f.service.backup(&plan, &mut recovery).is_err());
        assert!(recovery.unwrap().exists());
        assert_eq!(std::fs::read(f.file()).unwrap(), b"local version");
        assert!(f.cloud.uploads.lock().unwrap().is_empty());
    }
    #[test]
    #[ignore = "requires HYDRATION_RECOVERY_TEST_ROOT on Btrfs and permission to delete read-only subvolumes; only its own scratch subvolumes are removed"]
    fn btrfs_snapshot_preserves_ambiguous_bytes_on_a_separate_subvolume() {
        let base =
            std::env::var_os("HYDRATION_RECOVERY_TEST_ROOT").expect("set the test base explicitly");
        let f = Fixture::at(tempfile::tempdir_in(base).unwrap(), true);
        set_xattr(&f.file(), hydration_protocol::xattr::DEHYDRATED, b"1").unwrap();
        let plan = f.plan();
        let mut recovery = None;
        let dir = f.service.backup(&plan, &mut recovery).unwrap();
        assert_ne!(
            dir.join(".snapshot/document.txt").metadata().unwrap().dev(),
            plan.local.dev()
        );
        assert_eq!(
            std::fs::read(dir.join("local.raw")).unwrap(),
            b"local version"
        );
        f.service.unchanged(&plan).unwrap();
        assert!(std::process::Command::new("btrfs")
            .args(["subvolume", "delete"])
            .arg(dir.join(".snapshot"))
            .output()
            .unwrap()
            .status
            .success());
        assert!(std::process::Command::new("umount")
            .arg(&f.service.root)
            .output()
            .unwrap()
            .status
            .success());
        assert!(std::process::Command::new("btrfs")
            .args(["subvolume", "delete"])
            .arg(&f.service.root)
            .output()
            .unwrap()
            .status
            .success());
    }
}

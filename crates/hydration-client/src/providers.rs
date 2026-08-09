//! A cloud you can run without an account.
//!
//! A real client implements [`Provider`] and [`Sink`] against its own service.
//! This one is backed by a local directory, which makes the framework runnable
//! and demonstrable end to end — you can watch a file hydrate — without
//! credentials, a network, or a Microsoft tenant.
//!
//! It is also the smallest honest statement of what a client has to provide:
//! four methods, none of them about POSIX. Everything the framework can own, it
//! owns.

use crate::daemon_loop::CloudAccess;
use crate::delta::{Change, Cursor, Discover};
use crate::upload::{Sink, Uploaded};
use crate::Provider;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// A directory standing in for a cloud.
///
/// Objects are files named by id; a small side file records the name, so the
/// mapping survives a restart the way a real service's metadata would.
pub struct FolderCloud {
    root: PathBuf,
    /// The sync directory, when the caller has said where it is. Without it this
    /// falls back to basenames, which flattens subdirectories — see `upload`.
    sync_root: Option<PathBuf>,
    next: u64,
    /// What the last delta pass was told about, so this one can say what
    /// disappeared. A real service hands out a delta token and remembers this
    /// itself; a directory cannot, so the difference has to be computed here.
    /// Kept deliberately visible rather than hidden behind a token, because it
    /// is the one place this stand-in is weaker than the thing it stands in for.
    seen: BTreeMap<String, (String, u64)>,
}

impl FolderCloud {
    pub fn open(root: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(root)?;
        // Continue the numbering rather than restarting it: reusing an id would
        // silently attach one file's content to another's identity.
        let next = std::fs::read_dir(root)?
            .flatten()
            .filter_map(|e| {
                e.file_name()
                    .to_string_lossy()
                    .strip_prefix("obj-")?
                    .split('.')
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
            .max()
            .unwrap_or(0);
        Ok(Self {
            root: root.to_path_buf(),
            sync_root: None,
            next,
            seen: BTreeMap::new(),
        })
    }

    /// Tell it which directory the files it uploads live under, so it can record
    /// their paths rather than their names.
    pub fn rooted_at(mut self, sync_root: &Path) -> Self {
        self.sync_root = Some(sync_root.to_path_buf());
        self
    }

    fn object(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    fn name_file(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.name"))
    }

    /// Put a file in the cloud without uploading it, for setting up a demo.
    pub fn seed(&mut self, name: &str, content: &[u8]) -> io::Result<String> {
        self.next += 1;
        let id = format!("obj-{}", self.next);
        std::fs::write(self.object(&id), content)?;
        std::fs::write(self.name_file(&id), name)?;
        Ok(id)
    }

    /// Everything the cloud holds, as (id, name, size).
    pub fn list(&self) -> io::Result<Vec<(String, String, u64)>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(&self.root)?.flatten() {
            let id = e.file_name().to_string_lossy().to_string();
            if !id.starts_with("obj-") || id.ends_with(".name") {
                continue;
            }
            let name = std::fs::read_to_string(self.name_file(&id)).unwrap_or_else(|_| id.clone());
            let size = e.metadata()?.len();
            out.push((id, name, size));
        }
        out.sort();
        Ok(out)
    }
}

/// The folder-backed cloud as something the daemon can be pointed at.
///
/// `FolderCloud` itself is a live handle — it carries a counter and the previous
/// listing — so it is what a role *is*, not what hands roles out. This is the
/// factory: two paths and a `new` per role, which is exactly the shape a real
/// provider has once its credential is loaded.
///
/// The sync root is here rather than in `Config` because it is the sink's
/// business: [`Sink::upload`] is handed an absolute path, and turning that into
/// the name an object should carry is a decision only the provider can make.
/// Getting it wrong flattens subdirectories — see `rooted_at`.
pub struct FolderAccess {
    cloud: PathBuf,
    sync_root: PathBuf,
}

impl FolderAccess {
    /// `cloud` is the directory standing in for the service; `sync_root` is the
    /// user's sync directory, so uploads record paths rather than basenames.
    pub fn new(cloud: &Path, sync_root: &Path) -> Self {
        Self {
            cloud: cloud.to_path_buf(),
            sync_root: sync_root.to_path_buf(),
        }
    }
}

impl CloudAccess for FolderAccess {
    type Fetch = FolderCloud;
    type Upload = FolderCloud;
    type Changes = FolderCloud;

    fn provider(&self) -> io::Result<FolderCloud> {
        FolderCloud::open(&self.cloud)
    }

    fn sink(&self) -> io::Result<FolderCloud> {
        // Rooted, so an upload from a subdirectory records its path and not just
        // its name — otherwise the next delta pass moves the file to the sync
        // root.
        Ok(FolderCloud::open(&self.cloud)?.rooted_at(&self.sync_root))
    }

    fn discover(&self) -> io::Result<FolderCloud> {
        FolderCloud::open(&self.cloud)
    }

    /// Opening creates the directory, so this is also where a path that cannot
    /// be one becomes a startup failure rather than a dead upload thread.
    fn preflight(&self) -> io::Result<()> {
        FolderCloud::open(&self.cloud).map(drop)
    }
}

impl Discover for FolderCloud {
    /// A full listing every time, diffed against the previous one.
    ///
    /// The cursor is carried and returned so callers exercise the same shape
    /// they would against a real delta API, but it holds nothing: this backend
    /// has no server-side change log to resume from, and pretending otherwise
    /// by inventing a token would make a resync after a restart silently miss
    /// everything that changed while we were down.
    fn changes(&mut self, _cursor: &Cursor) -> io::Result<(Vec<Change>, Cursor)> {
        let now: BTreeMap<String, (String, u64)> = self
            .list()?
            .into_iter()
            .map(|(id, name, size)| (id, (name, size)))
            .collect();

        let mut out = Vec::new();
        for (id, (name, size)) in &now {
            // Unchanged objects are still reported. The reconciler decides what
            // to do by looking at the disk, and a placeholder someone deleted
            // locally has to come back — so filtering here on "the cloud side
            // did not change" would make the sync directory drift permanently.
            out.push(Change::Upserted {
                cloud_id: id.clone(),
                path: name.clone(),
                size: *size,
                etag: Some(size.to_string()),
            });
        }
        for id in self.seen.keys() {
            if !now.contains_key(id) {
                out.push(Change::Removed {
                    cloud_id: id.clone(),
                });
            }
        }
        self.seen = now;
        Ok((out, Cursor(None)))
    }
}

impl Provider for FolderCloud {
    fn fetch(
        &mut self,
        cloud_id: &str,
        _size: u64,
        out: &mut hydration_protocol::transport::Body<'_>,
    ) -> io::Result<()> {
        // What a real provider's implementation looks like too: open the
        // object, copy it into the sink, let the sink hold the contract.
        let mut src = std::fs::File::open(self.object(cloud_id))?;
        io::copy(&mut src, out)?;
        Ok(())
    }
}

impl Sink for FolderCloud {
    fn upload(&mut self, path: &Path, existing: Option<&str>) -> io::Result<Uploaded> {
        // Read at send time, like the name — see upload rule 2.
        let content = std::fs::read(path)?;
        // The *root-relative* path, not the basename.
        //
        // Recording only the file name was harmless while nothing acted on the
        // path a listing reported. It stopped being harmless the moment the
        // delta pass learned to translate a remote move into a local rename: a
        // file uploaded from `Documents/report.pdf` came back listed as
        // `report.pdf`, and the next pass dutifully moved the user's file to the
        // sync root. This is also the code implementors copy, so it modelled the
        // mistake.
        let name = self
            .sync_root
            .as_deref()
            .and_then(|r| path.strip_prefix(r).ok())
            .unwrap_or_else(|| Path::new(path.file_name().unwrap_or_default()))
            .to_string_lossy()
            .to_string();

        let id = match existing {
            Some(e) => e.to_string(),
            None => {
                self.next += 1;
                format!("obj-{}", self.next)
            }
        };
        std::fs::write(self.object(&id), &content)?;
        std::fs::write(self.name_file(&id), &name)?;
        Ok(Uploaded {
            cloud_id: id,
            etag: Some(format!("{}", content.len())),
        })
    }

    fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
        let _ = std::fs::remove_file(self.name_file(cloud_id));
        match std::fs::remove_file(self.object(cloud_id)) {
            Ok(()) => Ok(()),
            // Already gone is the outcome we wanted.
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

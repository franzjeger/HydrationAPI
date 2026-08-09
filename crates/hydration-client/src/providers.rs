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

use crate::upload::{Sink, Uploaded};
use crate::Provider;
use std::io;
use std::path::{Path, PathBuf};

/// A directory standing in for a cloud.
///
/// Objects are files named by id; a small side file records the name, so the
/// mapping survives a restart the way a real service's metadata would.
pub struct FolderCloud {
    root: PathBuf,
    next: u64,
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
            next,
        })
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

impl Provider for FolderCloud {
    fn fetch(&mut self, cloud_id: &str, _size: u64) -> io::Result<Vec<u8>> {
        std::fs::read(self.object(cloud_id))
    }
}

impl Sink for FolderCloud {
    fn upload(&mut self, path: &Path, existing: Option<&str>) -> io::Result<Uploaded> {
        // Read at send time, like the name — see upload rule 2.
        let content = std::fs::read(path)?;
        let name = path.file_name().unwrap().to_string_lossy().to_string();

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

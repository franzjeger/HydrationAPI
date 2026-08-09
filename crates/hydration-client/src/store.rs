//! Which cloud object a local file is, and what it is supposed to contain.
//!
//! The state lives in extended attributes on the files themselves rather than in
//! a database beside them, for one reason that turned out to matter more than
//! anything else: **the inode is the identity**.
//!
//! The FUSE client this replaces kept its state in a table keyed by cloud ID, so
//! a file created locally had to change identity when the upload told it what
//! its real ID was. That swap produced three data-loss bugs and three later
//! races, and the last of them was still being fixed the week this project
//! started. Here a locally created file has an inode from `creat(2)` and keeps it
//! forever; learning its cloud ID is writing one attribute onto a file that has
//! not moved. There is no swap to get wrong.
//!
//! An in-memory index maps `(fsid, ino)` back to a path, because that is what an
//! event gives us and xattrs are addressed by path. It is rebuilt by walking, so
//! losing it costs a scan and never costs correctness.

use hydration_protocol::FileId;
use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub use hydration_protocol::xattr::ETAG as XATTR_ETAG;
pub use hydration_protocol::xattr::MODE as XATTR_MODE;
pub use hydration_protocol::xattr::{DEHYDRATED as XATTR_DEHYDRATED, ID as XATTR_ID};

/// What the daemon knows about one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: PathBuf,
    /// `None` until the first upload completes — a locally created file is real
    /// before the cloud has heard of it, and must be usable in the meantime.
    pub cloud_id: Option<String>,
    pub etag: Option<String>,
    pub size: u64,
}

#[derive(Debug, Default)]
pub struct Store {
    index: HashMap<FileId, PathBuf>,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild the index by walking the sync directory.
    ///
    /// Reads no content, so it never hydrates anything: `stat` does not fire a
    /// pre-content event, which is the measured fact that makes a full scan
    /// affordable at all.
    pub fn scan(&mut self, root: &Path) -> io::Result<usize> {
        self.index.clear();
        let mut stack = vec![root.to_path_buf()];
        let mut found = 0;

        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let path = entry.path();
                let md = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                if md.is_dir() {
                    stack.push(path);
                    continue;
                }
                if !md.is_file() {
                    continue;
                }
                // Never index the framework's own files.
                //
                // The manifest is rewritten whenever the placeholder count
                // changes. Indexed, it becomes an ordinary local file: change
                // detection sees the write, the queue debounces it, the upload
                // gives it a cloud id, the next delta pass brings it back down,
                // and the rewrite after that starts the cycle again. Nothing
                // fails; the two ends simply never stop talking about a file the
                // user has never heard of.
                if path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(hydration_protocol::names::is_internal)
                {
                    continue;
                }
                self.index.insert(
                    FileId {
                        fsid: md.dev(),
                        ino: md.ino(),
                    },
                    path,
                );
                found += 1;
            }
        }
        Ok(found)
    }

    /// Index by cloud id, for the removal half of a delta pass.
    ///
    /// A remote deletion names an *object*, not a path — the file may have been
    /// renamed locally since, and looking it up by name would then miss it and
    /// leave a file the cloud no longer has.
    pub fn by_cloud_id(&self) -> HashMap<String, Entry> {
        let mut out = HashMap::new();
        for (id, path) in &self.index {
            if let Some(e) = self.lookup(id) {
                if let Some(cid) = e.cloud_id.clone() {
                    out.insert(cid, e);
                }
            }
            let _ = path;
        }
        out
    }

    pub fn remember(&mut self, id: FileId, path: &Path) {
        self.index.insert(id, path.to_path_buf());
    }

    pub fn forget(&mut self, id: &FileId) {
        self.index.remove(id);
    }

    /// Every file the scan indexed, in no particular order.
    ///
    /// Exposed so a caller can assert what is *not* in here — the framework's
    /// own files most of all, since including them is silent rather than loud.
    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        self.index.values().map(|p| p.as_path())
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Resolve an event's identity to the file it names.
    ///
    /// The index can be stale — a file may have been renamed or removed since
    /// the scan — so the answer is re-verified against the filesystem. A path
    /// whose inode no longer matches is not this file, and returning it would
    /// mean fetching content for one file and delivering it to another.
    pub fn lookup(&self, id: &FileId) -> Option<Entry> {
        let path = self.index.get(id)?;
        let md = std::fs::metadata(path).ok()?;
        if md.dev() != id.fsid || md.ino() != id.ino {
            return None;
        }
        Some(Entry {
            path: path.clone(),
            cloud_id: get_xattr_string(path, XATTR_ID),
            etag: get_xattr_string(path, XATTR_ETAG),
            size: md.len(),
        })
    }

    /// Record the cloud ID a completed upload returned.
    ///
    /// The file does not move, is not re-created, and keeps its inode. Compare
    /// with what this replaces, where the same event meant relocating a database
    /// row, renaming a cache file and repointing an inode, with readers running
    /// concurrently.
    pub fn adopt_cloud_id(
        &mut self,
        path: &Path,
        cloud_id: &str,
        etag: Option<&str>,
    ) -> io::Result<()> {
        set_xattr(path, XATTR_ID, cloud_id.as_bytes())?;
        if let Some(e) = etag {
            set_xattr(path, XATTR_ETAG, e.as_bytes())?;
        }
        Ok(())
    }
}

pub fn get_xattr(path: &Path, name: &str) -> io::Result<Option<Vec<u8>>> {
    let p = CString::new(path.as_os_str().as_bytes())?;
    let n = CString::new(name)?;
    let len = unsafe { libc::getxattr(p.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
    if len < 0 {
        let e = io::Error::last_os_error();
        // Absent is not an error: a file with no cloud ID is simply one the
        // cloud has not heard of yet.
        return match e.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(None),
            _ => Err(e),
        };
    }
    let mut buf = vec![0u8; len as usize];
    let got = unsafe {
        libc::getxattr(
            p.as_ptr(),
            n.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(got as usize);
    Ok(Some(buf))
}

pub fn set_xattr(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let p = CString::new(path.as_os_str().as_bytes())?;
    let n = CString::new(name)?;
    let rc = unsafe {
        libc::setxattr(
            p.as_ptr(),
            n.as_ptr(),
            value.as_ptr() as *const libc::c_void,
            value.len(),
            0,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn get_xattr_string(path: &Path, name: &str) -> Option<String> {
    get_xattr(path, name)
        .ok()
        .flatten()
        .and_then(|v| String::from_utf8(v).ok())
}

/// The mode remembered for a file, if one was.
pub fn remembered_mode(path: &Path) -> Option<u32> {
    get_xattr_string(path, XATTR_MODE).and_then(|s| s.parse().ok())
}

pub fn remember_mode(path: &Path, mode: u32) -> io::Result<()> {
    set_xattr(path, XATTR_MODE, mode.to_string().as_bytes())
}

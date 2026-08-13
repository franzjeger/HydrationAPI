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
    /// Where the last scan started, so a caller can look again without having to
    /// be told the root a second time — and without being able to get it wrong.
    root: Option<std::path::PathBuf>,
    /// What the files said the last time they still had their extended
    /// attributes. `None` unless the caller asked for it — see
    /// [`Store::remembering`].
    lineage: Option<crate::lineage::Lineage>,
    /// Whether this store maintains the record or only reads it.
    ///
    /// A daemon runs more than one `Store` — the delta pass has one, the upload
    /// driver has another — and two of them writing the same file would each
    /// overwrite the other's view with its own. Exactly one writes.
    lineage_writes: bool,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    /// Maintain, across scans, the record of what each path's extended
    /// attributes said.
    ///
    /// Off by default, and deliberately a choice the embedder makes: it puts a
    /// file in the user's sync root, and a caller that only wants to look
    /// something up should not leave one behind. See [`crate::lineage`] for what
    /// it is for — without it, every file saved atomically loses which cloud
    /// object it is and can never be uploaded again.
    ///
    /// This is the *writing* side, and it belongs to whichever scan runs while
    /// the files still have their attributes. In this framework that is
    /// `delta::apply`, which scans every round; the upload driver's scan runs
    /// only when something is already due, which for a file that was saved
    /// atomically is a quarter of an hour after the attributes went away.
    pub fn remembering(mut self) -> Self {
        self.lineage = Some(crate::lineage::Lineage::default());
        self.lineage_writes = true;
        self
    }

    /// Read the record, and never write it.
    ///
    /// For the half that consumes it. It is re-read from disk on every scan, so
    /// this store always sees what the maintaining one last wrote rather than a
    /// copy that stopped being true when it was taken.
    pub fn consulting(mut self) -> Self {
        self.lineage = Some(crate::lineage::Lineage::default());
        self.lineage_writes = false;
        self
    }

    /// What was recorded for `path` before it lost its extended attributes.
    pub fn remembered(&self, path: &Path) -> Option<&crate::lineage::Record> {
        let root = self.root.as_deref()?;
        let rel = crate::lineage::relative(root, path)?;
        self.lineage.as_ref()?.get(&rel)
    }

    /// Rebuild the index by walking the sync directory.
    ///
    /// Reads no content, so it never hydrates anything: `stat` does not fire a
    /// pre-content event, which is the measured fact that makes a full scan
    /// affordable at all.
    pub fn scan(&mut self, root: &Path) -> io::Result<usize> {
        // Re-read every scan, not cached from the first one. The root is not
        // known until now, and more importantly a daemon has a second `Store`
        // maintaining this file — a copy taken once would go on asserting a view
        // that stopped being true, and writing it back would undo the other's
        // work. Re-reading 0.3 MB a few times a minute is not the cost worth
        // optimising here.
        if self.lineage.is_some() {
            self.lineage = Some(crate::lineage::Lineage::load(root));
        }
        self.root = Some(root.to_path_buf());
        self.index.clear();
        // Gathered during the walk, applied once at the end. `absorb` decides
        // what an older record survives, and it can only decide that against the
        // *whole* of what this scan found — a record is evicted because some
        // other path now holds its object, and that other path may be visited
        // last.
        let mut seen: std::collections::HashMap<String, crate::lineage::Record> =
            std::collections::HashMap::new();
        let mut live: std::collections::HashSet<String> = std::collections::HashSet::new();
        let keeping_lineage = self.lineage.is_some();
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
                if keeping_lineage {
                    if let Some(rel) = crate::lineage::relative(root, &path) {
                        // Placeholders are left out, and the reason is size.
                        //
                        // Recording every file with a cloud id put 167,883 lines
                        // and 43 MB into the sync root on the measured account —
                        // a near-duplicate of the manifest, rewritten whenever
                        // any one object changed. The 1,018 files that actually
                        // hold content come to 0.3 MB.
                        //
                        // The limit this accepts: a placeholder that is replaced
                        // by an atomic save *without ever being read* loses its
                        // identity with no record here to recover it. Its
                        // identity is in §6d's manifest, which lists exactly the
                        // dehydrated files and carries the same three columns —
                        // so the information is not gone, only not wired to this
                        // path. Wiring it would double a 43 MB file to cover a
                        // case that needs a program to write over a document it
                        // never opened.
                        let placeholder = get_xattr(&path, hydration_protocol::xattr::DEHYDRATED)
                            .ok()
                            .flatten()
                            .is_some();
                        // Recorded from the file only when the file has something
                        // to say. A file that has lost its attributes contributes
                        // its *path* and nothing else, which is what keeps the
                        // record it needs alive rather than erasing it.
                        if !placeholder {
                            if let Some(cloud_id) = get_xattr_string(&path, XATTR_ID) {
                                seen.insert(
                                    rel.clone(),
                                    crate::lineage::Record {
                                        cloud_id,
                                        tag: get_xattr_string(&path, XATTR_ETAG),
                                    },
                                );
                            }
                            live.insert(rel);
                        }
                    }
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
        if let Some(l) = &mut self.lineage {
            l.absorb(seen, &live);
            // A failure here costs the atomic-save recovery until the next scan
            // and nothing else, so it must not fail the scan — which every delta
            // round and every upload batch depends on. It is not silent: the
            // record stays dirty and the next scan tries again.
            if self.lineage_writes {
                if let Err(e) = l.write(root) {
                    eprintln!(
                        "hydration-sync: could not write {}: {e} — a file saved \
                         atomically before the next scan will lose which cloud \
                         object it is",
                        crate::lineage::LINEAGE_NAME
                    );
                }
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

    /// The root the last [`Store::scan`] walked, if there has been one.
    pub fn root(&self) -> Option<&Path> {
        self.root.as_deref()
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
        let cloud_id = get_xattr_string(path, XATTR_ID);
        let etag = get_xattr_string(path, XATTR_ETAG);
        // Only when the file has nothing to say for itself.
        //
        // A file that still carries its own attributes is authoritative about
        // them — they were written when its content was placed or its upload
        // settled, and they are more recent than anything a scan wrote down. The
        // remembered record exists for one state: a save that replaced the inode
        // and took the attributes with it, which is how git and most editors
        // write. Without it the file reads as one the cloud has never heard of,
        // the upload becomes a create, and the service answers `409` for as long
        // as the daemon runs.
        //
        // Taken as a pair. Half of one record and half of another would be a tag
        // that does not belong to the object it is sent with — a precondition
        // guarding the wrong thing, which is worse than having none.
        if cloud_id.is_none() {
            if let Some(remembered) = self.remembered(path) {
                return Some(Entry {
                    path: path.clone(),
                    cloud_id: Some(remembered.cloud_id.clone()),
                    etag: remembered.tag.clone(),
                    size: md.len(),
                });
            }
        }
        Some(Entry {
            path: path.clone(),
            cloud_id,
            etag,
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
        write_xattr_even_if_read_only(path, XATTR_ID, cloud_id.as_bytes())?;
        if let Some(e) = etag {
            write_xattr_even_if_read_only(path, XATTR_ETAG, e.as_bytes())?;
        }
        Ok(())
    }
}

/// Set an extended attribute on a file whose mode forbids writing.
///
/// The kernel gates `user.*` attributes on write permission to the *inode*, not
/// on how it was opened — so a file the user owns and can chmod at will still
/// refuses, and this framework has no way to record what such a file is.
///
/// Measured on a live account on 2026-08-13: git creates its pack files 0444,
/// and three of them could not be given back the identity an atomic save had
/// destroyed. `adopt_cloud_id` failed with `EACCES`, the upload was re-queued,
/// and it would have repeated forever — the recovery worked and could not be
/// written down.
///
/// The mode is restored whichever way the write goes, including the failing one.
/// A file left writable because recording its id failed is a permission change
/// the user never made, on a file something else deliberately protected.
fn write_xattr_even_if_read_only(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    match set_xattr(path, name, value) {
        Err(e) if e.raw_os_error() == Some(libc::EACCES) => {}
        other => return other,
    }
    let mode = std::fs::metadata(path)?.permissions().mode();
    let mut relaxed = std::fs::Permissions::from_mode(mode | 0o200);
    std::fs::set_permissions(path, relaxed.clone())?;
    let out = set_xattr(path, name, value);
    relaxed.set_mode(mode);
    // Reported only if it is the only thing that went wrong. The caller is
    // owed the original failure ahead of this one.
    let restored = std::fs::set_permissions(path, relaxed);
    out.and(restored)
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

pub fn remove_xattr(path: &Path, name: &str) -> io::Result<()> {
    let p = CString::new(path.as_os_str().as_bytes())?;
    let n = CString::new(name)?;
    let rc = unsafe { libc::removexattr(p.as_ptr(), n.as_ptr()) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        return match e.raw_os_error() {
            Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(()),
            _ => Err(e),
        };
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

//! What a backup would miss, written down where the backup will find it.
//!
//! DESIGN.md §6d. A backup that skips dehydrated files does not contain the
//! cloud files — which may be correct, since they are in the cloud, but a user
//! who believed `restic` covered `~/OneDrive` and finds every dehydrated object
//! missing at restore time has lost data for the same reason as every bug this
//! framework exists to prevent: something answered "fine" to something it did
//! not do.
//!
//! The measurement that makes this load-bearing rather than a nicety: almost
//! nothing honours `nodump`. GNU `tar` and `rsync` have no support at all,
//! `bsdtar` and `borg` only with an explicit flag, and `restic` cannot. So the
//! flag cannot be relied on to exclude anything, and the manifest is not a
//! second line of defence — it is the mechanism.
//!
//! The file is small, it is never a placeholder, and it therefore ends up inside
//! whatever the backup did capture. A restore that finds it knows exactly what
//! was left out and where to get it.

use crate::store::{self, Store};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};

/// Lives in the sync root. Named so it sorts early and reads as what it is.
///
/// Defined in the shared crate, because the scan, the delta pass and the change
/// watcher all have to agree with the manifest builder about which files belong
/// to the framework rather than to the user.
pub use hydration_protocol::names::MANIFEST as MANIFEST_NAME;

/// What a backup is missing for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Relative to the sync root, so a restore to a different path still works.
    pub path: String,
    pub cloud_id: String,
    pub size: u64,
    pub etag: Option<String>,
}

/// What the user is told, and what a restore can act on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Manifest {
    pub entries: Vec<Entry>,
    /// Dehydrated, but with no cloud object to fetch. Nothing can restore these
    /// — which is exactly why they are named rather than quietly dropped.
    pub unrecoverable: Vec<String>,
}

impl Manifest {
    /// Everything in the sync directory that has no local content.
    ///
    /// Reads no content — `stat` and xattrs only — so building the manifest
    /// never hydrates the very files it is recording. That is not an
    /// optimisation: a manifest that pulled down the whole drive to describe it
    /// would be worse than none.
    pub fn build(root: &Path) -> io::Result<Self> {
        let mut entries = Vec::new();
        let mut unrecoverable = Vec::new();
        let mut stack = vec![root.to_path_buf()];

        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir)? {
                let e = e?;
                let path = e.path();
                let Ok(md) = e.metadata() else { continue };
                if md.is_dir() {
                    stack.push(path);
                    continue;
                }
                // The framework's own files are not the user's, and a manifest
                // that listed itself would be describing the wrong thing.
                if !md.is_file()
                    || path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(hydration_protocol::names::is_internal)
                {
                    continue;
                }
                // The dehydrated mark, not `st_blocks`.
                //
                // Using blocks here would repeat the project's own measured
                // mistake in the place it hurts most: btrfs stores small files
                // inline, so a dehydrated script or config still reports blocks
                // and would be silently left out of the manifest — and small
                // text files are exactly what a restoring user misses first. It
                // over-reports too: a hydrated file that is legitimately sparse
                // keeps its cloud id, and would be listed as missing when the
                // backup has all of it.
                if string_xattr(&path, hydration_protocol::xattr::DEHYDRATED).is_none() {
                    continue;
                }
                let Some(cloud_id) = string_xattr(&path, store::XATTR_ID) else {
                    // Dehydrated with no remote copy: there is no content
                    // anywhere, and no instruction that would get it back.
                    // Listing it would be a promise we cannot keep, and skipping
                    // it silently is how the count stops being true — so it is
                    // recorded as unrecoverable.
                    unrecoverable.push(
                        path.strip_prefix(root)
                            .unwrap_or(&path)
                            .to_string_lossy()
                            .to_string(),
                    );
                    continue;
                };
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .to_string();
                entries.push(Entry {
                    path: rel,
                    cloud_id,
                    size: md.len(),
                    etag: string_xattr(&path, store::XATTR_ETAG),
                });
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        unrecoverable.sort();
        Ok(Self {
            entries,
            unrecoverable,
        })
    }

    /// Write it into the sync root.
    ///
    /// Written via a temp file and renamed, so a backup running concurrently
    /// either sees the old manifest or the new one and never a half-written one.
    /// The same atomic-save shape §5.4 is about, applied to ourselves.
    pub fn write(&self, root: &Path) -> io::Result<PathBuf> {
        let target = root.join(MANIFEST_NAME);
        let tmp = root.join(format!("{MANIFEST_NAME}.tmp"));
        std::fs::write(&tmp, self.render())?;
        std::fs::rename(&tmp, &target)?;
        Ok(target)
    }

    /// Human-readable on purpose.
    ///
    /// Whoever reads this is restoring a backup and having a bad day. They
    /// should not need this project checked out to find out what is missing.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "# Files in this directory that were stored in the cloud and are NOT in your backup."
        );
        let _ = writeln!(
            out,
            "# Their metadata was backed up; their content was not. Sign in and re-sync to get it."
        );
        let _ = writeln!(out, "#");
        let _ = writeln!(out, "# path\tcloud-id\tsize\tetag");
        let _ = writeln!(out, "# {} file(s)", self.entries.len());
        for e in &self.entries {
            let _ = writeln!(
                out,
                "{}\t{}\t{}\t{}",
                e.path,
                e.cloud_id,
                e.size,
                e.etag.as_deref().unwrap_or("-")
            );
        }
        if !self.unrecoverable.is_empty() {
            let _ = writeln!(
                out,
                "#\n# WARNING: {} file(s) below have no content locally AND no cloud object.\n\
                 # Nothing can restore them. This should not happen; please report it.",
                self.unrecoverable.len()
            );
            for p in &self.unrecoverable {
                let _ = writeln!(out, "# UNRECOVERABLE\t{p}");
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Read the manifest back as `path → (cloud id, etag)`.
///
/// The counterpart to [`Manifest::render`], which produces the lines this
/// parses — `path\tcloud-id\tsize\tetag`, comments starting with `#`. It exists
/// for the offline-deletion reconciliation, which needs the whole *set* of
/// placeholder paths the last run recorded, not a single lookup.
///
/// A missing or unreadable manifest is an empty map, never an error. A sync root
/// that never wrote one — a fresh or rebuilt subvolume — has nothing to
/// reconcile, and an empty map is exactly the answer that makes an offline pass
/// over such a root delete nothing. That co-location, the record living in the
/// same directory as the files it describes, is what makes the whole offline
/// path safe: a wrong root carries no record and so produces no candidates.
///
/// `UNRECOVERABLE` lines are skipped along with every other comment: they name a
/// dehydrated file with no cloud object, so there is nothing a deletion could
/// withdraw for them.
pub fn entries(root: &Path) -> HashMap<String, (String, Option<String>)> {
    let raw = match std::fs::read_to_string(root.join(MANIFEST_NAME)) {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };
    let mut out = HashMap::new();
    for line in raw.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        if let (Some(p), Some(id), Some(_size), Some(tag)) =
            (f.next(), f.next(), f.next(), f.next())
        {
            if !p.is_empty() && !id.is_empty() {
                out.insert(
                    p.to_string(),
                    (id.to_string(), (tag != "-").then(|| tag.to_string())),
                );
            }
        }
    }
    out
}

/// What to do about backups, chosen at setup. §6d.
///
/// There is no safe default, so there is no default: `exclude` is the least bad
/// and its price is that the count must be visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupPolicy {
    /// Set `nodump` and let tools that honour it skip the files.
    Exclude,
    /// Let backups read everything, pulling the whole drive down.
    Hydrate,
    /// Refuse backup tools, so they fail loudly rather than skipping quietly.
    Deny,
}

/// The one sentence a user has to be shown, whichever policy is in force.
///
/// §6d requires the number to appear where "everything synced" appears — not in
/// a log, not behind a flag. This produces it so a client cannot get the wording
/// subtly wrong or omit it.
pub fn status_line(policy: BackupPolicy, dehydrated: usize) -> String {
    match policy {
        BackupPolicy::Exclude if dehydrated == 0 => {
            "No files are excluded from backup.".to_string()
        }
        BackupPolicy::Exclude => format!(
            "{dehydrated} file(s) excluded from backup because they are stored in the cloud. \
             See {MANIFEST_NAME} to get them back."
        ),
        BackupPolicy::Hydrate => format!(
            "{dehydrated} cloud-only file(s) will be downloaded in full by any backup that \
             reads them."
        ),
        BackupPolicy::Deny => format!(
            "{dehydrated} cloud-only file(s); backup tools will be refused rather than given \
             incomplete data."
        ),
    }
}

/// Set or clear the `nodump` flag.
///
/// Re-exported rather than reimplemented: the flag is set by the privileged side
/// when a file loses its content and cleared when it comes back, and a second
/// copy of the ioctl here is how the two ends start disagreeing about what the
/// flag means. See `hydration_protocol::flags` for why the request numbers are
/// computed rather than pasted.
pub use hydration_protocol::flags::{has_nodump, set_nodump};

fn string_xattr(path: &Path, name: &str) -> Option<String> {
    store::get_xattr(path, name)
        .ok()
        .flatten()
        .and_then(|v| String::from_utf8(v).ok())
}

/// Convenience: rebuild the manifest from a store's root and write it.
pub fn refresh(root: &Path, _store: &Store) -> io::Result<usize> {
    let m = Manifest::build(root)?;
    m.write(root)?;
    Ok(m.len())
}

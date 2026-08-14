//! What the framework last knew about the object at each path.
//!
//! # The failure this exists to survive
//!
//! An atomic save writes a new file and renames it over the old one. That is how
//! git writes its index, how most editors save, and what §5.4 is about. The
//! surviving inode is a *different* inode, and extended attributes do not travel
//! across a rename — so `user.hydration.id` and `user.hydration.etag` are gone
//! the instant the user presses save.
//!
//! Everything downstream then reads the file as one the cloud has never heard
//! of. The upload becomes a create, the service answers `409 nameAlreadyExists`,
//! the failure is re-queued, and it repeats for as long as the daemon runs.
//! Measured on a live account on 2026-08-13: six files, hours, no progress, and
//! the edits existed nowhere but that machine.
//!
//! # Why the answer cannot be to ask the service
//!
//! The tempting fix is to `GET` the object's current tag and write conditional
//! on that. It is worse than doing nothing. The tag that comes back describes
//! whatever the object holds *now*, including an edit another device made five
//! minutes ago — and writing "based on" it overwrites that edit while claiming
//! to have accounted for it. `GraphSink::precondition` says the same thing in
//! its own words: a precondition read immediately before the write is one that
//! can never fail.
//!
//! The version an edit is based on is a fact about the past. It has to have been
//! written down before the save destroyed it, which is what this module is.
//!
//! # Why a path is the key
//!
//! An inode cannot be: the whole failure is that the inode changed. The path is
//! what the user, the cloud and the service all agree the document is called,
//! and it is what a create would have collided on.
//!
//! That makes a stale record dangerous in one specific way. If the cloud renames
//! object `A` from `a.txt` to `b.txt`, and a *new* and unrelated `a.txt` then
//! appears locally, a record saying `a.txt → A` would send the new file's
//! contents into the object now called `b.txt`. That is real data loss, and it
//! is not caught by the `if-match` — the precondition guards the *version*, not
//! the identity.
//!
//! [`Lineage::absorb`] closes it with the one invariant that makes path-keying
//! safe: **an object is at exactly one path**. A scan that finds `A` living at
//! `b.txt` evicts every other path claiming `A`, in the same pass — and the scan
//! runs before every upload batch, so the stale record never survives to be
//! used. No hook in the rename path is needed, and none can be forgotten.
//!
//! # It is a bridge, not a second store
//!
//! A successful upload calls `Store::adopt_cloud_id`, which writes the extended
//! attributes back. So a file only depends on this record between the save that
//! destroyed its attributes and the upload that restores them. Nothing here is
//! authoritative over what is on the file itself; `Store::lookup` reads this
//! only when the file has nothing to say.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::path::Path;

pub use hydration_protocol::names::LINEAGE as LINEAGE_NAME;

/// What was recorded for one path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub cloud_id: String,
    /// The tag of the version an edit here is based on.
    ///
    /// Optional because a drive whose tags are not preconditions has none to
    /// record, and because an object created locally has no tag until its first
    /// upload settles. Both are ordinary; neither is a reason to withhold the
    /// identity, which is the half that turns a doomed create into an update.
    pub tag: Option<String>,
}

/// Paths to what the framework last knew about the object at each of them.
///
/// Keys are relative to the sync root and always `/`-separated, so the file can
/// be read by a person and does not change meaning if the root is moved.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Lineage {
    by_path: BTreeMap<String, Record>,
    /// Whether anything has changed since the last [`write`](Self::write).
    ///
    /// The scan runs before every upload batch and the record changes on almost
    /// none of them. Rewriting a file in the user's sync root a few times a
    /// minute to say exactly what it already said is not free — it is a write
    /// inside the marked mount, which is the one place in this system where
    /// writes are load-bearing (§6a-ter).
    dirty: bool,
}

impl Lineage {
    /// Read what is on disk, or start empty.
    ///
    /// Never fails. This is a recovery aid, and a missing or damaged one must
    /// not stop a daemon from syncing — it costs the atomic-save recovery until
    /// the next scan rewrites it, which is exactly the state everything was in
    /// before this module existed.
    ///
    /// Malformed lines are skipped rather than rejecting the file, for the same
    /// reason: half a memory is better than none, and the next write is a clean
    /// one.
    pub fn load(root: &Path) -> Self {
        let raw = match std::fs::read_to_string(root.join(LINEAGE_NAME)) {
            Ok(s) => s,
            Err(_) => return Self::default(),
        };
        let mut by_path = BTreeMap::new();
        for line in raw.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split('\t');
            let (Some(path), Some(cloud_id)) = (fields.next(), fields.next()) else {
                continue;
            };
            if path.is_empty() || cloud_id.is_empty() {
                continue;
            }
            let tag = fields.next().filter(|t| !t.is_empty()).map(str::to_string);
            by_path.insert(
                path.to_string(),
                Record {
                    cloud_id: cloud_id.to_string(),
                    tag,
                },
            );
        }
        Self {
            by_path,
            dirty: false,
        }
    }

    /// What was last known about the object at `rel`.
    pub fn get(&self, rel: &str) -> Option<&Record> {
        self.by_path.get(rel)
    }

    /// Every path recorded, with what was known about it.
    ///
    /// For the offline-deletion reconciliation, which needs the whole set of
    /// hydrated-file paths the last run recorded — the half of the presence
    /// journal the manifest does not cover.
    pub fn entries(&self) -> impl Iterator<Item = (&str, &Record)> {
        self.by_path.iter().map(|(p, r)| (p.as_str(), r))
    }

    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    pub fn needs_writing(&self) -> bool {
        self.dirty
    }

    /// Replace what is remembered with what a scan just saw, keeping only the
    /// records that survived it.
    ///
    /// `seen` is every path whose file still carries its own extended
    /// attributes — the fresh truth, straight off the files. `live` is every
    /// path the scan visited at all, carrying attributes or not.
    ///
    /// Three rules, and the second is the one that makes path-keying safe:
    ///
    /// 1. Everything in `seen` is recorded. It came from the file.
    /// 2. An older record is kept only if no path in `seen` claims *its object*.
    ///    An object is at one path; if the scan just found it somewhere else,
    ///    this record is describing a name that object no longer has, and using
    ///    it would send one file's contents into another file's object.
    /// 3. An older record is kept only if its path still exists. A path that has
    ///    gone cannot be the one an edit is about to arrive at, and keeping it
    ///    would let an unrelated file created there later inherit an identity
    ///    that was never its own.
    ///
    /// What survives all three is exactly the case this module is for: a path
    /// that is still there, holding a file that has lost its attributes, whose
    /// object nobody else has claimed.
    pub fn absorb(&mut self, seen: HashMap<String, Record>, live: &HashSet<String>) {
        let claimed: HashSet<&str> = seen.values().map(|r| r.cloud_id.as_str()).collect();
        let mut next: BTreeMap<String, Record> = BTreeMap::new();

        for (path, record) in &self.by_path {
            if seen.contains_key(path) {
                continue; // rule 1 puts the fresh one in below
            }
            if claimed.contains(record.cloud_id.as_str()) {
                continue; // rule 2
            }
            if !live.contains(path) {
                continue; // rule 3
            }
            next.insert(path.clone(), record.clone());
        }
        for (path, record) in seen {
            next.insert(path, record);
        }

        if next != self.by_path {
            self.by_path = next;
            self.dirty = true;
        }
    }

    /// Write it out, atomically, and only when it says something new.
    ///
    /// Temp file and rename, the same shape §5.4 is about, applied to ourselves:
    /// a daemon killed mid-write leaves the previous record intact rather than
    /// half of a new one. A half-read record would hand out a truncated cloud id,
    /// which addresses no object at all.
    pub fn write(&mut self, root: &Path) -> io::Result<()> {
        if !self.dirty {
            return Ok(());
        }
        let mut out = String::with_capacity(self.by_path.len() * 200 + 400);
        out.push_str(
            "# What each file's extended attributes said, the last time they were there.\n\
             # Written by the hydration framework so that a save which replaces a file\n\
             # — git, and most editors — does not lose which cloud object the file is,\n\
             # or which version of it the edit is based on. Not a backup, and not\n\
             # authoritative: the file's own attributes win whenever it still has them.\n\
             #\n\
             # path\tcloud-id\tetag\n",
        );
        for (path, record) in &self.by_path {
            out.push_str(path);
            out.push('\t');
            out.push_str(&record.cloud_id);
            out.push('\t');
            out.push_str(record.tag.as_deref().unwrap_or(""));
            out.push('\n');
        }
        let target = root.join(LINEAGE_NAME);
        let tmp = root.join(format!("{LINEAGE_NAME}.tmp"));
        std::fs::write(&tmp, out)?;
        std::fs::rename(&tmp, &target)?;
        self.dirty = false;
        Ok(())
    }
}

/// A path below the sync root, as this file records it.
///
/// `None` for anything not under the root, or not expressible as UTF-8. Both are
/// refusals rather than lossy conversions: a key that does not round-trip would
/// match the wrong file, and matching the wrong file here means writing one
/// document into another one's object.
pub fn relative(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    rel.to_str().map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory of our own.
    ///
    /// `CARGO_TARGET_TMPDIR` is not set for a unit test inside a library — cargo
    /// only sets it for integration tests — so the fallback is spelled out from
    /// the manifest directory, the same way `reclaim`'s tests do it.
    fn scratch(name: &str) -> std::path::PathBuf {
        test_scratch::scratch(
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
            &format!("lineage-tests/{name}"),
        )
    }

    fn record(id: &str, tag: Option<&str>) -> Record {
        Record {
            cloud_id: id.to_string(),
            tag: tag.map(str::to_string),
        }
    }

    fn seen(pairs: &[(&str, &str, Option<&str>)]) -> HashMap<String, Record> {
        pairs
            .iter()
            .map(|(p, id, tag)| (p.to_string(), record(id, *tag)))
            .collect()
    }

    fn live(paths: &[&str]) -> HashSet<String> {
        paths.iter().map(|p| p.to_string()).collect()
    }

    /// The case this exists for: the file is still there and has lost its
    /// attributes, so the scan sees it but learns nothing from it.
    #[test]
    fn a_path_that_lost_its_attributes_keeps_what_was_recorded_for_it() {
        let mut l = Lineage::default();
        l.absorb(seen(&[("a.txt", "A", Some("ct:1"))]), &live(&["a.txt"]));

        // The atomic save: same path, no attributes to be read from it.
        l.absorb(seen(&[]), &live(&["a.txt"]));

        assert_eq!(
            l.get("a.txt"),
            Some(&record("A", Some("ct:1"))),
            "the identity was forgotten the moment the file was saved, which is \
             the whole failure"
        );
    }

    /// Rule 2, and the reason a path may be used as a key at all.
    #[test]
    fn an_object_found_at_a_new_path_evicts_every_older_claim_to_it() {
        let mut l = Lineage::default();
        l.absorb(seen(&[("a.txt", "A", Some("ct:1"))]), &live(&["a.txt"]));

        // The cloud renamed A, the delta pass renamed the file, and an unrelated
        // `a.txt` was created and saved atomically before this scan.
        l.absorb(
            seen(&[("b.txt", "A", Some("ct:1"))]),
            &live(&["a.txt", "b.txt"]),
        );

        assert_eq!(
            l.get("a.txt"),
            None,
            "a new local file inherited the identity of an object that had been \
             renamed away from its path, and its contents would have been written \
             into the object now called b.txt"
        );
        assert_eq!(l.get("b.txt"), Some(&record("A", Some("ct:1"))));
    }

    /// Rule 3.
    #[test]
    fn a_path_that_is_gone_is_not_remembered_for_whatever_appears_there_next() {
        let mut l = Lineage::default();
        l.absorb(seen(&[("a.txt", "A", Some("ct:1"))]), &live(&["a.txt"]));
        l.absorb(seen(&[]), &live(&[]));
        assert_eq!(l.get("a.txt"), None);
    }

    /// A record that says exactly what the last one said is not written again.
    ///
    /// The scan runs before every upload batch. Rewriting an unchanged file into
    /// the user's sync root that often is a write inside the marked mount for no
    /// reason, and this system has a standing rule about those.
    #[test]
    fn an_unchanged_record_is_not_rewritten() {
        let mut l = Lineage::default();
        l.absorb(seen(&[("a.txt", "A", Some("ct:1"))]), &live(&["a.txt"]));
        assert!(l.needs_writing(), "the first record has to be written");

        let dir = scratch("unchanged");
        l.write(&dir).expect("write");
        assert!(!l.needs_writing());

        l.absorb(seen(&[("a.txt", "A", Some("ct:1"))]), &live(&["a.txt"]));
        assert!(
            !l.needs_writing(),
            "a scan that learned nothing new still asked for a write into the \
             user's sync root"
        );
    }

    #[test]
    fn what_is_written_reads_back_the_same() {
        let dir = scratch("round-trip");
        let mut l = Lineage::default();
        l.absorb(
            seen(&[
                ("a.txt", "A", Some("ct:1")),
                ("deep/b b.txt", "B", None),
                ("c.txt", "C", Some("ct:\"c:{G},9\"")),
            ]),
            &live(&["a.txt", "deep/b b.txt", "c.txt"]),
        );
        l.write(&dir).expect("write");

        let back = Lineage::load(&dir);
        assert_eq!(back.get("a.txt"), Some(&record("A", Some("ct:1"))));
        assert_eq!(
            back.get("deep/b b.txt"),
            Some(&record("B", None)),
            "a path with a space, and a record with no tag, are both ordinary"
        );
        assert_eq!(
            back.get("c.txt"),
            Some(&record("C", Some("ct:\"c:{G},9\""))),
            "a tag containing quotes and braces — which every Graph cTag does — \
             did not survive the round trip"
        );
        assert_eq!(back.len(), 3);
    }

    /// A damaged record costs the recovery, never the daemon.
    #[test]
    fn a_damaged_record_is_read_for_what_is_left_of_it() {
        let dir = scratch("damaged");
        std::fs::write(
            dir.join(LINEAGE_NAME),
            "# a comment\n\
             good.txt\tA\tct:1\n\
             \n\
             truncated-line-with-no-id\n\
             \tB\tct:2\n\
             also-good.txt\tC\n",
        )
        .expect("a damaged record");

        let l = Lineage::load(&dir);
        assert_eq!(l.get("good.txt"), Some(&record("A", Some("ct:1"))));
        assert_eq!(
            l.get("also-good.txt"),
            Some(&record("C", None)),
            "a line with no tag column is a record with no tag, not a broken line"
        );
        assert_eq!(l.len(), 2, "a malformed line was kept: {l:?}");
    }

    #[test]
    fn a_missing_record_is_an_empty_memory_and_not_an_error() {
        let dir = scratch("missing");
        let l = Lineage::load(&dir);
        assert!(l.is_empty());
        assert!(
            !l.needs_writing(),
            "nothing was learned, so nothing is owed"
        );
    }

    #[test]
    fn a_path_outside_the_root_has_no_key() {
        let root = Path::new("/sync");
        assert_eq!(
            relative(root, Path::new("/sync/a/b.txt")).as_deref(),
            Some("a/b.txt")
        );
        assert_eq!(relative(root, Path::new("/elsewhere/b.txt")), None);
    }
}

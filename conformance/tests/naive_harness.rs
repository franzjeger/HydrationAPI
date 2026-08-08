//! Proves the invariants have teeth, and demonstrates the central design claim.
//!
//! `NaiveLocal` is a deliberately simple model: real files on a real filesystem,
//! plus a sync layer that reproduces two bugs the reference client actually
//! shipped — uploading under the name captured when the job was queued, and
//! treating a missing local file as missing data rather than as a delete.
//!
//! The result is the argument in DESIGN.md §3, executable:
//!
//!   * The invariants the *kernel* owns pass for free, because the files are
//!     real. Nothing was implemented to make 5.1, 5.2 and 5.6 pass.
//!   * The invariants that need an interception mechanism fail, because this
//!     model has none. That is what fanotify pre-content buys.
//!   * The invariants that are genuinely distributed-systems problems fail,
//!     because they were modelled as the bugs they were. No architecture makes
//!     those free; the framework has to own them.
//!
//! If any invariant ever stops failing here without its bug being fixed, the
//! specification has lost a tooth and this test says so.

use hydration_conformance::invariants;
use hydration_conformance::{CloudObject, CloudOp, FetchBehaviour, Harness, Outcome};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::TempDir;

struct Pending {
    /// The name captured when the upload was queued. Capturing it here rather
    /// than resolving it at send time is the atomic-save bug.
    name: String,
    content: Vec<u8>,
}

struct NaiveLocal {
    dir: TempDir,
    cloud: HashMap<String, CloudObject>,
    ops: Vec<CloudOp>,
    holding: bool,
    /// Behind a `RefCell` so a change can be queued the moment it is observed,
    /// including from `&self`. A real client watches the filesystem; if the
    /// model only queued during an explicit `settle`, the atomic-save race
    /// could not be arranged at all and 5.4 would fail on setup rather than on
    /// the bug it exists to catch.
    pending: RefCell<Vec<Pending>>,
    next_id: u32,
}

impl NaiveLocal {
    fn new() -> Self {
        Self {
            dir: TempDir::new().expect("tempdir"),
            cloud: HashMap::new(),
            ops: Vec::new(),
            holding: false,
            pending: RefCell::new(Vec::new()),
            next_id: 1,
        }
    }

    /// Queue whatever local files differ from the cloud, capturing the name
    /// each file has *now*. Callable from `&self` so a write is noticed
    /// immediately, as a filesystem watcher would notice it.
    fn scan(&self) {
        let entries: Vec<PathBuf> = fs::read_dir(self.dir.path())
            .expect("readdir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();

        let mut pending = self.pending.borrow_mut();
        for path in entries {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let content = match fs::read(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let unchanged = self
                .cloud
                .values()
                .any(|o| o.name == name && o.content == content);
            let queued = pending.iter().any(|p| p.name == name);
            if !unchanged && !queued {
                pending.push(Pending { name, content });
            }
        }
    }

    fn flush(&mut self) {
        if self.holding {
            return;
        }
        let jobs = std::mem::take(&mut *self.pending.borrow_mut());
        for job in jobs {
            // BUG (reference client #52): the upload is addressed by the name
            // captured when it was queued, not the name the file has now. An
            // atomic save renames the file out from under this.
            //
            // BUG (reference client #51): a local file that is gone is treated
            // as "I have no fresh data" and the queued copy is uploaded anyway,
            // rather than as "the delete is the newer intention".
            let id = format!("cloud-{}", self.next_id);
            self.next_id += 1;
            self.ops.push(CloudOp::Put {
                name: job.name.clone(),
                content: job.content.clone(),
            });
            self.cloud.insert(
                id.clone(),
                CloudObject {
                    id,
                    name: job.name,
                    content: job.content,
                    etag: format!("etag-{}", self.next_id),
                },
            );
        }
    }
}

impl Harness for NaiveLocal {
    fn sync_dir(&self) -> &Path {
        self.dir.path()
    }

    fn seed_remote(&mut self, name: &str, content: &[u8], etag: &str) -> String {
        let id = format!("cloud-{}", self.next_id);
        self.next_id += 1;
        self.cloud.insert(
            id.clone(),
            CloudObject {
                id: id.clone(),
                name: name.to_string(),
                content: content.to_vec(),
                etag: etag.to_string(),
            },
        );
        // A placeholder: right size, no blocks. With no interception mechanism,
        // reading it will simply produce zeros -- which is the point.
        let path = self.dir.path().join(name);
        let f = fs::File::create(&path).expect("create placeholder");
        f.set_len(content.len() as u64).expect("truncate to size");
        id
    }

    fn remote(&self, name: &str) -> Option<CloudObject> {
        self.cloud.values().find(|o| o.name == name).cloned()
    }

    fn ops_observed(&self) -> Vec<CloudOp> {
        self.ops.clone()
    }

    fn hold_uploads(&mut self) {
        self.holding = true;
    }

    fn release_uploads(&mut self) {
        self.holding = false;
        self.flush();
    }

    fn wait_for_upload_start(&self, _timeout: Duration) -> bool {
        self.scan();
        !self.pending.borrow().is_empty()
    }

    fn settle(&mut self) {
        self.scan();
        self.flush();
    }

    fn set_fetch_behaviour(&mut self, _name: &str, _behaviour: FetchBehaviour) {
        // This model cannot intercept a read, so it cannot vary what hydration
        // returns. 5.7 fails here, correctly.
    }

    fn dehydrate(&mut self, name: &str) {
        let path = self.dir.path().join(name);
        let len = fs::metadata(&path).expect("stat").len();
        let f = fs::OpenOptions::new().write(true).open(&path).expect("open");
        f.set_len(0).expect("truncate");
        f.set_len(len).expect("restore size, no blocks");
    }

    /// Computed rather than cached: a real client watches the filesystem, so a
    /// change is unsent from the moment it is written, not from the moment some
    /// scan happens to notice. Caching it here would let 5.6 pass for the wrong
    /// reason -- the status would be right only just after a scan.
    fn pending_uploads(&self) -> usize {
        fs::read_dir(self.dir.path())
            .expect("readdir")
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .filter(|p| {
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                let content = match fs::read(p) {
                    Ok(c) => c,
                    Err(_) => return false,
                };
                !self
                    .cloud
                    .values()
                    .any(|o| o.name == name && o.content == content)
            })
            .count()
    }

    fn dehydrated_count(&self) -> usize {
        0
    }

    fn kill_hydration_worker(&mut self) {}

    fn has_separable_worker(&self) -> bool {
        false
    }
}

/// What this model is expected to do, invariant by invariant, and why.
/// A change here is a claim about the architecture and must be argued for.
fn expectation(name: &str) -> (bool, &'static str) {
    match name {
        "5.1 identity is stable" => (true, "free: the inode is real and never swapped"),
        "5.2 size is local truth" => (true, "free: stat reads a real inode"),
        "5.3 mode survives dehydration" => (false, "no interception: a dehydrated read gives zeros"),
        "5.4 atomic save keeps its name" => (false, "modelled bug: upload addressed by captured name"),
        "5.5 delete beats in-flight upload" => (false, "modelled bug: missing file read as missing data"),
        "5.6 fsync does not lie" => (true, "free: fsync(2) on a real file"),
        "5.7 hydration mismatch fails closed" => (false, "no interception: cannot refuse a read"),
        "6a worker death fails closed" => (false, "not applicable: no separable worker"),
        other => panic!("unexpected invariant {other}"),
    }
}

#[test]
fn the_specification_has_teeth() {
    let names = [
        "5.1 identity is stable",
        "5.2 size is local truth",
        "5.3 mode survives dehydration",
        "5.4 atomic save keeps its name",
        "5.5 delete beats in-flight upload",
        "5.6 fsync does not lie",
        "5.7 hydration mismatch fails closed",
        "6a worker death fails closed",
    ];

    // Each invariant gets a fresh harness: they are a specification, not a
    // sequence, and one must not be able to pass because another ran first.
    let runners: Vec<fn(&mut NaiveLocal) -> Outcome> = vec![
        invariants::identity_is_stable,
        invariants::size_is_local_truth,
        invariants::mode_survives_dehydration,
        invariants::atomic_save_keeps_its_name,
        invariants::delete_beats_inflight_upload,
        invariants::fsync_does_not_lie,
        invariants::hydration_mismatch_fails_closed,
        invariants::worker_death_fails_closed,
    ];

    let mut wrong = Vec::new();
    println!("\n  invariant                              result   expected");
    println!("  ---------------------------------------------------------");

    for (name, run) in names.iter().zip(runners) {
        let mut h = NaiveLocal::new();
        let outcome = catch_unwind(AssertUnwindSafe(|| run(&mut h)));

        let passed = matches!(&outcome, Ok(o) if o.is_pass());
        let label = match &outcome {
            Ok(Outcome::Pass) => "PASS",
            Ok(Outcome::NotApplicable(_)) => "N/A ",
            Err(_) => "FAIL",
        };
        let (want_pass, why) = expectation(name);
        let verdict = if passed == want_pass { "ok" } else { "UNEXPECTED" };
        println!("  {name:<38} {label}     {verdict} — {why}");

        if passed != want_pass {
            wrong.push(*name);
        }
    }
    println!();

    assert!(
        wrong.is_empty(),
        "these invariants did not behave as the architecture predicts: {wrong:?}. \
         Either a bug was fixed without updating the expectation, or an invariant \
         lost its teeth."
    );
}

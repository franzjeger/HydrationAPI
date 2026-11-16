//! Bounded desktop observations. The upload queue remains the owner of work.
use crate::store::Store;
use crate::upload::{Clock, Outcome, Queue};
use hydration_protocol::FileId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Event {
    pub time: u64,
    pub path: String,
    pub status: String,
    pub detail: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Issue {
    pub path: String,
    pub kind: String,
    pub detail: String,
}

#[derive(Default)]
struct AsyncHistoryFlusher {
    notify: (Mutex<(bool, bool)>, std::sync::Condvar),
}

#[derive(Default)]
pub struct Desktop {
    pub transfers: Arc<crate::transfers::Transfers>,
    until: AtomicU64,
    passes: AtomicU64,
    pub resolving: AtomicBool,
    pub refresh: AtomicU64,
    pub resolution: Mutex<serde_json::Value>,
    pub conflicts: Mutex<Option<Arc<dyn ConflictControl>>>,
    paths: Mutex<HashMap<FileId, String>>,
    errors: Mutex<HashMap<FileId, String>>,
    events: Arc<Mutex<Vec<Event>>>,
    issues: Mutex<Vec<Issue>>,
    history: Option<PathBuf>,
    flusher: Option<Arc<AsyncHistoryFlusher>>,
}

impl Drop for Desktop {
    fn drop(&mut self) {
        if let Some(flusher) = &self.flusher {
            let (lock, cvar) = &flusher.notify;
            let mut state = lock.lock().unwrap();
            let was_dirty = state.0;
            state.0 = false;
            state.1 = true;
            cvar.notify_all();
            drop(state);
            if was_dirty {
                if let Some(history_path) = &self.history {
                    let events = self.events.lock().unwrap();
                    let _ = write_events_atomic(history_path, &events);
                }
            }
        }
    }
}

fn write_events_atomic(history_path: &Path, events: &[Event]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = history_path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&serde_json::to_vec(events)?)?;
    f.sync_all()?;
    std::fs::rename(tmp, history_path)
}

impl Desktop {
    pub fn load(history: Option<PathBuf>) -> Self {
        let events = history
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .filter(|bytes| bytes.len() <= 512 * 1024)
            .and_then(|bytes| serde_json::from_slice::<Vec<Event>>(&bytes).ok())
            .unwrap_or_default();
        let issues = history
            .as_ref()
            .and_then(|p| std::fs::read(p.with_extension("issues.json")).ok())
            .filter(|bytes| bytes.len() <= 512 * 1024)
            .and_then(|bytes| serde_json::from_slice::<Vec<Issue>>(&bytes).ok())
            .unwrap_or_default();
        let events = Arc::new(Mutex::new(
            events.into_iter().take(100).collect::<Vec<Event>>(),
        ));
        let flusher = history.as_ref().map(|history_path| {
            let flusher = Arc::new(AsyncHistoryFlusher::default());
            let flusher_bg = Arc::clone(&flusher);
            let events_bg = Arc::clone(&events);
            let path_bg = history_path.clone();
            std::thread::spawn(move || {
                let (lock, cvar) = &flusher_bg.notify;
                loop {
                    let mut state = lock.lock().unwrap();
                    while !state.0 && !state.1 {
                        state = cvar.wait(state).unwrap();
                    }
                    if state.1 && !state.0 {
                        break;
                    }
                    drop(state);
                    // Coalesce bursts of on-demand hydrations into a single
                    // atomic fsync+rename instead of blocking `Daemon::serve`.
                    std::thread::sleep(std::time::Duration::from_millis(250));
                    let mut state = lock.lock().unwrap();
                    let stop = state.1;
                    if !state.0 {
                        if stop {
                            break;
                        }
                        continue;
                    }
                    state.0 = false;
                    drop(state);
                    let snapshot = events_bg.lock().unwrap().clone();
                    if let Err(e) = write_events_atomic(&path_bg, &snapshot) {
                        eprintln!("hydration-sync: could not save desktop history: {e}");
                    }
                    if stop {
                        break;
                    }
                }
            });
            flusher
        });
        let mut out = Self::default();
        out.events = events;
        out.issues = Mutex::new(issues.into_iter().take(100).collect());
        out.history = history;
        out.flusher = flusher;
        out
    }

    /// Pause new background passes. Work already executing finishes normally;
    /// on-demand reads still hydrate. Pause expires and never survives restart.
    pub fn pause(&self, seconds: u64) {
        self.until.store(
            if seconds == 0 {
                0
            } else {
                now().saturating_add(seconds.min(86400))
            },
            Ordering::SeqCst,
        );
    }
    pub fn paused(&self) -> bool {
        self.until.load(Ordering::SeqCst) > now()
    }

    pub fn begin_pass(&self) -> Option<Pass<'_>> {
        self.passes.fetch_add(1, Ordering::SeqCst);
        let pass = Pass(self);
        if self.paused() || self.resolving.load(Ordering::SeqCst) {
            None
        } else {
            Some(pass)
        }
    }
    /// Change rules only between complete engine passes. New passes observe
    /// pause after incrementing the counter, closing the check/start race.
    pub fn select(&self, root: &Path, paths: &[String]) -> std::io::Result<()> {
        if self.resolving.load(Ordering::SeqCst) {
            return Err(std::io::Error::other(
                "Finish the conflict resolution first",
            ));
        }
        let paths = crate::selection::validate(paths)?;
        let old = self.until.swap(now().saturating_add(60), Ordering::SeqCst);
        let result = (|| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(8);
            while self.passes.load(Ordering::SeqCst) > 0 {
                if std::time::Instant::now() >= deadline {
                    return Err(std::io::Error::other(
                        "Current sync work is still finishing; try again shortly",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            crate::selection::write(root, &paths)
        })();
        self.until.store(old, Ordering::SeqCst);
        result
    }

    pub fn wait_for_passes(&self) -> std::io::Result<()> {
        let end = std::time::Instant::now() + std::time::Duration::from_secs(8);
        while self.passes.load(Ordering::SeqCst) > 0 {
            if std::time::Instant::now() >= end {
                return Err(std::io::Error::other(
                    "Current sync work is still finishing; review again shortly",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Ok(())
    }

    pub fn index<C: Clock>(&self, root: &Path, store: &Store, queue: &Queue<C>) {
        let mut paths = self.paths.lock().unwrap();
        let pending = queue.snapshot();
        let ids: std::collections::HashSet<_> = pending.iter().map(|(id, _, _)| *id).collect();
        paths.retain(|id, _| ids.contains(id));
        for (file, _, _) in pending {
            if let Some(path) = store
                .lookup(&file)
                .and_then(|e| crate::lineage::relative(root, &e.path))
            {
                paths.insert(file, path);
            }
        }
    }

    pub fn record(&self, file: FileId, path: Option<&str>, outcome: &Outcome) {
        let (status, detail) = match outcome {
            Outcome::Sent { .. } => ("uploaded", "Upload confirmed".to_owned()),
            Outcome::Failed(error) => ("error", error.chars().take(2048).collect()),
            Outcome::DeletedInstead => ("deleted", "Cloud deletion confirmed".to_owned()),
            Outcome::Ignored | Outcome::NothingToDo => return,
        };
        if status != "error" {
            if let Some(path) = path {
                self.clear_issue(path);
            }
        }
        let mut errors = self.errors.lock().unwrap();
        if status == "error" {
            errors.insert(file, detail.clone());
        } else {
            errors.remove(&file);
        }
        drop(errors);
        self.push_event(path.unwrap_or(""), status, &detail);
    }

    fn insert_event_in_memory(
        events: &mut Vec<Event>,
        ts: u64,
        path: &str,
        status: &str,
        detail: &str,
    ) {
        events.retain(|e| !(e.path == path && e.status == status && e.detail == detail));
        events.insert(
            0,
            Event {
                time: ts,
                path: path.to_owned(),
                status: status.into(),
                detail: detail.into(),
            },
        );
        events.truncate(100);
    }

    pub fn push_event(&self, path: &str, status: &str, detail: &str) {
        let mut events = self.events.lock().unwrap();
        Self::insert_event_in_memory(&mut events, now(), path, status, detail);
        if let Some(history_path) = &self.history {
            if let Err(e) = write_events_atomic(history_path, &events) {
                eprintln!("hydration-sync: could not save desktop history: {e}");
            }
        }
    }

    /// Record an event in memory immediately and schedule persistence on the
    /// background flusher so latency-sensitive paths (`Daemon::serve`) never
    /// block on `fsync()`.
    pub fn push_event_async(&self, path: &str, status: &str, detail: &str) {
        {
            let mut events = self.events.lock().unwrap();
            Self::insert_event_in_memory(&mut events, now(), path, status, detail);
        }
        if let Some(flusher) = &self.flusher {
            let (lock, cvar) = &flusher.notify;
            let mut state = lock.lock().unwrap();
            state.0 = true;
            cvar.notify_one();
        }
    }

    /// Retain engine refusals until a confirmed operation resolves them.
    /// In particular, zero queued uploads is not proof of a healthy namespace.
    pub fn issue(&self, path: &str, kind: &str, detail: &str) {
        let mut issues = self.issues.lock().unwrap();
        let issue = Issue {
            path: path.into(),
            kind: kind.into(),
            detail: detail.chars().take(2048).collect(),
        };
        if issues.contains(&issue) {
            return;
        }
        // Ambiguous availability has a stronger read hazard than a later delta
        // refusal about the same path; preserve that explanation.
        if kind != "availability"
            && issues
                .iter()
                .any(|i| i.path == path && i.kind == "availability")
        {
            return;
        }
        issues.retain(|i| i.path != path);
        issues.insert(0, issue);
        issues.truncate(100);
        self.save_issues(&issues);
    }

    pub fn clear_issue(&self, path: &str) {
        let mut issues = self.issues.lock().unwrap();
        let len = issues.len();
        issues.retain(|i| i.path != path);
        if issues.len() != len {
            self.save_issues(&issues);
        }
    }

    /// Clear transient delta refusals only after a complete successful pass
    /// covered the path. Ambiguous local bytes require a confirmed upload.
    pub fn reconciled(&self, changes: &[crate::delta::Change], applied: &crate::delta::Applied) {
        if applied.stopped.is_some() {
            return;
        }
        let mut issues = self.issues.lock().unwrap();
        let len = issues.len();
        issues.retain(|issue| {
            issue.kind == "availability"
                || applied.kept_local.iter().any(|k| k.path == issue.path)
                || applied.failed.iter().any(|f| f.path == issue.path)
                || !changes.iter().any(|change| match change {
                    crate::delta::Change::Upserted { path, .. }
                    | crate::delta::Change::FolderUpserted { path, .. }
                    | crate::delta::Change::FolderRemoved { path, .. } => path == &issue.path,
                    crate::delta::Change::Removed { .. } => false,
                })
        });
        if issues.len() != len {
            self.save_issues(&issues);
        }
        drop(issues);

        if !applied.succeeded.is_empty() {
            // Only the last 100 entries can survive `events.truncate(100)`, and
            // persisting once per delta pass eliminates 165,000+ per-file `fsync()`
            // storms on initial sync while keeping the history identical.
            let tail_start = applied.succeeded.len().saturating_sub(100);
            let ts = now();
            let mut events = self.events.lock().unwrap();
            for (path, status) in &applied.succeeded[tail_start..] {
                Self::insert_event_in_memory(
                    &mut events,
                    ts,
                    path,
                    status,
                    "Namespace update from cloud",
                );
            }
            if let Some(history_path) = &self.history {
                if let Err(e) = write_events_atomic(history_path, &events) {
                    eprintln!("hydration-sync: could not save desktop history: {e}");
                }
            }
        }
    }

    fn save_issues(&self, issues: &[Issue]) {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let Some(history) = &self.history else {
            return;
        };
        let path = history.with_extension("issues.json");
        let write = || -> std::io::Result<()> {
            let tmp = path.with_extension("tmp");
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&serde_json::to_vec(issues)?)?;
            f.sync_all()?;
            std::fs::rename(tmp, path)
        };
        if let Err(e) = write() {
            eprintln!("hydration-sync: could not save sync issues: {e}");
        }
    }

    pub fn reconcile_availability(&self, root: &Path) {
        let paths: Vec<_> = self
            .issues
            .lock()
            .unwrap()
            .iter()
            .filter(|i| i.kind == "availability")
            .map(|i| i.path.clone())
            .collect();
        for path in paths {
            if matches!(
                hydration_protocol::stamp::state(&root.join(&path)),
                Ok(hydration_protocol::stamp::State::Clean)
            ) {
                self.clear_issue(&path);
            }
        }
    }

    pub fn snapshot<C: Clock>(&self, root: &Path, queue: &Queue<C>) -> String {
        let paths = self.paths.lock().unwrap();
        let mut errors = self.errors.lock().unwrap();
        let pending = queue.snapshot();
        errors.retain(|id, _| queue.has_failed(id));
        let rows: Vec<_> = pending.iter().take(500).map(|(id, sending, retry)| {
            serde_json::json!({"path": paths.get(id), "status": if *sending { "uploading" } else if errors.contains_key(id) { "retry" } else { "waiting" },
                "detail": errors.get(id), "retry_after": retry})
        }).collect();
        serde_json::json!({"version": 1, "mount": root, "paused": self.paused(), "pause_until": self.until.load(Ordering::SeqCst),
            "can_resolve": self.conflicts.lock().unwrap().is_some(), "resolution": *self.resolution.lock().unwrap(), "selection": crate::selection::read(root).ok(), "transfers": self.transfers.snapshot(), "queue": rows, "total": pending.len(), "history": *self.events.lock().unwrap(), "issues": *self.issues.lock().unwrap()}).to_string()
    }
}

/// One upload/delta pass; dropped across every return and panic path.
pub struct Pass<'a>(&'a Desktop);
impl Drop for Pass<'_> {
    fn drop(&mut self) {
        self.0.passes.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Explicit user choices, separate from automatic conflict/retry policy.
pub trait ConflictControl: Send + Sync {
    fn inspect(&self, relative: &str) -> std::io::Result<String>;
    fn start(&self, token: &str, choice: &str) -> std::io::Result<String>;
}

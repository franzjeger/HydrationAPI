//! Bounded desktop observations. The upload queue remains the owner of work.
use crate::store::Store;
use crate::upload::{Clock, Outcome, Queue};
use hydration_protocol::FileId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

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

#[derive(Default)]
pub struct Desktop {
    until: AtomicU64,
    paths: Mutex<HashMap<FileId, String>>,
    errors: Mutex<HashMap<FileId, String>>,
    events: Mutex<Vec<Event>>,
    history: Option<PathBuf>,
}

impl Desktop {
    pub fn load(history: Option<PathBuf>) -> Self {
        let events = history
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .filter(|bytes| bytes.len() <= 512 * 1024)
            .and_then(|bytes| serde_json::from_slice::<Vec<Event>>(&bytes).ok())
            .unwrap_or_default();
        Self {
            events: Mutex::new(events.into_iter().take(100).collect()),
            history,
            ..Self::default()
        }
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
        let mut errors = self.errors.lock().unwrap();
        if status == "error" {
            errors.insert(file, detail.clone());
        } else {
            errors.remove(&file);
        }
        drop(errors);
        let mut events = self.events.lock().unwrap();
        // Repeated retries of the same error update its timestamp, without
        // burying the rest of the history under identical messages.
        let path = path.unwrap_or("").to_owned();
        events.retain(|e| !(e.path == path && e.status == status && e.detail == detail));
        events.insert(
            0,
            Event {
                time: now(),
                path,
                status: status.into(),
                detail,
            },
        );
        events.truncate(100);
        if let Some(path) = &self.history {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let write = || -> std::io::Result<()> {
                let tmp = path.with_extension("tmp");
                let mut f = std::fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(0o600)
                    .open(&tmp)?;
                f.write_all(&serde_json::to_vec(&*events)?)?;
                f.sync_all()?;
                std::fs::rename(tmp, path)
            };
            if let Err(e) = write() {
                eprintln!("hydration-sync: could not save desktop history: {e}");
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
            "queue": rows, "total": pending.len(), "history": *self.events.lock().unwrap()}).to_string()
    }
}

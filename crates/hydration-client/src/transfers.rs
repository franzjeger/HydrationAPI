//! Observations of HTTP payload I/O, never a second work queue.
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, Read};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Upload,
    Download,
}

pub struct Transfers {
    next: AtomicU64,
    uploaded: AtomicU64,
    downloaded: AtomicU64,
    active: Mutex<BTreeMap<u64, Arc<Transfer>>>,
    names: Mutex<HashMap<String, String>>,
    samples: Mutex<VecDeque<(u64, u64, u64)>>,
    since: Instant,
}
impl Default for Transfers {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(0),
            uploaded: AtomicU64::new(0),
            downloaded: AtomicU64::new(0),
            active: Mutex::new(BTreeMap::new()),
            names: Mutex::new(HashMap::new()),
            samples: Mutex::new(VecDeque::new()),
            since: Instant::now(),
        }
    }
}

pub struct Transfer {
    path: String,
    direction: Direction,
    total: u64,
    offset: u64,
    object_size: u64,
    bytes: AtomicU64,
    position: AtomicU64,
    confirmed: AtomicU64,
}

/// Dropping any path (success, refusal or disconnect) removes the active row.
pub struct Running {
    pub transfer: Arc<Transfer>,
    monitor: Arc<Transfers>,
    id: u64,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.monitor.active.lock().unwrap().remove(&self.id);
    }
}
impl Transfers {
    pub fn name(&self, id: &str, path: &str) {
        let mut names = self.names.lock().unwrap();
        if names.len() >= 512 {
            names.clear();
        }
        names.insert(id.into(), path.into());
    }
    pub fn path(&self, id: &str) -> String {
        self.names
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default()
    }
    pub fn begin(
        self: &Arc<Self>,
        path: &str,
        direction: Direction,
        total: u64,
        offset: u64,
        object_size: u64,
    ) -> Running {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let transfer = Arc::new(Transfer {
            path: path.into(),
            direction,
            total,
            offset,
            object_size,
            bytes: AtomicU64::new(0),
            position: AtomicU64::new(0),
            confirmed: AtomicU64::new(0),
        });
        self.active
            .lock()
            .unwrap()
            .insert(id, Arc::clone(&transfer));
        Running {
            transfer,
            monitor: Arc::clone(self),
            id,
        }
    }
    pub fn add(&self, transfer: &Transfer, bytes: usize) {
        transfer.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        transfer.position.fetch_add(bytes as u64, Ordering::Relaxed);
        match transfer.direction {
            Direction::Upload => &self.uploaded,
            Direction::Download => &self.downloaded,
        }
        .fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> serde_json::Value {
        self.snapshot_at(self.since.elapsed().as_millis() as u64)
    }
    fn snapshot_at(&self, millis: u64) -> serde_json::Value {
        let uploaded = self.uploaded.load(Ordering::Relaxed);
        let downloaded = self.downloaded.load(Ordering::Relaxed);
        let mut samples = self.samples.lock().unwrap();
        if samples
            .back()
            .is_none_or(|s| millis.saturating_sub(s.0) >= 100)
        {
            samples.push_back((millis, uploaded, downloaded));
        }
        while samples.len() > 2 && samples[1].0 < millis.saturating_sub(5000) {
            samples.pop_front();
        }
        let (then, up, down) = samples
            .front()
            .copied()
            .unwrap_or((millis, uploaded, downloaded));
        let elapsed = millis.saturating_sub(then);
        let rate = |bytes: u64| {
            if elapsed >= 250 {
                bytes.saturating_mul(1000) / elapsed
            } else {
                0
            }
        };
        let active = self.active.lock().unwrap();
        let rows: Vec<_> = active.iter().take(64).map(|(id, t)| serde_json::json!({"id": id,
            "path": t.path, "direction": t.direction, "total": t.total, "offset": t.offset, "object_size": t.object_size,
            "bytes": t.bytes.load(Ordering::Relaxed), "position": t.position.load(Ordering::Relaxed).min(t.total),
            "confirmed": t.confirmed.load(Ordering::Relaxed).min(t.total)})).collect();
        serde_json::json!({"active": rows, "count": active.len(), "uploaded": uploaded, "downloaded": downloaded,
            "upload_rate": rate(uploaded.saturating_sub(up)), "download_rate": rate(downloaded.saturating_sub(down))})
    }
}
impl Transfer {
    pub fn position(&self, offset: u64) {
        self.position
            .store(offset.min(self.total), Ordering::Relaxed);
    }
    pub fn confirm(&self, offset: u64) {
        self.confirmed
            .store(offset.min(self.total), Ordering::Relaxed);
    }
}

/// Counts only bytes actually read by the HTTP writer/reader. Retries count as
/// traffic too; they never advance confirmed progress or produce success events.
pub struct Reader<R> {
    pub inner: R,
    pub monitor: Option<Arc<Transfers>>,
    pub transfer: Option<Arc<Transfer>>,
}
impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        if let (Some(m), Some(t)) = (&self.monitor, &self.transfer) {
            m.add(t, count);
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retries_count_traffic_without_claiming_confirmation_and_errors_drop_rows() {
        let m = Arc::new(Transfers::default());
        m.snapshot_at(0);
        let r = m.begin("a.txt", Direction::Upload, 100, 0, 100);
        m.add(&r.transfer, 80);
        r.transfer.position(0);
        m.add(&r.transfer, 60);
        let s = m.snapshot_at(1000);
        assert_eq!(s["uploaded"], 140);
        assert_eq!(s["upload_rate"], 140);
        assert_eq!(s["active"][0]["position"], 60);
        assert_eq!(s["active"][0]["confirmed"], 0);
        r.transfer.confirm(40);
        assert_eq!(m.snapshot_at(1100)["active"][0]["confirmed"], 40);
        drop(r);
        assert_eq!(m.snapshot_at(7000)["count"], 0);
        assert_eq!(m.snapshot_at(13000)["upload_rate"], 0);
    }
    #[test]
    fn actual_reader_counts_partial_io_and_keeps_ranges_distinct() {
        let m = Arc::new(Transfers::default());
        let r = m.begin("a.txt", Direction::Download, 4, 8, 20);
        let mut reader = Reader {
            inner: io::Cursor::new(vec![1, 2, 3, 4]),
            monitor: Some(m.clone()),
            transfer: Some(r.transfer.clone()),
        };
        let mut buf = [0; 2];
        assert_eq!(reader.read(&mut buf).unwrap(), 2);
        let s = m.snapshot_at(0);
        assert_eq!(s["downloaded"], 2);
        assert_eq!(s["active"][0]["offset"], 8);
        assert_eq!(s["active"][0]["total"], 4);
        assert_eq!(s["active"][0]["object_size"], 20);
    }
}

//! What the worker has already put into a placeholder that is not finished yet.
//!
//! Serving the demanded range rather than the whole object (§8d-bis) means a
//! marked file can legitimately hold content between events — the state §8d
//! called "partially present" and deliberately refused to introduce, because
//! "the store, the manifest, the delta pass, eviction and §5.8 are all two-state
//! about today".
//!
//! That objection is answered by making the third state **not persist**. This
//! record lives in the worker's memory and nowhere else. Nothing on disk says a
//! file is partly filled; no other component can read this, be confused by it,
//! or have to be taught about it. A file is still either marked or not, and a
//! marked file is still one nobody may be served from without asking us.
//!
//! What that costs is that a restart forgets the ranges, and the next event
//! punches the file and starts over. That is the right trade twice over: partial
//! content is a cache, and the alternative — an on-disk range map — has to be
//! correct across a crash *mid-write*, where a range recorded present but only
//! half written is served as content and is exactly the silent corruption the
//! framework exists to prevent.
//!
//! The other half of the design is [`Witness`]. Memory alone is not enough,
//! because between two events something else may write into the placeholder —
//! there is no pre-modify event in any released kernel (§5), so we do not see it
//! happen. A record is therefore only believed while the file still looks the
//! way we left it. Anything else and the record is dropped and the file punched,
//! which is what the code did unconditionally before ranges existed.

use hydration_protocol::{FileId, Span};

/// Enough of a file's state to notice that somebody else changed it.
///
/// The same triple the stamp xattr records (`mtime`, `mtime_nsec`, `size`), and
/// for the same reason — it is what changes when a file is written and does not
/// change when only an extended attribute is set. Kept as a separate value
/// rather than read back from the stamp because the stamp is owner-writable and
/// this is a memory of what *we* observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Witness {
    pub mtime: i64,
    pub mtime_nsec: i64,
    pub size: u64,
}

impl Witness {
    pub fn of(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            mtime: st.st_mtime,
            mtime_nsec: st.st_mtime_nsec,
            size: st.st_size as u64,
        })
    }
}

/// A set of byte ranges, kept sorted, non-overlapping and coalesced.
///
/// Coalescing is not tidiness: `covers` decides whether a read can be answered
/// without a round trip, and a set that stored two adjacent ranges separately
/// would answer "no" for a span that lies across their join. A sequential reader
/// produces exactly that shape — 128 KiB demands, each abutting the last
/// (measured, `probes/bigdemand.c`) — so the case that must work is the one that
/// would break.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ranges {
    /// `(start, end)`, sorted by start, no two touching.
    spans: Vec<(u64, u64)>,
}

impl Ranges {
    pub fn add(&mut self, span: Span) {
        if span.is_empty() {
            return;
        }
        let (start, end) = (span.offset, span.end());
        let at = self.spans.partition_point(|&(s, _)| s < start);
        self.spans.insert(at, (start, end));

        // One merge pass over the whole set. Cheap — a set that grows past a few
        // dozen entries is a file being read all over, and even then this is a
        // linear walk of something that fits in a cache line or two.
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(self.spans.len());
        for &(s, e) in &self.spans {
            match merged.last_mut() {
                // `>=` and not `>`: two ranges that merely touch are one range.
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        self.spans = merged;
    }

    /// Whether every byte of `span` is already here.
    pub fn covers(&self, span: Span) -> bool {
        span.is_empty()
            || self
                .spans
                .iter()
                .any(|&(s, e)| s <= span.offset && span.end() <= e)
    }

    /// The parts of `span` that are not here yet, in order.
    pub fn missing(&self, span: Span) -> Vec<Span> {
        let mut out = Vec::new();
        let mut at = span.offset;
        for &(s, e) in &self.spans {
            if e <= at {
                continue;
            }
            if s >= span.end() {
                break;
            }
            if s > at {
                out.push(Span::new(at, s - at));
            }
            at = at.max(e);
            if at >= span.end() {
                return out;
            }
        }
        if at < span.end() {
            out.push(Span::new(at, span.end() - at));
        }
        out
    }

    /// Total bytes held, for the log.
    pub fn total(&self) -> u64 {
        self.spans.iter().map(|&(s, e)| e - s).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.spans.is_empty()
    }
}

/// What we know about a placeholder's current contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Nothing on disk here is ours. Whatever the file holds is residue from an
    /// interrupted transfer or somebody else's writing, and it has to go before
    /// anything is served from this file.
    Unknown,
    /// These ranges are ours, and the file has not been touched since we wrote
    /// them.
    Ours(Ranges),
}

/// Every placeholder this worker is part way through.
#[derive(Debug)]
pub struct Partial {
    held: std::collections::HashMap<FileId, Held>,
    /// Monotonic, so the oldest record is the one evicted when the cap is hit.
    tick: u64,
    cap: usize,
}

#[derive(Debug)]
struct Held {
    witness: Witness,
    have: Ranges,
    used: u64,
}

/// How many part-filled placeholders are remembered at once.
///
/// A cap rather than no cap because this is memory in a root process that a
/// reader can grow: one entry per file anybody reads part of, and a sweep across
/// a large sync directory touches every file in it. Forgetting a file is always
/// safe — the next event punches it and refetches — so the cap costs bandwidth
/// in an unusual access pattern and nothing else.
const REMEMBERED: usize = 512;

impl Default for Partial {
    fn default() -> Self {
        Self::new(REMEMBERED)
    }
}

impl Partial {
    pub fn new(cap: usize) -> Self {
        Self {
            held: std::collections::HashMap::new(),
            tick: 0,
            cap,
        }
    }

    /// What is on disk for this file, as far as we are entitled to believe.
    ///
    /// A record that no longer matches the file is dropped here rather than
    /// repaired: we cannot tell which of our ranges survived somebody else's
    /// write, and guessing wrong means serving their bytes as though they came
    /// from the cloud.
    pub fn standing(&mut self, file: FileId, now: Witness) -> Standing {
        self.tick += 1;
        let tick = self.tick;
        match self.held.get_mut(&file) {
            Some(h) if h.witness == now => {
                h.used = tick;
                Standing::Ours(h.have.clone())
            }
            Some(_) => {
                self.held.remove(&file);
                Standing::Unknown
            }
            None => Standing::Unknown,
        }
    }

    /// Replace what we know about a file with what we now know.
    pub fn record(&mut self, file: FileId, witness: Witness, have: Ranges) {
        self.tick += 1;
        let used = self.tick;
        if have.is_empty() {
            self.held.remove(&file);
            return;
        }
        self.held.insert(
            file,
            Held {
                witness,
                have,
                used,
            },
        );
        if self.held.len() > self.cap {
            let oldest = self
                .held
                .iter()
                .min_by_key(|(_, h)| h.used)
                .map(|(f, _)| *f);
            if let Some(f) = oldest {
                self.held.remove(&f);
            }
        }
    }

    /// Stop tracking a file — it is finished, or it has been put back.
    pub fn forget(&mut self, file: &FileId) {
        self.held.remove(file);
    }

    pub fn tracked(&self) -> usize {
        self.held.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(size: u64) -> Witness {
        Witness {
            mtime: 1,
            mtime_nsec: 2,
            size,
        }
    }

    fn f(ino: u64) -> FileId {
        FileId { fsid: 1, ino }
    }

    #[test]
    fn adjacent_ranges_become_one() {
        // The sequential reader's shape: 128 KiB demands that abut. Kept apart,
        // a span lying across the join would be reported missing and refetched.
        let mut r = Ranges::default();
        r.add(Span::new(0, 4096));
        r.add(Span::new(4096, 4096));
        assert!(r.covers(Span::new(0, 8192)));
        assert_eq!(r.missing(Span::new(0, 8192)), vec![]);
        assert_eq!(r.total(), 8192);
    }

    #[test]
    fn overlapping_ranges_do_not_double_count() {
        let mut r = Ranges::default();
        r.add(Span::new(0, 4096));
        r.add(Span::new(2048, 4096));
        assert_eq!(r.total(), 6144);
        assert!(r.covers(Span::new(1000, 5000)));
    }

    #[test]
    fn a_hole_between_two_ranges_is_reported_missing() {
        let mut r = Ranges::default();
        r.add(Span::new(0, 4096));
        r.add(Span::new(1 << 20, 4096));
        assert!(!r.covers(Span::new(0, 1 << 21)));
        assert_eq!(
            r.missing(Span::new(0, (1 << 20) + 4096)),
            vec![Span::new(4096, (1 << 20) - 4096)]
        );
    }

    #[test]
    fn missing_of_an_untouched_file_is_the_whole_span() {
        let r = Ranges::default();
        assert_eq!(r.missing(Span::new(100, 50)), vec![Span::new(100, 50)]);
        assert!(!r.covers(Span::new(100, 50)));
    }

    #[test]
    fn missing_clips_to_the_span_asked_about() {
        // A record covering more than was asked about must not report anything
        // missing outside the question.
        let mut r = Ranges::default();
        r.add(Span::new(0, 1 << 20));
        assert_eq!(r.missing(Span::new(4096, 4096)), vec![]);
    }

    #[test]
    fn an_empty_span_is_always_covered() {
        // The clamped span at exactly EOF. Refusing it would fail every read of
        // the last page of a file whose size is a multiple of the page size.
        let r = Ranges::default();
        assert!(r.covers(Span::new(4096, 0)));
        assert_eq!(r.missing(Span::new(4096, 0)), vec![]);
    }

    #[test]
    fn a_record_is_not_believed_once_the_file_has_changed() {
        // The case memory alone cannot cover: no released kernel has a
        // pre-modify event, so a write into a placeholder between two reads is
        // something we learn about only by looking.
        let mut p = Partial::default();
        let mut r = Ranges::default();
        r.add(Span::new(0, 4096));
        p.record(f(7), w(100), r);
        assert!(matches!(p.standing(f(7), w(100)), Standing::Ours(_)));

        let changed = Witness {
            mtime: 99,
            ..w(100)
        };
        assert_eq!(p.standing(f(7), changed), Standing::Unknown);
        // And it stays forgotten rather than coming back on the next look.
        assert_eq!(p.standing(f(7), w(100)), Standing::Unknown);
    }

    #[test]
    fn the_cap_evicts_the_least_recently_used() {
        let mut p = Partial::new(2);
        let mut r = Ranges::default();
        r.add(Span::new(0, 1));
        p.record(f(1), w(1), r.clone());
        p.record(f(2), w(1), r.clone());
        // Touching 1 makes 2 the oldest.
        assert!(matches!(p.standing(f(1), w(1)), Standing::Ours(_)));
        p.record(f(3), w(1), r);
        assert_eq!(p.tracked(), 2);
        assert_eq!(p.standing(f(2), w(1)), Standing::Unknown);
        assert!(matches!(p.standing(f(1), w(1)), Standing::Ours(_)));
    }

    #[test]
    fn recording_nothing_forgets_the_file() {
        let mut p = Partial::default();
        let mut r = Ranges::default();
        r.add(Span::new(0, 8));
        p.record(f(1), w(1), r);
        p.record(f(1), w(1), Ranges::default());
        assert_eq!(p.tracked(), 0);
    }
}

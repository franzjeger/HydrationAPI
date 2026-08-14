//! The auto-eviction decision, kept pure so it can be tested without a thread,
//! a disk, or a `sleep`.
//!
//! When local disk is under pressure the daemon dehydrates the least-recently-
//! *acquired* unpinned files — back to placeholders, re-hydrated on next read —
//! until free space recovers. The signal is `hydrated_at` (recency of the last
//! fetch; there is no last-*use* signal on a `noatime` mount, see the `hydrated`
//! module), with `mtime` as the fallback the enumerator supplies. Nothing here
//! evicts: [`plan`] only *chooses*, and the driver executes the choice through
//! `reclaim::reclaim`, which keeps every safety refusal.
//!
//! The trigger is two watermarks with hysteresis: evict when free space falls
//! below the low mark, down to the high mark, then stop — a band, so a single
//! threshold cannot oscillate. **Measured (P1, `probes/statvfs-lag.c`):** on the
//! live btrfs pool `statvfs` reports the whole filesystem (not the subvol), is
//! coarse (~1 GiB granularity), and a delete registers only on the transaction
//! commit, never on `unlink`. So `plan` sizes the batch by the *measured*
//! reclaimable bytes each candidate gives back (block-accurate, immediate); the
//! driver re-reads `statvfs` only *between* sweeps, after a commit, to re-arm the
//! trigger — never per file, which would chase a number that has not moved.

use std::io;
use std::path::PathBuf;

/// How much room is free, and how big the filesystem is. Real is `statvfs`; a
/// `FakeDisk` double (in tests) lets a test drive "disk fills, evict, disk
/// recovers" deterministically.
pub trait FreeSpace: Send {
    /// Bytes available to a non-root user — the honest number the trigger reads.
    fn available(&self) -> io::Result<u64>;
    /// Total bytes, for resolving percentage watermarks.
    fn total(&self) -> io::Result<u64>;
}

/// `statvfs` on the sync mount. Note that this measures the whole pool, not the
/// subvolume — P1 measured `f_bavail` identical on the sync root, `$HOME`, and
/// `/` — which is why a footprint quota (a different mode) cannot read it.
pub struct StatvfsSpace {
    pub mount: PathBuf,
}

impl StatvfsSpace {
    fn stat(&self) -> io::Result<libc::statvfs> {
        let c =
            std::ffi::CString::new(self.mount.as_os_str().as_encoded_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "mount has an interior nul")
            })?;
        let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(s)
    }
}

impl FreeSpace for StatvfsSpace {
    fn available(&self) -> io::Result<u64> {
        let s = self.stat()?;
        Ok(s.f_bavail * s.f_frsize)
    }
    fn total(&self) -> io::Result<u64> {
        let s = self.stat()?;
        Ok(s.f_blocks * s.f_frsize)
    }
}

/// Wall-clock (`CLOCK_REALTIME`) seconds, comparable to a persisted `hydrated_at`.
///
/// Deliberately **not** `upload::SystemClock`, which is `Instant::elapsed()` —
/// monotonic from process start, not durable across a restart — and so cannot be
/// compared against a timestamp stored on disk. A wall clock that can step is
/// acceptable here: comparisons are cross-file recency, and a mis-order costs one
/// wrong eviction (latency), the safe direction.
pub trait Clock: Send {
    fn now_secs(&self) -> u64;
}

/// The real wall clock.
pub struct RealClock;

impl Clock for RealClock {
    fn now_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// The policy: when to run, how far to go, and the two thrash guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvictionConfig {
    /// Run when free space falls below `min(low_pct% of total, low_abs)`.
    pub low_pct: u32,
    pub low_abs: u64,
    /// Evict until free space would reach `min(high_pct% of total, high_abs)`.
    pub high_pct: u32,
    pub high_abs: u64,
    /// Never evict a file acquired within this many seconds (min-residency): a
    /// just-fetched file is in use, and re-fetching it rewrites `hydrated_at`,
    /// so this directly kills the evict-read-evict loop.
    pub grace_secs: u64,
    /// Never dehydrate more than this many bytes in one sweep, so one pressure
    /// spike cannot dehydrate the world and one re-read of the batch cannot
    /// flood the fetch path.
    pub sweep_cap: u64,
    /// Minimum seconds between sweeps (used by the driver, not by `plan`).
    pub min_interval_secs: u64,
}

impl EvictionConfig {
    /// The shipped default *when the user turns it on*. `min(fraction, absolute)`
    /// because 10% of a 4 TB pool hoards 400 GB while 10% of a 128 GB disk is too
    /// tight — the min behaves on both. Numbers are starting points the doc flags
    /// for tuning against a real re-access measurement (P3).
    pub fn default_pressure() -> Self {
        const GIB: u64 = 1024 * 1024 * 1024;
        EvictionConfig {
            low_pct: 10,
            low_abs: 10 * GIB,
            high_pct: 15,
            high_abs: 15 * GIB,
            grace_secs: 4 * 60 * 60,
            sweep_cap: 8 * GIB,
            min_interval_secs: 5 * 60,
        }
    }

    /// Resolve the low/high free-space marks against the filesystem's total.
    pub fn marks(&self, total: u64) -> (u64, u64) {
        let low = (total / 100 * self.low_pct as u64).min(self.low_abs);
        let high = (total / 100 * self.high_pct as u64).min(self.high_abs);
        (low, high)
    }
}

/// One evictable resident file, as the enumerator (step 3) produces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Relative to the sync root — what `reclaim::reclaim` takes.
    pub rel: String,
    /// Measured reclaimable disk (`st_blocks * 512`) — what actually comes back,
    /// not the logical size (which overstates on a small-inode filesystem, §8z).
    pub reclaimable: u64,
    /// Recency: `hydrated_at` if present, else `mtime`. Oldest evicted first.
    pub recency: u64,
}

/// Choose which candidates to evict, oldest-acquired first, to lift free space to
/// the high-water mark — or nothing if there is no pressure.
///
/// Pure: a function of the candidates, the current `available`/`total` free
/// space, the config, and `now`. It reasons in the *block-accurate* reclaimable
/// bytes each candidate gives back (P1: `statvfs` lags and is coarse, so the
/// driver must not re-measure it per file). It never selects a file inside the
/// grace window, never exceeds the per-sweep cap once it has made progress, and
/// never plans past the high mark — the blast-radius bound.
pub fn plan(
    mut candidates: Vec<Candidate>,
    available: u64,
    total: u64,
    cfg: &EvictionConfig,
    now: u64,
) -> Vec<String> {
    let (low, high) = cfg.marks(total);

    // The common path: no pressure, nothing to do. Also the idempotence guard —
    // a sweep run again at target selects nothing.
    if available >= low {
        return Vec::new();
    }

    // Oldest-acquired first; a larger reclaimable breaks ties so the target is
    // reached in fewer swaps. Recency orders, size meters.
    candidates.sort_by(|a, b| {
        a.recency
            .cmp(&b.recency)
            .then(b.reclaimable.cmp(&a.reclaimable))
    });

    let mut selected = Vec::new();
    let mut freed: u64 = 0;
    for c in candidates {
        // Reached the high mark (with block-accurate sizes, not lagging statvfs).
        if available.saturating_add(freed) >= high {
            break;
        }
        // Min-residency: a just-acquired file is presumed in use. Skip and keep
        // looking — a fresh working set legitimately yields no evictions.
        if now.saturating_sub(c.recency) < cfg.grace_secs {
            continue;
        }
        // Batch cap: stop once adding this would exceed the cap — but always let
        // the first selection through, so a single large file still makes
        // progress rather than deadlocking the policy.
        if !selected.is_empty() && freed.saturating_add(c.reclaimable) > cfg.sweep_cap {
            break;
        }
        freed = freed.saturating_add(c.reclaimable);
        selected.push(c.rel);
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// A settable free-space source, so a test can drive the trigger without a
    /// disk. `credit`/`debit` model the loop feeding measured reclaimed bytes
    /// back as it evicts.
    #[derive(Clone, Default)]
    struct FakeDisk {
        available: Arc<AtomicU64>,
        total: u64,
    }
    impl FakeDisk {
        fn new(available: u64, total: u64) -> Self {
            FakeDisk {
                available: Arc::new(AtomicU64::new(available)),
                total,
            }
        }
    }
    impl FreeSpace for FakeDisk {
        fn available(&self) -> io::Result<u64> {
            Ok(self.available.load(Ordering::SeqCst))
        }
        fn total(&self) -> io::Result<u64> {
            Ok(self.total)
        }
    }

    fn cfg() -> EvictionConfig {
        // Absolute marks below any percentage, so the total does not matter for
        // most tests: low = 100, high = 300, grace 10, cap 1000.
        EvictionConfig {
            low_pct: 100,
            low_abs: 100,
            high_pct: 100,
            high_abs: 300,
            grace_secs: 10,
            sweep_cap: 1000,
            min_interval_secs: 0,
        }
    }

    fn cand(rel: &str, reclaimable: u64, recency: u64) -> Candidate {
        Candidate {
            rel: rel.to_string(),
            reclaimable,
            recency,
        }
    }

    #[test]
    fn plan_driven_by_a_freespace_source() {
        // The exact shape the driver (step 4) uses: read available/total from a
        // FreeSpace, hand the numbers to the pure plan. FakeDisk stands in for
        // statvfs so there is no disk in the loop.
        let disk = FakeDisk::new(40, 10_000);
        let cs = vec![cand("old", 100, 1), cand("new", 100, 500)];
        let got = plan(
            cs,
            disk.available().unwrap(),
            disk.total().unwrap(),
            &cfg(),
            1000,
        );
        // 40 free, low 100 -> under pressure; high 300 needs +260, two 100s only
        // reach 240, so both are taken and the sweep is still short (the driver
        // re-arms next tick).
        assert_eq!(got, vec!["old", "new"]);
    }

    #[test]
    fn no_pressure_selects_nothing() {
        // available == low: not below it, so nothing runs (idempotence).
        let cs = vec![cand("a", 50, 1), cand("b", 50, 2)];
        assert!(plan(cs.clone(), 100, 10_000, &cfg(), 1000).is_empty());
        // And comfortably above.
        assert!(plan(cs, 500, 10_000, &cfg(), 1000).is_empty());
    }

    #[test]
    fn plan_orders_oldest_first() {
        // available 40, low 100 -> under pressure; high 300 needs +260. Oldest
        // (smallest recency) go first.
        let cs = vec![
            cand("new", 100, 500),
            cand("old", 100, 100),
            cand("mid", 100, 300),
        ];
        let got = plan(cs, 40, 10_000, &cfg(), 1000);
        assert_eq!(got, vec!["old", "mid", "new"]);
    }

    #[test]
    fn plan_stops_at_the_high_mark_and_not_before() {
        // available 40, high 300 -> need to reach 300, i.e. free +260. Three 100s
        // oldest-first: after two (40+200=240 < 300) take a third (340 >= 300);
        // stop there, never a fourth.
        let cs = vec![
            cand("a", 100, 1),
            cand("b", 100, 2),
            cand("c", 100, 3),
            cand("d", 100, 4),
        ];
        let got = plan(cs, 40, 10_000, &cfg(), 1000);
        assert_eq!(
            got,
            vec!["a", "b", "c"],
            "took more than needed to reach high"
        );
    }

    #[test]
    fn plan_never_selects_within_the_grace_window() {
        // now=1000, grace=10: recency > 990 is protected. The oldest are fresh;
        // only the one outside the window is eligible, and it alone cannot reach
        // high, so the sweep takes just it and stops.
        let cs = vec![
            cand("fresh1", 100, 995),
            cand("fresh2", 100, 999),
            cand("cold", 100, 500),
        ];
        let got = plan(cs, 40, 10_000, &cfg(), 1000);
        assert_eq!(got, vec!["cold"], "evicted a file inside the grace window");
    }

    #[test]
    fn size_breaks_ties_larger_first() {
        // Equal recency: the larger reclaimable is taken first (fewer swaps).
        let cs = vec![cand("small", 50, 100), cand("big", 200, 100)];
        let got = plan(cs, 40, 10_000, &cfg(), 1000);
        assert_eq!(got.first().map(String::as_str), Some("big"));
    }

    #[test]
    fn the_sweep_cap_bounds_a_batch_but_lets_the_first_through() {
        // cap 1000; a single 5000-byte file exceeds it but is the first, so it is
        // taken (progress). A second would exceed the cap after the first and is
        // refused.
        let big = EvictionConfig {
            sweep_cap: 1000,
            high_abs: 1_000_000,
            high_pct: 100,
            ..cfg()
        };
        let cs = vec![cand("huge", 5000, 1), cand("next", 5000, 2)];
        let got = plan(cs, 0, 10_000, &big, 1000);
        assert_eq!(
            got,
            vec!["huge"],
            "the cap must not stop the first, nor allow the second"
        );
    }

    #[test]
    fn marks_take_the_smaller_of_fraction_and_absolute() {
        let c = EvictionConfig::default_pressure();
        const GIB: u64 = 1024 * 1024 * 1024;
        // 4 TB pool: 10% = 400 GiB, capped to 10 GiB.
        let (low, high) = c.marks(4096 * GIB);
        assert_eq!((low, high), (10 * GIB, 15 * GIB));
        // 64 GiB disk: 10% = 6.4 GiB, below the 10 GiB cap, so the fraction wins.
        let (low, _) = c.marks(64 * GIB);
        assert_eq!(low, 64 * GIB / 100 * 10);
    }

    #[test]
    fn the_real_clock_is_wall_time_not_monotonic_from_zero() {
        // A regression guard for the whole reason this clock is separate from
        // upload::SystemClock: it must return a real epoch second, comparable to
        // a persisted hydrated_at, not seconds-since-process-start.
        assert!(
            RealClock.now_secs() > 1_700_000_000,
            "not a wall-clock second"
        );
    }
}

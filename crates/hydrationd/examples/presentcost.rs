//! Instrument, not a test: what does a read of an *already-present* range of a
//! still-marked file cost, against the same read once the file is hydrated?
//!
//! A file keeps its placeholder mark until every byte of it is present
//! (§8d-bis), so every read of it fires a `FAN_PRE_ACCESS` event — including
//! reads of ranges the worker has already filled. Those are answered
//! `AlreadyPresent` with no fetch, but the reader still pays a userspace round
//! trip: block in `read()`, wake the worker, ~a dozen syscalls in
//! `decide_and_fill`, answer, resume. This measures that round trip, because an
//! estimate of "about 61 ms" was once derived from a run that was actually
//! paying for fetches, and a number that wrong must not choose a design.
//!
//! Run as root against a scratch mount that **nothing else is watching** — a
//! second pre-content group on a production mount would receive its own copy of
//! every event and serve this instrument's synthetic content into real files:
//!
//! ```text
//! sudo HYDRATIOND_TEST_MOUNT=/path/to/scratch \
//!     target/debug/examples/presentcost [reads-per-rep]
//! ```
//!
//! What it prints, per repetition: mean ns per 4 KiB `pread` of a range that is
//! provably held (`SEEK_HOLE` says so, and every event in the phase is asserted
//! to be `AlreadyPresent` with the fetch count unchanged — a fetch anywhere in a
//! rep would be the same pollution the 61 ms figure came from), then the same
//! pattern after the file is completed and carries an ignore mark, where a read
//! fires no event at all. The difference is the per-event cost.
//!
//! It ends with a structure experiment, not a timing one: a cold sequential
//! walk, 128 KiB reads, recording how many events were answered with a fetch
//! and how big each fetch was. That is the datum that says what a walk of a
//! partially hydrated file costs *besides* the event round trip, priced at the
//! ~160 ms fixed cost per fetch measured live in §8d-ter.
//!
//! Reference run (7.1.6, release build, quiet machine, own loop mounts, 4000
//! reads per rep; DESIGN.md §8d-quater is the write-up):
//!
//! ```text
//!                                     btrfs        ext4
//! still marked, event per read      9.2 µs/read  7.1 µs/read
//! hydrated + ignore mark, no event  0.2 µs/read  0.2 µs/read
//!
//! cold 64 MiB walk in 512 reads:  demand-anchored window    449 fetches (448 of 128 KiB)
//!                                 frontier-anchored window    8 fetches (all 8 MiB)
//! ```

use hydration_protocol::{FileId, Span};
use hydrationd::daemon::{Fetch, Handled, Worker, READAHEAD};
use hydrationd::fanotify::Group;
use hydrationd::placeholder;
use hydrationd::policy::Policy;
use hydrationd::supervisor::InFlight;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Content generated from its own offset, so a byte proves where it came from.
/// Same rule as `tests/ranges.rs`, for the same reason.
fn expected_byte(at: u64) -> u8 {
    (at % 251) as u8
}

/// A local, effectively instant source. Instant is what the instrument needs:
/// any network-shaped latency in the fetcher would smear into the numbers, and
/// the phases that are being timed are asserted to perform no fetches at all.
struct Local {
    asked: Arc<Mutex<Vec<Span>>>,
    delivered: Arc<AtomicU64>,
}

impl Fetch for Local {
    fn fetch_into(
        &mut self,
        _file: FileId,
        _size: u64,
        span: Span,
        dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        progress: &mut dyn FnMut(u64),
    ) -> io::Result<()> {
        self.asked.lock().unwrap().push(span);
        let buf: Vec<u8> = (span.offset..span.end()).map(expected_byte).collect();
        dest(&buf, span.offset)?;
        progress(span.len);
        self.delivered.fetch_add(span.len, Ordering::SeqCst);
        Ok(())
    }
}

const SIZE: u64 = 64 << 20;
/// How much of the file the timed phases run over. Chosen so that every widened
/// window fits inside what the warm-up filled: reads stay below 32 MiB, the
/// window reaches at most 32 MiB + `READAHEAD`, and the warm-up fills to 48 MiB.
const TIMED_BELOW: u64 = 32 << 20;
const WARM_TO: u64 = 48 << 20;

fn main() {
    let mnt = PathBuf::from(
        std::env::var_os("HYDRATIOND_TEST_MOUNT")
            .expect("set HYDRATIOND_TEST_MOUNT to a scratch mount nothing else is watching"),
    );
    if unsafe { libc::geteuid() } != 0 {
        panic!("needs root: marking a mount is CAP_SYS_ADMIN");
    }
    // The live rig. A second group here would double-answer real events and
    // write this instrument's synthetic bytes into real files. Refuse by name;
    // it is a blunt check, but the mistake it stops is not recoverable.
    if mnt
        .components()
        .any(|c| c.as_os_str().eq_ignore_ascii_case("OneDrive"))
    {
        panic!("refusing to run against a OneDrive path: that mount is production");
    }
    let reads_per_rep: u64 = std::env::args()
        .nth(1)
        .map(|s| s.parse().expect("reads-per-rep must be a number"))
        .unwrap_or(4000);

    // Placeholders are created before the mount is marked — §6a-ter's rule for
    // every harness. Both files, so the walk experiment never writes into a
    // marked mount either.
    let timed = file_at(&mnt, "presentcost-timed.bin");
    let walked = file_at(&mnt, "presentcost-walk.bin");

    let asked = Arc::new(Mutex::new(Vec::new()));
    let delivered = Arc::new(AtomicU64::new(0));
    let group = Group::new_pre_content().expect("fanotify group");
    group.mark_mount(&mnt).expect("mark mount");
    let mut worker = Worker::new(
        group.try_clone().expect("clone group"),
        Local {
            asked: Arc::clone(&asked),
            delivered: Arc::clone(&delivered),
        },
        Policy::permissive(),
        InFlight::new(),
    );

    // Warm-up: fill [0, WARM_TO) through the worker, one read per readahead
    // window. Through the worker and not by writing directly, because the
    // record that lets a later event be answered `AlreadyPresent` lives in the
    // worker's memory (partial.rs) — bytes it did not put there are punched as
    // residue, which would make every timed read a fetch.
    for w in 0..(WARM_TO / READAHEAD) {
        let r = drive(&mut worker, pread_child(&timed, w * READAHEAD, 4096));
        assert_eq!(r.status, 0, "warm-up read failed");
    }
    assert!(
        placeholder::has_mark(&timed).expect("mark"),
        "the timed file must still be marked for the marked phase to mean anything"
    );
    // "Provably already held": ask the filesystem, not the worker. SEEK_HOLE
    // from 0 returns the first hole; everything before it is data.
    let held_to = first_hole(&timed);
    assert!(
        held_to >= WARM_TO,
        "warm-up left data only to {held_to}, wanted {WARM_TO}"
    );
    eprintln!(
        "warmed: data to {} MiB of {} MiB, still marked",
        held_to >> 20,
        SIZE >> 20
    );

    // Phase one: the file is marked, every read fires an event, every event is
    // answered without a fetch. Three repetitions, so a one-off stall shows as
    // an outlier instead of vanishing into a mean.
    let mut marked_ns = Vec::new();
    for rep in 0..3 {
        let fetches_before = asked.lock().unwrap().len();
        let r = drive(&mut worker, timed_child(&timed, reads_per_rep));
        assert_eq!(r.status, 0, "marked rep {rep}: reader failed");
        assert_eq!(
            asked.lock().unwrap().len(),
            fetches_before,
            "marked rep {rep}: a fetch happened; the measurement is polluted"
        );
        let events = r.outcomes.len() as u64;
        assert!(
            r.outcomes.iter().all(|o| *o == Handled::AlreadyPresent),
            "marked rep {rep}: an outcome was not AlreadyPresent: {:?}",
            r.outcomes.iter().find(|o| **o != Handled::AlreadyPresent)
        );
        assert_eq!(
            events, reads_per_rep,
            "marked rep {rep}: expected one event per read"
        );
        let per = r.child_ns / reads_per_rep;
        eprintln!("marked   rep {rep}: {per:>7} ns/read  ({events} events, all AlreadyPresent)");
        marked_ns.push(per);
    }

    // Complete the file: walk the remainder so the worker fetches it, clears
    // the mark and installs the ignore mark — the ordinary end of §8d-bis.
    let r = drive(
        &mut worker,
        walk_child(&timed, WARM_TO - READAHEAD, SIZE, 128 << 10),
    );
    assert_eq!(r.status, 0, "completing walk failed");
    assert!(
        !placeholder::has_mark(&timed).expect("mark"),
        "the file was read to the end and is still marked"
    );

    // Phase two: same file, same offsets, same pattern — but hydrated and
    // ignore-marked, so a read is just a read. This is the floor.
    let mut clear_ns = Vec::new();
    for rep in 0..3 {
        let r = drive(&mut worker, timed_child(&timed, reads_per_rep));
        assert_eq!(r.status, 0, "unmarked rep {rep}: reader failed");
        assert!(
            r.outcomes.is_empty(),
            "unmarked rep {rep}: {} events arrived; the ignore mark is not working",
            r.outcomes.len()
        );
        let per = r.child_ns / reads_per_rep;
        eprintln!("unmarked rep {rep}: {per:>7} ns/read  (no events)");
        clear_ns.push(per);
    }

    let marked = median(&mut marked_ns);
    let clear = median(&mut clear_ns);
    println!();
    println!("already-present read, still marked:  {marked:>7} ns/read (median of 3 reps)");
    println!("same read, hydrated + ignore mark:   {clear:>7} ns/read (median of 3 reps)");
    println!(
        "per-event cost of staying marked:    {:>7} ns",
        marked.saturating_sub(clear)
    );

    // The structure experiment: a cold sequential walk, which is the workload
    // the 2.77 GiB story is about. No timing — the local fetcher is instant and
    // the live per-fetch price is known (§8d-ter) — just how many reads there
    // were, how many became fetches, and how big the fetches were. If most
    // reads carry a fetch, a walk is priced by the per-fetch fixed cost and no
    // amount of cheapening the event round trip changes it.
    asked.lock().unwrap().clear();
    let step = 128 << 10;
    let r = drive(&mut worker, walk_child(&walked, 0, SIZE, step));
    assert_eq!(r.status, 0, "walk failed");
    let spans: Vec<Span> = asked.lock().unwrap().clone();
    let served = r
        .outcomes
        .iter()
        .filter(|o| matches!(o, Handled::Served { .. } | Handled::Hydrated { .. }))
        .count();
    let present = r
        .outcomes
        .iter()
        .filter(|o| **o == Handled::AlreadyPresent)
        .count();
    let mut sizes: Vec<u64> = spans.iter().map(|s| s.len).collect();
    sizes.sort_unstable();
    println!();
    println!(
        "cold sequential walk of {} MiB in {} KiB reads:",
        SIZE >> 20,
        step >> 10
    );
    println!(
        "  reads {}   events {}   answered-with-a-fetch {}   already-present {}",
        SIZE / step,
        r.outcomes.len(),
        served,
        present
    );
    if !sizes.is_empty() {
        println!(
            "  fetches {}   sizes KiB: min {} / median {} / max {}   first spans: {:?}",
            sizes.len(),
            sizes[0] >> 10,
            sizes[sizes.len() / 2] >> 10,
            sizes[sizes.len() - 1] >> 10,
            &spans[..spans.len().min(5)]
        );
    }
}

fn file_at(mnt: &Path, name: &str) -> PathBuf {
    let p = mnt.join(name);
    let _ = std::fs::remove_file(&p);
    placeholder::create(&p, SIZE, 0o644).expect("create placeholder");
    p
}

/// First hole in the file, by asking the filesystem. `SEEK_HOLE` at 0 lands on
/// the implicit hole at EOF when the file is fully mapped, so this needs no
/// special case for "no holes".
fn first_hole(path: &Path) -> u64 {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(path).expect("open for SEEK_HOLE");
    let r = unsafe { libc::lseek(f.as_raw_fd(), 0, libc::SEEK_HOLE) };
    assert!(r >= 0, "SEEK_HOLE failed: {}", io::Error::last_os_error());
    r as u64
}

struct Driven {
    status: i32,
    outcomes: Vec<Handled>,
    /// Nanoseconds the child spent inside its read loop, self-reported over a
    /// pipe — so fork and open cost is excluded from the mean.
    child_ns: u64,
}

/// Run the worker until the child exits, collecting every outcome the worker
/// produced along the way.
fn drive(worker: &mut Worker<Local>, child: (libc::pid_t, i32)) -> Driven {
    let (pid, pipe_rd) = child;
    let deadline = Instant::now() + Duration::from_secs(600);
    let mut outcomes = Vec::new();
    let mut status = 0;
    while Instant::now() < deadline {
        outcomes.extend(
            worker
                .run(Instant::now() + Duration::from_millis(50))
                .unwrap(),
        );
        if unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) } == pid {
            // The child is gone but its last events may still be queued; one
            // more pass drains them so no rep's events bleed into the next.
            outcomes.extend(
                worker
                    .run(Instant::now() + Duration::from_millis(50))
                    .unwrap(),
            );
            let mut buf = Vec::new();
            let mut chunk = [0u8; 64];
            loop {
                let n = unsafe {
                    libc::read(
                        pipe_rd,
                        chunk.as_mut_ptr() as *mut libc::c_void,
                        chunk.len(),
                    )
                };
                if n <= 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n as usize]);
            }
            unsafe { libc::close(pipe_rd) };
            let child_ns = String::from_utf8_lossy(&buf).trim().parse().unwrap_or(0);
            return Driven {
                status: libc::WEXITSTATUS(status),
                outcomes,
                child_ns,
            };
        }
    }
    unsafe { libc::kill(pid, libc::SIGKILL) };
    unsafe { libc::waitpid(pid, &mut status, 0) };
    panic!("the reader never came back");
}

/// One 4 KiB `pread` at `off`, verified against `expected_byte`.
fn pread_child(path: &Path, off: u64, len: usize) -> (libc::pid_t, i32) {
    let path = path.to_path_buf();
    spawn_reader(move |say_ns| {
        use std::os::unix::fs::FileExt;
        let f = std::fs::File::open(&path).map_err(|_| 1)?;
        let mut buf = vec![0u8; len];
        f.read_exact_at(&mut buf, off).map_err(|_| 1)?;
        if !buf
            .iter()
            .enumerate()
            .all(|(i, &b)| b == expected_byte(off + i as u64))
        {
            return Err(7);
        }
        say_ns(0);
        Ok(())
    })
}

/// `n` 4 KiB `pread`s cycling 128 KiB-apart offsets below [`TIMED_BELOW`],
/// timed around the loop only. Every offset it touches is inside the warmed
/// region, and every window widened from one stays inside it too.
fn timed_child(path: &Path, n: u64) -> (libc::pid_t, i32) {
    let path = path.to_path_buf();
    spawn_reader(move |say_ns| {
        use std::os::unix::fs::FileExt;
        let f = std::fs::File::open(&path).map_err(|_| 1)?;
        let mut buf = [0u8; 4096];
        let slots = TIMED_BELOW / (128 << 10);
        let began = Instant::now();
        for i in 0..n {
            let off = (i % slots) * (128 << 10);
            f.read_exact_at(&mut buf, off).map_err(|_| 1)?;
        }
        say_ns(began.elapsed().as_nanos() as u64);
        // Verified outside the timed loop: a wrong byte is a harness bug worth
        // failing on, but comparing inside the loop would time the comparison.
        if buf[0] != expected_byte((n - 1) % slots * (128 << 10)) {
            return Err(7);
        }
        Ok(())
    })
}

/// Sequential 4 KiB-buffered walk of `[from, to)` in `step` strides, every byte
/// checked. This is the reader the whole question is about.
fn walk_child(path: &Path, from: u64, to: u64, step: u64) -> (libc::pid_t, i32) {
    let path = path.to_path_buf();
    spawn_reader(move |say_ns| {
        use std::os::unix::fs::FileExt;
        let f = std::fs::File::open(&path).map_err(|_| 1)?;
        let mut buf = vec![0u8; step as usize];
        let mut at = from;
        while at < to {
            let want = step.min(to - at) as usize;
            f.read_exact_at(&mut buf[..want], at).map_err(|_| 1)?;
            if !buf[..want]
                .iter()
                .enumerate()
                .all(|(i, &b)| b == expected_byte(at + i as u64))
            {
                return Err(7);
            }
            at += want as u64;
        }
        say_ns(0);
        Ok(())
    })
}

/// Fork a reader. The closure reports its timing through `say_ns`, which writes
/// to a pipe — never to a file, because the child lives inside a marked mount
/// and a write there would fire an event of its own (§6a-ter).
fn spawn_reader<F>(work: F) -> (libc::pid_t, i32)
where
    F: FnOnce(&mut dyn FnMut(u64)) -> Result<(), i32>,
{
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe { libc::close(fds[0]) };
        let mut say = |ns: u64| {
            let s = format!("{ns}\n");
            unsafe {
                libc::write(fds[1], s.as_ptr() as *const libc::c_void, s.len());
            }
        };
        let code = match work(&mut say) {
            Ok(()) => 0,
            Err(c) => c,
        };
        unsafe { libc::_exit(code) };
    }
    unsafe { libc::close(fds[1]) };
    (pid, fds[0])
}

fn median(v: &mut [u64]) -> u64 {
    v.sort_unstable();
    v[v.len() / 2]
}

//! §8d-bis: a read of part of a placeholder fetches that part.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test ranges
//! ```
//!
//! What this is here to stop coming back: a 4096-byte read of a 2.77 GiB file on
//! a live account waited for the whole object, could not finish inside the
//! deadlines, and failed with `EIO` after 61.7 seconds. The fetch was for 2.77
//! GiB because the worker threw the event's range away and asked for the object.
//!
//! Every assertion below rests on `probes/bigdemand.c`, run on 7.1.6/btrfs
//! before any of this was written:
//!
//! ```text
//!   read() 4 KiB at 1 GiB of a 2.77 GiB file    1 event, off 1073741824 count 4096
//!   read() 4 KiB at 1 GiB, at 2 GiB, again      3 events — one per access, including the repeat
//!   mmap() 4 KiB window at 1 GiB                1 event, count 4096
//!   mmap() whole object                         1 event, count 2972712960
//! ```
//!
//! The third line is why ranged hydration works at all, and the fourth is why it
//! is not a complete answer: a mapping of the whole object still demands the
//! whole object in one event, so the deadlines still bound something real.
//!
//! These run against the kernel, not against a mock. A test that filled ranges
//! into a plain file and asserted about a `Ranges` set would pass whatever the
//! kernel did, which is the failure mode the project has already paid for.

use hydration_protocol::{FileId, Span};
use hydrationd::daemon::{Fetch, Worker};
use hydrationd::fanotify::Group;
use hydrationd::placeholder;
use hydrationd::policy::Policy;
use hydrationd::supervisor::InFlight;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn mount() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("HYDRATIOND_TEST_MOUNT")?);
    if !p.is_dir() || unsafe { libc::geteuid() } != 0 {
        return None;
    }
    Some(p)
}

fn skip(why: &str) {
    if std::env::var_os("HYDRATIOND_REQUIRE").is_some() {
        panic!("HYDRATIOND_REQUIRE is set but the test could not run: {why}");
    }
    eprintln!("SKIPPED: {why}");
}

fn placeholder_at(mnt: &std::path::Path, name: &str, size: u64) -> PathBuf {
    let p = mnt.join(name);
    let _ = std::fs::remove_file(&p);
    // Before the mark, always: giving a file its size is a write, and a write in
    // a marked mount fires an event nothing is answering yet (§6a-ter).
    placeholder::create(&p, size, 0o644).expect("placeholder");
    p
}

/// Content generated from its own offset, so a byte proves where it came from.
///
/// A constant fill would pass every one of these tests while the worker wrote
/// the right number of bytes to the wrong place — which is exactly the mistake
/// available when a body offset is relative to a span and the file's is not.
fn expected_byte(at: u64) -> u8 {
    (at % 251) as u8
}

/// Records what it was asked for, and answers with content that says where it
/// came from.
#[derive(Clone, Default)]
struct Asked(Arc<Mutex<Vec<Span>>>);

struct Ranged {
    asked: Asked,
    /// Bytes delivered in total, so a test can prove the *object* was not moved.
    delivered: Arc<AtomicU64>,
    /// Refuse any span reaching past this offset.
    ///
    /// Stands in for the thing that makes readahead a risk rather than a free
    /// win: the window is bytes nobody asked for, and a service that cannot
    /// deliver them must not thereby fail the read that could have been served.
    refuse_past: Option<u64>,
}

impl Fetch for Ranged {
    fn fetch_into(
        &mut self,
        _file: FileId,
        _size: u64,
        span: Span,
        dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        progress: &mut dyn FnMut(u64),
    ) -> io::Result<()> {
        self.asked.0.lock().unwrap().push(span);
        if self.refuse_past.is_some_and(|at| span.end() > at) {
            return Err(io::Error::other("this range is not available"));
        }
        let buf: Vec<u8> = (span.offset..span.end()).map(expected_byte).collect();
        dest(&buf, span.offset)?;
        progress(span.len);
        self.delivered
            .fetch_add(span.len, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// Run the worker until `reader` exits, then give back its status.
fn drive(worker: &mut Worker<Ranged>, reader: libc::pid_t) -> i32 {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut status = 0;
    while Instant::now() < deadline {
        let _ = worker.run(Instant::now() + Duration::from_millis(50));
        if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
            return libc::WEXITSTATUS(status);
        }
    }
    unsafe { libc::kill(reader, libc::SIGKILL) };
    unsafe { libc::waitpid(reader, &mut status, 0) };
    panic!("the reader never came back");
}

/// Read `len` at `off` in a child, checking every byte against its offset.
fn read_at(path: &std::path::Path, off: u64, len: usize) -> libc::pid_t {
    let path = path.to_path_buf();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        use std::os::unix::fs::FileExt;
        let code = match std::fs::File::open(&path) {
            Ok(f) => {
                let mut buf = vec![0u8; len];
                match f.read_exact_at(&mut buf, off) {
                    Ok(()) => {
                        if buf
                            .iter()
                            .enumerate()
                            .all(|(i, &b)| b == expected_byte(off + i as u64))
                        {
                            0
                        } else {
                            7
                        }
                    }
                    Err(_) => 1,
                }
            }
            Err(_) => 1,
        };
        unsafe { libc::_exit(code) };
    }
    pid
}

fn worker_for(mnt: &std::path::Path, asked: &Asked, delivered: &Arc<AtomicU64>) -> Worker<Ranged> {
    worker_refusing_past(mnt, asked, delivered, None)
}

fn worker_refusing_past(
    mnt: &std::path::Path,
    asked: &Asked,
    delivered: &Arc<AtomicU64>,
    refuse_past: Option<u64>,
) -> Worker<Ranged> {
    let group = Group::new_pre_content().expect("group");
    group.mark_mount(mnt).expect("mark");
    Worker::new(
        group.try_clone().expect("clone"),
        Ranged {
            asked: asked.clone(),
            delivered: Arc::clone(delivered),
            refuse_past,
        },
        Policy::permissive(),
        InFlight::new(),
    )
}

/// The bug, in one test.
///
/// A large placeholder, a small read. Before this change the fetcher was asked
/// for the object; on a real account that meant 2.77 GiB behind a four-kilobyte
/// read, and the read failed.
#[test]
fn a_small_read_of_a_large_placeholder_fetches_only_what_was_asked_for() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    // Large enough that "the object" and "the demand" cannot be confused, small
    // enough to live on a scratch image.
    const SIZE: u64 = 512 << 20;
    let path = placeholder_at(&mnt, "big-and-barely-read.bin", SIZE);

    let asked = Asked::default();
    let delivered = Arc::new(AtomicU64::new(0));
    let mut worker = worker_for(&mnt, &asked, &delivered);

    let reader = read_at(&path, 64 << 20, 4096);
    assert_eq!(
        drive(&mut worker, reader),
        0,
        "the reader did not get content"
    );

    let asked = asked.0.lock().unwrap().clone();
    assert_eq!(asked.len(), 1, "expected one fetch, got {asked:?}");
    assert!(
        asked[0].len <= 1 << 20,
        "the fetcher was asked for {} bytes to serve a 4096-byte read",
        asked[0].len
    );
    assert!(
        asked[0].offset <= 64 << 20 && asked[0].end() >= (64 << 20) + 4096,
        "the fetched span {asked:?} does not contain what was read"
    );
    assert!(
        delivered.load(Ordering::SeqCst) < SIZE,
        "the whole object was moved to serve a 4096-byte read"
    );

    // Still a placeholder: most of it is not here, and the mark is the only
    // thing standing between the holes and the next reader.
    assert!(
        placeholder::has_mark(&path).expect("mark"),
        "a partly filled file lost its placeholder mark"
    );
}

/// The second half of the measurement: a range that is already here is served
/// without another round trip, and a range that is not fires its own event.
#[test]
fn a_second_read_of_the_same_range_costs_no_fetch_and_a_new_range_does() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    const SIZE: u64 = 64 << 20;
    let path = placeholder_at(&mnt, "twice-and-elsewhere.bin", SIZE);

    let asked = Asked::default();
    let delivered = Arc::new(AtomicU64::new(0));
    let mut worker = worker_for(&mnt, &asked, &delivered);

    assert_eq!(drive(&mut worker, read_at(&path, 1 << 20, 4096)), 0);
    let after_first = asked.0.lock().unwrap().len();
    assert_eq!(after_first, 1);

    // The same range again. `probes/bigdemand.c` measured that this *does* fire
    // an event — the file is still marked and has no ignore mark — so the saving
    // has to come from the worker recognising what it already put there.
    assert_eq!(drive(&mut worker, read_at(&path, 1 << 20, 4096)), 0);
    assert_eq!(
        asked.0.lock().unwrap().len(),
        after_first,
        "a range already on disk was fetched again"
    );

    // Somewhere else in the file: that one has to be fetched.
    assert_eq!(drive(&mut worker, read_at(&path, 32 << 20, 4096)), 0);
    assert_eq!(
        asked.0.lock().unwrap().len(),
        after_first + 1,
        "a range that was not on disk was not fetched"
    );
    assert!(placeholder::has_mark(&path).expect("mark"));
}

/// Ranges accumulate until the file is whole, and only then does the mark go.
///
/// The completion rule is the one that must not be got wrong in either
/// direction: clearing the mark early serves holes as content, and never
/// clearing it means a fully present file goes on costing a round trip per read
/// forever — which is §2.4's zero-cost claim quietly withdrawn.
#[test]
fn a_file_read_all_the_way_through_ends_up_hydrated() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    // Small enough that reading all of it is quick, large enough that the read
    // is decomposed into several demands rather than one.
    const SIZE: u64 = 4 << 20;
    let path = placeholder_at(&mnt, "read-right-through.bin", SIZE);

    let asked = Asked::default();
    let delivered = Arc::new(AtomicU64::new(0));
    let mut worker = worker_for(&mnt, &asked, &delivered);

    let reader = {
        let path = path.clone();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            let code = match std::fs::read(&path) {
                Ok(b) if b.len() as u64 != SIZE => 2,
                Ok(b) => {
                    if b.iter()
                        .enumerate()
                        .all(|(i, &v)| v == expected_byte(i as u64))
                    {
                        0
                    } else {
                        7
                    }
                }
                Err(_) => 1,
            };
            unsafe { libc::_exit(code) };
        }
        pid
    };
    assert_eq!(drive(&mut worker, reader), 0, "the whole-file read failed");

    assert!(
        !placeholder::has_mark(&path).expect("mark"),
        "every byte is present and the file is still marked as a placeholder"
    );
    assert!(placeholder::holds_data(&path).expect("holds_data"));
    // Never more than the object, however many demands it took.
    assert_eq!(
        delivered.load(Ordering::SeqCst),
        SIZE,
        "reading a file once moved more than the file"
    );

    // And now it is free: an ignore mark is on it, so a further read produces no
    // event at all and the fetcher is not asked anything.
    let before = asked.0.lock().unwrap().len();
    assert_eq!(drive(&mut worker, read_at(&path, 0, 4096)), 0);
    assert_eq!(
        asked.0.lock().unwrap().len(),
        before,
        "a hydrated file still costs a fetch"
    );
}

/// Reading ahead must not be able to fail a read that would have succeeded.
///
/// Readahead widens the transfer past what the event demanded, which means the
/// demanded bytes and bytes nobody asked for now travel together. If that one
/// transfer decides the reader's outcome, then a speculative extension can turn
/// a 4 KiB read that the service could serve into `EIO` — a fetch made for
/// throughput costing correctness, which is the wrong way round for this
/// framework.
///
/// So the fetcher here refuses everything past the first page. The widened span
/// cannot succeed; the demand can. The reader must still get its content.
#[test]
fn a_readahead_that_fails_still_serves_what_the_reader_asked_for() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    // Bigger than one window, so the widening is a genuine extension of the
    // demand rather than the whole file.
    const SIZE: u64 = hydrationd::daemon::READAHEAD * 2;
    let path = placeholder_at(&mnt, "readahead-refused.bin", SIZE);

    let asked = Asked::default();
    let delivered = Arc::new(AtomicU64::new(0));
    // Everything past the first page is unavailable — including every byte the
    // readahead window would add, and none of the bytes the reader demands.
    let mut worker = worker_refusing_past(&mnt, &asked, &delivered, Some(4096));

    // At offset zero, so the reader is taken for a sequential one and the span
    // is widened to `READAHEAD`. `read_at` checks every byte against its own
    // offset, so a zero exit is real content and not a hole.
    assert_eq!(
        drive(&mut worker, read_at(&path, 0, 4096)),
        0,
        "a readahead that could not be delivered failed a read that could"
    );

    let asked = asked.0.lock().unwrap().clone();
    assert_eq!(
        asked.len(),
        2,
        "expected the widened span and then a retry of the demand, got {asked:?}"
    );
    assert_eq!(
        asked[0],
        Span::new(0, hydrationd::daemon::READAHEAD),
        "the first fetch was not the widened one"
    );
    assert_eq!(
        asked[1],
        Span::new(0, 4096),
        "the retry asked for something other than exactly what was demanded"
    );

    // Only what the reader demanded is on disk and recorded. The window was
    // punched back out, so nothing can later be served from bytes that never
    // arrived — the silent-zeros case (§8d) reached by way of an optimisation.
    assert_eq!(delivered.load(Ordering::SeqCst), 4096);
    assert!(
        placeholder::has_mark(&path).expect("mark"),
        "a file with one page of many lost its placeholder mark"
    );
}

/// A reader walking forward pays one fetch per window, not one per read.
///
/// The regression this pins down was invisible to every stride test: a window
/// anchored at the *demand* advances one reader-stride per event, so after the
/// first window a continuous walk fetched exactly one stride at the frontier,
/// per read. Measured (`examples/presentcost.rs`): 512 reads of a 64 MiB file
/// cost 449 fetches, 448 of them 128 KiB — and on a live account every one of
/// those pays the ~160 ms fixed price of a Graph span (§8d-ter), which caps a
/// walk at under a megabyte per second whatever the link can do. Anchoring the
/// window at the first missing byte makes the fetch count track windows, and
/// the reads in between are answered from what is already here.
#[test]
fn a_walker_pays_one_fetch_per_window_not_per_read() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    // Several windows, so "per window" and "per file" cannot be confused, and
    // enough reads per window that "per read" would be an order of magnitude
    // more fetches rather than a rounding difference.
    const SIZE: u64 = hydrationd::daemon::READAHEAD * 3;
    const STEP: u64 = 128 << 10;
    let path = placeholder_at(&mnt, "walked-straight-through.bin", SIZE);

    let asked = Asked::default();
    let delivered = Arc::new(AtomicU64::new(0));
    let mut worker = worker_for(&mnt, &asked, &delivered);

    // A continuous walker: sequential fixed-size reads through one descriptor,
    // every byte checked against its offset. `std::fs::read` is not used
    // because its internal chunking is not a contract; the stride here *is* the
    // experiment.
    let reader = {
        let path = path.clone();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            use std::os::unix::fs::FileExt;
            let code = (|| {
                let f = std::fs::File::open(&path).map_err(|_| 1)?;
                let mut buf = vec![0u8; STEP as usize];
                let mut at = 0u64;
                while at < SIZE {
                    f.read_exact_at(&mut buf, at).map_err(|_| 1)?;
                    if !buf
                        .iter()
                        .enumerate()
                        .all(|(i, &b)| b == expected_byte(at + i as u64))
                    {
                        return Err(7);
                    }
                    at += STEP;
                }
                Ok(0)
            })()
            .unwrap_or_else(|e| e);
            unsafe { libc::_exit(code) };
        }
        pid
    };
    assert_eq!(drive(&mut worker, reader), 0, "the walk failed");

    let asked = asked.0.lock().unwrap().clone();
    let windows = SIZE / hydrationd::daemon::READAHEAD;
    assert!(
        asked.len() as u64 <= windows + 1,
        "a walk of {} reads cost {} fetches; the window is advancing one \
         stride per read instead of one window per window",
        SIZE / STEP,
        asked.len()
    );
    // And the window never sprints ahead of the reader: however the fetches
    // were divided, reading the file once moved the file once.
    assert_eq!(
        delivered.load(Ordering::SeqCst),
        SIZE,
        "a single walk moved more bytes than the file holds"
    );
    // Read to the end is hydrated, same as ever.
    assert!(
        !placeholder::has_mark(&path).expect("mark"),
        "a file walked to its last byte is still marked"
    );
}

/// Somebody else wrote into the placeholder between two reads.
///
/// No released kernel has a pre-modify event (§5), so this happens without the
/// worker seeing it. Its memory of what it filled is therefore only believed
/// while the file still looks the way it left it — and when it does not, the
/// file is punched and refetched, which is what the code did unconditionally
/// before ranges existed.
#[test]
fn a_placeholder_written_by_someone_else_is_not_trusted() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    // Comfortably larger than one readahead window, and the meddling below lands
    // outside it. A reader starting at the top of a file is taken for a
    // sequential one, so the first read pulls `READAHEAD` bytes — on a file the
    // size of that window it would pull the whole thing, and the page this test
    // needs to be *absent* would already be there.
    const SIZE: u64 = hydrationd::daemon::READAHEAD * 4;
    let path = placeholder_at(&mnt, "meddled-with.bin", SIZE);

    let asked = Asked::default();
    let delivered = Arc::new(AtomicU64::new(0));
    let mut worker = worker_for(&mnt, &asked, &delivered);

    assert_eq!(drive(&mut worker, read_at(&path, 0, 4096)), 0);
    let after_first = asked.0.lock().unwrap().len();

    // A write into the middle of the placeholder, from outside — in a child,
    // with the worker running.
    //
    // It has to be a child, and finding that out was worth the detour. Written
    // inline, this test hung until `timeout` killed the suite: a *partial-page*
    // write has to bring the page in before it can modify part of it, that read
    // is a `FAN_PRE_ACCESS`, and the process issuing the write was the one that
    // would have had to answer it. §6a-ter's trap, in a ninth disguise — and this
    // time it is not the framework writing but anything else that edits a
    // placeholder in place.
    //
    // So the meddling is not invisible to the worker after all; what is
    // invisible is the *modification*. The worker sees a read of that page,
    // fills it with cloud content, allows it — and then the writer's bytes land
    // on top, with nothing further reported (§5: no released kernel has a
    // pre-modify event). Which is exactly the state this test is about.
    let meddler = {
        let path = path.clone();
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            use std::os::unix::fs::FileExt;
            let code = match std::fs::OpenOptions::new().write(true).open(&path) {
                Ok(f) => {
                    match f.write_all_at(b"not from the cloud", hydrationd::daemon::READAHEAD * 2) {
                        // And move the mtime somewhere the worker's witness
                        // cannot mistake for its own, rather than trusting the
                        // clock to have advanced.
                        //
                        // `partial::Witness` is `{mtime, mtime_nsec, size}`, and
                        // this write does not change the size. Measured
                        // (`probes/mtimegran.c`): ext4 with a 128-byte inode has
                        // no sub-second timestamp field — nsec reads 0 and mtime
                        // moves once a second — so a meddling write in the same
                        // second as the fill it lands on is invisible to the
                        // witness, and the worker correctly-but-uselessly trusts
                        // a record that no longer describes the file. On btrfs
                        // the same code is distinguishable within a millisecond
                        // and the test passed from the day it was written.
                        //
                        // That is a real limit and not only a test problem — see
                        // DESIGN.md §8z-bis. What is asserted here is the
                        // worker's rule, so the test states the premise the rule
                        // needs instead of hoping the filesystem supplies it.
                        Ok(()) => {
                            let older =
                                std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
                            match f
                                .set_times(std::fs::FileTimes::new().set_modified(older))
                                .and_then(|_| f.sync_all())
                            {
                                Ok(()) => 0,
                                Err(_) => 1,
                            }
                        }
                        Err(_) => 1,
                    }
                }
                Err(_) => 1,
            };
            unsafe { libc::_exit(code) };
        }
        pid
    };
    assert_eq!(drive(&mut worker, meddler), 0, "the meddling write failed");
    // The page the writer touched was fetched to be modified, so this is one
    // more than `after_first` — the count is taken again rather than predicted.
    let after_meddle = asked.0.lock().unwrap().len();
    assert!(after_meddle > after_first);

    // The same range as the first read. Its bytes are still on disk and still
    // correct — but the worker cannot know that any more, so it fetches again
    // rather than believing a record it can no longer vouch for.
    assert_eq!(drive(&mut worker, read_at(&path, 0, 4096)), 0);
    assert_eq!(
        asked.0.lock().unwrap().len(),
        after_meddle + 1,
        "the worker trusted its record of a file somebody else had written to"
    );

    // And the writer's bytes are gone: the file was punched back to a
    // placeholder before anything else was served from it, so what a reader gets
    // at that offset is cloud content. `read_at` checks every byte against its
    // own offset, so this fails both if the meddling survived and if the refill
    // landed in the wrong place.
    assert_eq!(
        drive(&mut worker, read_at(&path, 4 << 20, 4096)),
        0,
        "content somebody else wrote into a placeholder was served as cloud content"
    );
}

//! The worker's descriptor table does not grow with the number of reads it
//! answers.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test pidfd
//! ```
//!
//! What this is here to stop coming back: the group is created with
//! `FAN_REPORT_PIDFD`, so every event carries a descriptor for the process
//! behind it, and the worker closed it at exactly one point — inside the cgroup
//! lookup, two thirds of the way down the decision. Every earlier return leaked
//! it. That is not an exotic path: the first branch of the decision is "this
//! file already holds its content", which is what every hydrated file's first
//! read after a restart takes, and what *every* read of a file whose mark
//! someone stripped takes, because that case deliberately declines to install
//! the ignore mark that would suppress the next event.
//!
//! The end state of the leak is `EMFILE` in a root process that cannot then open
//! anything, which means the mount answers `EIO` — fail-closed, correctly, for no
//! reason at all. Nothing about it is visible before that: the worker keeps
//! answering, the reads keep succeeding, and the only symptom is a number in
//! `/proc/<pid>/fd` going up.
//!
//! So the assertion is that number, not the code path. Both suites below drive
//! real events through a real `Worker` in this process — `/proc/self/fd` *is*
//! the worker's table here — and require it to be the same size afterwards as
//! before. A unit test in `fanotify.rs` covers the ownership rule itself
//! without needing root; these cover the rule being enough.

use hydration_protocol::{FileId, Span};
use hydrationd::daemon::{Fetch, Handled, Worker};
use hydrationd::fanotify::Group;
use hydrationd::placeholder;
use hydrationd::policy::Policy;
use hydrationd::supervisor::InFlight;
use std::io;
use std::path::{Path, PathBuf};
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

/// How many descriptors this process holds.
///
/// The `read_dir` handle is counted too, and deliberately not subtracted: it is
/// counted identically in every call, and the number that matters here is the
/// difference between two of them.
fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("/proc/self/fd")
        .count()
}

/// A fetcher that fails if it is ever asked for anything.
///
/// The first suite is about events that are answered without a round trip. If
/// this is called, the test is measuring something else than it claims to.
struct NeverAsked;

impl Fetch for NeverAsked {
    fn fetch_into(
        &mut self,
        _file: FileId,
        _size: u64,
        _span: Span,
        _dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        _progress: &mut dyn FnMut(u64),
    ) -> io::Result<()> {
        Err(io::Error::other("this suite must not reach the network"))
    }
}

/// Delivers whatever it is asked for, so the ordinary hydration path runs.
struct Zeros;

impl Fetch for Zeros {
    fn fetch_into(
        &mut self,
        _file: FileId,
        _size: u64,
        span: Span,
        dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        progress: &mut dyn FnMut(u64),
    ) -> io::Result<()> {
        // In chunks, because a readahead window is megabytes and one allocation
        // of it per event is the kind of thing that makes a descriptor count
        // hard to read.
        const CHUNK: u64 = 256 << 10;
        let buf = vec![0xa5u8; CHUNK as usize];
        let mut at = span.offset;
        while at < span.end() {
            let n = CHUNK.min(span.end() - at);
            dest(&buf[..n as usize], at)?;
            progress(n);
            at += n;
        }
        Ok(())
    }
}

fn worker_for<F: Fetch + 'static>(mnt: &Path, fetch: F) -> Worker<F> {
    let group = Group::new_pre_content().expect("group");
    group.mark_mount(mnt).expect("mark");
    Worker::new(
        group.try_clone().expect("clone"),
        fetch,
        Policy::permissive(),
        InFlight::new(),
    )
}

/// A sized file with no content and no placeholder mark.
///
/// This is the `looks_stripped` case — a same-uid process can remove
/// `user.hydration.dehydrated`, and the worker cannot tell the result from a
/// genuinely sparse hydrated file. It is used here because of what the worker
/// does about it: it declines to install an ignore mark, so the file goes on
/// generating an event per read forever, which is precisely the shape that turns
/// a one-descriptor leak into an exhausted table.
///
/// Created before the mount is marked. Sizing a file is a write, and a write
/// inside a marked mount by the process that must answer the event it fires is
/// the deadlock in §6a-ter.
fn sparse_unmarked(mnt: &Path, name: &str, size: u64) -> PathBuf {
    let p = mnt.join(name);
    let _ = std::fs::remove_file(&p);
    let f = std::fs::File::create(&p).expect("create");
    f.set_len(size).expect("set_len");
    p
}

/// Read one page at each of `offsets`, in a child, and report success by status.
///
/// A child rather than this process: a read inside the marked mount, made by the
/// only process that can answer the event it fires, does not come back.
fn reader_at(path: &Path, offsets: Vec<u64>) -> libc::pid_t {
    let path = path.to_path_buf();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        use std::os::unix::fs::FileExt;
        let code = match std::fs::File::open(&path) {
            Ok(f) => {
                let mut buf = [0u8; 4096];
                let mut code = 0;
                for off in offsets {
                    if f.read_exact_at(&mut buf, off).is_err() {
                        code = 1;
                        break;
                    }
                }
                code
            }
            Err(_) => 1,
        };
        unsafe { libc::_exit(code) };
    }
    pid
}

/// Run the worker until the reader exits; give back its status and what the
/// worker did.
fn drive<F: Fetch + 'static>(worker: &mut Worker<F>, reader: libc::pid_t) -> (i32, Vec<Handled>) {
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut status = 0;
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        if let Ok(mut batch) = worker.run(Instant::now() + Duration::from_millis(50)) {
            seen.append(&mut batch);
        }
        if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
            return (libc::WEXITSTATUS(status), seen);
        }
    }
    unsafe { libc::kill(reader, libc::SIGKILL) };
    unsafe { libc::waitpid(reader, &mut status, 0) };
    panic!("the reader never came back");
}

/// One page every megabyte: distinct pages, so each read is its own event.
///
/// Re-reading one offset is not a reliable event generator — the second read of
/// a page that is already in cache need not reach the filesystem — and a test
/// that quietly produced one event instead of sixty-four would report a leak
/// fixed when it had only stopped being exercised. Hence the count assertion in
/// both tests below.
fn scattered(n: usize) -> Vec<u64> {
    (0..n as u64).map(|i| i * (1 << 20)).collect()
}

const READS: usize = 64;
const SIZE: u64 = 96 << 20;

#[test]
fn answering_an_already_present_read_does_not_leak_the_readers_pidfd() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = sparse_unmarked(&mnt, "stripped-and-read-often.bin", SIZE);
    let mut worker = worker_for(&mnt, NeverAsked);

    // Answer one event before measuring. Whatever the first one allocates and
    // keeps — and the point of the test is that nothing does — is then inside
    // the baseline rather than inside the delta.
    let (code, first) = drive(&mut worker, reader_at(&path, scattered(1)));
    assert_eq!(code, 0, "the warm-up read did not succeed");
    assert!(
        matches!(first.as_slice(), [Handled::AlreadyPresent]),
        "the warm-up did not take the already-present path: {first:?}"
    );

    let before = open_fds();
    let (code, seen) = drive(&mut worker, reader_at(&path, scattered(READS)));
    let after = open_fds();

    assert_eq!(code, 0, "a read failed");
    let answered = seen
        .iter()
        .filter(|h| **h == Handled::AlreadyPresent)
        .count();
    assert!(
        answered >= READS,
        "only {answered} of {READS} reads fired an event, so this run did not \
         exercise the leak at all — see `scattered`. Outcomes: {seen:?}"
    );
    assert_eq!(
        after, before,
        "the worker held {before} descriptors before answering {answered} events \
         and {after} after; a pidfd is leaking on the already-present path"
    );
}

#[test]
fn hydrating_does_not_leak_the_readers_pidfd_either() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    // The path that does look the pidfd up, which is where a fix that closed it
    // twice — once in the lookup, once on the drop — would show up instead. A
    // double close is not a missing descriptor but a stolen one: the number is
    // reused, and the second close takes it away from whatever opened it next.
    let path = mnt.join("hydrated-and-read-often.bin");
    let _ = std::fs::remove_file(&path);
    placeholder::create(&path, SIZE, 0o644).expect("placeholder");
    let mut worker = worker_for(&mnt, Zeros);

    let (code, first) = drive(&mut worker, reader_at(&path, scattered(1)));
    assert_eq!(code, 0, "the warm-up read did not succeed");
    assert!(
        !first.is_empty(),
        "the warm-up fired no event at all: {first:?}"
    );

    let before = open_fds();
    let (code, seen) = drive(&mut worker, reader_at(&path, scattered(READS)));
    let after = open_fds();

    assert_eq!(code, 0, "a read failed");
    assert!(
        seen.len() >= READS,
        "only {} of {READS} reads fired an event, so this run did not exercise \
         the lookup path: {seen:?}",
        seen.len()
    );
    assert!(
        !seen
            .iter()
            .any(|h| matches!(h, Handled::Failed { .. } | Handled::Denied { .. })),
        "the reads were not served: {seen:?}"
    );
    assert_eq!(
        after,
        before,
        "the worker held {before} descriptors before answering {} events and \
         {after} after",
        seen.len()
    );
}

//! §6a-bis: a slow cloud must not be able to lock a filesystem.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test deadlines
//! ```
//!
//! The failure this guards against was measured during development and is nastier
//! than it sounds. A process blocked in a pre-content event cannot be killed by a
//! signal — the event has to be answered first. So a worker that never answers
//! does not merely stop working: every later operation on the mount blocks behind
//! it, the blocked reader cannot be killed, and the group cannot be closed
//! because the stuck process still holds its descriptor. The mount looks healthy
//! from the outside. Nothing recovers on its own.
//!
//! Two mechanisms have to hold, and they are tested separately because either one
//! alone leaves the hole open:
//!
//!   1. the worker gives up on a fetch and answers `EIO` itself, and
//!   2. the supervisor notices a worker that has stopped answering at all.

use hydration_protocol::{FileId, Span};
use hydrationd::daemon::{spawn_split, Fetch, FetchWhole, Handled, Worker};
use hydrationd::fanotify::Group;
use hydrationd::placeholder;
use hydrationd::policy::Policy;
use hydrationd::supervisor::InFlight;
use std::io;
use std::path::PathBuf;
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

/// A cloud that never answers. Not slow — stopped.
struct NeverReturns;

impl FetchWhole for NeverReturns {
    fn fetch(&mut self, _file: FileId, _size: u64) -> io::Result<Vec<u8>> {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}

/// Slow once — long enough to miss its deadline, but it does finish.
///
/// Deliberately not "sleeps forever": that is [`NeverReturns`], and it is a
/// different question. The point here is recovery.
struct SlowOnce(std::sync::atomic::AtomicUsize);

impl FetchWhole for SlowOnce {
    fn fetch(&mut self, _file: FileId, size: u64) -> io::Result<Vec<u8>> {
        if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            std::thread::sleep(Duration::from_secs(4));
        }
        Ok(vec![b'H'; size as usize])
    }
}

fn placeholder_at(mnt: &std::path::Path, name: &str, size: u64) -> PathBuf {
    let p = mnt.join(name);
    let _ = std::fs::remove_file(&p);
    // Before the mark, always: giving a file its size is a write, and a write in
    // a marked mount fires an event nothing is answering yet (§6a-ter).
    placeholder::create(&p, size, 0o644).expect("placeholder");
    p
}

/// Requirement 1: the worker gives up rather than holding the reader forever.
#[test]
fn a_fetch_that_never_returns_is_answered_with_an_error() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = placeholder_at(&mnt, "never-returns.bin", 4096);

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::with_deadline(
        group.try_clone().expect("clone"),
        NeverReturns,
        Policy::permissive(),
        InFlight::new(),
        Duration::from_secs(2),
    );

    let reader = unsafe { libc::fork() };
    if reader == 0 {
        // Exit code says which happened: content, error, or zeros.
        let code = match std::fs::read(&path) {
            Ok(b) if b.iter().all(|&x| x == 0) => 7,
            Ok(_) => 0,
            Err(_) => 1,
        };
        unsafe { libc::_exit(code) };
    }

    let began = Instant::now();
    let mut status = 0;
    let mut done = false;
    while began.elapsed() < Duration::from_secs(20) {
        let _ = worker.run(Instant::now() + Duration::from_millis(200));
        if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
            done = true;
            break;
        }
    }
    if !done {
        unsafe {
            libc::kill(reader, libc::SIGKILL);
            libc::waitpid(reader, &mut status, 0);
        }
        panic!(
            "the reader was still blocked after 20s; a stopped cloud locks the \
             filesystem and the reader cannot even be killed"
        );
    }

    assert_eq!(
        libc::WEXITSTATUS(status),
        1,
        "expected EIO; 7 means zeros were served, 0 means content appeared from \
         a fetch that never returned"
    );
    assert!(
        began.elapsed() < Duration::from_secs(15),
        "the deadline did not bound the wait: {:?}",
        began.elapsed()
    );
    let _ = std::fs::remove_file(&path);
}

/// One missed deadline must not condemn the fetcher.
///
/// The deadline is per event, so a fetch that overruns costs its own reader an
/// `EIO` — and nothing more, once it finishes. A fetcher that answers again is
/// working again.
///
/// What this test does *not* claim, because it is not true: that the second read
/// is unaffected while the first is still running. Fetches are serialised —
/// there is one connection to the sync daemon and one request outstanding on it
/// — so a fetch that has overrun its deadline still holds the queue until it
/// returns, and reads behind it get `EIO` rather than content. That is a
/// degradation, not a lock-up, and it is the distinction §6a-bis cares about:
/// every reader is answered promptly. Removing it needs request pipelining,
/// which the protocol's `id` field already allows for and the transport does not
/// yet implement. See §6a-bis.
#[test]
fn a_missed_deadline_does_not_disable_later_fetches() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let slow = placeholder_at(&mnt, "slow-once-a.bin", 64);
    let ok = placeholder_at(&mnt, "slow-once-b.bin", 64);

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::with_deadline(
        group.try_clone().expect("clone"),
        SlowOnce(std::sync::atomic::AtomicUsize::new(0)),
        Policy::permissive(),
        InFlight::new(),
        Duration::from_secs(2),
    );

    // Sequential, with the second read starting after the first fetch has had
    // time to finish. Overlapping them would test the serialisation limit above
    // rather than recovery.
    for (path, want) in [(&slow, 1), (&ok, 0)] {
        if path == &ok {
            std::thread::sleep(Duration::from_secs(4));
        }
        let reader = unsafe { libc::fork() };
        if reader == 0 {
            let code = match std::fs::read(path) {
                Ok(b) if b.first() == Some(&b'H') => 0,
                Ok(_) => 7,
                Err(_) => 1,
            };
            unsafe { libc::_exit(code) };
        }
        let began = Instant::now();
        let mut status = 0;
        let mut done = false;
        while began.elapsed() < Duration::from_secs(20) {
            let _ = worker.run(Instant::now() + Duration::from_millis(200));
            if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
                done = true;
                break;
            }
        }
        assert!(done, "reader for {} never finished", path.display());
        assert_eq!(
            libc::WEXITSTATUS(status),
            want,
            "unexpected outcome for {}",
            path.display()
        );
    }
    assert!(
        !worker.fetcher_wedged(),
        "one slow object marked the whole fetcher unresponsive"
    );
    let _ = std::fs::remove_file(&slow);
    let _ = std::fs::remove_file(&ok);
}

/// Requirement 2: the supervisor notices a worker that stopped answering.
///
/// A fetch that never returns is no longer this state — the worker waits on it
/// through its own loop, bumping the liveness counter, and gives up when the
/// transfer cap expires. That is the streaming design working, and it is why
/// this test cannot use a slow provider to produce a stuck worker any more.
///
/// The state that must still be caught is a worker that has stopped running its
/// loop at all while holding an event: blocked in an uninterruptible filesystem
/// operation, or deadlocked on a pre-content event of its own making. `SIGSTOP`
/// reproduces exactly that shape — alive, holding, bumping nothing — without
/// needing to arrange a real deadlock.
#[test]
fn a_worker_that_stops_answering_is_taken_over() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = placeholder_at(&mnt, "stalled-worker.bin", 4096);

    let handle = spawn_split(
        &mnt,
        NeverReturns,
        Policy::permissive(),
        Duration::from_secs(120),
    )
    .expect("split");

    let reader = unsafe { libc::fork() };
    if reader == 0 {
        let code = match std::fs::read(&path) {
            Ok(b) if b.iter().all(|&x| x == 0) => 7,
            Ok(_) => 0,
            Err(_) => 1,
        };
        unsafe { libc::_exit(code) };
    }

    // Give the worker time to dequeue the event, then freeze it holding it.
    std::thread::sleep(Duration::from_secs(2));
    unsafe { libc::kill(handle.worker_pid(), libc::SIGSTOP) };

    let report = handle
        .supervise_with_stall(
            Instant::now() + Duration::from_secs(30),
            Duration::from_secs(3),
        )
        .expect("supervise");

    assert!(
        report.stalled,
        "the supervisor did not notice a worker that had stopped answering: {report:?}"
    );
    assert!(
        report.stranded_answered.is_some(),
        "the stalled worker's event was never answered, so the reader is still \
         blocked and cannot be killed: {report:?}"
    );

    let mut status = 0;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut done = false;
    while Instant::now() < deadline {
        if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
            done = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(done, "the reader never came back after the takeover");
    assert_eq!(
        libc::WEXITSTATUS(status),
        1,
        "the reader should get EIO; 7 means it was served zeros"
    );
    let _ = std::fs::remove_file(&path);
}

/// The deadline must not turn a working fetch into a failure.
#[test]
fn a_prompt_fetch_is_unaffected() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = placeholder_at(&mnt, "prompt.bin", 32);

    struct Prompt;
    impl FetchWhole for Prompt {
        fn fetch(&mut self, _f: FileId, size: u64) -> io::Result<Vec<u8>> {
            Ok(vec![b'H'; size as usize])
        }
    }

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::with_deadline(
        group.try_clone().expect("clone"),
        Prompt,
        Policy::permissive(),
        InFlight::new(),
        Duration::from_secs(2),
    );

    let reader = unsafe { libc::fork() };
    if reader == 0 {
        let code = match std::fs::read(&path) {
            Ok(b) if b.first() == Some(&b'H') => 0,
            _ => 1,
        };
        unsafe { libc::_exit(code) };
    }
    let mut status = 0;
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut outcomes = Vec::new();
    while Instant::now() < deadline {
        outcomes.extend(
            worker
                .run(Instant::now() + Duration::from_millis(200))
                .unwrap_or_default(),
        );
        if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
            break;
        }
    }
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "a prompt fetch did not deliver"
    );
    assert!(
        outcomes
            .iter()
            .any(|h| matches!(h, Handled::Hydrated { .. })),
        "expected a hydration: {outcomes:?}"
    );
    let _ = std::fs::remove_file(&path);
}

/// A fetcher that stops answering must not be a one-way door.
///
/// The deadline machinery counts consecutive misses and stops waiting after a
/// few, so that a genuinely unresponsive client costs each reader a prompt
/// denial rather than a full timeout. The first version of that made the state
/// permanent: the short-circuit ran before the request was sent, so no reply
/// could ever arrive, so the counter could never reset. Three missed deadlines
/// turned the mount into instant `EIO` forever — served by two healthy-looking
/// processes, with nothing to tear anything down, which is precisely the state
/// §6a-bis says must not persist.
///
/// A fetcher that answers again is working again, however long it took.
#[test]
fn a_fetcher_that_recovers_is_used_again() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };

    /// Blocks for longer than several deadlines, then serves normally.
    struct SlowStart(std::sync::atomic::AtomicUsize);
    impl FetchWhole for SlowStart {
        fn fetch(&mut self, _f: FileId, size: u64) -> io::Result<Vec<u8>> {
            if self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                std::thread::sleep(Duration::from_secs(5));
            }
            Ok(vec![b'H'; size as usize])
        }
    }

    let group = Group::new_pre_content().expect("group");
    let paths: Vec<PathBuf> = (0..5)
        .map(|i| placeholder_at(&mnt, &format!("recover-{i}.bin"), 32))
        .collect();
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::with_deadline(
        group.try_clone().expect("clone"),
        SlowStart(std::sync::atomic::AtomicUsize::new(0)),
        Policy::permissive(),
        InFlight::new(),
        Duration::from_millis(500),
    );

    let mut outcomes = Vec::new();
    for path in &paths {
        let reader = unsafe { libc::fork() };
        if reader == 0 {
            let code = match std::fs::read(path) {
                Ok(b) if b.first() == Some(&b'H') => 0,
                Ok(_) => 7,
                Err(_) => 1,
            };
            unsafe { libc::_exit(code) };
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut status = 0;
        let mut done = false;
        while Instant::now() < deadline {
            let _ = worker.run(Instant::now() + Duration::from_millis(100));
            if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
                done = true;
                break;
            }
        }
        assert!(done, "reader for {} never finished", path.display());
        outcomes.push(libc::WEXITSTATUS(status));
        // Enough that the abandoned first fetch has finished by the last read.
        std::thread::sleep(Duration::from_millis(1500));
    }

    assert!(
        outcomes.contains(&1),
        "expected at least one denial while the fetcher was stuck: {outcomes:?}"
    );
    assert_eq!(
        outcomes.last(),
        Some(&0),
        "the fetcher recovered but was never used again — the wedge is a one-way \
         door and this mount serves EIO forever: {outcomes:?}"
    );
    assert!(
        !worker.fetcher_wedged(),
        "still reported as wedged after a successful fetch"
    );
    for p in &paths {
        let _ = std::fs::remove_file(p);
    }
}

/// A peer that has gone away must not be mistaken for a peer that is refusing.
///
/// The give-up clock counted missed deadlines, and a dead socket fails
/// instantly rather than slowly — so it never started, and the worker served
/// instant `EIO` forever under two units that both looked healthy. §6a-bis
/// says that state must come down. Connection losses therefore count toward
/// `wedged()` — through their own counter, because unlike a deadline miss they
/// are cheap to retry and the retry is where `SocketFetch` reconnects
/// (`tests/reconnect.rs` pins that recovery; this test pins the bound behind
/// it, for a peer that never comes back).
///
/// The second half matters as much as the first: an ordinary per-file refusal —
/// "there is no cloud object for this inode" — is an answer, not a fault, and
/// counting it would tear the mount down over one unsyncable file.
#[test]
fn a_lost_connection_counts_towards_giving_up_and_a_refusal_does_not() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };

    struct Fails(io::ErrorKind);
    impl FetchWhole for Fails {
        fn fetch(&mut self, _f: FileId, _size: u64) -> io::Result<Vec<u8>> {
            Err(io::Error::new(self.0, "measured failure"))
        }
    }

    for (label, kind, expect_wedged) in [
        ("connection lost", io::ErrorKind::UnexpectedEof, true),
        ("per-file refusal", io::ErrorKind::NotFound, false),
    ] {
        let paths: Vec<PathBuf> = (0..4)
            .map(|i| placeholder_at(&mnt, &format!("lost-{}-{i}.bin", expect_wedged as u8), 32))
            .collect();
        let group = Group::new_pre_content().expect("group");
        group.mark_mount(&mnt).expect("mark");
        let mut worker = Worker::with_deadline(
            group.try_clone().expect("clone"),
            Fails(kind),
            Policy::permissive(),
            InFlight::new(),
            Duration::from_secs(5),
        );

        for path in &paths {
            let reader = unsafe { libc::fork() };
            if reader == 0 {
                let _ = std::fs::read(path);
                unsafe { libc::_exit(0) };
            }
            let mut status = 0;
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut done = false;
            while Instant::now() < deadline {
                let _ = worker.run(Instant::now() + Duration::from_millis(100));
                if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
                    done = true;
                    break;
                }
            }
            if !done {
                unsafe {
                    libc::kill(reader, libc::SIGKILL);
                    libc::waitpid(reader, &mut status, 0);
                }
                panic!("[{label}] a reader was left blocked");
            }
        }

        assert_eq!(
            worker.fetcher_wedged(),
            expect_wedged,
            "[{label}] wedged={} after four failures; a lost connection must \
             eventually bring the mount down, and a per-file refusal must never",
            worker.fetcher_wedged()
        );
        for p in &paths {
            let _ = std::fs::remove_file(p);
        }
    }
}

/// The reason streaming exists: an object bigger than one deadline's worth of
/// bandwidth, served by a provider that is slow but never stops.
///
/// Under the old design this was unservable at any speed — the whole object had
/// to arrive inside a single 30-second window, and its failure took three
/// consecutive misses to wedge the fetcher and the mount with it. Under
/// streaming the transfer simply continues, because the deadline that matters is
/// "has it stopped", not "is it finished".
///
/// It also pins the memory claim: the helper buffers one chunk, so a large
/// object costs a chunk rather than its size.
#[test]
fn a_slow_but_steady_transfer_completes_past_the_first_byte_deadline() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    use hydrationd::daemon::Limits;

    const SIZE: u64 = 6 << 20;

    /// Delivers in slices, pausing between them for longer than the first-byte
    /// deadline would have allowed in total.
    struct Dribbles;
    impl Fetch for Dribbles {
        fn fetch_into(
            &mut self,
            _file: FileId,
            _size: u64,
            span: Span,
            dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
            progress: &mut dyn FnMut(u64),
        ) -> io::Result<()> {
            let chunk = vec![b'H'; 512 * 1024];
            let mut done = 0u64;
            while done < span.len {
                let n = chunk.len().min((span.len - done) as usize);
                dest(&chunk[..n], span.offset + done)?;
                done += n as u64;
                progress(done);
                std::thread::sleep(Duration::from_millis(400));
            }
            Ok(())
        }
    }

    let path = placeholder_at(&mnt, "slow-and-large.bin", SIZE);
    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::with_limits(
        group.try_clone().expect("clone"),
        Dribbles,
        Policy::permissive(),
        InFlight::new(),
        Limits {
            // Deliberately shorter than the transfer takes. Under the old design
            // this alone made the object unservable.
            first_byte: Duration::from_secs(2),
            stall: Duration::from_secs(2),
            total: Duration::from_secs(60),
        },
    );

    let reader = unsafe { libc::fork() };
    if reader == 0 {
        let got = std::fs::read(&path).unwrap_or_default();
        let ok = got.len() as u64 == SIZE && got.iter().all(|&b| b == b'H');
        unsafe { libc::_exit(if ok { 0 } else { 7 }) };
    }

    let began = Instant::now();
    let mut status = 0;
    let mut done = false;
    while began.elapsed() < Duration::from_secs(45) {
        let _ = worker.run(Instant::now() + Duration::from_millis(200));
        if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
            done = true;
            break;
        }
    }
    if !done {
        unsafe {
            libc::kill(reader, libc::SIGKILL);
            libc::waitpid(reader, &mut status, 0);
        }
        panic!("a slow but steady 6 MiB transfer never completed");
    }
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "the object was not delivered whole; 7 means the content was wrong"
    );
    assert!(
        began.elapsed() > Duration::from_secs(4),
        "the transfer finished too fast to have exercised the deadline: {:?}",
        began.elapsed()
    );
    assert!(
        !worker.fetcher_wedged(),
        "a slow transfer counted as unresponsive"
    );
    let _ = std::fs::remove_file(&path);
}

/// An abandoned transfer must not write into the next file.
///
/// The fetch thread was handed the event fd as a raw number. The worker closes
/// that descriptor the moment it answers, so an abandoned transfer left the
/// fetch thread still writing to a number the kernel had by then handed to the
/// *next* event. Measured before the fix: 8 MiB of one object written into a
/// different 4096-byte placeholder, its mark cleared, reported as `Hydrated`.
/// Silent, durable, cross-file corruption — and not a race that needs luck,
/// because event fds are allocated lowest-free-first and the worker holds
/// almost none.
#[test]
fn an_abandoned_transfer_cannot_write_into_the_next_file() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    use hydrationd::daemon::Limits;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Stalls on the first object past its deadline, then wakes up and writes
    /// the whole thing — into whatever descriptor it was given.
    struct StallsThenWakes(Arc<AtomicUsize>);
    impl Fetch for StallsThenWakes {
        fn fetch_into(
            &mut self,
            _file: FileId,
            _size: u64,
            span: Span,
            dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
            progress: &mut dyn FnMut(u64),
        ) -> io::Result<()> {
            let first = self.0.fetch_add(1, Ordering::SeqCst) == 0;
            if first {
                // Long enough that the worker gives up and answers the reader.
                std::thread::sleep(Duration::from_secs(4));
            }
            let buf = vec![if first { b'A' } else { b'B' }; span.len as usize];
            dest(&buf, span.offset)?;
            progress(span.len);
            Ok(())
        }
    }

    let big = placeholder_at(&mnt, "uaf-big.bin", 8 << 20);
    let small = placeholder_at(&mnt, "uaf-small.bin", 4096);
    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::with_limits(
        group.try_clone().expect("clone"),
        StallsThenWakes(Arc::new(AtomicUsize::new(0))),
        Policy::permissive(),
        InFlight::new(),
        Limits {
            first_byte: Duration::from_secs(1),
            stall: Duration::from_secs(1),
            total: Duration::from_secs(2),
        },
    );

    for path in [&big, &small] {
        let reader = unsafe { libc::fork() };
        if reader == 0 {
            let _ = std::fs::read(path);
            unsafe { libc::_exit(0) };
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut status = 0;
        while Instant::now() < deadline {
            let _ = worker.run(Instant::now() + Duration::from_millis(100));
            if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
                break;
            }
        }
        // Let the abandoned first transfer wake up while the second is served.
        std::thread::sleep(Duration::from_millis(500));
        let _ = worker.run(Instant::now() + Duration::from_secs(4));
    }

    let md = std::fs::metadata(&small).expect("the small placeholder is gone");
    assert_eq!(
        md.len(),
        4096,
        "an abandoned transfer grew a different file to {} bytes",
        md.len()
    );
    let body = std::fs::read(&small).unwrap_or_default();
    assert!(
        !body.contains(&b'A'),
        "content from a different object was written into this file"
    );
    for p in [&big, &small] {
        let _ = std::fs::remove_file(p);
    }
}

/// A `Fetch` that writes less than the object and claims success must not be
/// believed.
///
/// `Body` holds a *provider* to the object's length. Nothing held the privileged
/// `Fetch` trait to it, so an implementation that wrote half and returned `Ok`
/// produced a file that was half content and half zeros, unmarked, reported as
/// hydrated. The guarantee cannot live only in the half of the stack that
/// happens to be typed for it.
#[test]
fn a_fetch_that_delivers_short_and_claims_success_is_refused() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };

    struct Lies;
    impl Fetch for Lies {
        fn fetch_into(
            &mut self,
            _file: FileId,
            _size: u64,
            span: Span,
            dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
            progress: &mut dyn FnMut(u64),
        ) -> io::Result<()> {
            let half = (span.len / 2) as usize;
            dest(&vec![b'H'; half], span.offset)?;
            progress(half as u64);
            Ok(())
        }
    }

    let path = placeholder_at(&mnt, "short-and-proud.bin", 8192);
    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::new(
        group.try_clone().expect("clone"),
        Lies,
        Policy::permissive(),
        InFlight::new(),
    );

    let reader = unsafe { libc::fork() };
    if reader == 0 {
        let code = match std::fs::read(&path) {
            Ok(b) if b.contains(&0) => 7,
            Ok(_) => 0,
            Err(_) => 1,
        };
        unsafe { libc::_exit(code) };
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut status = 0;
    let mut done = false;
    while Instant::now() < deadline {
        let _ = worker.run(Instant::now() + Duration::from_millis(100));
        if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
            done = true;
            break;
        }
    }
    assert!(done, "the reader never came back");
    assert_eq!(
        libc::WEXITSTATUS(status),
        1,
        "expected EIO; 7 means the reader was handed half content and half zeros"
    );
    assert!(
        hydrationd::placeholder::has_mark(&path).unwrap_or(false),
        "the placeholder mark was cleared for a transfer that never completed"
    );
    let _ = std::fs::remove_file(&path);
}

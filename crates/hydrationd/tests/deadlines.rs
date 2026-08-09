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

use hydration_protocol::FileId;
use hydrationd::daemon::{spawn_split, Fetch, Handled, Worker};
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

impl Fetch for NeverReturns {
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

impl Fetch for SlowOnce {
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
/// The worker here has no deadline worth the name, so it will sit on the event
/// forever. That is precisely the state a signal cannot fix, and the supervisor
/// has to reach it on its own.
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
    impl Fetch for Prompt {
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
    assert_eq!(libc::WEXITSTATUS(status), 0, "a prompt fetch did not deliver");
    assert!(
        outcomes.iter().any(|h| matches!(h, Handled::Hydrated { .. })),
        "expected a hydration: {outcomes:?}"
    );
    let _ = std::fs::remove_file(&path);
}

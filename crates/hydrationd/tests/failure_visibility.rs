//! §6c, applied to faults: a read answered `EIO` is never silent.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test failure_visibility
//! ```
//!
//! §6c says a *refusal* must be visible, and the denial log has always done
//! that. `Handled::Failed` was outside it. It is returned from seven places in
//! `daemon.rs`, it answers `FAN_DENY` at every one of them — so the reader gets
//! `EIO` exactly as a refused reader does — and until this suite existed it
//! recorded nothing anywhere.
//!
//! That is not a missing nicety. It was measured on a live deployment on
//! 2026-08-13: a photo would not open, the application showed an error, and the
//! journal for both halves of the pair had nothing in it for that minute. There
//! was no way to tell a fault from a slow queue from a policy refusal, because
//! two of the three say so and the third had been built not to.
//!
//! The control test is the load-bearing half. A log that recorded every event
//! would pass the first test while telling the user nothing, and that is the
//! easier mistake to make than the one being fixed.

use hydration_protocol::{FileId, Span};
use hydrationd::daemon::{Fetch, Worker};
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

fn placeholder_at(mnt: &std::path::Path, name: &str, size: u64) -> PathBuf {
    let p = mnt.join(name);
    let _ = std::fs::remove_file(&p);
    // Before the mark, always: sizing a file is a write, and a write inside a
    // marked mount fires an event nothing is answering yet (§6a-ter).
    placeholder::create(&p, size, 0o644).expect("placeholder");
    p
}

/// Fails the way a provider fault does: promptly, with a message.
///
/// Not a timeout. A transfer that runs out of time becomes `Abandoned`, which
/// already records itself — routing this test through that path would prove the
/// thing that already worked.
struct AlwaysFails(&'static str);

impl Fetch for AlwaysFails {
    fn fetch_into(
        &mut self,
        _file: FileId,
        _size: u64,
        _span: Span,
        _dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        _progress: &mut dyn FnMut(u64),
    ) -> io::Result<()> {
        Err(io::Error::other(self.0))
    }
}

/// Delivers whatever was asked for, so the control has something to succeed at.
struct AlwaysWorks;

impl Fetch for AlwaysWorks {
    fn fetch_into(
        &mut self,
        _file: FileId,
        _size: u64,
        span: Span,
        dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        progress: &mut dyn FnMut(u64),
    ) -> io::Result<()> {
        let buf = vec![0xABu8; span.len as usize];
        dest(&buf, span.offset)?;
        progress(span.len);
        Ok(())
    }
}

fn worker_with<F: Fetch + 'static>(mnt: &std::path::Path, fetch: F) -> Worker<F> {
    let group = Group::new_pre_content().expect("group");
    group.mark_mount(mnt).expect("mark");
    Worker::new(
        group.try_clone().expect("clone"),
        fetch,
        Policy::permissive(),
        InFlight::new(),
    )
}

/// Run the worker until `reader` exits, then give back its status.
fn drive<F: Fetch + 'static>(worker: &mut Worker<F>, reader: libc::pid_t) -> i32 {
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

/// Read the first bytes of `path` in a child. Exits 0 on success, 1 on error.
fn read_head(path: &std::path::Path) -> libc::pid_t {
    let path = path.to_path_buf();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        use std::os::unix::fs::FileExt;
        let code = match std::fs::File::open(&path) {
            Ok(f) => {
                let mut buf = vec![0u8; 4096];
                match f.read_exact_at(&mut buf, 0) {
                    Ok(()) => 0,
                    Err(_) => 1,
                }
            }
            Err(_) => 1,
        };
        unsafe { libc::_exit(code) };
    }
    pid
}

/// The bug, in one test.
#[test]
fn a_failed_hydration_names_the_file_and_says_why() {
    let Some(mnt) = mount() else {
        return skip("needs root and HYDRATIOND_TEST_MOUNT");
    };
    let p = placeholder_at(&mnt, "failure-visibility-broken", 64 * 1024);
    let mut w = worker_with(&mnt, AlwaysFails("the provider said no"));

    let code = drive(&mut w, read_head(&p));
    let _ = std::fs::remove_file(&p);

    // The reader really did get an error — otherwise this test would be
    // asserting about a log entry for a read that quietly succeeded.
    assert_eq!(code, 1, "the reader was served rather than refused");

    assert_eq!(
        w.failures.total(),
        1,
        "a read was answered EIO and the failure log stayed empty — the exact \
         state that left a live deployment with an unopenable file and a blank \
         journal"
    );

    let last = w.failures.recent().next_back().expect("one entry");
    assert!(
        last.reason.contains("the provider said no"),
        "the recorded reason lost what actually went wrong: {:?}",
        last.reason
    );
    // The path is the half that makes the log usable. A count answers "is this
    // happening a lot"; a person with one file that will not open needs that
    // file named, and the name has to be resolved before the event fd is closed.
    assert_eq!(
        last.path.as_deref(),
        Some(p.to_str().expect("utf-8 path")),
        "the failure did not name the file it happened to"
    );
}

/// The control, and the reason the first test means anything.
///
/// A log that recorded every event — or that a later change made record every
/// event — would satisfy `a_failed_hydration_names_the_file_and_says_why`
/// completely while telling the user nothing at all. This is the assertion that
/// can catch that, and it is the easier mistake to make of the two.
#[test]
fn a_hydration_that_worked_records_nothing() {
    let Some(mnt) = mount() else {
        return skip("needs root and HYDRATIOND_TEST_MOUNT");
    };
    let p = placeholder_at(&mnt, "failure-visibility-fine", 64 * 1024);
    let mut w = worker_with(&mnt, AlwaysWorks);

    let code = drive(&mut w, read_head(&p));
    let _ = std::fs::remove_file(&p);

    assert_eq!(code, 0, "the reader could not read a file that was served");
    assert_eq!(
        w.failures.total(),
        0,
        "a successful hydration was recorded as a failure: {:?}",
        w.failures.summary()
    );
}

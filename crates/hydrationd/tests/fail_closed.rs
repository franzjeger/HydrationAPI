//! The helper against a real kernel: hydration, and what happens when it dies.
//!
//! Needs `CAP_SYS_ADMIN` and a filesystem that supports pre-content events, so
//! it does not run in an ordinary `cargo test`. Set `HYDRATIOND_TEST_MOUNT` to a
//! mount point on ext4/btrfs/xfs and run as root:
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test fail_closed
//! ```
//!
//! A skip is reported as "did not run", never as a pass. `HYDRATIOND_REQUIRE`
//! turns a skip into a failure, which is what CI should set once there is a
//! runner that can provide the mount.

use hydration_protocol::FileId;
use hydrationd::daemon::{spawn_split, Fetch, Handled, Worker};
use hydrationd::fanotify::Group;
use hydrationd::placeholder;
use hydrationd::policy::Policy;
use hydrationd::supervisor::InFlight;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const CONTENT: &[u8] = b"REAL-CLOUD-CONTENT-FETCHED-ON-DEMAND";

fn skip(why: &str) -> bool {
    if std::env::var_os("HYDRATIOND_REQUIRE").is_some() {
        panic!("HYDRATIOND_REQUIRE is set but the test could not run: {why}");
    }
    eprintln!("SKIPPED: {why}");
    true
}

/// The mount to work in, or `None` if this environment cannot run the test.
fn mount() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("HYDRATIOND_TEST_MOUNT")?);
    if !p.is_dir() {
        return None;
    }
    if unsafe { libc::geteuid() } != 0 {
        return None;
    }
    Some(p)
}

struct Canned(Vec<u8>);
impl Fetch for Canned {
    fn fetch(&mut self, _file: FileId, _size: u64) -> io::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}

/// A fetcher that answers with the wrong length, to drive §5.7.
struct Short;
impl Fetch for Short {
    fn fetch(&mut self, _file: FileId, size: u64) -> io::Result<Vec<u8>> {
        Ok(vec![b'x'; (size / 2) as usize])
    }
}

/// A fetcher that never returns, so the worker can be killed mid-event.
struct Hangs;
impl Fetch for Hangs {
    fn fetch(&mut self, _file: FileId, _size: u64) -> io::Result<Vec<u8>> {
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
}

fn placeholder_at(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
    let p = dir.join(name);
    let _ = std::fs::remove_file(&p);
    placeholder::create(&p, content.len() as u64, 0o644).expect("create placeholder");
    p
}

#[test]
fn a_read_of_a_placeholder_is_filled_before_it_returns() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let file = placeholder_at(&mnt, "hydrate-me.bin", CONTENT);
    assert!(placeholder::is_dehydrated(&file).unwrap());

    let group = Group::new_pre_content().expect("pre-content group");
    group.mark_mount(&mnt).expect("mark mount");
    let mut worker = Worker::new(
        group,
        Canned(CONTENT.to_vec()),
        Policy::permissive(),
        InFlight::new(),
    );

    // A reader in another process, so the event actually blocks someone.
    let reader = std::process::Command::new("cat")
        .arg(&file)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("spawn reader");

    let seen = worker
        .run(Instant::now() + Duration::from_secs(5))
        .expect("worker loop");
    let out = reader.wait_with_output().expect("reader");

    assert!(
        seen.iter().any(|h| matches!(h, Handled::Hydrated { .. })),
        "no event was hydrated: {seen:?}"
    );
    assert_eq!(
        out.stdout, CONTENT,
        "the reader did not receive the content the placeholder promised"
    );
    assert!(!placeholder::is_dehydrated(&file).unwrap());
}

#[test]
fn a_short_fetch_reaches_the_reader_as_an_error_not_as_zeros() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let file = placeholder_at(&mnt, "short.bin", &vec![b'q'; 4096]);

    let group = Group::new_pre_content().expect("pre-content group");
    group.mark_mount(&mnt).expect("mark mount");
    let mut worker = Worker::new(group, Short, Policy::permissive(), InFlight::new());

    let reader = std::process::Command::new("cat")
        .arg(&file)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn reader");

    let seen = worker
        .run(Instant::now() + Duration::from_secs(5))
        .expect("worker loop");
    let out = reader.wait_with_output().expect("reader");

    assert!(
        seen.iter().any(|h| matches!(h, Handled::Failed { .. })),
        "a fetch of half the promised bytes was not refused: {seen:?}"
    );
    assert!(
        !out.status.success(),
        "the reader succeeded on a placeholder that was never filled — it was \
         handed {} bytes",
        out.stdout.len()
    );
    assert!(
        placeholder::is_dehydrated(&file).unwrap(),
        "a partially filled placeholder survived the refusal"
    );
}

/// The measured failure that made the supervisor necessary, as a test.
///
/// Bare fanotify fails open: with no daemon, this read returns zeros and exit 0.
/// With the split, the worker dies holding the event and the supervisor answers
/// it — so the reader gets an error instead of hanging, and never sees zeros.
#[test]
fn killing_the_worker_mid_event_gives_the_reader_an_error_not_zeros() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let file = placeholder_at(&mnt, "stranded.bin", &vec![b'w'; 512]);

    let handle = spawn_split(&mnt, Hangs, Policy::permissive(), Duration::from_secs(60))
        .expect("split helper");

    // Give the worker its mark, then block a reader on it.
    std::thread::sleep(Duration::from_millis(300));
    let mut reader = std::process::Command::new("cat")
        .arg(&file)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn reader");

    // The worker is now stuck in `fetch`, holding the event.
    std::thread::sleep(Duration::from_secs(1));
    unsafe { libc::kill(handle.worker_pid(), libc::SIGKILL) };

    let report = handle
        .supervise(Instant::now() + Duration::from_secs(3))
        .expect("supervise");

    let out = reader.wait().expect("reader exits");

    assert_eq!(
        report.worker_signal,
        Some(libc::SIGKILL),
        "the worker was not killed as intended"
    );
    assert!(
        report.stranded_answered.is_some(),
        "the supervisor found nothing stranded — the worker died holding an \
         event and nobody answered it, which leaves the reader hanging"
    );
    assert!(
        !out.success(),
        "the reader succeeded with no worker alive; a dehydrated file was \
         served as zeros"
    );
    assert!(
        placeholder::is_dehydrated(&file).unwrap(),
        "the file gained content while nothing was hydrating it"
    );

    // Clean up: the reader is gone, but the file should not be.
    let _ = std::fs::remove_file(&file);
}

#[test]
fn a_denied_reader_is_refused_and_recorded() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let file = placeholder_at(&mnt, "backup-target.bin", CONTENT);

    let group = Group::new_pre_content().expect("pre-content group");
    group.mark_mount(&mnt).expect("mark mount");
    // Deny whatever cgroup this test itself runs in, so the reader we spawn is
    // treated the way a backup unit would be.
    let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let leaf = own
        .lines()
        .next()
        .and_then(|l| l.rsplit('/').next())
        .unwrap_or("")
        .trim()
        .to_string();
    if leaf.is_empty() {
        skip("could not determine our own cgroup to deny");
        return;
    }
    let mut worker = Worker::new(
        group,
        Canned(CONTENT.to_vec()),
        Policy::new(vec![leaf.clone()]),
        InFlight::new(),
    );

    let reader = std::process::Command::new("cat")
        .arg(&file)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn reader");

    let seen = worker
        .run(Instant::now() + Duration::from_secs(5))
        .expect("worker loop");
    let out = reader.wait_with_output().expect("reader");

    assert!(
        seen.iter().any(|h| matches!(h, Handled::Denied { .. })),
        "the policy did not refuse a reader in a denied cgroup: {seen:?}"
    );
    assert!(
        !out.status.success(),
        "a denied reader still got its content"
    );
    assert!(
        placeholder::is_dehydrated(&file).unwrap(),
        "a denied read hydrated the file anyway"
    );
    assert_eq!(
        worker.log.summary().len(),
        1,
        "the denial was not recorded; §6c requires it be visible"
    );
}

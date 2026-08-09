//! Eviction against a real kernel, including the order that deadlocks.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test eviction
//! ```

use hydration_protocol::FileId;
use hydrationd::daemon::{FetchWhole, Worker};
use hydrationd::evict::{evict, Backup, Refused};
use hydrationd::policy::Policy;
use hydrationd::supervisor::InFlight;
use hydrationd::fanotify::Group;
use hydrationd::placeholder;
use std::path::PathBuf;

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

/// A full file becomes a placeholder again, and the disk comes back.
#[test]
fn evicting_returns_the_disk_and_keeps_the_metadata() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = mnt.join("evict-me.bin");
    let _ = std::fs::remove_file(&path);
    let body = vec![b'e'; 8192];
    placeholder::create(&path, body.len() as u64, 0o750).expect("create");

    // Filled before the mount is marked: a fresh open for writing inside a
    // marked mount blocks on a pre-content event that nothing here would answer.
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    placeholder::hydrate_fd(std::os::fd::AsFd::as_fd(&f), &body, body.len() as u64).unwrap();
    drop(f);

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    group
        .ignore(&path)
        .expect("ignore mark, as after hydration");
    assert!(!placeholder::is_dehydrated(&path).unwrap());

    // Would block forever if the punch happened after the mark was dropped.
    let outcome = evict(&group, &path, Backup::Exclude, || true).expect("evict");
    assert_eq!(outcome, Ok(()));

    let md = std::fs::metadata(&path).unwrap();
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    assert_eq!(md.len(), 8192, "size lost");
    assert_eq!(md.permissions().mode() & 0o777, 0o750, "mode lost");
    assert_eq!(md.blocks(), 0, "the disk was not actually returned");
    let _ = std::fs::remove_file(&path);
}

/// The rule that matters more than any disk saving.
///
/// A file whose only copy is the local one is not a candidate at any price:
/// evicting it is deleting it, and the user would find out by reading zeros.
#[test]
fn a_file_that_is_not_in_the_cloud_is_never_evicted() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = mnt.join("unsent.bin");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, vec![b'u'; 4096]).expect("write");

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    group.ignore(&path).expect("ignore");

    // The unprivileged side reports that this content exists nowhere else.
    let outcome = evict(&group, &path, Backup::Exclude, || false).expect("evict");
    assert_eq!(
        outcome,
        Err(Refused::NotUploaded),
        "a file with no remote copy was evicted — that is a delete, not a saving"
    );
    assert!(
        !placeholder::is_dehydrated(&path).unwrap(),
        "the content was thrown away anyway"
    );
    assert_eq!(std::fs::read(&path).unwrap().len(), 4096);
    let _ = std::fs::remove_file(&path);
}

/// Evicting twice is not an error, and does not do anything the second time.
#[test]
fn evicting_something_already_empty_is_refused_not_repeated() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = mnt.join("already.bin");
    let _ = std::fs::remove_file(&path);
    placeholder::create(&path, 1024, 0o644).expect("create");

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");

    assert_eq!(
        evict(&group, &path, Backup::Exclude, || true).expect("evict"),
        Err(Refused::AlreadyDehydrated)
    );
    let _ = std::fs::remove_file(&path);
}

/// After eviction the file is intercepted again, so the next read hydrates.
///
/// Without dropping the ignore mark, an evicted file reads back as zeros
/// forever — the exact silent failure this project exists to prevent, arrived at
/// by saving disk.
#[test]
fn an_evicted_file_is_intercepted_again() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = mnt.join("rearmed.bin");
    let _ = std::fs::remove_file(&path);
    let body = vec![b'r'; 2048];
    placeholder::create(&path, body.len() as u64, 0o644).expect("create");

    // Filled before the mount is marked. Opening a file for writing inside a
    // marked mount blocks on a pre-content event, and nothing is answering
    // events here — the worker only gets away with it because it writes through
    // the event fd it was handed, which is not itself intercepted.
    let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    placeholder::hydrate_fd(std::os::fd::AsFd::as_fd(&f), &body, body.len() as u64).unwrap();
    drop(f);

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    group.ignore(&path).unwrap();
    evict(&group, &path, Backup::Exclude, || true)
        .expect("evict")
        .expect("evicted");

    // Nobody is answering events now, so a read must block rather than succeed.
    // Succeeding would mean the file is no longer intercepted and the reader is
    // getting the zeros the eviction left behind.
    let mut child = std::process::Command::new("cat")
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("reader");

    std::thread::sleep(std::time::Duration::from_secs(2));
    let finished = child.try_wait().expect("try_wait");

    assert!(
        finished.is_none(),
        "a read of an evicted file completed with nobody hydrating it — it was \
         served the zeros the eviction left behind"
    );

    // Releasing the reader is the awkward part. It is blocked inside a
    // pre-content event, and an event has to be *answered* before the process
    // can be reaped — a signal alone does not do it. Closing the group is the
    // answer: the kernel releases everything pending when the last descriptor
    // goes away, which is the same mechanism that makes bare fanotify fail
    // *open* and is why §6a needs a supervisor holding a second copy.
    drop(group);

    // Bounded, because a test that can hang is a test that stops being run.
    let mut released = None;
    for _ in 0..40 {
        if let Some(s) = child.try_wait().expect("try_wait") {
            released = Some(s);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if released.is_none() {
        let _ = child.kill();
    }
    assert!(
        released.is_some(),
        "closing the group did not release the blocked reader"
    );

    let _ = std::fs::remove_file(&path);
}

/// Content that is unmistakably content.
struct Canned(Vec<u8>);

impl FetchWhole for Canned {
    fn fetch(&mut self, _file: FileId, size: u64) -> std::io::Result<Vec<u8>> {
        let mut v = self.0.clone();
        v.resize(size as usize, b'.');
        Ok(v)
    }
}

/// §6d's flag, both ends of its life.
///
/// The flag exists so that backup tools which honour it skip a file with no
/// content. That makes *clearing* it the load-bearing half: a hydrated file that
/// is still flagged goes on being skipped by every such backup, which is the
/// §6d harm arriving by the back door — content that exists only on this machine
/// and is excluded from the backup anyway.
///
/// Measured (`probes/nodump.c`): the flag survives being written through, so
/// hydration does not clear it as a side effect. It has to be an explicit step,
/// and this is what checks that it is.
#[test]
fn the_backup_flag_is_set_on_eviction_and_cleared_on_hydration() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    use hydration_protocol::flags::has_nodump;

    let path = mnt.join("nodump-lifecycle.bin");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, b"content that will be evicted and then fetched back").expect("seed");
    assert!(!has_nodump(&path).unwrap(), "the flag was already set");

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    group.ignore(&path).expect("ignore");

    evict(&group, &path, Backup::Exclude, || true)
        .expect("evict")
        .expect("refused");
    assert!(
        has_nodump(&path).unwrap(),
        "eviction left the placeholder visible to backups that honour nodump"
    );

    // Hydration through the event fd, which is the only way it happens in
    // production — and the only way that exercises the clearing step.
    let mut worker = Worker::new(
        group.try_clone().expect("clone"),
        Canned(b"fetched back from the cloud".to_vec()),
        Policy::permissive(),
        InFlight::new(),
    );
    let reader = unsafe { libc::fork() };
    if reader == 0 {
        let _ = std::fs::read(&path);
        unsafe { libc::_exit(0) };
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut status = 0;
    let mut done = false;
    while std::time::Instant::now() < deadline {
        let _ = worker.run(std::time::Instant::now() + std::time::Duration::from_millis(200));
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
        panic!("the read never completed");
    }

    assert!(
        !has_nodump(&path).unwrap(),
        "the file has its content back but is still flagged nodump: every backup \
         that honours the flag will keep skipping it"
    );
    let _ = std::fs::remove_file(&path);
}

/// Under the other policy the flag must not appear at all — a backup is meant to
/// read these files and pull them down.
#[test]
fn including_a_placeholder_in_backups_leaves_the_flag_alone() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    use hydration_protocol::flags::has_nodump;

    let path = mnt.join("nodump-include.bin");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, b"content").expect("seed");

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    group.ignore(&path).expect("ignore");

    evict(&group, &path, Backup::Include, || true)
        .expect("evict")
        .expect("refused");
    assert!(
        !has_nodump(&path).unwrap(),
        "Backup::Include set the flag anyway"
    );
    let _ = std::fs::remove_file(&path);
}

/// Eviction is the framework writing, so it must leave the file looking clean.
///
/// Punching a hole moves mtime (measured, `probes/nodump.c`'s sibling
/// measurement), so a placeholder that was not re-stamped reads as
/// changed-by-someone-else. That breaks both directions at once: a delta pass
/// refuses to refresh it, and a resync walk queues it for upload — and uploading
/// a placeholder means *reading* it, which hydrates the very file whose disk we
/// just reclaimed. One overflow after an eviction sweep would re-download
/// everything that was evicted.
#[test]
fn an_evicted_placeholder_still_looks_like_our_own_work() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    use hydration_protocol::stamp::{self, State};

    let path = mnt.join("evicted-stamp.bin");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, vec![b'x'; 16384]).expect("seed");
    stamp::write(&path).expect("stamp");

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    group.ignore(&path).expect("ignore");

    evict(&group, &path, Backup::Exclude, || true)
        .expect("evict")
        .expect("refused");

    assert_eq!(
        stamp::state(&path).unwrap(),
        State::Clean,
        "eviction left the placeholder looking edited: a resync would queue it \
         for upload, and uploading it would read it back down"
    );
    let _ = std::fs::remove_file(&path);
}

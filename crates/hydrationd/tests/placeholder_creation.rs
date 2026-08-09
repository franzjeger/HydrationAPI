//! Creating a placeholder inside the mount that is being watched.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test placeholder_creation
//! ```
//!
//! This is the sixth appearance of the trap this project keeps walking into: a
//! write inside a marked mount, performed by the only process that could answer
//! the event it fires. Delta sync has to create placeholders, creating one means
//! giving a file a size, and giving a file a size inside the mount fires a
//! pre-content event that the unprivileged daemon cannot answer.
//!
//! The way out is that the placeholder is built on an anonymous inode and only
//! given a name once complete. What has to be true for that to be safe is
//! asserted here rather than reasoned about, because every previous appearance
//! of this trap looked safe when reasoned about.

use hydration_client::delta::Materialise;
use hydration_client::place::TmpfilePlacer;
use hydration_protocol::{xattr, FileId};
use hydrationd::daemon::{Fetch, Worker};
use hydrationd::fanotify::Group;
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

/// Content that is unmistakably content, so "did this hydrate" is not a guess.
struct Canned(Vec<u8>);

impl Fetch for Canned {
    fn fetch(&mut self, _file: FileId, size: u64) -> io::Result<Vec<u8>> {
        let mut v = self.0.clone();
        v.resize(size as usize, b'.');
        Ok(v)
    }
}

/// Run the placer in a child while the parent answers events, and report
/// whether the child finished.
///
/// The split matters: if creating a placeholder blocks on an event, doing both
/// in one process deadlocks and the test hangs instead of failing. A hang is the
/// least informative outcome available and has misled this project repeatedly,
/// so the failure mode is made observable by construction.
fn place_while_answering(
    group: &Group,
    worker: &mut Worker<Canned>,
    target: &std::path::Path,
    size: u64,
    cloud_id: &str,
) -> bool {
    let root = target.parent().unwrap().to_path_buf();
    let target = target.to_path_buf();
    let cloud_id = cloud_id.to_string();

    let child = unsafe { libc::fork() };
    if child == 0 {
        let mut p = TmpfilePlacer::new(&root);
        let code = match p.place(&target, size, &cloud_id, Some("etag-1")) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("  place failed: {e}");
                1
            }
        };
        unsafe { libc::_exit(code) };
    }
    assert!(child > 0, "fork failed");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut status = 0;
    while Instant::now() < deadline {
        let _ = worker.run(Instant::now() + Duration::from_millis(200));
        if unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } == child {
            let _ = group;
            return libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        }
    }
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, &mut status, 0);
    }
    panic!("creating a placeholder never completed — the sizing event was not answered");
}

/// The whole question, in one test.
#[test]
fn a_placeholder_can_be_created_inside_the_watched_mount() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let target = mnt.join("delta-created.bin");
    let _ = std::fs::remove_file(&target);

    let group = Group::new_pre_content().expect("pre-content group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::new(
        group.try_clone().expect("clone"),
        Canned(b"HYDRATED-CONTENT".to_vec()),
        Policy::permissive(),
        InFlight::new(),
    );

    assert!(
        place_while_answering(&group, &mut worker, &target, 64, "cloud-1"),
        "the unprivileged side could not create a placeholder in the marked mount"
    );

    let md = std::fs::metadata(&target).expect("the placeholder does not exist");
    assert_eq!(md.len(), 64, "the placeholder has the wrong size");
    use std::os::unix::fs::MetadataExt;
    assert_eq!(md.blocks(), 0, "the placeholder occupies disk");
    assert!(
        hydrationd::placeholder::has_mark(&target).unwrap_or(false),
        "the placeholder is not marked dehydrated — it would never be intercepted"
    );
    assert!(
        !has_xattr(&target, xattr::BUILDING),
        "the construction mark survived into the sync directory: this file would \
         be allowed without hydrating and read as zeros"
    );

    let _ = std::fs::remove_file(&target);
}

/// The trap, asserted directly.
///
/// A placeholder is only worth creating if reading it still hydrates. Every
/// previous form of this bug produced a file that looked correct and was never
/// intercepted again — an ignore mark left behind by the very act of creating
/// it. So the test does not stop at "the file exists": it reads it.
#[test]
fn reading_a_freshly_created_placeholder_still_hydrates() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let target = mnt.join("delta-created-then-read.bin");
    let _ = std::fs::remove_file(&target);

    let group = Group::new_pre_content().expect("pre-content group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::new(
        group.try_clone().expect("clone"),
        Canned(b"HYDRATED-CONTENT".to_vec()),
        Policy::permissive(),
        InFlight::new(),
    );

    assert!(place_while_answering(
        &group,
        &mut worker,
        &target,
        32,
        "cloud-2"
    ));

    // A separate process reads it, because a read by the answering process is
    // the deadlock this framework spends its time avoiding and would not
    // exercise the interception path anyway.
    let reader = unsafe { libc::fork() };
    if reader == 0 {
        let out = std::fs::read(&target).unwrap_or_default();
        unsafe { libc::_exit(if out.starts_with(b"HYDRATED") { 0 } else { 7 }) };
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut status = 0;
    let mut done = false;
    while Instant::now() < deadline {
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
        panic!("the read never completed");
    }

    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "a freshly created placeholder read as zeros: creating it left an ignore \
         mark behind, and this file is silently empty forever"
    );

    let _ = std::fs::remove_file(&target);
}

/// The rule's other half, which is what keeps it from being a hole.
///
/// `nlink == 0` alone also describes a genuine placeholder that someone unlinked
/// while holding it open. Allowing that without hydrating would hand the reader
/// zeros — so the construction mark, not the missing name, is what authorises
/// the shortcut.
#[test]
fn an_unlinked_placeholder_still_hydrates() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let target = mnt.join("unlinked-while-open.bin");
    let _ = std::fs::remove_file(&target);
    std::fs::write(&target, vec![0u8; 32]).expect("seed");

    // Dehydrate before marking, not after.
    //
    // Punching the hole is a write inside the mount, and once the mount is
    // marked the only process that could answer the event it fires is this one —
    // which is busy performing the write. The first version of this test had the
    // two lines the other way round and wedged the whole suite for 300s, which is
    // the trap in §6a-ter demonstrating itself on the test that exists to check
    // for it.
    hydrationd::placeholder::dehydrate(&target).expect("dehydrate");

    let group = Group::new_pre_content().expect("pre-content group");
    group.mark_mount(&mnt).expect("mark");

    let mut worker = Worker::new(
        group.try_clone().expect("clone"),
        Canned(b"HYDRATED-CONTENT".to_vec()),
        Policy::permissive(),
        InFlight::new(),
    );

    let reader = unsafe { libc::fork() };
    if reader == 0 {
        // Open first, then remove the name: from here the inode has nlink == 0
        // and no construction mark, which is exactly the case the rule must not
        // shortcut.
        let f = std::fs::File::open(&target);
        let _ = std::fs::remove_file(&target);
        let code = match f {
            Ok(mut f) => {
                use std::io::Read;
                let mut buf = Vec::new();
                let _ = f.read_to_end(&mut buf);
                if buf.starts_with(b"HYDRATED") {
                    0
                } else {
                    7
                }
            }
            Err(_) => 9,
        };
        unsafe { libc::_exit(code) };
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut status = 0;
    let mut done = false;
    while Instant::now() < deadline {
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
        panic!("the read never completed");
    }
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "a placeholder unlinked while open was served as zeros: the nameless rule \
         is being applied without checking the construction mark"
    );
}

fn has_xattr(p: &std::path::Path, name: &str) -> bool {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let n = std::ffi::CString::new(name).unwrap();
    (unsafe { libc::getxattr(c.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) }) >= 0
}

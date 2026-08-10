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
use hydration_protocol::FileId;

/// The name of a mechanism that was removed for being exploitable. Kept here so
/// the tests below can assert its absence.
const REMOVED_BUILDING_MARK: &str = "user.hydration.building";
use hydrationd::daemon::{FetchWhole, Worker};
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

impl FetchWhole for Canned {
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
    assert!(
        !hydrationd::placeholder::holds_data(&target).expect("SEEK_DATA"),
        "the placeholder holds content"
    );
    assert!(
        hydrationd::placeholder::has_mark(&target).unwrap_or(false),
        "the placeholder is not marked dehydrated — it would never be intercepted"
    );
    assert!(
        !has_xattr(&target, REMOVED_BUILDING_MARK),
        "the forgeable construction mark is back and reached the sync directory"
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

/// The attack that killed the first version of this rule.
///
/// The first rule was `nlink == 0 && carries the construction mark`, and the
/// mark was a `user.*` xattr — which any process sharing the file's uid can set,
/// and in this threat model the compromised sync daemon runs as exactly that
/// uid. So the mark was not evidence of anything. Measured attack:
///
///   1. attacker sets the construction mark on a real placeholder it owns
///   2. victim opens it and reads; the read blocks on the pre-content event
///   3. attacker unlinks it — not a content access, so it fires no event
///   4. worker sees nlink == 0 and the mark, allows without hydrating
///   5. victim's read returns zeros and it archives them as real content
///
/// It also bypassed the §6c policy gate entirely, because the shortcut ran
/// before it: a backup that policy would have refused with EIO — the safe
/// answer — was instead allowed with zeros.
///
/// The discriminator is now the file's size, which is not a claim anyone makes
/// but a property: at the moment the sizing event fires the inode is still
/// empty (measured), and an empty file has no content that could be served
/// wrongly. There is nothing here for an attacker to assert.
#[test]
fn a_forged_construction_mark_cannot_make_a_placeholder_serve_zeros() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let target = mnt.join("forged-building-mark.bin");
    let _ = std::fs::remove_file(&target);
    std::fs::write(&target, vec![0u8; 32]).expect("seed");
    hydrationd::placeholder::dehydrate(&target).expect("dehydrate");

    // Step 1, and the whole point: this needs no privilege at all.
    set_xattr(&target, REMOVED_BUILDING_MARK, b"1");
    assert!(
        has_xattr(&target, REMOVED_BUILDING_MARK),
        "could not forge the mark, so this test proves nothing"
    );

    let group = Group::new_pre_content().expect("pre-content group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::new(
        group.try_clone().expect("clone"),
        Canned(b"HYDRATED-CONTENT".to_vec()),
        Policy::permissive(),
        InFlight::new(),
    );

    let victim = unsafe { libc::fork() };
    if victim == 0 {
        use std::io::Read;
        let f = std::fs::File::open(&target);
        // Steps 2–3 collapsed into one process, which makes the race
        // deterministic rather than merely likely. The separate-attacker
        // version is the same event sequence with worse timing.
        let _ = std::fs::remove_file(&target);
        let code = match f {
            Ok(mut f) => {
                let mut buf = Vec::new();
                let _ = f.read_to_end(&mut buf);
                if buf.starts_with(b"HYDRATED") {
                    0 // hydrated: correct
                } else if buf.is_empty() {
                    1 // refused: safe, though not ideal
                } else {
                    7 // served zeros: the outcome this framework exists to prevent
                }
            }
            Err(_) => 1,
        };
        unsafe { libc::_exit(code) };
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut status = 0;
    let mut done = false;
    while Instant::now() < deadline {
        let _ = worker.run(Instant::now() + Duration::from_millis(200));
        if unsafe { libc::waitpid(victim, &mut status, libc::WNOHANG) } == victim {
            done = true;
            break;
        }
    }
    if !done {
        unsafe {
            libc::kill(victim, libc::SIGKILL);
            libc::waitpid(victim, &mut status, 0);
        }
        panic!("the read never completed");
    }

    assert_ne!(
        libc::WEXITSTATUS(status),
        7,
        "a forged xattr made the helper serve 32 zero bytes as though they were \
         the file's content — no privilege required"
    );
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "the read did not hydrate; the content was fetchable throughout"
    );
}

fn set_xattr(p: &std::path::Path, name: &str, v: &[u8]) {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let n = std::ffi::CString::new(name).unwrap();
    let rc = unsafe {
        libc::setxattr(
            c.as_ptr(),
            n.as_ptr(),
            v.as_ptr() as *const libc::c_void,
            v.len(),
            0,
        )
    };
    assert_eq!(rc, 0, "setxattr failed: {}", io::Error::last_os_error());
}

/// The other direction of the same attack, and the harder one.
///
/// The forged-mark test above covers *adding* an xattr the helper trusts. This
/// covers *removing* one: `user.hydration.dehydrated` is what tells the worker a
/// file is a placeholder, and it is owner-writable like every `user.*` attribute.
/// Strip it and the worker concludes the content is already present.
///
/// A same-uid attacker could overwrite the file with zeros directly, so this is
/// not a new capability — but it is a quieter one: no bytes are written, so the
/// mtime does not change, no upload is triggered, and no disk is used. What this
/// test pins down is the blast radius: the read must not become permanently
/// zero-serving, so that restoring the mark restores the file.
#[test]
fn stripping_the_placeholder_mark_does_not_permanently_disable_interception() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let target = mnt.join("stripped-mark.bin");
    let _ = std::fs::remove_file(&target);
    std::fs::write(&target, vec![0u8; 4096]).expect("seed");
    hydrationd::placeholder::dehydrate(&target).expect("dehydrate");

    let group = Group::new_pre_content().expect("pre-content group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::new(
        group.try_clone().expect("clone"),
        Canned(b"HYDRATED-CONTENT".to_vec()),
        Policy::permissive(),
        InFlight::new(),
    );

    // The attack: one xattr removal, no privilege, no race.
    remove_xattr(&target, "user.hydration.dehydrated");
    read_through(&mut worker, &target);

    // Restoring the mark must restore interception. If the first read installed
    // a surviving ignore mark, it will not — and the file is silently zeros
    // forever, with no further attacker involvement and nothing to observe.
    hydrationd::placeholder::mark_dehydrated(&target, true).expect("re-mark");
    let out = read_through(&mut worker, &target);
    assert!(
        out.starts_with(b"HYDRATED"),
        "restoring the placeholder mark did not restore interception: one xattr \
         removal disabled hydration for this file permanently"
    );

    let _ = std::fs::remove_file(&target);
}

/// Read `path` in a child while the worker answers, and return what it got.
fn read_through(worker: &mut Worker<Canned>, path: &std::path::Path) -> Vec<u8> {
    let out = path.with_extension("readback");
    let _ = std::fs::remove_file(&out);
    let child = unsafe { libc::fork() };
    if child == 0 {
        let got = std::fs::read(path).unwrap_or_default();
        // Written outside the marked mount, so recording the answer does not
        // itself fire an event that nobody is left to answer.
        let _ = std::fs::write(std::env::temp_dir().join("hydration-readback"), &got);
        unsafe { libc::_exit(0) };
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut status = 0;
    while Instant::now() < deadline {
        let _ = worker.run(Instant::now() + Duration::from_millis(200));
        if unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) } == child {
            return std::fs::read(std::env::temp_dir().join("hydration-readback"))
                .unwrap_or_default();
        }
    }
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, &mut status, 0);
    }
    panic!("the read never completed");
}

fn remove_xattr(p: &std::path::Path, name: &str) {
    let c = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()).unwrap();
    let n = std::ffi::CString::new(name).unwrap();
    let rc = unsafe { libc::removexattr(c.as_ptr(), n.as_ptr()) };
    assert_eq!(rc, 0, "removexattr failed: {}", io::Error::last_os_error());
}

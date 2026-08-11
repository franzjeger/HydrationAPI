//! The helper's proof that its mark still covers the path.
//!
//! Privileged, and unavoidably so: the thing under test is a mount being
//! replaced, which needs root and a real filesystem. The unit tests in
//! `selfcheck.rs` cover the parts that do not.
//!
//! What makes this worth a suite of its own is that the failure it guards
//! against is invisible from inside the process. A mark on a mount that has been
//! replaced is still a valid mark: `fanotify_mark` succeeded, the group is open,
//! the worker is answering — and every read at the path goes through a mount
//! nothing is watching and comes back as zeros. It happened on a real
//! deployment, twice, with `systemctl is-active` reporting active throughout.

use hydrationd::selfcheck::{reach, MountIdentity, Reach};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn env() -> Option<PathBuf> {
    let mount = PathBuf::from(std::env::var_os("HYDRATIOND_TEST_MOUNT")?);
    if !mount.is_dir() || unsafe { libc::geteuid() } != 0 {
        return None;
    }
    Some(mount)
}

fn skip(why: &str) {
    if std::env::var_os("HYDRATIOND_REQUIRE").is_some() {
        panic!("HYDRATIOND_REQUIRE is set but the test could not run: {why}");
    }
    eprintln!("SKIPPED: {why}");
}

/// A tmpfs of our own, so nothing here touches the mount the suite was given.
///
/// tmpfs is deliberate: no pre-content event is ever asked for, and the claim
/// under test is about mount identity, which no filesystem gets a say in.
fn mount_tmpfs(at: &Path) -> bool {
    let _ = std::fs::create_dir_all(at);
    Command::new("mount")
        .args(["-t", "tmpfs", "none"])
        .arg(at)
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn unmount(at: &Path) {
    for _ in 0..3 {
        let _ = Command::new("umount")
            .arg(at)
            .stderr(Stdio::null())
            .status();
    }
}

#[test]
fn a_replaced_mount_is_not_reported_as_the_one_that_was_marked() {
    let Some(mount) = env() else {
        return skip("needs root and HYDRATIOND_TEST_MOUNT");
    };
    let at = mount.join("selfcheck-replaced");
    // Cleared first, not only last: a previous run that panicked half way leaves
    // a tmpfs behind, and the next one then measures the wrong mount.
    unmount(&at);

    assert!(mount_tmpfs(&at), "could not mount a tmpfs to test with");
    let marked = MountIdentity::capture(&at).expect("mount id of a fresh mount");

    assert!(
        marked.still_current(&at).expect("re-read the same mount"),
        "an untouched mount was reported as replaced"
    );

    // Replaced the way a restart cycle does it: taken down and put straight back
    // at the same path, with nothing in between. This is where the small
    // `STATX_MNT_ID` is handed back unchanged — measured in `probes/mntid.c` —
    // so a check built on that id would pass here and protect nothing.
    unmount(&at);
    assert!(mount_tmpfs(&at), "could not remount");

    let verdict = marked.still_current(&at);
    unmount(&at);
    let _ = std::fs::remove_dir(&at);

    assert!(
        !verdict.expect("the path is mounted, so this must answer"),
        "a mount replaced at the same path was reported as the one that was marked"
    );
}

#[test]
fn a_vanished_mount_is_an_error_rather_than_an_all_clear() {
    let Some(mount) = env() else {
        return skip("needs root and HYDRATIOND_TEST_MOUNT");
    };
    let at = mount.join("selfcheck-vanished");
    unmount(&at);
    assert!(mount_tmpfs(&at), "could not mount a tmpfs to test with");
    let marked = MountIdentity::capture(&at).expect("mount id of a fresh mount");

    // The path itself goes, not just the mount on it. `Ok(true)` here would be
    // the helper deciding it is still protecting files it can no longer find;
    // the caller is written to treat an error as a failure, so an error is what
    // this has to produce.
    unmount(&at);
    let _ = std::fs::remove_dir(&at);

    assert!(
        marked.still_current(&at).is_err(),
        "a path that no longer exists was answered rather than refused"
    );
}

#[test]
fn a_privileged_run_can_decide_its_own_reach() {
    if env().is_none() {
        return skip("needs root and HYDRATIOND_TEST_MOUNT");
    }
    // As root, `/proc/1/ns/mnt` is readable, so the comparison the unprivileged
    // unit test cannot make is available here. The suite runs outside systemd
    // sandboxing, so the answer is decided — and `Unknown` would mean the check
    // has quietly stopped being able to answer at all, which is the state in
    // which it protects nothing while appearing to work.
    match reach() {
        Reach::Everyone => {}
        other => panic!("expected a decided reach in the privileged suite, got {other:?}"),
    }
}

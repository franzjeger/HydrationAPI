//! Exposure detection against a real kernel.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch HYDRATIOND_TEST_IMAGE=/path/to.img \
//!   cargo test -p hydrationd --test exposure
//! ```
//!
//! Needs the image as well as the mount, because the whole point is to create a
//! *second* mount of the same filesystem and check it is noticed.

use hydrationd::exposure::ExposureWatch;
use std::path::PathBuf;
use std::time::Duration;

fn env() -> Option<(PathBuf, PathBuf)> {
    let mount = PathBuf::from(std::env::var_os("HYDRATIOND_TEST_MOUNT")?);
    let image = PathBuf::from(std::env::var_os("HYDRATIOND_TEST_IMAGE")?);
    if !mount.is_dir() || !image.is_file() || unsafe { libc::geteuid() } != 0 {
        return None;
    }
    Some((mount, image))
}

/// Unmount and remove a bypass, whatever state it is in.
///
/// Called at the *start* of every test that makes one, not only at the end. A
/// test that panics half way leaves the bind mount behind, and the next run then
/// fails on a dirty starting point — which is exactly what happened here, and
/// cost a debugging round chasing a bug that was not there.
fn clear(bypass: &std::path::Path) {
    for _ in 0..3 {
        let _ = std::process::Command::new("umount")
            .arg(bypass)
            .stderr(std::process::Stdio::null())
            .status();
    }
    let _ = std::fs::create_dir_all(bypass);
}

fn skip(why: &str) {
    if std::env::var_os("HYDRATIOND_REQUIRE").is_some() {
        panic!("HYDRATIOND_REQUIRE is set but the test could not run: {why}");
    }
    eprintln!("SKIPPED: {why}");
}

/// A directory that is not a mount point is an error, never "healthy".
///
/// Reporting no exposures there would be the check telling the user they are
/// safe at the moment it stopped being able to tell.
#[test]
fn a_non_mountpoint_is_an_error_not_an_all_clear() {
    let Some((mount, _)) = env() else {
        skip("needs root, HYDRATIOND_TEST_MOUNT and HYDRATIOND_TEST_IMAGE");
        return;
    };
    let plain = mount.parent().unwrap().join("not-a-mount");
    let _ = std::fs::create_dir_all(&plain);

    let w = ExposureWatch::new(&plain).expect("watch");
    let err = w
        .current()
        .expect_err("a plain directory reported an all-clear it could not know");
    assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
}

/// A healthy machine reports nothing.
#[test]
fn our_own_mount_is_not_an_exposure() {
    let Some((mount, _)) = env() else {
        skip("needs root, HYDRATIOND_TEST_MOUNT and HYDRATIOND_TEST_IMAGE");
        return;
    };
    let w = ExposureWatch::new(&mount).expect("watch");
    assert_eq!(
        w.current().expect("current"),
        Vec::<String>::new(),
        "the sync mount reported itself as a way around itself"
    );
}

/// The bypass from §6.4a, created and then removed.
///
/// A bind mount of the sync directory elsewhere reaches the same files by a path
/// that hydration does not cover. It cannot be prevented; it must be reported.
#[test]
fn a_second_mount_of_the_same_files_is_reported() {
    let Some((mount, _image)) = env() else {
        skip("needs root, HYDRATIOND_TEST_MOUNT and HYDRATIOND_TEST_IMAGE");
        return;
    };
    let bypass = mount.parent().unwrap().join("exposure-bypass");
    clear(&bypass);

    let mut w = ExposureWatch::new(&mount).expect("watch");
    assert!(
        w.current().unwrap().is_empty(),
        "not a clean starting point"
    );

    let ok = std::process::Command::new("mount")
        .args([
            "--bind",
            &mount.to_string_lossy(),
            &bypass.to_string_lossy(),
        ])
        .status()
        .expect("mount --bind")
        .success();
    assert!(ok, "could not create the bypass mount");

    // The event is a trigger; the answer is the re-examined mount table.
    let mut seen = None;
    for _ in 0..20 {
        if let Some(list) = w.poll(Duration::from_millis(200)).expect("poll") {
            if !list.is_empty() {
                seen = Some(list);
                break;
            }
        }
    }

    let cleanup = std::process::Command::new("umount").arg(&bypass).status();

    let seen = seen.expect(
        "a second mount of the sync files was not reported — a reader could take \
         that path and be served zeros, with nothing to tell the user",
    );
    assert!(
        seen.iter().any(|m| m.contains("exposure-bypass")),
        "the wrong mount was reported: {seen:?}"
    );
    assert!(cleanup.is_ok());
}

/// After the bypass goes away, so does the warning.
///
/// A stale exposure is its own problem: a user told they are unsafe when they
/// are not learns to ignore the message.
#[test]
fn the_report_clears_when_the_bypass_is_removed() {
    let Some((mount, _)) = env() else {
        skip("needs root, HYDRATIOND_TEST_MOUNT and HYDRATIOND_TEST_IMAGE");
        return;
    };
    let bypass = mount.parent().unwrap().join("exposure-transient");
    clear(&bypass);

    let w = ExposureWatch::new(&mount).expect("watch");
    let _ = std::process::Command::new("mount")
        .args([
            "--bind",
            &mount.to_string_lossy(),
            &bypass.to_string_lossy(),
        ])
        .status();
    assert!(
        !w.current().unwrap().is_empty(),
        "the bypass was not visible while it existed"
    );

    let _ = std::process::Command::new("umount").arg(&bypass).status();
    assert!(
        w.current().unwrap().is_empty(),
        "the warning outlived the condition it was warning about"
    );
}

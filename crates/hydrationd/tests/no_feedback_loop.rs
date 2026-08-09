//! Change detection against a real kernel, and the loop it must not close.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test no_feedback_loop
//! ```

use hydrationd::placeholder;
use hydrationd::watch::{Change, Watcher};
use std::path::PathBuf;
use std::time::Duration;

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

/// A write by anyone else is a change worth uploading.
#[test]
fn a_local_edit_is_observed() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = mnt.join("edited-by-user.txt");
    let _ = std::fs::remove_file(&path);
    std::fs::write(&path, b"initial").expect("seed");

    // Ignore nobody: this is the ordinary case.
    let mut w = Watcher::new(&mnt, Vec::new()).expect("watcher");

    // Another process, so the write is not ours.
    let ok = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("printf edited > {}", path.display()))
        .status()
        .expect("writer")
        .success();
    assert!(ok, "the writer failed");

    let mut seen = Vec::new();
    for _ in 0..10 {
        seen.extend(w.poll(Duration::from_millis(300)).expect("poll"));
        if !seen.is_empty() {
            break;
        }
    }
    assert!(
        !seen.is_empty(),
        "a local edit produced no change event; nothing would ever upload"
    );
    assert!(
        seen.iter()
            .any(|o| o.what == Change::Closed || o.what == Change::Modified),
        "unexpected change kinds: {seen:?}"
    );
    let _ = std::fs::remove_file(&path);
}

/// The loop: our own hydration must not look like a local edit.
///
/// Without the pid filter, filling a placeholder queues an upload of the content
/// that was just downloaded — which uploads it, which changes it, which queues
/// another. Neither half is doing anything wrong on its own, which is exactly
/// why this only appears once they are connected.
#[test]
fn hydrating_a_file_is_not_reported_as_a_local_edit() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let path = mnt.join("hydrated-not-edited.bin");
    let _ = std::fs::remove_file(&path);
    let body = vec![b'h'; 2048];
    placeholder::create(&path, body.len() as u64, 0o644).expect("placeholder");

    // We are the process that will write the content, so our writes are ours.
    let me = unsafe { libc::getpid() };
    let mut w = Watcher::new(&mnt, vec![me]).expect("watcher");

    // Fill it the way the worker does: through an open fd, in this process.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open placeholder");
    placeholder::hydrate_fd(std::os::fd::AsFd::as_fd(&f), &body, body.len() as u64)
        .expect("hydrate");
    drop(f);

    let mut seen = Vec::new();
    for _ in 0..6 {
        seen.extend(w.poll(Duration::from_millis(300)).expect("poll"));
    }

    assert!(
        seen.is_empty(),
        "hydration was reported as a local edit ({seen:?}) — the content just \
         downloaded would be queued for upload, and uploading it would look like \
         another edit"
    );
    assert!(!placeholder::is_dehydrated(&path).unwrap());
    let _ = std::fs::remove_file(&path);
}

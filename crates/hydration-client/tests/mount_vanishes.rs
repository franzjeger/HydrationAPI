//! The sync mount goes away in the middle of a delta pass.
//!
//! Privileged, and unavoidably so: the thing under test is a mount being
//! detached, which needs root and a real filesystem.
//!
//! The startup guard and the once-a-round re-check both hold the mount at a
//! moment when nothing is being written. A pass is the other thing — on
//! 2026-08-12 a live rig applied 147,540 changes into a sync root whose mount
//! had been detached 300 seconds earlier by `hydrationd`'s own fail-closed exit,
//! producing a complete 37 MB placeholder tree in the btrfs subvolume underneath
//! the bare mountpoint. Every file in it reads back as zeros and looks exactly
//! like the real thing. The round's check had passed; the mount vanished
//! afterwards, and a pass of that size takes minutes.
//!
//! So the window is not a corner case, it is most of the pass, and a test that
//! only removes the mount *between* passes cannot see it. This removes the mount
//! partway through one, deterministically, from inside the placer's own call
//! sequence rather than from a racing thread.
//!
//! The detach is `MNT_DETACH`, because that is what `hydrationd` uses on the way
//! out (`bin/hydrationd.rs`). It matters here: a lazy detach makes the path
//! resolve to the directory underneath *immediately*, which is precisely the
//! state that turns every subsequent `place()` into a shadow file.

use hydration_client::delta::{self, Change, Materialise};
use hydration_client::place::TmpfilePlacer;
use hydration_client::store::Store;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// How many changes the pass carries, and how many land before the mount goes.
///
/// Small enough to stay fast, large enough that "the rest of the pass" is
/// unmistakably a tree and not an edge effect.
const CHANGES: usize = 400;
const DETACH_AFTER: usize = 20;

fn env() -> Option<PathBuf> {
    let mount = PathBuf::from(std::env::var_os("HYDRATION_TEST_MOUNT")?);
    if !mount.is_dir() || unsafe { libc::geteuid() } != 0 {
        return None;
    }
    Some(mount)
}

fn skip(why: &str) {
    if std::env::var_os("HYDRATION_REQUIRE").is_some() {
        panic!("HYDRATION_REQUIRE is set but the test could not run: {why}");
    }
    eprintln!("SKIPPED: {why}");
}

/// A tmpfs of our own, so nothing here touches the mount the suite was given.
///
/// Measured before relying on it: tmpfs on this kernel supports `O_TMPFILE`,
/// `user.*` extended attributes and `ftruncate`, which is everything
/// `TmpfilePlacer` needs. Without all three the placer would fail for its own
/// reasons and the test would report "no shadow tree" while measuring nothing.
fn mount_tmpfs(at: &Path) -> bool {
    // A previous run that panicked between the mount and the detach leaves one
    // here. Mounting over it would stack a second tmpfs and the walk afterwards
    // would be looking at the first, which still counts as an empty directory —
    // a test that passes because it is measuring the wrong filesystem. Detach
    // until nothing is left.
    while is_mounted(at) {
        if detach(at).is_err() {
            break;
        }
    }
    let _ = std::fs::remove_dir_all(at);
    let _ = std::fs::create_dir_all(at);
    Command::new("mount")
        .args(["-t", "tmpfs", "none"])
        .arg(at)
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn detach(at: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(at.as_os_str().as_bytes()).unwrap();
    if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Everything reachable under `dir`, as paths relative to it.
///
/// Used on the *bare* directory after the detach, so anything it returns is a
/// file that exists somewhere nothing can ever hydrate it.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push(e.path());
            } else if let Ok(rel) = e.path().strip_prefix(dir) {
                out.push(rel.to_path_buf());
            }
        }
    }
    out
}

/// The real placer, with the mount pulled out from under it partway through.
///
/// Deterministic on purpose. A thread that unmounts after a sleep reproduces the
/// same failure but only sometimes, and a test that fails only sometimes is one
/// that gets re-run rather than read.
struct Vanishing {
    inner: TmpfilePlacer,
    at: PathBuf,
    calls: usize,
    detached: bool,
}

impl Materialise for Vanishing {
    fn place(
        &mut self,
        path: &Path,
        size: u64,
        cloud_id: &str,
        etag: Option<&str>,
    ) -> io::Result<()> {
        self.calls += 1;
        if self.calls == DETACH_AFTER && !self.detached {
            detach(&self.at).expect("detach the sync mount mid-pass");
            self.detached = true;
        }
        self.inner.place(path, size, cloud_id, etag)
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        self.inner.remove(path)
    }

    /// Forwarded, not defaulted. The blanket `Ok(true)` is right for the doubles
    /// that have no mount to lose, and taking it here would mean the wrapper
    /// quietly disabled the very thing under test — a test that passes because
    /// it stopped asking the question.
    fn root_still_current(&self) -> io::Result<bool> {
        self.inner.root_still_current()
    }
}

#[test]
fn a_pass_writes_nothing_into_the_bare_directory_when_the_mount_goes_away() {
    let Some(base) = env() else {
        return skip("needs root and HYDRATION_TEST_MOUNT");
    };
    let root = base.join("vanishing-root");
    let _ = std::fs::remove_dir_all(&root);
    if !mount_tmpfs(&root) {
        return skip("could not mount a tmpfs of our own");
    }

    // The bare directory has to start empty, or a file found afterwards proves
    // nothing about who put it there.
    {
        let changes: Vec<Change> = (0..CHANGES)
            .map(|i| Change::Upserted {
                cloud_id: format!("obj-{i}"),
                // Spread across directories, because the tree the incident left
                // behind was a tree: `create_dir_all` is part of what runs on
                // the bare path, not only the file creation.
                path: format!("d{}/file-{i}.bin", i % 8),
                size: 4096,
                etag: Some(format!("v{i}")),
            })
            .collect();

        let mut store = Store::new();
        let waiting = HashSet::new();
        let mut vanishing = Vanishing {
            inner: TmpfilePlacer::new(&root).expect("open the sync root"),
            at: root.clone(),
            calls: 0,
            detached: false,
        };
        let applied = delta::apply(&root, &changes, &mut store, &waiting, &mut vanishing);
        assert!(
            vanishing.detached,
            "the mount was never detached; the test measured an ordinary pass"
        );
        // Not asserted as an error. `hydrationd` detaching the mount is a
        // deliberate fail-closed action, so the pass meeting it is expected
        // behaviour and has to end in something a caller can act on.
        let applied = applied.expect("a vanished mount is not an io error for the pass");
        eprintln!(
            "pass after detach: +{} ~{} failed {} stopped {:?}",
            applied.created,
            applied.updated,
            applied.failed.len(),
            applied.stopped
        );
        assert_eq!(
            applied.stopped,
            Some(delta::Stopped::MountChanged),
            "the pass ran to the end without noticing the mount had gone. Even \
             with the placeholders landing somewhere harmless, a pass that does \
             not stop keeps a whole feed's worth of changes moving against a \
             root the user cannot reach, and reports success for it"
        );
        assert!(
            applied.retryable,
            "a stopped pass left the cursor free to advance, so the changes it \
             never applied would never be offered again"
        );
        // The stop has to come promptly. Anything else and "stop cleanly" means
        // "finish the pass and mention it afterwards" — which is what the old
        // code did.
        assert!(
            applied.created < DETACH_AFTER + 4,
            "the pass applied {} changes after the mount went away; the check \
             is meant to be per change, not per pass",
            applied.created - DETACH_AFTER.min(applied.created)
        );
    }

    // The mount is gone; this path is the bare directory that was underneath it.
    assert!(
        !is_mounted(&root),
        "the tmpfs is still mounted, so the walk below would be looking at it \
         rather than at the directory underneath"
    );
    let shadow = walk(&root);
    let n = shadow.len();
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(
        n,
        0,
        "the pass wrote {n} files into the bare directory underneath the \
         detached mount — a shadow tree that reads back as zeros and that \
         nothing can ever hydrate. First few: {:?}",
        shadow.iter().take(5).collect::<Vec<_>>()
    );
}

fn is_mounted(p: &Path) -> bool {
    hydration_client::mount::is_mount_point(p).unwrap_or(false)
}

/// The same detach, with the stop deliberately switched off.
///
/// The test above passes if *either* half of the fix works, and it is the wrong
/// half that would go unnoticed: the pass stops before it reaches a single
/// `place()` after the detach, so the descriptor pinning is never asked to
/// prove anything. A test that cannot fail for the reason it claims is the trap
/// CLAUDE.md names, and this is the same failure wired so it can.
///
/// `root_still_current` here answers `Ok(true)` forever — which is not a
/// contrived state. It is the trait's own default, so any `Materialise` that
/// does not override it, and any future wrapper that forgets to forward it,
/// arrives at exactly this. What must hold then is the property that does not
/// depend on noticing anything in time: **the placer cannot write outside the
/// filesystem it opened, whatever the path has come to mean.**
struct Oblivious(Vanishing);

impl Materialise for Oblivious {
    fn place(
        &mut self,
        path: &Path,
        size: u64,
        cloud_id: &str,
        etag: Option<&str>,
    ) -> io::Result<()> {
        self.0.place(path, size, cloud_id, etag)
    }

    fn remove(&mut self, path: &Path) -> io::Result<()> {
        self.0.remove(path)
    }

    // Deliberately not forwarded.
}

#[test]
fn a_placer_that_never_notices_still_cannot_write_outside_its_own_filesystem() {
    let Some(base) = env() else {
        return skip("needs root and HYDRATION_TEST_MOUNT");
    };
    let root = base.join("oblivious-root");
    let _ = std::fs::remove_dir_all(&root);
    if !mount_tmpfs(&root) {
        return skip("could not mount a tmpfs of our own");
    }

    let changes: Vec<Change> = (0..CHANGES)
        .map(|i| Change::Upserted {
            cloud_id: format!("obj-{i}"),
            path: format!("d{}/file-{i}.bin", i % 8),
            size: 4096,
            etag: Some(format!("v{i}")),
        })
        .collect();

    let mut store = Store::new();
    let waiting = HashSet::new();
    let mut mat = Oblivious(Vanishing {
        inner: TmpfilePlacer::new(&root).expect("open the sync root"),
        at: root.clone(),
        calls: 0,
        detached: false,
    });
    let applied = delta::apply(&root, &changes, &mut store, &waiting, &mut mat)
        .expect("a vanished mount is not an io error for the pass");
    assert!(mat.0.detached, "the mount was never detached");
    assert_eq!(
        applied.stopped, None,
        "the pass stopped after all, so this test measured the same thing as \
         the one above rather than the descriptor"
    );

    let shadow = walk(&root);
    let n = shadow.len();

    // Both halves of the discriminator, because an empty directory on its own is
    // ambiguous: a placer that failed every call would leave one too, and would
    // look identical to a placer that wrote all 400 files to the right place.
    assert_eq!(
        applied.created,
        CHANGES,
        "only {} of {CHANGES} placeholders were created ({} failed) — so the \
         empty directory below proves nothing about where bytes went, only that \
         they did not go anywhere. First failure: {:?}",
        applied.created,
        applied.failed.len(),
        applied.failed.first()
    );
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(
        n,
        0,
        "all {CHANGES} placeholders were created and {n} of them landed in the \
         bare directory underneath the detached mount. The descriptor did not \
         pin the destination. First few: {:?}",
        shadow.iter().take(5).collect::<Vec<_>>()
    );
}

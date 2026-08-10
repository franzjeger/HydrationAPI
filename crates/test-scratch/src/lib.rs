//! Which filesystem the tests run on — a runtime choice, not a build-time one.
//!
//! Most of this workspace's tests are assertions about filesystem behaviour, so
//! the filesystem they run on is part of the test, not part of the environment.
//! Two of them disagree today: on ext4 with a small inode a placeholder's
//! extended attributes spill into a block of their own and an empty file is
//! charged for it, and on btrfs they do not (§8z). A suite that only ever runs
//! on one of them is measuring one filesystem and reporting on all of them.
//!
//! The obvious way to point the tests elsewhere does not work. `CARGO_TARGET_TMPDIR`
//! is a **compile-time** macro, and cargo sets it itself from the target
//! directory; exporting it before `cargo test` is silently ignored, measured:
//!
//! ```text
//!   CARGO_TARGET_TMPDIR=/mnt/elsewhere cargo test   ->  .../tt/target/tmp
//!   CARGO_TARGET_DIR=/mnt/elsewhere cargo test      ->  /mnt/elsewhere/tmp
//! ```
//!
//! The first is the natural way to write a filesystem matrix in CI, and it
//! produces four green legs that all ran on the same filesystem. That is worse
//! than having no matrix, because it looks like coverage.
//!
//! `CARGO_TARGET_DIR` does work, but it moves the whole build onto the test
//! filesystem: a full rebuild per matrix leg, a build cache that no longer
//! matches, and an image big enough to hold the compiler's output rather than
//! the test data. The build is not what is being tested.
//!
//! So the choice is made here instead, at run time, by `HYDRATION_TEST_DIR`.
//!
//! ## Why this is its own crate
//!
//! Because it is a test helper, and test helpers do not belong in the crates
//! that ship. A probe placed in a runtime crate is available to production code
//! that has no business calling it, and the next person to need something
//! nearby finds it and uses it — which is how a block-counting helper that was
//! documented as "not a placeholder test" would have ended up being used as
//! one. This crate is a `dev-dependency` everywhere and is not published.

use std::path::{Path, PathBuf};

/// The environment variable that decides which filesystem the tests use.
pub const TEST_DIR: &str = "HYDRATION_TEST_DIR";

/// The root the tests write under: `HYDRATION_TEST_DIR` if set, `fallback`
/// otherwise. Neither created nor emptied — for callers that manage their own
/// layout underneath it, such as a shared directory holding one file per test.
pub fn base(fallback: &str) -> PathBuf {
    std::env::var_os(TEST_DIR)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(fallback))
}

/// A fresh, empty directory for one test.
///
/// `fallback` is the crate's own `env!("CARGO_TARGET_TMPDIR")`, expanded at the
/// call site because the macro reads the environment of whatever crate it is
/// compiled in. It is used when `HYDRATION_TEST_DIR` is unset, which is the
/// ordinary developer case and keeps the scratch space on the same real disk as
/// the target directory.
///
/// The directory is removed and recreated, so a test never inherits the residue
/// of the last run — including a placeholder from a run that crashed, which
/// would make the next run's first assertion pass for the wrong reason.
pub fn scratch(fallback: &str, name: &str) -> PathBuf {
    let d = base(fallback).join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d)
        .unwrap_or_else(|e| panic!("could not create scratch directory {}: {e}", d.display()));
    d
}

/// What an empty file costs on the filesystem under `dir`, in 512-byte units.
///
/// Zero on btrfs, xfs and ext4 with a roomy inode; one filesystem block wherever
/// the extended attributes do not fit in the inode. Probed rather than assumed,
/// because the answer depends on the filesystem, its inode size *and* its block
/// size — `mkfs.ext4` picks the block size from the filesystem size, so the same
/// configuration gives a floor of 2 on a small scratch image and 8 on a real
/// volume. A constant here is wrong even on the filesystem it was measured on.
///
/// This is an **upper bound to assert against**, never a test for whether a file
/// holds content: a placeholder truncated to its object's size reports the same
/// count as an empty one, so the number cannot tell the two apart. Ask
/// `holds_data` for that.
pub fn empty_file_floor(dir: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    // Named per process: several test binaries run at once, and a shared probe
    // name means one test deleting the file another just created.
    let probe = dir.join(format!(".floor-probe-{}", std::process::id()));
    let _ = std::fs::write(&probe, b"");
    let blocks = std::fs::metadata(&probe).map(|m| m.blocks()).unwrap_or(0);
    let _ = std::fs::remove_file(&probe);
    blocks
}

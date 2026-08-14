//! Placeholder behaviour, against a real filesystem.
//!
//! An integration test rather than a unit one for a specific reason: hole
//! punching is a filesystem feature, and `/tmp` on a typical machine is tmpfs,
//! where it does not behave the way ext4/btrfs/xfs do. `CARGO_TARGET_TMPDIR`
//! puts the scratch directory under `target/`, on the real disk — so a pass here
//! means the thing works, not that it was never exercised.

use hydrationd::placeholder::*;
use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

fn scratch(name: &str) -> PathBuf {
    // Shared directory, one file per test, so this must not empty it — see
    // `test_scratch::scratch` for the callers that do want that.
    let d = test_scratch::base(env!("CARGO_TARGET_TMPDIR")).join("placeholder");
    fs::create_dir_all(&d).expect("scratch dir");
    let p = d.join(name);
    let _ = fs::remove_file(&p);
    p
}

/// Guards the whole premise: if the scratch filesystem cannot punch holes, every
/// other test here would pass vacuously.
#[test]
fn the_scratch_filesystem_can_actually_punch_holes() {
    let p = scratch("premise.bin");
    create(&p, 65536, 0o644).expect("create");
    hydrate(&p, &vec![b'a'; 65536], 65536).expect("hydrate");
    assert!(
        hydrationd::placeholder::holds_data(&p).expect("SEEK_DATA"),
        "a filled file reports no blocks — this filesystem is not telling the truth \
         about allocation, and the rest of these tests would prove nothing"
    );
    dehydrate(&p).expect("dehydrate");
    assert!(
        !hydrationd::placeholder::holds_data(&p).expect("SEEK_DATA"),
        "punching a hole did not free the blocks — is CARGO_TARGET_TMPDIR on tmpfs?"
    );
}

#[test]
fn a_placeholder_has_size_and_holds_no_data() {
    let p = scratch("basic.bin");
    create(&p, 65536, 0o644).expect("create");

    let md = fs::metadata(&p).expect("stat");
    assert_eq!(md.len(), 65536, "a placeholder must report the real size");
    assert!(
        !hydrationd::placeholder::holds_data(&p).expect("SEEK_DATA"),
        "a placeholder reported {} blocks for content it does not hold; du would \
         claim disk that is not in use",
        md.blocks()
    );
}

#[test]
fn mode_is_a_real_mode() {
    let p = scratch("mode.sh");
    create(&p, 10, 0o755).expect("create");
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o755,
        "the exec bit is the kernel's to keep, and it did not"
    );
}

#[test]
fn a_short_fetch_is_refused_and_leaves_the_placeholder_alone() {
    let p = scratch("short.bin");
    create(&p, 4096, 0o644).expect("create");

    let err = hydrate(&p, &vec![b'x'; 2048], 4096)
        .expect_err("a fetch of 2048 bytes must not fill a 4096-byte placeholder");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    assert_eq!(fs::metadata(&p).unwrap().len(), 4096, "the size changed");
    assert!(
        is_dehydrated(&p).unwrap(),
        "the placeholder gained content from a fetch that was refused — it now \
         looks hydrated and is not"
    );
}

#[test]
fn a_matching_fetch_fills_it() {
    let p = scratch("good.bin");
    create(&p, 4096, 0o644).expect("create");
    hydrate(&p, &vec![b'y'; 4096], 4096).expect("hydrate");

    assert_eq!(fs::read(&p).unwrap(), vec![b'y'; 4096]);
    assert!(!is_dehydrated(&p).unwrap(), "still reports no content");
}

#[test]
fn dehydrate_keeps_size_and_mode_and_drops_the_content() {
    let p = scratch("round.bin");
    create(&p, 8192, 0o750).expect("create");
    hydrate(&p, &vec![b'z'; 8192], 8192).expect("hydrate");
    assert!(!is_dehydrated(&p).unwrap());

    dehydrate(&p).expect("dehydrate");
    let md = fs::metadata(&p).unwrap();
    assert_eq!(md.len(), 8192, "size lost across dehydration");
    assert_eq!(md.permissions().mode() & 0o777, 0o750, "mode lost");
    assert!(
        !hydrationd::placeholder::holds_data(&p).expect("SEEK_DATA"),
        "still occupying disk"
    );
}

/// The identity half of §5.1, at this layer: nothing about dehydrating or
/// rehydrating a file may change which file it is.
#[test]
fn the_inode_survives_a_full_round_trip() {
    let p = scratch("identity.bin");
    let id = create(&p, 2048, 0o644).expect("create");
    hydrate(&p, &vec![b'q'; 2048], 2048).expect("hydrate");
    dehydrate(&p).expect("dehydrate");
    hydrate(&p, &vec![b'q'; 2048], 2048).expect("rehydrate");

    assert_eq!(
        id_of(&p).unwrap(),
        id,
        "the file changed identity across a hydrate/dehydrate cycle — a reader \
         holding it saw it become a different file"
    );
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A completed fill records when it happened, for the auto-eviction recency
/// ranking. A fresh placeholder has no such time — the signal is set at
/// acquisition, not creation — and the completed fill stamps it with now.
#[test]
fn a_completed_hydration_records_hydrated_at() {
    let p = scratch("hydrated-at.bin");
    create(&p, 4096, 0o644).expect("create");
    assert!(
        hydration_protocol::hydrated::at(&p).unwrap().is_none(),
        "a placeholder that was never filled already carries a hydration time"
    );

    let before = now_secs();
    hydrate(&p, &vec![b'h'; 4096], 4096).expect("hydrate");
    let after = now_secs();

    let at = hydration_protocol::hydrated::at(&p)
        .expect("getxattr")
        .expect("a completed fill must record hydrated_at");
    assert!(
        before <= at && at <= after,
        "hydrated_at {at} is not within the fill window [{before}, {after}]"
    );
}

/// A partial fill (`settle_range`) leaves the file a marked placeholder — still
/// holes, not yet an eviction candidate — so it must NOT record a hydration
/// time. Recording it there would let the selector treat a half-filled file as
/// resident.
#[test]
fn a_partial_fill_records_no_hydrated_at() {
    use std::os::fd::AsFd;
    let p = scratch("partial-at.bin");
    create(&p, 8192, 0o644).expect("create");

    let f = fs::OpenOptions::new().write(true).open(&p).expect("open");
    // Fill only the first half, then settle that range — the streamed-partial
    // path, which deliberately keeps the placeholder mark.
    write_at(f.as_fd(), &vec![b'p'; 4096], 0).expect("write range");
    settle_range(f.as_fd()).expect("settle_range");
    drop(f);

    assert!(
        is_dehydrated(&p).unwrap(),
        "settle_range cleared the placeholder mark — that is finish_hydration's job"
    );
    assert!(
        hydration_protocol::hydrated::at(&p).unwrap().is_none(),
        "a partial fill recorded a hydration time; the file is still a placeholder"
    );
}

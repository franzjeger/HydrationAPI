//! The backup manifest: §6d, against a real filesystem.
//!
//! An integration test because hole punching and `st_blocks` are filesystem
//! behaviour, and `CARGO_TARGET_TMPDIR` is on a real disk rather than tmpfs.

use hydration_client::manifest::{self, BackupPolicy, Manifest, MANIFEST_NAME};
use hydration_client::store;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

fn scratch(name: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("manifest")
        .join(name);
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).expect("scratch");
    d
}

/// A placeholder: right size, no content, known to the cloud, and *marked*.
///
/// The mark is not decoration — it is what "is a placeholder" means, because
/// neither size nor `st_blocks` can tell a dehydrated file from a new one or a
/// legitimately sparse one.
fn placeholder(dir: &Path, name: &str, size: u64, id: &str) -> PathBuf {
    let p = dir.join(name);
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let f = fs::File::create(&p).unwrap();
    f.set_len(size).unwrap();
    store::set_xattr(&p, hydration_protocol::xattr::DEHYDRATED, b"1").unwrap();
    store::set_xattr(&p, store::XATTR_ID, id.as_bytes()).unwrap();
    store::set_xattr(&p, store::XATTR_ETAG, b"etag-1").unwrap();
    p
}

/// A dehydrated file small enough that btrfs stores it inline, so it still
/// reports blocks. The case a `st_blocks == 0` predicate silently omits.
fn small_placeholder(dir: &Path, name: &str, id: &str) -> PathBuf {
    let p = placeholder(dir, name, 21, id);
    fs::write(&p, b"#!/bin/sh\necho hello\n").unwrap();
    store::set_xattr(&p, hydration_protocol::xattr::DEHYDRATED, b"1").unwrap();
    p
}

#[test]
fn it_lists_what_the_backup_will_not_contain() {
    let dir = scratch("basic");
    placeholder(&dir, "report.pdf", 4096, "cloud-1");
    placeholder(&dir, "sub/deep.bin", 8192, "cloud-2");
    fs::write(dir.join("local.txt"), b"content that is really here").unwrap();

    let m = Manifest::build(&dir).expect("build");
    let paths: Vec<&str> = m.entries.iter().map(|e| e.path.as_str()).collect();

    assert_eq!(
        paths,
        vec!["report.pdf", "sub/deep.bin"],
        "the manifest should list exactly the files whose content is not on disk"
    );
    assert_eq!(m.entries[0].size, 4096, "the real size has to be recorded");
    assert_eq!(m.entries[0].cloud_id, "cloud-1");
}

/// The case a blocks-based predicate loses, and the one users notice first.
///
/// btrfs stores small files inline, so a dehydrated script still reports
/// allocated blocks. Judging by blocks would leave every small text file out of
/// the manifest — and small text files are what a restoring user misses first.
#[test]
fn a_small_dehydrated_file_is_listed_even_though_it_reports_blocks() {
    let dir = scratch("inline");
    let p = small_placeholder(&dir, "run.sh", "cloud-7");
    assert!(
        fs::metadata(&p).unwrap().blocks() > 0,
        "this filesystem did not inline the file, so the test proves nothing"
    );

    let m = Manifest::build(&dir).expect("build");
    assert_eq!(
        m.entries
            .iter()
            .map(|e| e.path.as_str())
            .collect::<Vec<_>>(),
        vec!["run.sh"],
        "a dehydrated file was omitted because it still reported blocks"
    );
}

/// Dehydrated with no cloud object: nothing can restore it, so it is named
/// rather than quietly dropped from the count.
#[test]
fn a_dehydrated_file_with_no_cloud_object_is_reported_as_unrecoverable() {
    let dir = scratch("orphan");
    let p = dir.join("orphan.bin");
    fs::File::create(&p).unwrap().set_len(64).unwrap();
    store::set_xattr(&p, hydration_protocol::xattr::DEHYDRATED, b"1").unwrap();

    let m = Manifest::build(&dir).expect("build");
    assert!(m.entries.is_empty(), "it was listed as recoverable");
    assert_eq!(m.unrecoverable, vec!["orphan.bin".to_string()]);
    assert!(
        m.render().contains("UNRECOVERABLE"),
        "the file the user cannot get back is not mentioned: {}",
        m.render()
    );
}

/// A file the cloud has never heard of has no remote copy to point at, so
/// listing it would tell a restoring user to fetch something that is not there.
#[test]
fn a_local_only_empty_file_is_not_listed() {
    let dir = scratch("local-only");
    let p = dir.join("empty.log");
    fs::File::create(&p).unwrap().set_len(4096).unwrap();
    // Deliberately no cloud id.

    let m = Manifest::build(&dir).expect("build");
    assert!(
        m.is_empty(),
        "a sparse local file with no remote copy was listed as recoverable: {:?}",
        m.entries
    );
}

/// The whole point: the manifest must be in the backup, so it must have content.
#[test]
fn the_manifest_itself_is_never_a_placeholder() {
    let dir = scratch("dense");
    placeholder(&dir, "a.bin", 1024, "cloud-1");

    let m = Manifest::build(&dir).expect("build");
    let written = m.write(&dir).expect("write");

    let md = fs::metadata(&written).unwrap();
    assert!(md.len() > 0, "the manifest is empty");
    assert!(
        md.blocks() > 0,
        "the manifest occupies no disk, so a backup that skips empty files skips \
         the one file that says what it is missing"
    );

    // And it does not describe itself.
    let again = Manifest::build(&dir).expect("rebuild");
    assert!(
        !again.entries.iter().any(|e| e.path.contains(MANIFEST_NAME)),
        "the manifest listed itself"
    );
}

/// Written by rename, so a backup reading it concurrently never sees half a file.
#[test]
fn writing_leaves_no_partial_file_behind() {
    let dir = scratch("atomic");
    placeholder(&dir, "a.bin", 512, "cloud-1");
    Manifest::build(&dir).unwrap().write(&dir).unwrap();
    Manifest::build(&dir).unwrap().write(&dir).unwrap();

    let leftovers: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".tmp"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temp files left behind: {leftovers:?}"
    );
}

/// A restoring user reads this without the source checked out.
#[test]
fn the_rendered_file_says_what_it_is_for() {
    let dir = scratch("render");
    placeholder(&dir, "holiday.raw", 99, "cloud-9");
    let text = Manifest::build(&dir).unwrap().render();

    assert!(text.contains("NOT in your backup"), "{text}");
    assert!(
        text.contains("re-sync"),
        "no hint about how to recover: {text}"
    );
    assert!(
        text.contains("holiday.raw") && text.contains("cloud-9"),
        "{text}"
    );
}

/// §6d: the number has to be sayable, and has to be right.
#[test]
fn the_status_line_names_the_number() {
    let line = manifest::status_line(BackupPolicy::Exclude, 412);
    assert!(line.contains("412"), "{line}");
    assert!(
        line.contains(MANIFEST_NAME),
        "the user is told a number but not where to look: {line}"
    );

    assert!(
        !manifest::status_line(BackupPolicy::Exclude, 0).contains('0'),
        "with nothing excluded the line should not read like a count"
    );

    // The other policies say something different, because they mean something
    // different — a client must not be able to show the wrong one.
    assert!(manifest::status_line(BackupPolicy::Hydrate, 5).contains("downloaded"));
    assert!(manifest::status_line(BackupPolicy::Deny, 5).contains("refused"));
}

#[test]
fn nodump_can_be_set_and_cleared() {
    let dir = scratch("nodump");
    let p = placeholder(&dir, "x.bin", 128, "cloud-1");

    manifest::set_nodump(&p, true).expect("set nodump");
    let out = std::process::Command::new("lsattr")
        .arg(&p)
        .output()
        .expect("lsattr");
    // The flags field only. Asserting over the whole line matched the scratch
    // directory's own name ("nodump") and passed with the flag absent — a test
    // that could not fail.
    let s = String::from_utf8_lossy(&out.stdout);
    let flags = s.split_whitespace().next().unwrap_or("");
    assert!(flags.contains('d'), "nodump not visible in lsattr: {s}");

    manifest::set_nodump(&p, false).expect("clear nodump");
    let out = std::process::Command::new("lsattr")
        .arg(&p)
        .output()
        .unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    let flags = s.split_whitespace().next().unwrap_or("");
    assert!(!flags.contains('d'), "nodump not cleared: {s}");
}

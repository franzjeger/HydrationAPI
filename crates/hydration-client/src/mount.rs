//! Is the sync root actually a mount?
//!
//! The daemon materialises placeholders into whatever directory it is given, and
//! a directory is not enough. §6.4a already establishes why: a directory mark
//! delivers no pre-content events at all, so a sync root that is not its own
//! mount can never be protected — and a placeholder that cannot be hydrated is
//! not a file with its content elsewhere, it is a file that reads as zeros.
//!
//! This is not hypothetical. On a real deployment the daemon started while its
//! mount was down and wrote a complete tree into the directory underneath: 145,711
//! files, 102 GB of apparent size, 37 MB of actual content, every byte of it
//! zero. It looked exactly like the real thing. The user found out by opening an
//! archive from it and being told it was corrupt — and the archive was fine; the
//! zeros were what `gzip`'s CRC had noticed. Any backup or indexer walking that
//! tree would have been told the same story with no CRC to catch it.
//!
//! # Why `/proc/self/mountinfo` and not `st_dev`
//!
//! Comparing a directory's device number against its parent's is the classic
//! check, and on the layout this project *recommends* it is wrong. Measured, on
//! btrfs:
//!
//! ```text
//! /mnt/scratch          st_dev=142  parent=36   -> differs, and it is a mount
//! /mnt/scratch/subvol   st_dev=143  parent=142  -> differs, and it is NOT a mount
//! /mnt/scratch/plaindir st_dev=142  parent=142  -> same
//! ```
//!
//! Every btrfs subvolume gets its own anonymous device whether or not anything
//! is mounted on it. `deploy/README.md` tells the reader to make the sync root a
//! subvolume, so `st_dev` would answer "yes, a mount" for the one case this
//! check exists to refuse: a subvolume that was never mounted. `exposure.rs`
//! records the same trap from the other side.
//!
//! The mount table has no such ambiguity, and it costs one read of a file that
//! is a few kilobytes.

use std::io;
use std::path::Path;

/// Whether something is mounted at exactly this path, in this namespace.
///
/// A path that does not appear is not a mount, which is the answer the caller
/// needs. Errors are only ever the mount table itself being unreadable, and are
/// passed up rather than folded into `false`: "there is no mount here" and "I
/// could not find out" lead to the same refusal but not to the same message.
pub fn is_mount_point(path: &Path) -> io::Result<bool> {
    let target = path.to_string_lossy();
    let info = std::fs::read_to_string("/proc/self/mountinfo")?;
    Ok(info
        .lines()
        .any(|line| mount_point_of(line).as_deref() == Some(&*target)))
}

/// The mount point field of one `mountinfo` line, unescaped.
///
/// Returned as an owned comparison rather than a slice because unescaping may
/// allocate; the borrow checker gets in the way of a cleaner signature here and
/// the line count is in the dozens.
fn mount_point_of(line: &str) -> Option<String> {
    // `id parent major:minor root point opts [optional...] - fstype src super`
    //
    // Split at the separator first. The optional fields are variable in number —
    // that is the entire reason ` - ` exists — so counting from the left past
    // field 6 is the only safe way to read anything after them, and counting
    // from the right without it is guesswork.
    let (left, _) = line.split_once(" - ")?;
    let point = left.split_whitespace().nth(4)?;
    Some(unescape(point))
}

/// `/proc/self/mountinfo` escapes space, tab, newline and backslash as octal.
///
/// A sync root under `~/My Documents` is an ordinary thing to want, and without
/// this it would never match its own line — the check would refuse a mount that
/// is perfectly real, which is a different bug with the same symptom.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Some(c) = std::str::from_utf8(&b[i + 1..i + 4])
                .ok()
                .and_then(|o| u8::from_str_radix(o, 8).ok())
            {
                out.push(c as char);
                i += 4;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_is_a_mount_and_a_directory_under_it_is_not() {
        assert!(is_mount_point(Path::new("/")).unwrap());
        // `/proc` is a mount on every Linux system this runs on, and a directory
        // inside it is not — a pair rather than a single case, so a function that
        // always answered the same way could not pass.
        assert!(is_mount_point(Path::new("/proc")).unwrap());
        assert!(!is_mount_point(Path::new("/proc/self")).unwrap());
    }

    #[test]
    fn a_path_that_does_not_exist_is_not_a_mount() {
        assert!(!is_mount_point(Path::new("/no-such-path-9d3f2a")).unwrap());
    }

    #[test]
    fn a_mount_point_field_is_read_past_the_optional_fields() {
        // The shape that breaks a naive parser: two optional fields, and a
        // mount point that would be picked up by counting from the right.
        let line = "31 64 0:34 /@onedrive /home/frank/OneDrive rw,noatime \
                    shared:563 master:526 - btrfs /dev/nvme1n1p2 rw,subvol=/@onedrive";
        assert_eq!(
            mount_point_of(line).as_deref(),
            Some("/home/frank/OneDrive")
        );
    }

    #[test]
    fn an_escaped_mount_point_is_matched_by_its_real_name() {
        let line = "31 64 0:34 / /home/frank/My\\040Documents rw - btrfs /dev/x rw";
        assert_eq!(
            mount_point_of(line).as_deref(),
            Some("/home/frank/My Documents")
        );
    }
}

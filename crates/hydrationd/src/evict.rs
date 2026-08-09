//! Giving disk back, in the one order that works.
//!
//! Eviction is the reverse of hydration and has a trap hydration does not.
//! Punching a hole is a write, and a write inside the marked mount fires a
//! pre-content event — so dehydrating a file blocks on an event that the process
//! doing the dehydrating is often the only one able to answer. Measured: with no
//! ignore mark in place, `fallocate(PUNCH_HOLE)` never returns.
//!
//! A hydrated file already carries an ignore mark, added when it was filled. So
//! there is exactly one safe order:
//!
//! 1. Punch the hole **while the ignore mark is still in place**.
//! 2. *Then* remove the mark, so the next read is intercepted again.
//!
//! Reversing those two deadlocks. [`evict`] is the only way this crate offers to
//! do it, so the order cannot be gotten wrong by a caller who did not know.

use crate::fanotify::Group;
use crate::placeholder;
use std::io;
use std::path::Path;

/// Why a file was not evicted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The content is not in the cloud. Evicting it would be deleting it.
    NotUploaded,
    /// Already has no content.
    AlreadyDehydrated,
}

/// Drop a file's content, keeping its metadata.
///
/// `is_safe` decides whether the content exists anywhere else. It is a
/// parameter rather than a check inside this function because only the
/// unprivileged side knows — and getting it wrong is not a performance problem,
/// it is data loss with no error message.
/// What eviction should tell cooperating backup tools. §6d.
///
/// No default, because there is no safe one: excluding means a backup silently
/// lacks the content, and including means any backup sweep pulls the whole drive
/// down. The caller has to have decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backup {
    /// Set `nodump`, so tools that honour it skip the placeholder.
    Exclude,
    /// Leave the flag alone; the file is readable like any other and reading it
    /// will hydrate it.
    Include,
}

pub fn evict(
    group: &Group,
    path: &Path,
    backup: Backup,
    is_safe: impl FnOnce() -> bool,
) -> io::Result<Result<(), Refused>> {
    if placeholder::is_dehydrated(path)? {
        return Ok(Err(Refused::AlreadyDehydrated));
    }

    // The whole point of eviction is that the content can be fetched again. A
    // file whose only copy is this one is not a candidate at any price: throwing
    // it away to save disk is indistinguishable from deleting it, and the user
    // would find out by reading zeros.
    if !is_safe() {
        return Ok(Err(Refused::NotUploaded));
    }

    // Marked before the content goes, not after: between the punch and the mark
    // the file would be empty and unmarked, which is exactly a plain local file
    // with no content — and a reader arriving there would be given zeros and
    // told they were real.
    placeholder::mark_dehydrated(path, true)?;

    // Alongside the mark, and for the same reason: the moment the content goes,
    // a backup reading this file gets a hole. Setting the flag fires no
    // pre-content event (measured, `probes/nodump.c`), which is what makes it
    // safe to do here — inside the marked mount, in the process that answers
    // events.
    //
    // A filesystem with no such flag is not a failure of eviction. It is a
    // failure of the backup policy, and §6d already requires the count to be
    // visible in the manifest, which is the mechanism that does not depend on
    // anyone honouring a flag.
    if backup == Backup::Exclude {
        match hydration_protocol::flags::set_nodump(path, true) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::Unsupported => {}
            Err(e) => return Err(e),
        }
    }

    // Step 1. Still under the ignore mark the file got when it was hydrated, so
    // this write does not generate an event nobody is going to answer.
    let file = std::fs::OpenOptions::new().write(true).open(path)?;
    let len = file.metadata()?.len();
    placeholder::punch_fd(std::os::fd::AsFd::as_fd(&file), len)?;
    drop(file);

    // Step 2, and only now. Between these two lines the file is empty and not
    // intercepted, so a read landing here would see zeros — the window is why
    // this is two syscalls and not two functions a caller sequences themselves.
    group.unignore(path)?;

    Ok(Ok(()))
}

/// Re-arm interception for a file that is already dehydrated.
///
/// Used at startup, when the marks from the previous run are gone but the
/// placeholders on disk are not.
pub fn arm(group: &Group, path: &Path) -> io::Result<()> {
    group.unignore(path).or_else(|e| {
        // Removing a mark that was never added is not a failure; after a
        // restart, none of them were.
        if e.raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(e)
        }
    })
}

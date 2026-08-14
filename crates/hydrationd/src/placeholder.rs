//! Making a file exist without its content, and undoing that.
//!
//! This is the part the kernel gives away. A placeholder is a sparse file with
//! the right size, so `stat` is right by construction, `st_blocks` is zero
//! because the file genuinely occupies nothing, `chmod` is a real `chmod`, and
//! `rename` is atomic because it is `rename(2)`. Four of the eight invariants in
//! DESIGN.md §5 are satisfied here by not doing anything.
//!
//! The interesting code is in what it refuses to do.

use hydration_protocol::FileId;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Marks a file as holding no content *on purpose*.
///
/// `st_blocks == 0` is not enough to recognise a placeholder, and assuming it
/// was cost a conformance run: a file that has just been created has no blocks
/// either, so the very first `write()` into a new file was taken for a read of
/// an empty placeholder, sent to the cloud, and refused. Creating a file inside
/// the sync directory failed with `EIO`.
///
/// A legitimately sparse local file — `truncate -s 100 notes.txt` — has the same
/// shape again, and no amount of looking at size and blocks separates the three
/// cases. The distinction is not observable; it is a fact the framework knows
/// and therefore has to write down.
pub use hydration_protocol::xattr::DEHYDRATED as XATTR_DEHYDRATED;

/// `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`.
const PUNCH_HOLE: i32 = 0x02;
const KEEP_SIZE: i32 = 0x01;

/// Create a file that has metadata and no content.
/// Only safe **before** the mount is marked, or from a process that is not the
/// one answering events. Inside a marked mount, use [`create_under`].
///
/// `set_len` is a truncate, and a truncate inside a marked mount fires a
/// pre-content event — see [`create_under`] for what that costs.
pub fn create(path: &Path, size: u64, mode: u32) -> io::Result<FileId> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.set_len(size)?;
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
    mark_dehydrated(path, true)?;
    id_of(path)
}

/// Create a placeholder inside a mount that is already being watched.
///
/// The window between `open` and the dehydrated mark is the problem, and it is
/// not theoretical — it silently broke three conformance invariants.
///
/// Giving the file its size is `ftruncate`, which fires a pre-content event. At
/// that instant the file exists but is not yet marked, so the worker answering
/// the event asks "is this a placeholder?", is told no, concludes the content is
/// already present, and **adds an ignore mark**. That mark is permanent: the
/// finished placeholder — correct size, correct xattrs, zero blocks — is then
/// invisible to hydration for the rest of the group's life, and every read of it
/// returns zeros with no event and no error.
///
/// Marking first does not help either: then the same `ftruncate` is a write to a
/// *known* placeholder, hydration is attempted, there is nothing to fetch yet,
/// and the create fails. The window has to be closed rather than moved, so the
/// whole construction happens under an ignore mark — the same shape [`evict`]
/// uses for the same reason.
///
/// [`evict`]: crate::evict::evict
pub fn create_under(
    group: &crate::fanotify::Group,
    path: &Path,
    size: u64,
    mode: u32,
) -> io::Result<FileId> {
    // Creating an empty file touches no content, so this much is safe unmarked.
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    drop(file);

    // From here until the mark is set, the file must not generate events.
    group.ignore(path)?;
    let finish = || -> io::Result<()> {
        let file = fs::OpenOptions::new().write(true).open(path)?;
        file.set_len(size)?;
        drop(file);
        fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
        mark_dehydrated(path, true)
    };
    let result = finish();

    // Re-armed whatever happened. A placeholder left ignored is worse than no
    // placeholder at all: it exists, it looks right, and it reads as zeros.
    let rearm = group.unignore(path);
    result?;
    rearm?;
    id_of(path)
}

/// Drop a file's content, keeping everything else.
///
/// The size and mode survive because only the extents are punched. That is what
/// makes a dehydrated file indistinguishable from a hydrated one to everything
/// except `st_blocks` -- which is the point, and also why §5.8 requires
/// `st_blocks` to be honest.
/// Note: like [`evict`](crate::evict::evict), this re-stamps afterwards.
/// Punching a hole moves mtime, and a placeholder left looking
/// changed-by-someone-else is refused by the delta pass and queued for upload by
/// a resync walk — where uploading it reads it, and reading it hydrates it.
pub fn dehydrate(path: &Path) -> io::Result<()> {
    let file = fs::OpenOptions::new().write(true).open(path)?;
    let len = file.metadata()?.len();
    let rc = unsafe {
        libc::fallocate(
            std::os::fd::AsRawFd::as_raw_fd(&file),
            PUNCH_HOLE | KEEP_SIZE,
            0,
            len as libc::off_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // Set after the content is gone, never before: the two have to end up
    // agreeing, and this is the direction where a crash in between leaves a file
    // that is empty and known to be empty.
    mark_dehydrated(path, true)?;
    let _ = hydration_protocol::stamp::write(path);
    Ok(())
}

/// Fill a placeholder, refusing anything that is not exactly what was promised.
///
/// §5.7, and the reason this takes `expected` at all: a fetch that ends early is
/// not a small problem to be papered over. The reader asked about a file of one
/// size and would receive another, with no error -- and because a partially
/// filled file looks hydrated, the wrong size would become durable.
///
/// So: write into a hole, verify, and if it does not match, put the file back
/// the way it was found and report failure. There is no third outcome.
pub fn hydrate(path: &Path, content: &[u8], expected: u64) -> io::Result<()> {
    if content.len() as u64 != expected {
        // Caught before a byte is written. The cheap case.
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "fetch delivered {} bytes for a placeholder promising {expected}",
                content.len()
            ),
        ));
    }

    let file = fs::OpenOptions::new().write(true).open(path)?;
    let before = file.metadata()?.len();
    if before != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("placeholder is {before} bytes, not the {expected} it declared"),
        ));
    }

    if let Err(e) = std::os::unix::fs::FileExt::write_all_at(&file, content, 0) {
        // A half-written placeholder must not survive the failure: it would
        // look hydrated, and the next reader would be served whatever landed.
        let _ = dehydrate(path);
        return Err(e);
    }
    file.sync_all()?;

    let after = file.metadata()?.len();
    if after != expected {
        let _ = dehydrate(path);
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("placeholder became {after} bytes while being filled"),
        ));
    }
    // The mark is the state, so filling the file has to clear it. Leaving it set
    // would leave a full file that every reader is told is empty.
    mark_dehydrated(path, false)?;
    // The acquisition time for the auto-eviction ranking — recorded here too, so a
    // completed fill through *any* of the three paths (this, `hydrate_fd`,
    // `finish_hydration`) records it and the signal never disagrees between them.
    // Through the fd we already hold, best-effort; a failed timestamp is not a
    // failed hydration.
    let _ = hydration_protocol::hydrated::write_fd(std::os::fd::AsFd::as_fd(&file));
    Ok(())
}

/// Fill a placeholder through the fd the kernel handed us with the event.
///
/// This is not an optimisation, it is the only thing that works. Re-opening the
/// path creates a new `struct file`, which carries the HSM mode — so writing to
/// it fires another pre-content event, and the only process that can answer that
/// event is the one now blocked inside the write. The helper deadlocks against
/// itself, the reader waits forever, and nothing in the log says why.
///
/// The event fd is already open and is not itself intercepted, which is
/// precisely why the kernel hands it over.
pub fn hydrate_fd(
    fd: std::os::fd::BorrowedFd<'_>,
    content: &[u8],
    expected: u64,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    if content.len() as u64 != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "fetch delivered {} bytes for a placeholder promising {expected}",
                content.len()
            ),
        ));
    }

    let mut written = 0usize;
    while written < content.len() {
        let n = unsafe {
            libc::pwrite(
                fd.as_raw_fd(),
                content[written..].as_ptr() as *const libc::c_void,
                content.len() - written,
                written as libc::off_t,
            )
        };
        if n <= 0 {
            let e = io::Error::last_os_error();
            // Nothing partial may survive a failure: it would look hydrated.
            let _ = punch_fd(fd, expected);
            // And the rollback is a write of ours too. Left unstamped, the
            // failed hydration reads as a local edit and a resync walk queues it
            // for upload, which reads it, which hydrates it — a loop started by
            // a failure.
            let _ = hydration_protocol::stamp::write_fd(fd);
            return Err(e);
        }
        written += n as usize;
    }

    if unsafe { libc::fsync(fd.as_raw_fd()) } < 0 {
        let e = io::Error::last_os_error();
        let _ = punch_fd(fd, expected);
        let _ = hydration_protocol::stamp::write_fd(fd);
        return Err(e);
    }

    // The mark is the state, so filling the file clears it — here, in the same
    // function that did the filling, rather than as a separate step the caller
    // has to remember. `hydrate` and `hydrate_fd` behaving differently about
    // this is the shape of every bug in this project: two ways in, one of them
    // leaving the state disagreeing with the content.
    //
    // Cleared through the fd rather than the path: re-opening a path inside a
    // marked mount is the trap this whole module is arranged to avoid.
    unmark_fd(fd)?;

    // And the backup flag, in the same breath, because filling the file does not
    // clear it — measured (`probes/nodump.c`: "survives being written through:
    // yes"). Left set, a hydrated file would go on being skipped by every backup
    // that honours it, which is §6d's harm arriving by the back door: content
    // that exists only here and is excluded from the backup anyway.
    //
    // Unconditional, and not gated on having set it ourselves. The narrow cost
    // is a user who set `nodump` by hand on a file that later turns out to be a
    // cloud placeholder: hydrating it clears their flag. That errs towards more
    // data in the backup, which is the direction §6d exists to protect.
    // A filesystem without the flag has nothing to clear, and a hydration that
    // delivered its content must not be reported as failed over a backup hint.
    match hydration_protocol::flags::set_nodump_fd(fd, false) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {}
        Err(e) => return Err(e),
    }

    // And record what we just wrote, so a later pass can tell this content from
    // a user's edit without having been told about either. Last, because it
    // records the mtime the write produced — and safely last, because setting an
    // extended attribute moves ctime rather than mtime.
    //
    // A failure here is not a failed hydration: the content is in place and the
    // reader is entitled to it. It costs an unnecessary upload later, which is
    // the harmless direction.
    let _ = hydration_protocol::stamp::write_fd(fd);
    // And *when* we brought it down, for the auto-eviction recency ranking. The
    // acquisition moment is exactly here — the placeholder is now fully resident,
    // both ways in (this and `finish_hydration`) so the signal does not disagree
    // between them. Same best-effort, same fd, same no-event metadata write as
    // the stamp above; a failed timestamp is not a failed hydration.
    let _ = hydration_protocol::hydrated::write_fd(fd);
    Ok(())
}

/// Clear the placeholder mark through an already-open descriptor.
fn unmark_fd(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let n = std::ffi::CString::new(XATTR_DEHYDRATED).unwrap();
    let rc = unsafe { libc::fremovexattr(fd.as_raw_fd(), n.as_ptr()) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        // Not marked is the state we wanted.
        if e.raw_os_error() != Some(libc::ENODATA) {
            return Err(e);
        }
    }
    Ok(())
}

/// Punch a file's content away through an already-open fd.
pub fn punch_fd(fd: std::os::fd::BorrowedFd<'_>, len: u64) -> io::Result<()> {
    punch_range_fd(fd, 0, len)
}

/// Punch away one range, leaving the rest of the file alone.
///
/// What a failed *ranged* fill rolls back. Punching the whole file would also be
/// correct — nothing is lost that cannot be fetched again — but it throws away
/// every other range the worker has already paid for, so a transient error two
/// gigabytes into a sequential read would restart the whole file. The narrower
/// rollback is safe for the same reason the wide one is: the placeholder mark
/// stays set either way, so nothing is served from this file without asking.
pub fn punch_range_fd(fd: std::os::fd::BorrowedFd<'_>, offset: u64, len: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if len == 0 {
        return Ok(());
    }
    let rc = unsafe {
        libc::fallocate(
            fd.as_raw_fd(),
            PUNCH_HOLE | KEEP_SIZE,
            offset as libc::off_t,
            len as libc::off_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// True when the file is a placeholder.
///
/// The mark alone, deliberately. `st_blocks == 0` was part of this test until a
/// conformance run showed why it cannot be: btrfs stores small files *inline* in
/// metadata, so punching a hole in a 21-byte file leaves its blocks unchanged.
/// A dehydrated script reported blocks, was taken for a file that already had
/// content, and was served as zeros.
///
/// Sparseness is an observation, and on a real filesystem it is one that can
/// disagree with the truth in both directions. Whether a file is a placeholder
/// is not an observation at all — it is a fact the framework decided, so it is
/// the framework that has to record it.
pub fn is_dehydrated(path: &Path) -> io::Result<bool> {
    has_mark(path)
}

/// Whether the file holds any content at all.
///
/// Asked of the file rather than inferred from its block count, because a block
/// count answers a different question and answers it differently on every
/// filesystem. Measured, an empty 1 MiB placeholder carrying the four identity
/// attributes:
///
/// ```text
///   btrfs                    blocks=0   SEEK_DATA=ENXIO
///   ext4, 128-byte inode     blocks=2   SEEK_DATA=ENXIO
///   ext4, one byte of data   blocks=2   SEEK_DATA=found data
/// ```
///
/// The last two lines are the point: where the attributes do not fit in the
/// inode they spill into a block of their own, and `st_blocks` charges for it —
/// so on that filesystem *an empty placeholder* and *a file with content in it*
/// report the same number. No threshold separates them, because there is
/// nothing to separate.
///
/// `SEEK_DATA` asks the filesystem directly and gets `ENXIO` when the file holds
/// no data anywhere. That is the question §5.8 is really about: not whether a
/// placeholder costs an inode's worth of metadata, but whether the drive is
/// quietly full of content the user thought was in the cloud.
pub fn holds_data(path: &Path) -> io::Result<bool> {
    let f = fs::File::open(path)?;
    holds_data_fd(std::os::fd::AsFd::as_fd(&f))
}

/// As [`holds_data`], on a descriptor that is already open.
pub fn holds_data_fd(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    // SEEK_DATA moves to the first byte at or after the offset that is not in a
    // hole. On a file that is entirely a hole there is none, and the kernel says
    // so with ENXIO — which is the answer, not an error.
    let r = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_DATA) };
    if r >= 0 {
        return Ok(true);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ENXIO) => Ok(false),
        // A filesystem without SEEK_DATA support cannot answer, and guessing
        // would be worse than saying so.
        _ => Err(io::Error::last_os_error()),
    }
}

// There was an `occupies_disk` here — `metadata.blocks() > 0`, public, with a
// comment saying it was not a placeholder test. It had no callers, and it was
// exactly the predicate that produced the bug this module's `holds_data` was
// written to replace: on ext4 with a small inode the extended attributes spill
// into a block of their own, so a placeholder holding nothing reports blocks,
// and on any filesystem a file truncated to its object's size reports the same
// count as an empty one (§8z).
//
// A documented trap in a public API is still a trap. The next person needs a
// block count for something legitimate, finds a function that returns one,
// and does not read the comment — so it is gone rather than annotated. Callers
// who genuinely mean blocks can say `metadata.blocks()` and own the meaning.

/// True when the file carries the placeholder mark, whatever its blocks say.
pub fn has_mark(path: &Path) -> io::Result<bool> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has an interior nul"))?;
    let n = std::ffi::CString::new(XATTR_DEHYDRATED).unwrap();
    let rc = unsafe { libc::getxattr(c.as_ptr(), n.as_ptr(), std::ptr::null_mut(), 0) };
    if rc >= 0 {
        return Ok(true);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Write one chunk of hydrated content at `offset`.
///
/// Through the event fd, never by re-opening the path — the trap this module is
/// arranged around (§6a-ter). Measured (`probes/stream.c`): these partial writes
/// fire no further pre-content events, and a bystander cannot observe the
/// half-filled file because their own event queues behind the one being served.
pub fn write_at(fd: std::os::fd::BorrowedFd<'_>, buf: &[u8], offset: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let mut done = 0usize;
    while done < buf.len() {
        let n = unsafe {
            libc::pwrite(
                fd.as_raw_fd(),
                buf[done..].as_ptr() as *const libc::c_void,
                buf.len() - done,
                (offset + done as u64) as libc::off_t,
            )
        };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        done += n as usize;
    }
    Ok(())
}

/// Everything a completed streamed transfer still owes the file.
///
/// The same four steps `hydrate` ends with, in the same order and for the same
/// reasons — separated only because the content arrived in pieces rather than
/// all at once, and the caller wrote it as it came.
pub fn finish_hydration(fd: std::os::fd::BorrowedFd<'_>, expected: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::fsync(fd.as_raw_fd()) } < 0 {
        let e = io::Error::last_os_error();
        let _ = punch_fd(fd, expected);
        let _ = hydration_protocol::stamp::write_fd(fd);
        return Err(e);
    }
    unmark_fd(fd)?;
    match hydration_protocol::flags::set_nodump_fd(fd, false) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::Unsupported => {}
        Err(e) => return Err(e),
    }
    let _ = hydration_protocol::stamp::write_fd(fd);
    // The acquisition timestamp for the auto-eviction recency ranking — the
    // streamed twin of the record in `hydrate_fd`, recorded only on the completed
    // fill (`have.covers(whole)`), never in `settle_range`, which leaves the file
    // a marked placeholder and so not an eviction candidate at all.
    let _ = hydration_protocol::hydrated::write_fd(fd);
    Ok(())
}

/// Make a range that has just been filled durable, without finishing the file.
///
/// The counterpart of [`finish_hydration`] for a fill that covered only what a
/// reader demanded (§8d-bis). It does the two things that must happen before the
/// event is answered, and deliberately not the two that must not:
///
/// * **fsync**, because the reader is about to be allowed and the bytes have to
///   be there.
/// * **the stamp**, because we just moved the file's mtime. Left unstamped, a
///   resync walk reads the fill as the user's own edit and queues the file for
///   upload — where uploading it reads it, and reading it hydrates it. The loop
///   is the one `hydrate_fd`'s rollback path already had to be taught about.
///
/// It does *not* clear the placeholder mark, and it does not clear `nodump`. The
/// file still has holes in it; saying otherwise would let the next reader be
/// served the parts that are not there.
pub fn settle_range(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if unsafe { libc::fsync(fd.as_raw_fd()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // Failing to stamp is not a failed fill: the content is in place and the
    // reader is entitled to it. It costs an unnecessary upload later, which is
    // the harmless direction — the same judgement `hydrate_fd` makes.
    let _ = hydration_protocol::stamp::write_fd(fd);
    Ok(())
}

/// Put a placeholder back exactly as it was, whatever a failed transfer left.
///
/// Punches the *whole declared size*, never only what was written: a previous
/// abandoned attempt may have left residue further in, and punching only the
/// latest range would leave a file that is marked as empty and is not.
pub fn abandon(fd: std::os::fd::BorrowedFd<'_>, expected: u64) -> io::Result<()> {
    punch_fd(fd, expected)?;
    let _ = hydration_protocol::stamp::write_fd(fd);
    Ok(())
}

/// Clear whatever an interrupted transfer left, before the next one starts.
///
/// A marked file that occupies disk cannot exist between transfers, but it is
/// exactly what a crash mid-stream leaves — and the supervisor cannot clean it
/// up, because it holds the event fd's *number* and not the descriptor. So the
/// next transfer does it, which is the only place that can.
///
/// Unconditional, and that is the point. The first version asked `st_blocks > 0`
/// first, which walked straight back into the trap this module's own
/// documentation records paying for once already: btrfs stores small files
/// inline, so a fully punched 21-byte placeholder still reports blocks. Every
/// small file would have reported residue on every ordinary read, and the log
/// line saying so would have been false — corrosive to the one log §6c requires
/// to be true. Punching a placeholder that has nothing in it costs one syscall
/// and tells no lies.
pub fn clear_residue(fd: std::os::fd::BorrowedFd<'_>, expected: u64) -> io::Result<()> {
    punch_fd(fd, expected)
}

/// The same question asked of an open file rather than a name.
///
/// This is the one the worker uses. A name is a weaker handle than it looks:
/// it can be renamed between resolving it and using it, and a file that is
/// unlinked while someone holds it open has no name at all — while still being
/// a placeholder whose content is perfectly fetchable. Asking the descriptor
/// removes both problems, because the descriptor *is* the file the event is
/// about.
pub fn has_mark_fd(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    let n = std::ffi::CString::new(XATTR_DEHYDRATED).unwrap();
    let rc = unsafe { libc::fgetxattr(fd.as_raw_fd(), n.as_ptr(), std::ptr::null_mut(), 0) };
    if rc >= 0 {
        return Ok(true);
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ENODATA) | Some(libc::ENOTSUP) => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Identity and size of an open file, in one `fstat`.
pub fn id_and_size_fd(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<(FileId, u64)> {
    use std::os::fd::AsRawFd;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        FileId {
            fsid: st.st_dev,
            ino: st.st_ino,
        },
        st.st_size as u64,
    ))
}

/// Add or remove the placeholder mark.
pub fn mark_dehydrated(path: &Path, on: bool) -> io::Result<()> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path has an interior nul"))?;
    let n = std::ffi::CString::new(XATTR_DEHYDRATED).unwrap();
    let rc = if on {
        unsafe {
            libc::setxattr(
                c.as_ptr(),
                n.as_ptr(),
                b"1".as_ptr() as *const libc::c_void,
                1,
                0,
            )
        }
    } else {
        let r = unsafe { libc::removexattr(c.as_ptr(), n.as_ptr()) };
        if r < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::ENODATA) {
            0
        } else {
            r
        }
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn id_of(path: &Path) -> io::Result<FileId> {
    let md = fs::metadata(path)?;
    Ok(FileId {
        fsid: md.dev(),
        ino: md.ino(),
    })
}

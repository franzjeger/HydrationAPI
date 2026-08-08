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

/// `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)`.
const PUNCH_HOLE: i32 = 0x02;
const KEEP_SIZE: i32 = 0x01;

/// Create a file that has metadata and no content.
pub fn create(path: &Path, size: u64, mode: u32) -> io::Result<FileId> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.set_len(size)?;
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))?;
    id_of(path)
}

/// Drop a file's content, keeping everything else.
///
/// The size and mode survive because only the extents are punched. That is what
/// makes a dehydrated file indistinguishable from a hydrated one to everything
/// except `st_blocks` -- which is the point, and also why §5.8 requires
/// `st_blocks` to be honest.
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
            return Err(e);
        }
        written += n as usize;
    }

    if unsafe { libc::fsync(fd.as_raw_fd()) } < 0 {
        let e = io::Error::last_os_error();
        let _ = punch_fd(fd, expected);
        return Err(e);
    }
    Ok(())
}

/// Punch a file's content away through an already-open fd.
pub fn punch_fd(fd: std::os::fd::BorrowedFd<'_>, len: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let rc = unsafe {
        libc::fallocate(
            fd.as_raw_fd(),
            PUNCH_HOLE | KEEP_SIZE,
            0,
            len as libc::off_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// True when the file holds no content.
pub fn is_dehydrated(path: &Path) -> io::Result<bool> {
    Ok(fs::metadata(path)?.blocks() == 0)
}

pub fn id_of(path: &Path) -> io::Result<FileId> {
    let md = fs::metadata(path)?;
    Ok(FileId {
        fsid: md.dev(),
        ino: md.ino(),
    })
}

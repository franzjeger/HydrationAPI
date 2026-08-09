//! Framing for the privilege boundary.
//!
//! A JSON line, and for a `Ready` response exactly `len` raw bytes after it. The
//! socket is the only thing the two halves share, so everything that arrives on
//! it is treated as hostile input — not because the sync daemon is expected to
//! be compromised, but because the entire value of the split is that it stays
//! contained if it is.
//!
//! Concretely, that means the reading side never allocates on a length it was
//! told without checking it against a length it already knew.

use crate::{decode, encode, FetchResponse, FromHelper, ToHelper};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};

/// The helper's end.
///
/// The writer is shared and the reader is not, which is what lets the helper
/// send unsolicited messages — change notifications — from a thread other than
/// the one waiting on a fetch reply. Two writers on one socket would interleave
/// their lines and destroy the framing, so every write goes through the same
/// lock; the lock is never held across a read, so a slow reply cannot stall a
/// notification or the other way round.
pub struct HelperConn {
    reader: BufReader<UnixStream>,
    writer: Arc<Mutex<UnixStream>>,
}

/// A send-only handle onto a [`HelperConn`], for threads that only report.
///
/// Deliberately cannot receive. A second reader on the socket would take replies
/// belonging to the fetch path and match them to the wrong request, which is the
/// one failure this framing exists to make impossible.
#[derive(Clone)]
pub struct Notifier {
    writer: Arc<Mutex<UnixStream>>,
}

impl Notifier {
    pub fn send(&self, msg: &FromHelper) -> io::Result<()> {
        let line = encode(msg).map_err(io::Error::other)?;
        let mut w = self.writer.lock().map_err(|_| {
            io::Error::other("the connection lock was poisoned by a panicking writer")
        })?;
        w.write_all(line.as_bytes())?;
        w.flush()
    }
}

/// How a streamed transfer ended.
#[derive(Debug)]
pub enum Streamed {
    /// Every promised byte landed.
    Complete,
    /// The daemon gave up part way. The placeholder must be put back.
    Aborted { errno: i32, reason: String },
    /// The daemon refused before sending anything.
    Refused(FetchResponse),
}

/// The sync daemon's end.
pub struct DaemonConn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

fn split(stream: UnixStream) -> io::Result<(BufReader<UnixStream>, UnixStream)> {
    let writer = stream.try_clone()?;
    Ok((BufReader::new(stream), writer))
}

impl HelperConn {
    pub fn new(stream: UnixStream) -> io::Result<Self> {
        let (reader, writer) = split(stream)?;
        Ok(Self {
            reader,
            writer: Arc::new(Mutex::new(writer)),
        })
    }

    /// A handle for reporting from another thread.
    pub fn notifier(&self) -> Notifier {
        Notifier {
            writer: Arc::clone(&self.writer),
        }
    }

    pub fn send(&mut self, msg: &FromHelper) -> io::Result<()> {
        self.notifier().send(msg)
    }

    /// Read a streamed body into `dest`, one chunk at a time.
    ///
    /// `expected` is the placeholder's size, taken from the filesystem rather
    /// than from anything the daemon said. The `Ready` line is refused if it
    /// disagrees — before a byte is read, so the daemon cannot choose how much a
    /// root process allocates — and from then on the running total is checked
    /// against it on every chunk.
    ///
    /// `on_progress` is called after each chunk lands, and is how the worker
    /// keeps its stall clock and its liveness signal honest during a transfer
    /// that may legitimately take minutes.
    ///
    /// Nothing is buffered beyond one chunk, so a 10 GB object costs
    /// [`crate::MAX_CHUNK`] of memory rather than 10 GB.
    pub fn recv_streamed(
        &mut self,
        expected: u64,
        dest: &mut dyn FnMut(&[u8], u64) -> io::Result<()>,
        on_progress: &mut dyn FnMut(u64),
    ) -> io::Result<Streamed> {
        if expected > crate::MAX_OBJECT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("placeholder claims {expected} bytes; the helper's limit is {}", crate::MAX_OBJECT),
            ));
        }
        let mut total = 0u64;
        let mut buf = vec![0u8; crate::MAX_CHUNK as usize];
        loop {
            let mut line = String::new();
            if self.reader.read_line(&mut line)? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the sync daemon closed the connection mid-transfer",
                ));
            }
            match decode::<ToHelper>(&line).map_err(io::Error::other)? {
                ToHelper::Fetch(FetchResponse::Ready { len, .. }) => {
                    if len != expected {
                        // Refused on the declaration, before the body. The stream
                        // is now out of step, so the caller must drop the
                        // connection rather than resynchronise.
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("daemon offered {len} bytes for a {expected}-byte placeholder"),
                        ));
                    }
                }
                ToHelper::Chunk { len, .. } => {
                    if len > crate::MAX_CHUNK || total + len > expected {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("chunk of {len} would overrun a {expected}-byte object"),
                        ));
                    }
                    let n = len as usize;
                    self.reader.read_exact(&mut buf[..n])?;
                    dest(&buf[..n], total)?;
                    total += len;
                    on_progress(total);
                }
                ToHelper::Done { .. } => {
                    if total != expected {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("daemon claimed completion at {total} of {expected} bytes"),
                        ));
                    }
                    return Ok(Streamed::Complete);
                }
                ToHelper::Abort { errno, reason, .. } => {
                    return Ok(Streamed::Aborted { errno, reason });
                }
                ToHelper::Fetch(other) => return Ok(Streamed::Refused(other)),
                ToHelper::Control(_) => continue,
            }
        }
    }

    /// Read one response, and its content if it has any.
    ///
    /// `expected` is the size the placeholder actually is, taken from the
    /// filesystem rather than from the message. A `Ready` that disagrees is
    /// refused before a single byte is read, so a daemon claiming a 4 GB body
    /// for a 12-byte file gets a rejection, not an allocation.
    pub fn recv(&mut self, expected: u64) -> io::Result<(FetchResponse, Vec<u8>)> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "the sync daemon closed the connection",
            ));
        }
        let msg: ToHelper = decode(&line).map_err(io::Error::other)?;
        let ToHelper::Fetch(resp) = msg else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected a fetch response",
            ));
        };

        match &resp {
            FetchResponse::Ready { len, .. } => {
                if *len != expected {
                    // Refused on the declaration, before reading the body. The
                    // stream is now out of step, so the caller must drop the
                    // connection rather than try to resynchronise — a desync is
                    // exactly the state where a later response could be matched
                    // to the wrong request.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("daemon offered {len} bytes for a {expected}-byte placeholder"),
                    ));
                }
                let mut buf = vec![0u8; *len as usize];
                self.reader.read_exact(&mut buf)?;
                Ok((resp, buf))
            }
            _ => Ok((resp, Vec::new())),
        }
    }
}

/// Where a provider's bytes go, and the only way they get there.
///
/// Holds the promise made by the `Ready` line and will not let it be broken:
/// writing past `promised` fails at the offending byte, and finishing short is
/// an [`ToHelper::Abort`] rather than a silent truncation. Both are the same
/// rule from §5.7 — the whole object or nothing — moved from something a
/// provider must remember into something it cannot avoid.
pub struct Body<'a> {
    writer: &'a mut UnixStream,
    id: u64,
    promised: u64,
    written: u64,
    finished: bool,
}

impl Body<'_> {
    /// How many bytes are still owed.
    pub fn remaining(&self) -> u64 {
        self.promised.saturating_sub(self.written)
    }

    /// Finish, or say why not.
    ///
    /// Consuming rather than borrowing, so a body cannot be left in an
    /// indeterminate state: every path out of a fetch either completes the
    /// promise or aborts it.
    pub fn finish(mut self) -> io::Result<()> {
        if self.written != self.promised {
            let short = self.promised - self.written;
            self.abort_with(
                libc::EIO,
                &format!("provider delivered {short} bytes fewer than the object's size"),
            )?;
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("short delivery: {} of {} bytes", self.written, self.promised),
            ));
        }
        let line = encode(&ToHelper::Done { id: self.id }).map_err(io::Error::other)?;
        self.finished = true;
        self.send_line(&line)
    }

    /// Give up on this transfer without desynchronising the stream.
    pub fn abort(mut self, errno: i32, reason: &str) -> io::Result<()> {
        self.abort_with(errno, reason)
    }

    fn abort_with(&mut self, errno: i32, reason: &str) -> io::Result<()> {
        let line = encode(&ToHelper::Abort {
            id: self.id,
            errno,
            reason: reason.to_string(),
        })
        .map_err(io::Error::other)?;
        self.finished = true;
        self.send_line(&line)
    }

    fn send_line(&mut self, line: &str) -> io::Result<()> {
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()
    }
}

impl Write for Body<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Refused at the offending byte, not counted up and complained about
        // afterwards. A provider that would have sent too much finds out where.
        if self.written + buf.len() as u64 > self.promised {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "provider offered more than the object's size: {} written, {} promised, \
                     {} more offered",
                    self.written,
                    self.promised,
                    buf.len()
                ),
            ));
        }
        let n = buf.len().min(crate::MAX_CHUNK as usize);
        let line = encode(&ToHelper::Chunk {
            id: self.id,
            len: n as u64,
        })
        .map_err(io::Error::other)?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(&buf[..n])?;
        self.writer.flush()?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Body<'_> {
    fn drop(&mut self) {
        // A body dropped without `finish` or `abort` is a provider that panicked
        // or returned early. The helper is waiting on a promise nobody is going
        // to keep, so it is told — an unanswered stream is a reader blocked for
        // as long as the deadline allows, for no reason.
        if !self.finished {
            let _ = self.abort_with(libc::EIO, "the provider abandoned the transfer");
        }
    }
}

impl DaemonConn {
    pub fn new(stream: UnixStream) -> io::Result<Self> {
        let (reader, writer) = split(stream)?;
        Ok(Self { reader, writer })
    }

    /// Wait for the next thing the helper wants. `None` means it went away.
    pub fn recv(&mut self) -> io::Result<Option<FromHelper>> {
        let mut line = String::new();
        if self.reader.read_line(&mut line)? == 0 {
            return Ok(None);
        }
        decode(&line).map(Some).map_err(io::Error::other)
    }

    /// Begin a streamed answer, and return the sink the content goes into.
    ///
    /// `len` is the placeholder's size, which the daemon already knows — it never
    /// has to declare a length it has not received. The returned [`Body`] is what
    /// enforces that promise: it counts, it refuses the byte that would exceed
    /// `len` at that byte rather than at the end, and it frames each write onto
    /// the wire. A provider whose whole implementation is `io::copy(&mut resp,
    /// out)` cannot get the contract wrong, which is the point of handing it a
    /// concrete type rather than a `dyn Write`.
    pub fn begin(&mut self, id: u64, len: u64) -> io::Result<Body<'_>> {
        let line = encode(&ToHelper::Fetch(FetchResponse::Ready { id, len }))
            .map_err(io::Error::other)?;
        self.writer.write_all(line.as_bytes())?;
        Ok(Body {
            writer: &mut self.writer,
            id,
            promised: len,
            written: 0,
            finished: false,
        })
    }

    /// Answer with content.
    pub fn send_ready(&mut self, id: u64, content: &[u8]) -> io::Result<()> {
        let line = encode(&ToHelper::Fetch(FetchResponse::Ready {
            id,
            len: content.len() as u64,
        }))
        .map_err(io::Error::other)?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.write_all(content)?;
        self.writer.flush()
    }

    /// Answer without content.
    pub fn send(&mut self, resp: FetchResponse) -> io::Result<()> {
        let line = encode(&ToHelper::Fetch(resp)).map_err(io::Error::other)?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FetchRequest, FileId};

    fn pair() -> (HelperConn, DaemonConn) {
        let (a, b) = UnixStream::pair().expect("socketpair");
        (HelperConn::new(a).unwrap(), DaemonConn::new(b).unwrap())
    }

    #[test]
    fn a_request_and_its_content_survive_the_round_trip() {
        let (mut helper, mut daemon) = pair();
        let req = FetchRequest {
            id: 1,
            file: FileId { fsid: 3, ino: 9 },
            offset: 0,
            len: 5,
            cgroup: None,
        };
        helper.send(&FromHelper::Fetch(req.clone())).unwrap();

        let got = daemon.recv().unwrap().unwrap();
        assert_eq!(got, FromHelper::Fetch(req));
        daemon.send_ready(1, b"hello").unwrap();

        let (resp, body) = helper.recv(5).unwrap();
        assert_eq!(resp, FetchResponse::Ready { id: 1, len: 5 });
        assert_eq!(body, b"hello");
    }

    #[test]
    fn a_body_that_disagrees_with_the_placeholder_is_refused_before_it_is_read() {
        // The daemon claims more than the file can be. Refusing on the header
        // rather than after the read is what stops a compromised daemon from
        // choosing how much memory the root helper allocates.
        let (mut helper, mut daemon) = pair();
        daemon.send_ready(1, &vec![b'x'; 4096]).unwrap();

        let err = helper
            .recv(12)
            .expect_err("a 4096-byte body for a 12-byte placeholder must be refused");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("4096") && err.to_string().contains("12"),
            "the error should name both lengths: {err}"
        );
    }

    #[test]
    fn a_failure_carries_no_body() {
        let (mut helper, mut daemon) = pair();
        daemon
            .send(FetchResponse::Failed {
                id: 7,
                errno: 5,
                reason: "upstream closed early".into(),
            })
            .unwrap();

        let (resp, body) = helper.recv(4096).unwrap();
        assert!(matches!(resp, FetchResponse::Failed { errno: 5, .. }));
        assert!(body.is_empty(), "a failure must not be followed by bytes");
    }

    #[test]
    fn a_closed_daemon_is_an_error_and_not_an_empty_success() {
        // If this ever returned Ok with no content, the helper would write
        // nothing into a placeholder and call it hydrated.
        let (mut helper, daemon) = pair();
        drop(daemon);
        let err = helper
            .recv(10)
            .expect_err("a closed socket is not a success");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }
}

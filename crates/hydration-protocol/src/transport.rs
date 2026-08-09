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

/// The helper's end.
pub struct HelperConn {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
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
        Ok(Self { reader, writer })
    }

    pub fn send(&mut self, msg: &FromHelper) -> io::Result<()> {
        let line = encode(msg).map_err(io::Error::other)?;
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()
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

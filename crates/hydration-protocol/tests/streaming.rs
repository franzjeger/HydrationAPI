//! The framing that carries §5.7, tested where it can be tested cheaply.
//!
//! Everything here was previously exercised only by root-only suites that skip
//! without a mount — so the type holding the whole-object-or-nothing guarantee
//! had no unit test at all, and four defects in it were found by attacking the
//! running system rather than by running `cargo test`.

use hydration_protocol::transport::{DaemonConn, HelperConn, Streamed};
use hydration_protocol::{encode, FetchResponse, ToHelper};
use std::io::Write;
use std::os::unix::net::UnixStream;

fn pair() -> (HelperConn, DaemonConn) {
    let (a, b) = UnixStream::pair().unwrap();
    (HelperConn::new(a).unwrap(), DaemonConn::new(b).unwrap())
}

/// Collect a streamed body, ignoring where each chunk landed.
fn drain(helper: &mut HelperConn, id: u64, expected: u64) -> std::io::Result<(Streamed, Vec<u8>)> {
    let mut got = Vec::new();
    let out = helper.recv_streamed(
        id,
        expected,
        &mut |buf, _off| {
            got.extend_from_slice(buf);
            Ok(())
        },
        &mut |_| {},
    )?;
    Ok((out, got))
}

#[test]
fn a_complete_body_arrives_whole() {
    let (mut helper, mut daemon) = pair();
    let body = vec![b'H'; 300_000];
    let sent = body.clone();
    std::thread::spawn(move || {
        let mut b = daemon.begin(1, sent.len() as u64).unwrap();
        b.write_all(&sent).unwrap();
        b.finish().unwrap();
    });

    let (out, got) = drain(&mut helper, 1, body.len() as u64).unwrap();
    assert!(matches!(out, Streamed::Complete), "{out:?}");
    assert_eq!(got, body);
}

/// §5.7 from the provider's side: finishing short is an abort, not a truncation.
#[test]
fn a_short_delivery_becomes_an_abort() {
    let (mut helper, mut daemon) = pair();
    std::thread::spawn(move || {
        let mut b = daemon.begin(1, 1000).unwrap();
        b.write_all(&[b'x'; 400]).unwrap();
        let _ = b.finish();
    });

    let (out, got) = drain(&mut helper, 1, 1000).unwrap();
    assert!(
        matches!(out, Streamed::Aborted { .. }),
        "a short delivery was not refused: {out:?}"
    );
    assert!(got.len() < 1000, "the helper accepted a truncated object");
}

/// And a provider that writes past the object's size fails at that byte, rather
/// than being counted up and complained about afterwards.
#[test]
fn over_delivery_fails_at_the_offending_byte() {
    let (_helper, mut daemon) = pair();
    let mut b = daemon.begin(1, 100).unwrap();
    b.write_all(&[b'x'; 100]).unwrap();
    let err = b.write(&[b'y'; 1]).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
}

/// A provider that panics leaves the wire consistent, not the helper waiting.
#[test]
fn a_dropped_body_aborts_rather_than_leaving_the_helper_waiting() {
    let (mut helper, mut daemon) = pair();
    std::thread::spawn(move || {
        let mut b = daemon.begin(1, 500).unwrap();
        b.write_all(&[b'x'; 100]).unwrap();
    });

    let (out, _) = drain(&mut helper, 1, 500).unwrap();
    assert!(
        matches!(out, Streamed::Aborted { .. }),
        "an abandoned body left the helper waiting: {out:?}"
    );
}

/// A length that disagrees with the placeholder, refused before the body.
#[test]
fn a_wrong_length_is_refused_before_the_body() {
    let (mut helper, mut daemon) = pair();
    std::thread::spawn(move || {
        let _ = daemon.begin(1, 999);
    });
    assert!(
        drain(&mut helper, 1, 100).is_err(),
        "a wrong length was accepted"
    );
}

#[test]
fn a_chunk_that_would_overrun_is_refused() {
    let (mut helper, mut daemon) = pair();
    std::thread::spawn(move || {
        let raw = daemon.raw_writer();
        let _ = raw.write_all(
            encode(&ToHelper::Fetch(FetchResponse::Ready { id: 1, len: 100 }))
                .unwrap()
                .as_bytes(),
        );
        let _ = raw.write_all(
            encode(&ToHelper::Chunk { id: 1, len: 500 })
                .unwrap()
                .as_bytes(),
        );
        let _ = raw.write_all(&[b'x'; 500]);
    });
    assert!(
        drain(&mut helper, 1, 100).is_err(),
        "a chunk was allowed to overrun the object"
    );
}

/// A zero-length chunk is not progress.
///
/// Treating it as such let a daemon reset the worker's stall clock indefinitely
/// without delivering a byte — measured at 2.3 million callbacks in three
/// seconds, with the stall deadline never firing.
#[test]
fn an_empty_chunk_is_refused() {
    let (mut helper, mut daemon) = pair();
    std::thread::spawn(move || {
        let raw = daemon.raw_writer();
        let _ = raw.write_all(
            encode(&ToHelper::Fetch(FetchResponse::Ready { id: 1, len: 100 }))
                .unwrap()
                .as_bytes(),
        );
        for _ in 0..10 {
            let _ = raw.write_all(
                encode(&ToHelper::Chunk { id: 1, len: 0 })
                    .unwrap()
                    .as_bytes(),
            );
        }
    });
    assert!(
        drain(&mut helper, 1, 100).is_err(),
        "empty chunks were accepted as progress"
    );
}

/// Every frame must answer the request that is outstanding.
///
/// Harmless while one request is in flight, and a cross-file content
/// substitution the day pipelining lands — which is what this framing exists to
/// enable.
#[test]
fn a_frame_answering_another_request_is_refused() {
    let (mut helper, mut daemon) = pair();
    std::thread::spawn(move || {
        let mut b = daemon.begin(99, 100).unwrap();
        let _ = b.write_all(&[b'x'; 100]);
        let _ = b.finish();
    });
    assert!(
        drain(&mut helper, 1, 100).is_err(),
        "a response to request 99 was accepted as an answer to request 1"
    );
}

/// The helper's own object limit, independent of the daemon's.
#[test]
fn an_object_larger_than_the_helpers_limit_is_refused_before_anything_is_read() {
    let (mut helper, _daemon) = pair();
    let err = drain(&mut helper, 1, hydration_protocol::MAX_OBJECT + 1).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData, "{err}");
}

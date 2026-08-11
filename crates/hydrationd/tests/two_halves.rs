//! Both halves, connected: an unprivileged daemon serving a privileged helper.
//!
//! Same requirements as `fail_closed.rs` — root and a real mount — because there
//! is no way to exercise a pre-content event without them.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test two_halves
//! ```

use hydration_client::{store, Daemon, Provider};
use hydration_protocol::transport::{DaemonConn, HelperConn};
use hydrationd::daemon::{Handled, Worker};
use hydrationd::fanotify::Group;
use hydrationd::placeholder;
use hydrationd::policy::Policy;
use hydrationd::remote::SocketFetch;
use hydrationd::supervisor::InFlight;
use std::io;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

const BODY: &[u8] = b"content that only the unprivileged half can reach\n";

fn mount() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var_os("HYDRATIOND_TEST_MOUNT")?);
    if !p.is_dir() || unsafe { libc::geteuid() } != 0 {
        return None;
    }
    Some(p)
}

fn skip(why: &str) {
    if std::env::var_os("HYDRATIOND_REQUIRE").is_some() {
        panic!("HYDRATIOND_REQUIRE is set but the test could not run: {why}");
    }
    eprintln!("SKIPPED: {why}");
}

/// Stands in for a cloud. What matters is that it is on the far side of the
/// socket and the helper cannot reach it.
struct Fake {
    body: Vec<u8>,
    /// Serve fewer bytes than recorded, to drive §5.7 through the whole stack.
    truncate_to: Option<usize>,
}

impl Provider for Fake {
    fn fetch(
        &mut self,
        _cloud_id: &str,
        _size: u64,
        _content_tag: Option<&str>,
        span: hydration_protocol::Span,
        out: &mut hydration_protocol::transport::Body<'_>,
    ) -> io::Result<()> {
        use std::io::Write;
        let slice = {
            let end = (span.end() as usize).min(self.body.len());
            let start = (span.offset as usize).min(end);
            self.body[start..end].to_vec()
        };
        let body = match self.truncate_to {
            Some(n) => slice[..n.min(slice.len())].to_vec(),
            None => slice,
        };
        // A short body is written and then simply not finished; `Body` turns
        // that into an abort rather than a truncated file, which is §5.7 moved
        // out of the provider's hands.
        out.write_all(&body)?;
        Ok(())
    }
}

/// Set up a placeholder that the daemon knows the cloud ID of.
fn seed(dir: &std::path::Path, name: &str, body: &[u8]) -> PathBuf {
    let p = dir.join(name);
    let _ = std::fs::remove_file(&p);
    placeholder::create(&p, body.len() as u64, 0o644).expect("create placeholder");
    store::set_xattr(&p, store::XATTR_ID, b"cloud-object-1").expect("record cloud id");
    p
}

/// Run the daemon on a thread and hand back the helper's end of the socket.
fn start_daemon(root: &std::path::Path, provider: Fake) -> HelperConn {
    let (helper_side, daemon_side) = UnixStream::pair().expect("socketpair");
    let root = root.to_path_buf();
    std::thread::spawn(move || {
        let mut d = Daemon::new(provider, &root).expect("daemon");
        let mut conn = DaemonConn::new(daemon_side).expect("daemon conn");
        let _ = d.serve(&mut conn);
    });
    HelperConn::new(helper_side).expect("helper conn")
}

#[test]
fn content_crosses_the_boundary_and_reaches_the_reader() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let file = seed(&mnt, "across.bin", BODY);

    let conn = start_daemon(
        &mnt,
        Fake {
            body: BODY.to_vec(),
            truncate_to: None,
        },
    );

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::new(
        group,
        SocketFetch::new(conn, &mnt),
        Policy::permissive(),
        InFlight::new(),
    );

    let reader = std::process::Command::new("cat")
        .arg(&file)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("reader");

    let seen = worker
        .run(Instant::now() + Duration::from_secs(5))
        .expect("worker");
    let out = reader.wait_with_output().expect("reader output");

    assert!(
        seen.iter().any(|h| matches!(h, Handled::Hydrated { .. })),
        "nothing was hydrated across the socket: {seen:?}"
    );
    assert_eq!(
        out.stdout, BODY,
        "the reader did not receive what the unprivileged half held"
    );
    let _ = std::fs::remove_file(&file);
}

/// §5.7, through the whole stack rather than at one layer.
///
/// The provider lies about length. The daemon catches it, and so would the
/// helper — the point of the test is that the reader gets an error and the file
/// is left exactly as it was, whichever check fired.
#[test]
fn a_lying_provider_reaches_the_reader_as_an_error() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let file = seed(&mnt, "liar.bin", BODY);

    let conn = start_daemon(
        &mnt,
        Fake {
            body: BODY.to_vec(),
            truncate_to: Some(BODY.len() / 2),
        },
    );

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::new(
        group,
        SocketFetch::new(conn, &mnt),
        Policy::permissive(),
        InFlight::new(),
    );

    let reader = std::process::Command::new("cat")
        .arg(&file)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("reader");

    let seen = worker
        .run(Instant::now() + Duration::from_secs(5))
        .expect("worker");
    let out = reader.wait_with_output().expect("reader output");

    assert!(
        seen.iter().any(|h| matches!(h, Handled::Failed { .. })),
        "a short body was accepted somewhere in the stack: {seen:?}"
    );
    assert!(
        !out.status.success(),
        "the reader was handed {} bytes of a file it asked {} bytes about",
        out.stdout.len(),
        BODY.len()
    );
    assert!(
        placeholder::is_dehydrated(&file).unwrap(),
        "a partially filled placeholder survived"
    );
    let _ = std::fs::remove_file(&file);
}

/// A file the daemon has no cloud ID for is refused, and refused distinctly.
///
/// This is the locally-created case: the file exists, it has never been
/// uploaded, and the only copy is the one on disk. Serving zeros for it would be
/// the exact failure this framework exists to make impossible.
#[test]
fn a_file_that_was_never_uploaded_is_not_served_as_zeros() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    let file = mnt.join("never-uploaded.bin");
    let _ = std::fs::remove_file(&file);
    placeholder::create(&file, 128, 0o644).expect("create");
    // Deliberately no cloud-id xattr.

    let conn = start_daemon(
        &mnt,
        Fake {
            body: vec![b'?'; 128],
            truncate_to: None,
        },
    );

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let mut worker = Worker::new(
        group,
        SocketFetch::new(conn, &mnt),
        Policy::permissive(),
        InFlight::new(),
    );

    let reader = std::process::Command::new("cat")
        .arg(&file)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("reader");

    let seen = worker
        .run(Instant::now() + Duration::from_secs(5))
        .expect("worker");
    let out = reader.wait_with_output().expect("reader output");

    assert!(
        seen.iter().any(|h| matches!(h, Handled::Failed { .. })),
        "a file with no remote copy was hydrated anyway: {seen:?}"
    );
    assert!(
        !out.status.success(),
        "a file with no remote copy was served as {} bytes",
        out.stdout.len()
    );
    let _ = std::fs::remove_file(&file);
}

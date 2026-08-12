//! A client restart must not cost the mount.
//!
//! ```text
//! sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch cargo test -p hydrationd --test reconnect
//! ```
//!
//! Measured on a live deployment, 2026-08-12: `systemctl --user restart
//! onedrive-hydration.service` — which systemd does on upgrade, on failure, and
//! on a user's whim — killed the helper's established socket. The helper had no
//! way back to a peer that was listening again seconds later: every fetch
//! failed on the dead connection, the failures counted toward `wedged()`, and
//! 4½ minutes later the worker gave up and the helper detached the mount. A
//! routine restart of the unprivileged half tore down the privileged one.
//!
//! These tests drive that exact sequence at test scale: a real listener at a
//! real socket path, a real `Daemon` behind it, a worker fetching through
//! `SocketFetch` — then the client is killed and a new one binds the same path,
//! which is what a systemd restart looks like from the helper's end of the
//! socket.

use hydration_client::{store, Daemon, Provider};
use hydration_protocol::transport::DaemonConn;
use hydrationd::daemon::Worker;
use hydrationd::fanotify::Group;
use hydrationd::placeholder;
use hydrationd::policy::Policy;
use hydrationd::remote::SocketFetch;
use hydrationd::supervisor::InFlight;
use std::io;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

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

/// Somewhere short enough for `sun_path` (108 bytes), outside the marked
/// mount — a write inside it is §6a-ter's trap, and binding a socket there
/// would be exactly the kind of clever that has cost this project time.
fn socket_path(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hydrarc-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    dir.join(format!("{tag}.sock"))
}

/// Stands in for a cloud, on the far side of the socket.
struct Fake {
    body: Vec<u8>,
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
        let end = (span.end() as usize).min(self.body.len());
        let start = (span.offset as usize).min(end);
        out.write_all(&self.body[start..end])
    }
}

/// A placeholder the daemon knows the cloud ID of. Created before the mark,
/// always: giving a file its size is a write (§6a-ter).
fn seed(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
    let p = dir.join(name);
    let _ = std::fs::remove_file(&p);
    placeholder::create(&p, body.len() as u64, 0o644).expect("create placeholder");
    store::set_xattr(&p, store::XATTR_ID, b"cloud-object-1").expect("record cloud id");
    p
}

/// One incarnation of the sync daemon: a listener at `sock`, one accepted
/// connection served until it dies. `die` shuts the accepted stream down the
/// way process death does — from the helper's side the two are the same FIN.
struct Client {
    /// Delivered by the serving thread once it has accepted. Fetched lazily,
    /// because the accept can only happen after `start` has returned and the
    /// helper has connected — waiting for it inside `start` deadlocks.
    accepted: mpsc::Receiver<UnixStream>,
    thread: std::thread::JoinHandle<()>,
}

impl Client {
    fn start(root: &Path, sock: &Path, body: &[u8]) -> Self {
        // What the real daemon does on every start: unlink whatever a previous
        // life left at the path, bind fresh.
        let _ = std::fs::remove_file(sock);
        let listener = UnixListener::bind(sock).expect("bind");
        let (tx, rx) = mpsc::channel();
        let root = root.to_path_buf();
        let provider = Fake {
            body: body.to_vec(),
        };
        let thread = std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            tx.send(stream.try_clone().expect("clone"))
                .expect("handoff");
            let mut d = Daemon::new(provider, &root).expect("daemon");
            let mut conn = DaemonConn::new(stream).expect("daemon conn");
            let _ = d.serve(&mut conn);
        });
        Self {
            accepted: rx,
            thread,
        }
    }

    /// The client dies. `shutdown` on both halves is what the kernel does to
    /// the socket when the process is killed.
    fn die(self) {
        let conn = self
            .accepted
            .recv_timeout(Duration::from_secs(10))
            .expect("the client never accepted a connection, so there is nothing to restart");
        let _ = conn.shutdown(std::net::Shutdown::Both);
        let _ = self.thread.join();
    }
}

/// Fork a reader and wait for it, insisting it comes back at all.
///
/// Exit code says what happened: 0 content, 1 error, 7 zeros. A reader that
/// never returns is the §6a-bis failure — blocked in `read()`, unkillable — and
/// is reported as such rather than as a timeout.
fn read_outcome(worker: &mut Worker<SocketFetch>, path: &Path, patience: Duration) -> i32 {
    let reader = unsafe { libc::fork() };
    if reader == 0 {
        let code = match std::fs::read(path) {
            Ok(b) if b.iter().all(|&x| x == 0) => 7,
            Ok(_) => 0,
            Err(_) => 1,
        };
        unsafe { libc::_exit(code) };
    }
    let began = Instant::now();
    let mut status = 0;
    while began.elapsed() < patience {
        let _ = worker.run(Instant::now() + Duration::from_millis(200));
        if unsafe { libc::waitpid(reader, &mut status, libc::WNOHANG) } == reader {
            return libc::WEXITSTATUS(status);
        }
    }
    unsafe {
        libc::kill(reader, libc::SIGKILL);
        libc::waitpid(reader, &mut status, 0);
    }
    panic!(
        "a reader of {} was still blocked after {patience:?}",
        path.display()
    );
}

/// The incident: restart the client under a live helper, and the mount must
/// survive — the next read hydrates instead of feeding the give-up clock.
#[test]
fn a_client_restart_does_not_cost_the_mount() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    const BODY: &[u8] = b"content that survived a client restart\n";
    let sock = socket_path("restart");
    let before = seed(&mnt, "before-restart.bin", BODY);
    let after = seed(&mnt, "after-restart.bin", BODY);

    let first = Client::start(&mnt, &sock, BODY);
    let stream = UnixStream::connect(&sock).expect("connect");
    let conn = hydration_protocol::transport::HelperConn::new(stream).expect("helper conn");

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let uid = unsafe { libc::geteuid() };
    let mut worker = Worker::with_deadline(
        group.try_clone().expect("clone"),
        SocketFetch::reconnecting(conn, &mnt, &sock, Some(uid)),
        Policy::permissive(),
        InFlight::new(),
        Duration::from_secs(5),
    );

    // The pair works before anything is restarted, or the test is measuring a
    // broken harness rather than a restart.
    assert_eq!(
        read_outcome(&mut worker, &before, Duration::from_secs(20)),
        0,
        "the first read did not hydrate; the harness never worked"
    );

    // The restart. The helper is told nothing — exactly as in production,
    // where the first it hears of it is its next fetch failing.
    first.die();
    let second = Client::start(&mnt, &sock, BODY);

    let outcome = read_outcome(&mut worker, &after, Duration::from_secs(20));
    assert_eq!(
        outcome, 0,
        "a read after a client restart returned {outcome} (1=EIO, 7=zeros) — \
         the helper never found its way back to a peer that was listening again"
    );
    assert!(
        !worker.fetcher_wedged(),
        "the fetcher is still counting toward giving up after a successful \
         reconnect; the mount would come down {}s later for no reason",
        hydrationd::daemon::WEDGED_LIMIT.as_secs()
    );

    second.die();
    for p in [&before, &after] {
        let _ = std::fs::remove_file(p);
    }
    let _ = std::fs::remove_file(&sock);
}

/// The bound behind the reconnect: a client that stays gone must still bring
/// the mount down, §6a-bis — promptly answered readers all the while.
///
/// This is the same fact `deadlines.rs` pins with a fake fetcher, driven here
/// through the real socket path so the reconnect machinery is what produces
/// the connection-lost errors being counted.
#[test]
fn a_client_that_stays_gone_still_counts_toward_giving_up() {
    let Some(mnt) = mount() else {
        skip("needs root and HYDRATIOND_TEST_MOUNT on a real filesystem");
        return;
    };
    const BODY: &[u8] = b"content nobody will get to fetch twice\n";
    let sock = socket_path("gone");
    let warm = seed(&mnt, "gone-0.bin", BODY);
    let cold: Vec<PathBuf> = (1..5)
        .map(|i| seed(&mnt, &format!("gone-{i}.bin"), BODY))
        .collect();

    let only = Client::start(&mnt, &sock, BODY);
    let stream = UnixStream::connect(&sock).expect("connect");
    let conn = hydration_protocol::transport::HelperConn::new(stream).expect("helper conn");

    let group = Group::new_pre_content().expect("group");
    group.mark_mount(&mnt).expect("mark");
    let uid = unsafe { libc::geteuid() };
    let mut worker = Worker::with_deadline(
        group.try_clone().expect("clone"),
        SocketFetch::reconnecting(conn, &mnt, &sock, Some(uid)),
        Policy::permissive(),
        InFlight::new(),
        Duration::from_secs(5),
    );

    assert_eq!(
        read_outcome(&mut worker, &warm, Duration::from_secs(20)),
        0,
        "the first read did not hydrate; the harness never worked"
    );

    // Gone for good: no process will ever bind this path again. `connect()`
    // gets ENOENT rather than ECONNREFUSED; both must count the same way.
    only.die();
    let _ = std::fs::remove_file(&sock);

    for path in &cold {
        let began = Instant::now();
        let outcome = read_outcome(&mut worker, path, Duration::from_secs(30));
        assert_eq!(
            outcome, 1,
            "a read with no client anywhere returned {outcome}; 7 means zeros \
             were served"
        );
        // Prompt, not a deadline each: the reconnect attempts are bounded and
        // a dead socket path fails fast. 15s of patience allows for the
        // bounded in-event retry window plus scheduling noise; what it must
        // never be is the full first-byte deadline plus the wedge limit.
        assert!(
            began.elapsed() < Duration::from_secs(15),
            "a reader waited {:?} on a client that is provably gone",
            began.elapsed()
        );
    }

    assert!(
        worker.fetcher_wedged(),
        "four fetches against a vanished client left the fetcher unwedged — \
         nothing would ever bring this mount down, and it would serve EIO \
         forever behind two healthy-looking processes"
    );
    for p in std::iter::once(&warm).chain(&cold) {
        let _ = std::fs::remove_file(p);
    }
}

//! The conformance suite, against this framework.
//!
//! The suite is what makes either architecture trustworthy, and until now it had
//! only ever been pointed at the FUSE client it was written to measure. A
//! framework that has never been held to its own contract is a framework that
//! passes its own bespoke tests, which is a weaker claim than it looks.
//!
//! Running it here also makes invariant 6a *applicable* for the first time.
//! Against a FUSE client it is `N/A` — there is no separable hydration worker to
//! kill. Here it is the whole point, and the thing the design spends a
//! supervisor and a shared memory page on.
//!
//! # Shape
//!
//! Both halves, for real, in the arrangement the deployment uses:
//!
//! ```text
//!   test process
//!     main thread    the invariant, doing ordinary POSIX operations
//!     daemon thread  serves fetch requests over the socket
//!     upload thread  drives the queue
//!     supervisor     waits for the worker, then fails closed
//!   forked child
//!     worker         answers pre-content events, fetches over the socket
//! ```
//!
//! The fork happens before any thread is spawned. That ordering is not style: a
//! thread holding a lock at fork time leaves the child holding it forever.

pub mod cloud;

use cloud::Cloud;
use hydration_client::store::{self, Store};
use hydration_client::upload::{run_upload, Queue, SystemClock};
use hydration_client::Daemon;
use hydration_conformance::{CloudObject, CloudOp, FetchBehaviour, Harness};
use hydration_protocol::transport::{DaemonConn, HelperConn};
use hydrationd::daemon::Worker;
use hydrationd::fanotify::Group;
use hydrationd::policy::Policy;
use hydrationd::remote::SocketFetch;
use hydrationd::supervisor::{deny, InFlight};
use hydrationd::{evict, placeholder};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Short enough that a test does not sit through it, long enough that an edit is
/// still visibly pending the moment after it is written — which is what §5.6
/// asks about.
const DEBOUNCE: Duration = Duration::from_secs(3);

pub struct Framework {
    mount: PathBuf,
    cloud: Cloud,
    store: Arc<Mutex<Store>>,
    queue: Arc<Mutex<Queue<SystemClock>>>,
    group: Arc<Group>,
    worker_pid: i32,
    worker_dead: Arc<AtomicBool>,
    in_flight: InFlight,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl Framework {
    /// `None` where this cannot run: not root, or no real mount to work in.
    pub fn start() -> Option<Self> {
        let mount = PathBuf::from(std::env::var_os("HYDRATION_TEST_MOUNT")?);
        if !mount.is_dir() || unsafe { libc::geteuid() } != 0 {
            return None;
        }
        // Each run starts from an empty directory: the invariants are a
        // specification, not a sequence, and one must not pass because another
        // left something behind.
        for e in std::fs::read_dir(&mount).ok()?.flatten() {
            let _ = std::fs::remove_file(e.path());
        }

        let cloud = Cloud::default();
        let (helper_side, daemon_side) = UnixStream::pair().ok()?;

        let group = Group::new_pre_content().ok()?;
        group.mark_mount(&mount).ok()?;
        let in_flight = InFlight::new();
        let worker_view = in_flight.share();

        // Fork before any thread exists.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return None;
        }
        let group = Arc::new(group);

        if child == 0 {
            let fetch = SocketFetch::new(HelperConn::new(helper_side).unwrap(), &mount);
            let mut w = Worker::new(
                group.try_clone().unwrap(),
                fetch,
                Policy::permissive(),
                worker_view,
            );
            let _ = w.run(Instant::now() + Duration::from_secs(600));
            unsafe { libc::_exit(0) };
        }
        drop(helper_side);

        // The parent keeps a handle on the *same* group, inherited across the
        // fork. Creating a second one and marking the mount again looks
        // harmless and is not: every marked group gets its own copy of every
        // event, and every copy has to be answered. A second group with nobody
        // serving it means the first write into the sync directory blocks
        // forever — which is what happened here, and took a thread-state dump
        // to find, because the worker sits in `poll()` looking perfectly
        // healthy while the writer is stuck in the kernel.

        let store = Arc::new(Mutex::new({
            let mut s = Store::new();
            let _ = s.scan(&mount);
            s
        }));
        let queue = Arc::new(Mutex::new(Queue::new(DEBOUNCE, SystemClock::default())));
        let stop = Arc::new(AtomicBool::new(false));
        let worker_dead = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();

        // The unprivileged daemon: answers fetches over the socket.
        {
            let cloud = cloud.clone();
            let mount = mount.clone();
            threads.push(std::thread::spawn(move || {
                let mut d = match Daemon::new(cloud, &mount) {
                    Ok(d) => d,
                    Err(_) => return,
                };
                let mut conn = match DaemonConn::new(daemon_side) {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let _ = d.serve(&mut conn);
            }));
        }

        // The upload driver.
        //
        // It keeps its *own* Store rather than sharing the harness's. The store
        // is only an index over the filesystem, so a second copy costs a walk
        // and nothing else — and sharing it deadlocks: a held upload waits on
        // the gate from inside `Sink::upload`, which runs with the store
        // borrowed, so every status query behind that lock stops until the
        // upload is released. Both threads sat in futex and neither could say
        // why.
        {
            let (q, cl, stop, mount) = (
                Arc::clone(&queue),
                cloud.clone(),
                Arc::clone(&stop),
                mount.clone(),
            );
            threads.push(std::thread::spawn(move || {
                let mut sink = cl;
                let mut store = Store::new();
                while !stop.load(Ordering::SeqCst) {
                    let due = q.lock().unwrap().due();
                    if !due.is_empty() {
                        let _ = store.scan(&mount);
                    }
                    for file in due {
                        q.lock().unwrap().begin(file);
                        let outcome = run_upload(file, &mut store, &mut sink);
                        q.lock().unwrap().finish();
                        let _ = outcome;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }));
        }

        // The supervisor. Once the worker is gone, everything is denied — this
        // is the half of §6a that a FUSE client has no equivalent for.
        {
            let (g, inf, dead, stop) = (
                Arc::clone(&group),
                in_flight.share(),
                Arc::clone(&worker_dead),
                Arc::clone(&stop),
            );
            threads.push(std::thread::spawn(move || {
                let mut status = 0;
                unsafe { libc::waitpid(child, &mut status, 0) };
                dead.store(true, Ordering::SeqCst);

                // The event the worker died holding left the queue with it, so
                // it can only be answered by number.
                if let Some(stranded) = inf.current() {
                    let _ = deny(&g, stranded);
                }

                let mut buf = vec![0u8; 64 * 1024];
                while !stop.load(Ordering::SeqCst) {
                    let mut pfd = libc::pollfd {
                        fd: g.as_raw(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
                        continue;
                    }
                    let Ok(len) = g.read_events(&mut buf) else {
                        break;
                    };
                    for ev in hydrationd::fanotify::events(&buf, len) {
                        if ev.fd >= 0 {
                            let _ = deny(&g, ev.fd);
                            unsafe { libc::close(ev.fd) };
                        }
                    }
                }
            }));
        }

        Some(Self {
            mount,
            cloud,
            store,
            queue,
            group,
            worker_pid: child,
            worker_dead,
            in_flight,
            stop,
            threads,
        })
    }

    fn rescan(&self) {
        let mut s = self.store.lock().unwrap();
        let _ = s.scan(&self.mount);
    }

    /// Notice local changes and queue them.
    ///
    /// The real daemon learns this from the watcher; here it is a scan, because
    /// the invariants are about what happens to a queued change and not about
    /// how promptly it was noticed.
    fn notice_changes(&self) {
        self.rescan();

        // Gathered under the store lock, queued under the queue lock, never
        // both at once. The upload thread takes them in the other order —
        // queue, then store — so holding both here is a lock-order inversion.
        // It deadlocked the whole suite at 5.4, with every thread asleep and
        // nothing to say why.
        let mut changed = Vec::new();
        {
            let store = self.store.lock().unwrap();
            for entry in std::fs::read_dir(&self.mount)
                .into_iter()
                .flatten()
                .flatten()
            {
                let Ok(md) = entry.metadata() else { continue };
                if !md.is_file() {
                    continue;
                }
                let id = hydration_protocol::FileId {
                    fsid: md.dev(),
                    ino: md.ino(),
                };
                // A dehydrated file has no local content to send. Reading one
                // here would also hydrate it, which is a side effect a scan has
                // no business having.
                if placeholder::is_dehydrated(&entry.path()).unwrap_or(false) {
                    continue;
                }
                let local = std::fs::read(entry.path()).unwrap_or_default();
                let same = store
                    .lookup(&id)
                    .and_then(|e| e.cloud_id)
                    .and_then(|cid| self.cloud.state.lock().unwrap().objects.get(&cid).cloned())
                    .map(|o| o.content == local)
                    .unwrap_or(false);
                if !same {
                    changed.push(id);
                }
            }
        }

        let mut q = self.queue.lock().unwrap();
        for id in changed {
            q.touch(id);
        }
    }
}

impl Harness for Framework {
    fn sync_dir(&self) -> &Path {
        &self.mount
    }

    fn seed_remote(&mut self, name: &str, content: &[u8], etag: &str) -> String {
        let id = self.cloud.seed(name, content, etag);
        let path = self.mount.join(name);
        let _ = std::fs::remove_file(&path);
        placeholder::create(&path, content.len() as u64, 0o644).expect("placeholder");
        store::set_xattr(&path, store::XATTR_ID, id.as_bytes()).expect("record cloud id");
        store::set_xattr(&path, store::XATTR_ETAG, etag.as_bytes()).ok();
        self.rescan();
        id
    }

    fn remote(&self, name: &str) -> Option<CloudObject> {
        self.cloud.by_name(name)
    }

    fn ops_observed(&self) -> Vec<CloudOp> {
        self.cloud.ops()
    }

    fn hold_uploads(&mut self) {
        // Holding also brings the deadlines forward. Otherwise arranging a race
        // would mean sitting out the debounce first, and a test that waits is a
        // test that gets shortened until it stops testing the race.
        self.cloud.hold();
        self.notice_changes();
        self.queue.lock().unwrap().flush_now();
    }

    fn release_uploads(&mut self) {
        self.cloud.release();
    }

    fn wait_for_upload_start(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            self.notice_changes();
            self.queue.lock().unwrap().flush_now();
            if self.cloud.upload_started() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        false
    }

    fn settle(&mut self) {
        self.cloud.release();
        for _ in 0..80 {
            self.notice_changes();
            self.queue.lock().unwrap().flush_now();
            std::thread::sleep(Duration::from_millis(50));
            if self.queue.lock().unwrap().pending() == 0 {
                // One more pass: a change made during the last sleep would
                // otherwise be left queued and reported as settled.
                self.notice_changes();
                if self.queue.lock().unwrap().pending() == 0 {
                    break;
                }
            }
        }
        self.rescan();
    }

    fn set_fetch_behaviour(&mut self, name: &str, behaviour: FetchBehaviour) {
        self.cloud.set_behaviour(name, behaviour);
    }

    fn dehydrate(&mut self, name: &str) {
        let path = self.mount.join(name);
        // The content has to exist somewhere else first, or evicting it is
        // deleting it. Settling makes sure it does.
        self.settle();

        // The ignore mark protects the punch from generating an event nobody
        // answers. It must come off again whatever happens next: `evict` removes
        // it on success, but on any early return it would be left behind — and a
        // file with an ignore mark is never intercepted again, so every later
        // read of it is served the zeros the eviction left behind. Silently.
        let _ = self.group.ignore(&path);
        let safe = || {
            store::get_xattr(&path, store::XATTR_ID)
                .ok()
                .flatten()
                .is_some()
        };
        let outcome = evict::evict(&self.group, &path, safe);
        match outcome {
            Ok(Ok(())) => {}
            other => {
                // evict did not get as far as removing the mark. Undo it here
                // rather than leaving the file permanently invisible.
                let _ = self.group.unignore(&path);
                match other {
                    Ok(Err(r)) => panic!("the harness could not dehydrate {name}: {r:?}"),
                    Err(e) => panic!("the harness could not dehydrate {name}: {e}"),
                    Ok(Ok(())) => unreachable!(),
                }
            }
        }
    }

    fn pending_uploads(&self) -> usize {
        self.notice_changes();
        self.queue.lock().unwrap().pending()
    }

    fn dehydrated_count(&self) -> usize {
        std::fs::read_dir(&self.mount)
            .into_iter()
            .flatten()
            .flatten()
            .filter(|e| {
                e.metadata()
                    .map(|m| m.is_file() && m.blocks() == 0)
                    .unwrap_or(false)
            })
            .count()
    }

    fn kill_hydration_worker(&mut self) {
        unsafe { libc::kill(self.worker_pid, libc::SIGKILL) };
        // The supervisor thread reaps it and takes over.
        for _ in 0..100 {
            if self.worker_dead.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The reason this adapter exists.
    fn has_separable_worker(&self) -> bool {
        true
    }
}

impl Drop for Framework {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        unsafe { libc::kill(self.worker_pid, libc::SIGKILL) };
        let _ = self.in_flight.current();
        for t in self.threads.drain(..) {
            // The daemon thread blocks on a socket the child owned; closing our
            // end is what lets it finish.
            let _ = t.join();
        }
    }
}

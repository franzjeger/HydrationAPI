//! Attack tests for the `hydration-graph` *driver* — everything between
//! `Discover::changes` and the `PageSource` seam.
//!
//! `tests/mapping.rs` covers one page in isolation. Nothing there can fail an
//! implementation that maps every item perfectly and then asks for the wrong
//! URL, persists the wrong string, or answers a repeated cursor by consuming a
//! tombstone the framework never applied. Those are the failures in this file,
//! and every one of them is silent on the day it happens.
//!
//! Three construction rules, all of them paid for by the critiques in
//! `docs/GRAPH-GROUNDWORK.md`:
//!
//!   * **The wrong branch is always scripted to succeed.** A test that passes
//!     because the bad path happened to error is a test that passes for the
//!     wrong reason. `latest()` returns a valid page. `first()` returns a valid
//!     enumeration. A foreign host answers with a well-formed deltaLink. The
//!     only thing that distinguishes right from wrong is the recorded log.
//!   * **Every refusal has a positive control.** "Never enumerate", "never
//!     resume", "never advance" and "always escalate" each satisfy a whole
//!     class of these tests while destroying the product.
//!   * **Nothing sleeps, and nothing touches a clock, a socket or a disk.** The
//!     `Sleeper` is injected and records; a throttling test that asserts on
//!     wall-clock time puts a seven-second floor under the suite and is skipped
//!     in CI within a month.
//!
//! ## The two cursors
//!
//! `PROVIDER.md:127-131` says the framework does not persist `Cursor`, and
//! `bin/hydration-sync.rs:452` hands `Cursor::default()` after every restart.
//! The `StateStore` is therefore the only durable position. But the incoming
//! cursor is not noise either — being handed a value already served is the
//! *only* signal a provider ever gets that the framework could not apply the
//! last batch (`hydration-sync.rs:483-490` holds the cursor on a retryable pass
//! and never speaks to the provider about it again).
//!
//! Both readings are load-bearing, so this file fixes the discriminator
//! explicitly, and every test below is written against it:
//!
//!   * a **fresh instance** — a restart — starts from the store, whatever
//!     cursor it is handed;
//!   * the **same instance** handed the same *input* cursor it was last handed,
//!     after a call that succeeded, is a repeat: re-serve from memory, issue no
//!     request, and count it toward the stall guard;
//!   * the same instance handed anything else runs the next round.
//!
//! A call that returned `Err` is not remembered, so a retry after a failure is a
//! fresh round rather than a repeat.
//!
//! That third case carries one more job. A round derives its tree and its token
//! and writes *neither*: being handed a different cursor is the only evidence
//! this trait ever gives that a batch was applied, so it is the only moment at
//! which advancing the durable position is safe. The previous round's pair is
//! committed there — tree first, then token, the ordering rule unchanged —
//! before the new round reads the store. A crash in between costs one round
//! trip and nothing else, whereas advancing under an unapplied batch loses any
//! removal in it for good: Graph does not replay a consumed tombstone,
//! `listing()` cannot express a deletion, and `Namespace::apply(Item::Delete)`
//! for an id the tree no longer holds emits nothing at all. Tests that need a
//! round's state on disk say so with [`ack`].

#![allow(clippy::type_complexity)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hydration_client::delta::{Change, Cursor, Discover};
use hydration_client::namespace::{Item, Kind};
use hydration_graph::{
    delta_url, DriveId, DriveScope, Escalation, GraphDiscover, ItemId, ObjectKey,
    PageSource, PersistedState, RawPage, Sleeper, StateStore, TagSource, TokenBlob, TreeBlob,
    MAX_PAGES_PER_ROUND,
};

// ===========================================================================
// Ids, links and fixtures
// ===========================================================================

const MINE: &str = "b!mine";
const THEIRS: &str = "b!theirs";
const OLD: &str = "b!old";
const NEW: &str = "b!new";
const ROOT: &str = "01ROOT";

fn drive_id(s: &str) -> DriveId {
    DriveId::parse(s).unwrap_or_else(|e| panic!("fixture drive id {s:?} must parse: {e:?}"))
}

fn item_id(s: &str) -> ItemId {
    ItemId::parse(s).unwrap_or_else(|e| panic!("fixture item id {s:?} must parse: {e:?}"))
}

fn okey(drive: &str, item: &str) -> ObjectKey {
    ObjectKey::new(drive_id(drive), item_id(item))
}

/// The expected `cloud_id`, built the only way the crate permits one to be built.
fn cloud(drive: &str, item: &str) -> String {
    okey(drive, item).to_cloud_id().into_inner()
}

fn primary(drive: &str) -> DriveScope {
    DriveScope::primary(drive_id(drive))
}

/// A link on the real endpoint. Every legitimate link in this file goes through
/// here, so the origin check has one thing to agree with.
fn link_on(drive: &str, token: &str) -> String {
    format!("https://graph.microsoft.com/v1.0/drives/{drive}/root/delta?token={token}")
}

/// A link on the primary drive.
fn lnk(token: &str) -> String {
    link_on(MINE, token)
}

// --- wire fixtures ---------------------------------------------------------

fn root_json(drive: &str, id: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"root","root":{{}},"folder":{{"childCount":1}},
            "parentReference":{{"driveId":"{drive}"}}}}"#
    )
}

fn file_json(drive: &str, id: &str, name: &str, parent: &str, size: u64, ctag: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","size":{size},"cTag":"{ctag}",
            "file":{{"mimeType":"text/plain"}},
            "parentReference":{{"driveId":"{drive}","id":"{parent}"}},
            "fileSystemInfo":{{"lastModifiedDateTime":"2026-08-02T09:15:31Z"}}}}"#
    )
}

/// A file that carries a quickXorHash and no cTag — the drive shape that pins
/// `TagSource::QuickXor`.
fn qx_file_json(drive: &str, id: &str, name: &str, parent: &str, size: u64, qx: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","size":{size},
            "file":{{"mimeType":"text/plain","hashes":{{"quickXorHash":"{qx}"}}}},
            "parentReference":{{"driveId":"{drive}","id":"{parent}"}}}}"#
    )
}

/// The same item once the service has started reporting a cTag as well.
fn qx_and_ctag_file_json(
    drive: &str,
    id: &str,
    name: &str,
    parent: &str,
    size: u64,
    qx: &str,
    ctag: &str,
) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","size":{size},"cTag":"{ctag}",
            "file":{{"mimeType":"text/plain","hashes":{{"quickXorHash":"{qx}"}}}},
            "parentReference":{{"driveId":"{drive}","id":"{parent}"}}}}"#
    )
}

fn folder_json(drive: &str, id: &str, name: &str, parent: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","size":4096,"folder":{{"childCount":0}},
            "parentReference":{{"driveId":"{drive}","id":"{parent}"}}}}"#
    )
}

fn package_json(drive: &str, id: &str, name: &str, parent: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","size":4096,"folder":{{"childCount":3}},
            "package":{{"type":"oneNote"}},
            "parentReference":{{"driveId":"{drive}","id":"{parent}"}}}}"#
    )
}

/// Graph sends a bare `"deleted":{}` as often as it sends a state.
fn tomb_json(drive: &str, id: &str, name: &str, parent: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","deleted":{{}},
            "parentReference":{{"driveId":"{drive}","id":"{parent}"}}}}"#
    )
}

/// A near-drive placeholder for a folder that lives on another drive.
fn share_json(
    near_drive: &str,
    near_id: &str,
    name: &str,
    near_parent: &str,
    far_drive: &str,
    far_id: &str,
    far_parent: &str,
) -> String {
    format!(
        r#"{{"id":"{near_id}","name":"{name}","size":4096,
            "remoteItem":{{"id":"{far_id}","name":"{name}","size":4096,
              "folder":{{"childCount":1}},
              "parentReference":{{"driveId":"{far_drive}","id":"{far_parent}"}}}},
            "parentReference":{{"driveId":"{near_drive}","id":"{near_parent}"}}}}"#
    )
}

fn body_next(items: &[String], next: &str) -> String {
    format!(
        r#"{{"value":[{}],"@odata.nextLink":"{}"}}"#,
        items.join(","),
        next
    )
}

fn body_delta(items: &[String], delta: &str) -> String {
    format!(
        r#"{{"value":[{}],"@odata.deltaLink":"{}"}}"#,
        items.join(","),
        delta
    )
}

// --- tree fixtures ---------------------------------------------------------

fn root_item(drive: &str, id: &str) -> Item {
    Item::Root {
        id: cloud(drive, id),
    }
}

fn file_item(drive: &str, id: &str, parent: &str, name: &str, size: u64, ctag: &str) -> Item {
    Item::Upsert {
        id: cloud(drive, id),
        parent: cloud(drive, parent),
        name: name.into(),
        kind: Kind::File {
            size,
            ctag: Some(format!("ct:{ctag}")),
        },
    }
}

fn folder_item(drive: &str, id: &str, parent: &str, name: &str) -> Item {
    Item::Upsert {
        id: cloud(drive, id),
        parent: cloud(drive, parent),
        name: name.into(),
        kind: Kind::Folder,
    }
}

/// A tree and a token that agree, as a completed round would have written them.
fn primed(items: &[Item], token: Option<&str>) -> PersistedState {
    let drive = drive_id(MINE);
    match token {
        Some(t) => PersistedState::consistent(
            &drive,
            TagSource::CTag,
            items,
            &TokenBlob::one(&drive, &lnk(t)),
        ),
        None => PersistedState::tree_only(&drive, TagSource::CTag, items),
    }
}

// ===========================================================================
// The doubles
//
// One journal shared by the page source, the store and the sleeper, so the
// *interleaving* of a request, a sleep and a write is observable — which is the
// only way to say "it slept between the two fetches" rather than "it slept".
// ===========================================================================

/// A request as the seam sees it. `First`/`Latest` carry the drive so a fan-out
/// round can be told apart from a re-enumeration of the primary.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Req {
    First(String),
    Next(String),
    Resume(String),
    Latest(String),
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Ev {
    Call(Req),
    Slept(Duration),
    Load,
    /// The number of items in the blob handed to `save_tree`.
    SaveTree(usize),
    SaveTreeFailed,
    /// `drive=link` pairs, sorted and joined — the whole blob, renderable.
    SaveToken(String),
    SaveTokenFailed,
}

#[derive(Clone, Default)]
struct Journal(Arc<Mutex<Vec<Ev>>>);

impl Journal {
    fn push(&self, e: Ev) {
        self.0.lock().unwrap().push(e);
    }

    fn all(&self) -> Vec<Ev> {
        self.0.lock().unwrap().clone()
    }

    fn calls(&self) -> Vec<Req> {
        self.all()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Call(r) => Some(r),
                _ => None,
            })
            .collect()
    }

    fn sleeps(&self) -> Vec<Duration> {
        self.all()
            .into_iter()
            .filter_map(|e| match e {
                Ev::Slept(d) => Some(d),
                _ => None,
            })
            .collect()
    }

    /// Everything the store did, in order.
    fn store_events(&self) -> Vec<Ev> {
        self.all()
            .into_iter()
            .filter(|e| {
                matches!(
                    e,
                    Ev::Load
                        | Ev::SaveTree(_)
                        | Ev::SaveTreeFailed
                        | Ev::SaveToken(_)
                        | Ev::SaveTokenFailed
                )
            })
            .collect()
    }

    /// The store's writes only — `load` is noise in an ordering assertion.
    fn writes(&self) -> Vec<Ev> {
        self.store_events()
            .into_iter()
            .filter(|e| !matches!(e, Ev::Load))
            .collect()
    }

    fn token_writes(&self) -> Vec<String> {
        self.all()
            .into_iter()
            .filter_map(|e| match e {
                Ev::SaveToken(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

// --- the page source -------------------------------------------------------

#[derive(Clone, Debug)]
enum Reply {
    Page(RawPage),
    Fail(io::ErrorKind, String),
}

impl Reply {
    fn ok(body: String) -> Reply {
        Reply::Page(RawPage {
            status: 200,
            retry_after: None,
            body: body.into_bytes(),
        })
    }

    fn status(status: u16, body: &str) -> Reply {
        Reply::Page(RawPage {
            status,
            retry_after: None,
            body: body.as_bytes().to_vec(),
        })
    }

    fn throttled(secs: u64) -> Reply {
        Reply::Page(RawPage {
            status: 429,
            retry_after: Some(Duration::from_secs(secs)),
            body: br#"{"error":{"code":"activityLimitReached"}}"#.to_vec(),
        })
    }

    fn fail(kind: io::ErrorKind, what: &str) -> Reply {
        Reply::Fail(kind, what.to_string())
    }

    fn to_result(&self) -> io::Result<RawPage> {
        match self {
            Reply::Page(p) => Ok(p.clone()),
            Reply::Fail(k, what) => Err(io::Error::new(*k, what.clone())),
        }
    }
}

/// A `PageSource` scripted by request.
///
/// The last reply for a key repeats forever, so `[throttled, ok]` means "429
/// once, then fine" and `[ok]` means "answerable as often as asked". An
/// unscripted request is *recorded* and then fails, so an attempt to take a path
/// this test forbids is visible in the log rather than silently satisfied.
///
/// A hard call cap panics with the whole journal attached: a driver that loops
/// must fail deterministically in milliseconds, not hang the suite.
#[derive(Clone)]
struct Pages {
    journal: Journal,
    script: Arc<Mutex<BTreeMap<Req, Vec<Reply>>>>,
    calls: Arc<Mutex<usize>>,
    cap: usize,
}

impl Pages {
    fn new(journal: Journal, cap: usize) -> Self {
        Self {
            journal,
            script: Arc::new(Mutex::new(BTreeMap::new())),
            calls: Arc::new(Mutex::new(0)),
            cap,
        }
    }

    fn script(&self, req: Req, replies: Vec<Reply>) {
        self.script.lock().unwrap().insert(req, replies);
    }

    fn answer(&mut self, req: Req) -> io::Result<RawPage> {
        self.journal.push(Ev::Call(req.clone()));
        let n = {
            let mut c = self.calls.lock().unwrap();
            *c += 1;
            *c
        };
        assert!(
            n <= self.cap,
            "the page source was called {n} times (cap {}); the driver is looping.\n{:#?}",
            self.cap,
            self.journal.all()
        );
        let mut script = self.script.lock().unwrap();
        let Some(queue) = script.get_mut(&req) else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unscripted request: {req:?}"),
            ));
        };
        let reply = if queue.len() > 1 {
            queue.remove(0)
        } else {
            queue[0].clone()
        };
        reply.to_result()
    }
}

impl PageSource for Pages {
    fn first(&mut self, scope: &DriveScope) -> io::Result<RawPage> {
        self.answer(Req::First(scope.drive().as_str().to_string()))
    }

    fn next(&mut self, link: &hydration_graph::NextLink) -> io::Result<RawPage> {
        self.answer(Req::Next(link.as_str().to_string()))
    }

    fn resume(&mut self, link: &hydration_graph::DeltaLink) -> io::Result<RawPage> {
        self.answer(Req::Resume(link.as_str().to_string()))
    }

    fn latest(&mut self, scope: &DriveScope) -> io::Result<RawPage> {
        self.answer(Req::Latest(scope.drive().as_str().to_string()))
    }
}

/// A source that manufactures pages, because a `VecDeque` cannot express an
/// unbounded chain at all.
///
/// Round `r` serves `rounds[r]` pages and ends with `D{r}`; page `p` of round
/// `r` hands out `P{r}_{p+1}` as its nextLink. `resume(D{r})` starts round
/// `r + 1`. With `endless` set, round 0 never reaches a deltaLink.
#[derive(Clone)]
struct GeneratedPages {
    journal: Journal,
    rounds: Arc<Vec<usize>>,
    endless: bool,
    calls: Arc<Mutex<usize>>,
    cap: usize,
}

impl GeneratedPages {
    fn bounded(journal: Journal, rounds: Vec<usize>) -> Self {
        Self {
            journal,
            rounds: Arc::new(rounds),
            endless: false,
            calls: Arc::new(Mutex::new(0)),
            cap: 4 * MAX_PAGES_PER_ROUND,
        }
    }

    fn endless(journal: Journal) -> Self {
        Self {
            journal,
            rounds: Arc::new(vec![]),
            endless: true,
            calls: Arc::new(Mutex::new(0)),
            cap: 4 * MAX_PAGES_PER_ROUND,
        }
    }

    fn count(&mut self) {
        let mut c = self.calls.lock().unwrap();
        *c += 1;
        assert!(
            *c <= self.cap,
            "the generator was asked for {} pages (cap {}); the round has no budget",
            *c,
            self.cap
        );
    }

    fn page(&self, r: usize, p: usize) -> io::Result<RawPage> {
        let mut items = Vec::new();
        if p == 0 {
            items.push(root_json(MINE, ROOT));
        }
        items.push(file_json(
            MINE,
            &format!("01F{r}_{p}"),
            &format!("f{r}_{p}.txt"),
            ROOT,
            1,
            &format!("c:{{G}},{r}_{p}"),
        ));
        let last = !self.endless && p + 1 >= self.rounds[r];
        let body = if last {
            body_delta(&items, &lnk(&format!("D{r}")))
        } else {
            body_next(&items, &lnk(&format!("P{r}_{}", p + 1)))
        };
        Ok(RawPage {
            status: 200,
            retry_after: None,
            body: body.into_bytes(),
        })
    }

    /// `P{r}_{p}` out of a link, or `D{r}`.
    fn token_of(link: &str) -> &str {
        link.rsplit("token=").next().unwrap_or("")
    }
}

impl PageSource for GeneratedPages {
    fn first(&mut self, scope: &DriveScope) -> io::Result<RawPage> {
        self.journal
            .push(Ev::Call(Req::First(scope.drive().as_str().to_string())));
        self.count();
        self.page(0, 0)
    }

    fn next(&mut self, link: &hydration_graph::NextLink) -> io::Result<RawPage> {
        self.journal
            .push(Ev::Call(Req::Next(link.as_str().to_string())));
        self.count();
        let tok = Self::token_of(link.as_str());
        let rest = tok.strip_prefix('P').unwrap_or_else(|| {
            panic!("the driver followed something that is not a nextLink: {tok}")
        });
        let (r, p) = rest.split_once('_').expect("P{r}_{p}");
        self.page(r.parse().unwrap(), p.parse().unwrap())
    }

    fn resume(&mut self, link: &hydration_graph::DeltaLink) -> io::Result<RawPage> {
        self.journal
            .push(Ev::Call(Req::Resume(link.as_str().to_string())));
        self.count();
        let tok = Self::token_of(link.as_str());
        let r: usize = tok
            .strip_prefix('D')
            .unwrap_or_else(|| panic!("the driver resumed something that is not a token: {tok}"))
            .parse()
            .unwrap();
        assert!(r + 1 < self.rounds.len(), "no round after D{r} was scripted");
        self.page(r + 1, 0)
    }

    fn latest(&mut self, scope: &DriveScope) -> io::Result<RawPage> {
        self.journal
            .push(Ev::Call(Req::Latest(scope.drive().as_str().to_string())));
        self.count();
        Ok(RawPage {
            status: 200,
            retry_after: None,
            body: body_delta(&[], &lnk("DLATEST")).into_bytes(),
        })
    }
}

// --- the store -------------------------------------------------------------

struct Disk {
    tree: Option<TreeBlob>,
    token: Option<TokenBlob>,
    fail_tree: Option<io::ErrorKind>,
    fail_token: Option<io::ErrorKind>,
    /// Serve the first `n` writes of the process faithfully and fail the next —
    /// deliberately method-agnostic, so a test does not have to name which write
    /// it is killing. A power cut does not know either.
    fail_after_n_writes: Option<usize>,
    writes: usize,
    /// A write that returns success and does not land.
    swallow_tree_write: bool,
    trees: Vec<TreeBlob>,
    tokens: Vec<TokenBlob>,
}

/// An in-memory `StateStore`. Cloning shares the disk, which is how a second
/// provider instance over the same state directory is expressed.
#[derive(Clone)]
struct RecordingStore {
    journal: Journal,
    disk: Arc<Mutex<Disk>>,
}

impl RecordingStore {
    fn new(journal: Journal) -> Self {
        Self {
            journal,
            disk: Arc::new(Mutex::new(Disk {
                tree: None,
                token: None,
                fail_tree: None,
                fail_token: None,
                fail_after_n_writes: None,
                writes: 0,
                swallow_tree_write: false,
                trees: Vec::new(),
                tokens: Vec::new(),
            })),
        }
    }

    fn preload(&self, state: PersistedState) {
        let mut d = self.disk.lock().unwrap();
        d.tree = state.tree().cloned();
        d.token = state.token().cloned();
    }

    fn preload_raw(&self, tree: Option<TreeBlob>, token: Option<TokenBlob>) {
        let mut d = self.disk.lock().unwrap();
        d.tree = tree;
        d.token = token;
    }

    fn fail_tree(&self, kind: io::ErrorKind) {
        self.disk.lock().unwrap().fail_tree = Some(kind);
    }

    fn fail_token(&self, kind: io::ErrorKind) {
        self.disk.lock().unwrap().fail_token = Some(kind);
    }

    fn fail_after_n_writes(&self, n: usize) {
        let mut d = self.disk.lock().unwrap();
        d.fail_after_n_writes = Some(n);
        d.writes = 0;
    }

    fn swallow_tree_write(&self, yes: bool) {
        self.disk.lock().unwrap().swallow_tree_write = yes;
    }

    fn clear_faults(&self) {
        let mut d = self.disk.lock().unwrap();
        d.fail_tree = None;
        d.fail_token = None;
        d.fail_after_n_writes = None;
        d.writes = 0;
        d.swallow_tree_write = false;
    }

    fn tree_bytes(&self) -> Option<Vec<u8>> {
        self.disk
            .lock()
            .unwrap()
            .tree
            .as_ref()
            .map(|t| t.as_bytes().to_vec())
    }

    fn token_bytes(&self) -> Option<Vec<u8>> {
        self.disk
            .lock()
            .unwrap()
            .token
            .as_ref()
            .map(|t| t.as_bytes())
    }

    fn stored_tree(&self) -> Option<TreeBlob> {
        self.disk.lock().unwrap().tree.clone()
    }

    fn stored_token(&self) -> Option<TokenBlob> {
        self.disk.lock().unwrap().token.clone()
    }

    /// Every blob ever handed to `save_tree`, whether or not it landed.
    fn trees_written(&self) -> Vec<TreeBlob> {
        self.disk.lock().unwrap().trees.clone()
    }

    fn tokens_written(&self) -> Vec<TokenBlob> {
        self.disk.lock().unwrap().tokens.clone()
    }

    fn next_write_fails(disk: &mut Disk) -> bool {
        disk.writes += 1;
        matches!(disk.fail_after_n_writes, Some(n) if disk.writes > n)
    }
}

fn render_token(t: &TokenBlob) -> String {
    let mut parts: Vec<String> = t
        .drives()
        .iter()
        .map(|d| format!("{}={}", d.as_str(), t.get(d).unwrap_or_default()))
        .collect();
    parts.sort();
    parts.join(",")
}

impl StateStore for RecordingStore {
    fn load(&mut self) -> io::Result<Option<PersistedState>> {
        self.journal.push(Ev::Load);
        let d = self.disk.lock().unwrap();
        if d.tree.is_none() && d.token.is_none() {
            return Ok(None);
        }
        Ok(Some(PersistedState::raw(d.tree.clone(), d.token.clone())))
    }

    fn save_tree(&mut self, tree: &TreeBlob) -> io::Result<()> {
        let mut d = self.disk.lock().unwrap();
        d.trees.push(tree.clone());
        if let Some(kind) = d.fail_tree {
            self.journal.push(Ev::SaveTreeFailed);
            return Err(io::Error::new(kind, "save_tree"));
        }
        if Self::next_write_fails(&mut d) {
            self.journal.push(Ev::SaveTreeFailed);
            return Err(io::Error::new(io::ErrorKind::Interrupted, "save_tree"));
        }
        self.journal
            .push(Ev::SaveTree(tree.items().map(|i| i.len()).unwrap_or(0)));
        if !d.swallow_tree_write {
            d.tree = Some(tree.clone());
        }
        Ok(())
    }

    fn save_token(&mut self, token: &TokenBlob) -> io::Result<()> {
        let mut d = self.disk.lock().unwrap();
        d.tokens.push(token.clone());
        if let Some(kind) = d.fail_token {
            self.journal.push(Ev::SaveTokenFailed);
            return Err(io::Error::new(kind, "save_token"));
        }
        if Self::next_write_fails(&mut d) {
            self.journal.push(Ev::SaveTokenFailed);
            return Err(io::Error::new(io::ErrorKind::Interrupted, "save_token"));
        }
        self.journal.push(Ev::SaveToken(render_token(token)));
        d.token = Some(token.clone());
        Ok(())
    }
}

// --- the clock -------------------------------------------------------------

/// Records what it was asked for and returns immediately. Nothing in this suite
/// spends a second of wall time on a throttling policy.
#[derive(Clone)]
struct RecordingSleeper {
    journal: Journal,
}

impl Sleeper for RecordingSleeper {
    fn sleep(&mut self, how_long: Duration) {
        self.journal.push(Ev::Slept(how_long));
    }
}

// ===========================================================================
// The harness
// ===========================================================================

type Provider<P> = GraphDiscover<P, RecordingStore, RecordingSleeper>;

struct Rig {
    journal: Journal,
    pages: Pages,
    store: RecordingStore,
}

impl Rig {
    fn new() -> Self {
        Self::with_cap(64)
    }

    fn with_cap(cap: usize) -> Self {
        let journal = Journal::default();
        Self {
            pages: Pages::new(journal.clone(), cap),
            store: RecordingStore::new(journal.clone()),
            journal,
        }
    }

    /// A provider instance. A *fresh* one is a restart: it holds no memory of a
    /// cursor and must start from the store.
    fn provider(&self) -> Provider<Pages> {
        self.provider_for(primary(MINE))
    }

    fn provider_for(&self, scope: DriveScope) -> Provider<Pages> {
        GraphDiscover::new(
            scope,
            self.pages.clone(),
            self.store.clone(),
            RecordingSleeper {
                journal: self.journal.clone(),
            },
        )
    }

    fn generated(&self, pages: GeneratedPages) -> Provider<GeneratedPages> {
        GraphDiscover::new(
            primary(MINE),
            pages,
            self.store.clone(),
            RecordingSleeper {
                journal: self.journal.clone(),
            },
        )
    }

    fn script(&self, req: Req, replies: Vec<Reply>) {
        self.pages.script(req, replies);
    }
}

/// Acknowledge a round: hand the *same* instance the cursor that round minted.
///
/// A round derives its tree and its token and writes neither. The pair lands on
/// the next call whose cursor differs from the one the instance was last handed
/// — the only evidence `hydration-sync` ever gives that a batch was applied
/// (`hydration-sync.rs`, the delta thread: `cursor = next` on a clean or quiet
/// pass, and the cursor left untouched on a retryable one). This is that call.
///
/// Deliberately `let _ =`: the round this call goes on to *start* is not the
/// subject of any test that uses it, and is usually unscripted. The previous
/// round's pair is on disk before that round issues its first request, so the
/// outcome either way is irrelevant — which is exactly the property being
/// relied on.
fn ack<P: PageSource>(d: &mut Provider<P>, cursor: &Cursor) {
    let _ = d.changes(cursor);
}

// --- request shorthands ----------------------------------------------------

fn first_req(drive: &str) -> Req {
    Req::First(drive.to_string())
}

fn latest_req(drive: &str) -> Req {
    Req::Latest(drive.to_string())
}

fn resume_req(token: &str) -> Req {
    Req::Resume(lnk(token))
}

fn next_req(token: &str) -> Req {
    Req::Next(lnk(token))
}

fn resume_req_on(drive: &str, token: &str) -> Req {
    Req::Resume(link_on(drive, token))
}

fn next_req_on(drive: &str, token: &str) -> Req {
    Req::Next(link_on(drive, token))
}

// --- assertion helpers -----------------------------------------------------

fn upserted(cs: &[Change]) -> BTreeSet<String> {
    cs.iter()
        .filter_map(|c| match c {
            Change::Upserted { cloud_id, .. } => Some(cloud_id.clone()),
            _ => None,
        })
        .collect()
}

fn removed(cs: &[Change]) -> BTreeSet<String> {
    cs.iter()
        .filter_map(|c| match c {
            Change::Removed { cloud_id } => Some(cloud_id.clone()),
            _ => None,
        })
        .collect()
}

fn upsert_count(cs: &[Change]) -> usize {
    cs.iter()
        .filter(|c| matches!(c, Change::Upserted { .. }))
        .count()
}

fn path_of<'a>(cs: &'a [Change], id: &str) -> Option<&'a str> {
    cs.iter().find_map(|c| match c {
        Change::Upserted { cloud_id, path, .. } if cloud_id == id => Some(path.as_str()),
        _ => None,
    })
}

fn etag_of<'a>(cs: &'a [Change], id: &str) -> Option<&'a str> {
    cs.iter().find_map(|c| match c {
        Change::Upserted { cloud_id, etag, .. } if cloud_id == id => etag.as_deref(),
        _ => None,
    })
}

fn paths(cs: &[Change]) -> BTreeSet<String> {
    cs.iter()
        .filter_map(|c| match c {
            Change::Upserted { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect()
}

fn cursor_str(c: &Cursor) -> String {
    c.0.clone()
        .unwrap_or_else(|| panic!("a completed round must return a cursor, got Cursor(None)"))
}

fn tree_ids(blob: &TreeBlob) -> BTreeSet<String> {
    blob.items()
        .expect("the tree the provider wrote must parse")
        .iter()
        .map(|i| match i {
            Item::Root { id } | Item::Upsert { id, .. } | Item::Delete { id } => id.clone(),
        })
        .collect()
}

fn tree_entry(blob: &TreeBlob, id: &str) -> Option<Item> {
    blob.items()
        .expect("the tree the provider wrote must parse")
        .into_iter()
        .find(|i| match i {
            Item::Root { id: x } | Item::Upsert { id: x, .. } | Item::Delete { id: x } => x == id,
        })
}

fn set(ids: &[String]) -> BTreeSet<String> {
    ids.iter().cloned().collect()
}

// ===========================================================================
// CLASS A — A restart is not a resync
//
// The framework hands `Cursor::default()` after every restart and never gives
// the cursor back (PROVIDER.md:127-131). Read literally that is a full paged
// enumeration on every daemon start — several hundred requests against a
// throttling endpoint on a 100k-item drive, which makes a crash loop into a
// self-inflicted throttle. Read as "ignore the cursor entirely" it costs the one
// signal the framework gives about a batch it could not apply. Both halves are
// below.
// ===========================================================================

/// The one-line reading of the trait doc — `if cursor.0.is_none() { first() }` —
/// compiles, passes every test in `tests/mapping.rs`, and produces
/// `log == [First]` here.
#[test]
fn an_empty_cursor_with_persisted_state_resumes_the_stored_token() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            folder_item(MINE, "01W", ROOT, "Work"),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
        ],
        Some("D9"),
    ));
    // `first()` and `latest()` stay unscripted: an attempt shows up in the log
    // as an error rather than being quietly satisfied.
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(&[], &lnk("D10")))],
    );

    let mut d = rig.provider();
    let (_, cursor) = d
        .changes(&Cursor::default())
        .expect("a restart with good state must not fail");

    assert_eq!(
        rig.journal.calls(),
        vec![resume_req("D9")],
        "exactly one request, carrying the persisted token byte for byte"
    );
    assert!(cursor.0.is_some(), "a completed round issues a cursor");
}

/// POSITIVE CONTROL. Keeps the rule above from becoming "never enumerate" — a
/// provider that refuses to enumerate without a token never syncs a fresh
/// account at all, and the daemon just logs an empty pass every five seconds.
#[test]
fn positive_control_an_empty_cursor_with_no_persisted_state_does_enumerate() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("N1"),
        ))],
    );
    rig.script(
        next_req("N1"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("D1"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("a first run must sync");

    assert_eq!(
        rig.journal.calls(),
        vec![first_req(MINE), next_req("N1")],
        "a tokenless start enumerates, and follows its nextLink"
    );
    assert_eq!(
        upserted(&changes),
        set(&[cloud(MINE, "01A"), cloud(MINE, "01B")])
    );
    // The two writes moved one call later, and nothing else about them changed.
    // A round that derived a batch is not a round the framework applied, and
    // persisting the position under an unapplied batch is what makes a
    // tombstone in it unrecoverable — so the round itself writes nothing.
    assert_eq!(
        rig.journal.store_events(),
        vec![Ev::Load],
        "the round reads the store and writes nothing"
    );
    ack(&mut d, &cursor);
    assert_eq!(
        rig.journal.store_events(),
        vec![
            Ev::Load,
            Ev::SaveTree(3),
            Ev::SaveToken(format!("{MINE}={}", lnk("D1"))),
            Ev::Load,
        ],
        "load, then the tree, then the token — on the acknowledging call, and \
         before that call reads the store for its own round"
    );
}

/// A token newer than its tree is the one unrecoverable state
/// (PROVIDER.md:196-203). Resuming D9 with no tree builds the provider's
/// `Namespace` out of only what changed since D9: every unchanged file is absent
/// from `listing()` forever, and the next expired-token diff reads all of them
/// as deletions and removes the user's files locally.
///
/// Both branches are scripted, so the wrong one succeeds quietly rather than
/// erroring for an unrelated reason.
#[test]
fn a_stored_token_with_no_stored_tree_is_discarded_rather_than_resumed() {
    let rig = Rig::new();
    rig.store
        .preload_raw(None, Some(TokenBlob::one(&drive_id(MINE), &lnk("D9"))));
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
            ],
            &lnk("D10"),
        ))],
    );
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("D10"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("recoverable");

    assert_eq!(rig.journal.calls(), vec![first_req(MINE)]);
    assert!(
        !rig.journal.calls().contains(&resume_req("D9")),
        "a token whose tree is missing must not be resumed"
    );
    assert_eq!(
        upserted(&changes),
        set(&[cloud(MINE, "01A"), cloud(MINE, "01B")])
    );
    assert!(
        removed(&changes).is_empty(),
        "there was no tree to diff against, so nothing can be concluded gone"
    );
    // The pair lands on the call that proves the batch was applied, not on the
    // round that derived it. Same two writes, same order, one call later.
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    ack(&mut d, &cursor);
    assert_eq!(
        rig.journal.writes(),
        vec![
            Ev::SaveTree(3),
            Ev::SaveToken(format!("{MINE}={}", lnk("D10")))
        ]
    );
    assert_eq!(
        rig.store.stored_token().and_then(|t| t.get(&drive_id(MINE)).map(str::to_string)),
        Some(lnk("D10")),
        "the stale token is replaced, not kept"
    );
}

/// The crash-between-writes state the mandated write order is designed to
/// produce. Two failures at once: wedging here means an interrupted first sync
/// never recovers without a human deleting the state directory; discarding the
/// tree instead loses the 01C deletion, because `listing()` says what exists and
/// never what stopped existing.
#[test]
fn a_stored_tree_with_no_stored_token_enumerates_and_still_diffs_for_deletions() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            file_item(MINE, "01B", ROOT, "b.txt", 11, "c:{G},2"),
            file_item(MINE, "01C", ROOT, "c.txt", 12, "c:{G},3"),
        ],
        None,
    ));
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
            ],
            &lnk("D2"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("recoverable");

    assert_eq!(
        rig.journal.calls(),
        vec![first_req(MINE)],
        "no resume at all — in particular none with an empty token"
    );
    assert_eq!(
        removed(&changes),
        set(&[cloud(MINE, "01C")]),
        "a full enumeration must be diffed against the tree, or the deletion is \
         invisible and the local placeholder survives forever"
    );
    assert_eq!(
        upserted(&changes),
        set(&[cloud(MINE, "01A"), cloud(MINE, "01B")])
    );
    assert!(cursor_str(&cursor).contains("D2"));
    // The tree lands on the call that proves the batch was applied, so the
    // deletion only leaves the persisted tree once the framework has seen it.
    ack(&mut d, &cursor);
    let tree = rig.store.stored_tree().expect("a tree was written");
    assert!(!tree_ids(&tree).contains(&cloud(MINE, "01C")));
}

/// PROVIDER.md:103-105. After a restart the framework's `Store` knows only what
/// is on disk; filtering to what the service says changed means a placeholder
/// the user deleted locally never comes back, and the restart is precisely when
/// the framework has lost every other way to find out.
///
/// `Ok((completed.changes, next))` — returning what `Namespace::apply` emitted —
/// is the shortest implementation that type-checks and passes all 60 mapping
/// tests. It returns one change here.
#[test]
fn a_restart_reports_every_object_the_tree_knows_not_only_what_the_page_named() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            folder_item(MINE, "01W", ROOT, "Work"),
            file_item(MINE, "01B", "01W", "b.txt", 11, "c:{G},2"),
            file_item(MINE, "01C", "01W", "c.txt", 12, "c:{G},3"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},7")],
            &lnk("D10"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, _) = d.changes(&Cursor::default()).expect("resumable");

    assert_eq!(
        upserted(&changes),
        set(&[
            cloud(MINE, "01A"),
            cloud(MINE, "01B"),
            cloud(MINE, "01C")
        ]),
        "the batch is what the tree knows, not what the page named"
    );
    assert_eq!(
        paths(&changes),
        set(&[
            "a.txt".to_string(),
            "Work/b.txt".to_string(),
            "Work/c.txt".to_string()
        ]),
        "folders emit no change of their own"
    );
}

/// The mirror image, and the more expensive mistake. `deletions_since(before,
/// after)` is the *correct* code for the expired-token path; running it on the
/// resume path is a one-word confusion between "the framework lost its place"
/// and "I lost my place", and it deletes the user's entire sync directory on an
/// ordinary restart.
///
/// `Ok` is asserted as well as zero removals, so the blast-radius guard cannot
/// rescue the wrong implementation into passing: refusing to sync after every
/// restart is the same drive-wide outage with a nicer log line.
#[test]
fn a_restart_never_reads_the_stored_tree_as_a_page_of_deletions() {
    let rig = Rig::new();
    let mut items = vec![root_item(MINE, ROOT)];
    for i in 0..500 {
        items.push(file_item(
            MINE,
            &format!("01F{i:03}"),
            ROOT,
            &format!("f{i:03}.txt"),
            1,
            &format!("c:{{G}},{i}"),
        ));
    }
    rig.store.preload(primed(&items, Some("D9")));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(&[], &lnk("D10")))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d
        .changes(&Cursor::default())
        .expect("an ordinary restart is not an escalation");

    assert!(
        removed(&changes).is_empty(),
        "500 removals on a restart is the user's sync directory: {:?}",
        removed(&changes)
    );
    assert_eq!(upsert_count(&changes), 500);
    // The pair lands on the call that proves the batch was applied. Same two
    // writes, same order, same contents, one call later.
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    ack(&mut d, &cursor);
    assert_eq!(
        rig.journal.writes(),
        vec![
            Ev::SaveTree(501),
            Ev::SaveToken(format!("{MINE}={}", lnk("D10")))
        ]
    );
    assert_eq!(tree_ids(&rig.store.stored_tree().unwrap()).len(), 501);
}

/// `?token=latest` returns a fresh token and no items: everything that happened
/// while the daemon was down is skipped, and a delta feed never re-reports it.
/// It is the cheapest-looking way to make a restart fast, it returns `Ok`
/// instantly, and it passes the "no full enumeration" and "no removals" tests
/// above. Here it silently loses a deletion.
#[test]
fn a_restart_never_asks_for_token_latest() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            file_item(MINE, "01B", ROOT, "b.txt", 11, "c:{G},2"),
        ],
        Some("D9"),
    ));
    // Both plausible answers are scripted, so neither path errors out and skews
    // the result.
    rig.script(
        latest_req(MINE),
        vec![Reply::ok(body_delta(&[], &lnk("DL")))],
    );
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[tomb_json(MINE, "01B", "b.txt", ROOT)],
            &lnk("D10"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("resumable");

    assert_eq!(rig.journal.calls(), vec![resume_req("D9")]);
    assert!(
        !rig.journal.calls().contains(&latest_req(MINE)),
        "?token=latest skips every change made while the daemon was down"
    );
    assert_eq!(removed(&changes), set(&[cloud(MINE, "01B")]));
    // The token lands on the call that proves the batch was applied — the same
    // one token, one call later.
    assert!(rig.journal.token_writes().is_empty());
    ack(&mut d, &cursor);
    assert_eq!(
        rig.journal.token_writes(),
        vec![format!("{MINE}={}", lnk("D10"))]
    );
}

/// A nextLink is a position inside one enumeration, not a resume point.
/// Persisting it means the next round begins in the middle: every item before it
/// is missing from the provider's tree, therefore from `listing()`, therefore
/// from every future batch — and the eventual expired-token diff reads those
/// files as deletions.
#[test]
fn a_round_interrupted_mid_enumeration_resumes_from_the_token_not_the_next_link() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_next(
            &[
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
                file_json(MINE, "01C", "c.txt", ROOT, 12, "c:{G},3"),
            ],
            &lnk("N1"),
        ))],
    );
    rig.script(
        next_req("N1"),
        vec![Reply::fail(io::ErrorKind::ConnectionReset, "reset by peer")],
    );

    let mut d = rig.provider();
    assert!(
        d.changes(&Cursor::default()).is_err(),
        "a round that never reached a deltaLink did not complete"
    );
    assert!(
        rig.journal.writes().is_empty(),
        "a half-finished round describes half a drive: {:?}",
        rig.journal.writes()
    );

    rig.journal.clear();
    rig.script(
        next_req("N1"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01D", "d.txt", ROOT, 13, "c:{G},4")],
            &lnk("D10"),
        ))],
    );
    let (changes, cursor) = d.changes(&Cursor::default()).expect("the retry completes");

    assert_eq!(
        rig.journal.calls().first(),
        Some(&resume_req("D9")),
        "the round restarts from the token, not from the nextLink it died on"
    );
    assert!(upserted(&changes).contains(&cloud(MINE, "01B")));
    assert!(upserted(&changes).contains(&cloud(MINE, "01C")));
    assert!(upserted(&changes).contains(&cloud(MINE, "01D")));
    // D10 reaches the disk on the call that proves the batch was applied, not
    // on the round that reached it.
    ack(&mut d, &cursor);
    assert_eq!(
        rig.store
            .stored_token()
            .and_then(|t| t.get(&drive_id(MINE)).map(str::to_string)),
        Some(lnk("D10"))
    );
}

/// A resumed round is still a paged round.
///
/// The full enumeration is scripted with a drive-sized page and must not be
/// used: an empty cursor read as "enumerate everything" re-fetches the whole
/// drive on every restart, which is the request volume that gets the app
/// registration throttled.
#[test]
fn a_resumed_round_still_follows_its_next_links() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("D1"),
        ))],
    );
    let mut round_one = rig.provider();
    let (_, c1) = round_one
        .changes(&Cursor::default())
        .expect("the first round enumerates");
    // Round one's writes land on the call that proves the framework applied its
    // batch, so the predecessor is acknowledged before it is dropped. Without
    // that, the restart below would inherit an empty store — which is the
    // correct outcome for a round nobody applied, and not the case under test.
    ack(&mut round_one, &c1);

    // A restart: a *fresh* instance, handed the empty cursor the framework
    // always hands after one.
    rig.journal.clear();
    let big: Vec<String> = (0..3000)
        .map(|i| {
            file_json(
                MINE,
                &format!("01BIG{i}"),
                &format!("big{i}.txt"),
                ROOT,
                1,
                &format!("c:{{G}},{i}"),
            )
        })
        .collect();
    let mut whole_world = vec![root_json(MINE, ROOT)];
    whole_world.extend(big);
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(&whole_world, &lnk("DBIG")))],
    );
    rig.script(
        resume_req("D1"),
        vec![Reply::ok(body_next(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("P1"),
        ))],
    );
    rig.script(
        next_req("P1"),
        vec![Reply::ok(body_delta(&[], &lnk("D2")))],
    );

    let mut round_two = rig.provider();
    let (changes, cursor) = round_two.changes(&Cursor::default()).expect("resumable");

    assert_eq!(
        rig.journal.calls(),
        vec![resume_req("D1"), next_req("P1")],
        "resume, then follow — and never the full enumeration"
    );
    assert!(cursor_str(&cursor).contains("D2"));
    assert!(
        !upserted(&changes).contains(&cloud(MINE, "01BIG0")),
        "the drive-sized page was not supposed to be read"
    );
}

/// POSITIVE CONTROL for the whole class. Without it, every "discard the token"
/// test here is passed by a provider that ignores its store and re-enumerates
/// from scratch every round — the behaviour `StateStore` exists to prevent.
#[test]
fn positive_control_a_fresh_instance_resumes_the_token_its_predecessor_wrote() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
            ],
            &lnk("D1"),
        ))],
    );
    let mut one = rig.provider();
    let (_, c1) = one.changes(&Cursor::default()).expect("round one");
    // The predecessor's writes land on the call that proves its batch was
    // applied; that call is what makes it a predecessor with state on disk.
    ack(&mut one, &c1);

    rig.journal.clear();
    rig.script(
        resume_req("D1"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01A", "a2.txt", ROOT, 10, "c:{G},9")],
            &lnk("D2"),
        ))],
    );

    let mut two = rig.provider();
    two.changes(&Cursor::default()).expect("round two");

    assert!(rig.journal.calls().contains(&resume_req("D1")));
    assert!(
        !rig.journal.calls().contains(&first_req(MINE)),
        "a good token was on disk and must be used"
    );
    assert!(tree_ids(&rig.store.stored_tree().unwrap()).contains(&cloud(MINE, "01B")));
}

// ===========================================================================
// CLASS B — A repeated cursor is the only feedback channel there is
//
// `Applied::retryable` is a pass-wide bool with no attempt counter, no backoff
// and no escape, and nothing ever hands `Applied` back to the provider
// (`hydration-sync.rs:454-496` consumes it and never speaks to `cloud` again).
// Being re-called with a cursor already served is the only evidence a provider
// can get that the framework is wedged — and on a retryable pass the driver
// leaves `cursor` untouched, so the value it repeats is the one it was *given*.
// ===========================================================================

/// The headline case. `Namespace::listing()` cannot express deletions, so once
/// 01X leaves the provider's tree the removal exists nowhere: Graph will not
/// replay a consumed tombstone and the listing can never mention it again. The
/// user keeps a placeholder for an object that no longer exists, and because it
/// still carries a cloud id, an edit to it uploads content back into a deleted
/// object.
#[test]
fn a_removal_the_framework_could_not_apply_is_re_served_not_forgotten() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            file_item(MINE, "01B", ROOT, "b.txt", 11, "c:{G},2"),
            file_item(MINE, "01X", ROOT, "x.txt", 12, "c:{G},3"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[tomb_json(MINE, "01X", "x.txt", ROOT)],
            &lnk("D10"),
        ))],
    );
    rig.script(
        resume_req("D10"),
        vec![Reply::ok(body_delta(&[], &lnk("D10")))],
    );

    let mut d = rig.provider();
    let (b1, c1) = d.changes(&Cursor::default()).expect("round one");
    assert_eq!(removed(&b1), set(&[cloud(MINE, "01X")]));

    // `hydration-sync.rs:483-490`: the pass was retryable, so the driver does
    // not assign `cursor = next` — the next call carries the value it carried
    // before, which is the empty cursor it started with.
    let (b2, c2) = d.changes(&Cursor::default()).expect("the repeat");

    assert_eq!(
        removed(&b2),
        set(&[cloud(MINE, "01X")]),
        "a deletion the framework could not apply must be re-served; the \
         listing is precisely the thing that cannot carry one"
    );
    assert_eq!(c2, c1, "a repeat re-issues the cursor it already served");
}

/// The driver loops every five seconds and holds the cursor for as long as a
/// pass stays retryable — a two-object path swap was measured at 25 consecutive
/// passes. Re-rounding per call issues 25 delta requests into a throttling
/// endpoint while the framework makes no progress at all, and each page it
/// consumes carries tombstones that `listing()` can never re-express.
#[test]
fn a_repeated_cursor_is_served_from_memory_with_no_request_and_no_backoff() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            file_item(MINE, "01X", ROOT, "x.txt", 12, "c:{G},3"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[tomb_json(MINE, "01X", "x.txt", ROOT)],
            &lnk("D10"),
        ))],
    );
    // Scripted so a re-rounding implementation hits the throttle and records a
    // 30-second sleep rather than failing for some unrelated reason.
    rig.script(
        resume_req("D10"),
        vec![
            Reply::throttled(30),
            Reply::ok(body_delta(
                &[file_json(MINE, "01C", "c.txt", ROOT, 13, "c:{G},4")],
                &lnk("D11"),
            )),
        ],
    );
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[root_json(MINE, ROOT)],
            &lnk("DFULL"),
        ))],
    );

    let mut d = rig.provider();
    let (_, c1) = d.changes(&Cursor::default()).expect("round one");
    let mut batches = Vec::new();
    for _ in 0..3 {
        batches.push(d.changes(&Cursor::default()).expect("a repeat"));
    }

    assert_eq!(
        rig.journal.calls(),
        vec![resume_req("D9")],
        "three repeats must cost nothing"
    );
    assert!(
        rig.journal.sleeps().is_empty(),
        "no backoff, because there was no request: {:?}",
        rig.journal.sleeps()
    );
    for (b, _) in &batches {
        assert!(
            !upserted(b).contains(&cloud(MINE, "01C")),
            "the next round's page was consumed by a repeat"
        );
    }
    // A repeat is the framework saying it could not apply the batch, so the
    // round's pair is still held: nothing at all has been written yet. Moving
    // the position under an unapplied batch is what lost the removal.
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    ack(&mut d, &c1);
    assert_eq!(rig.journal.token_writes().len(), 1);
    assert_eq!(
        rig.journal.writes(),
        vec![
            Ev::SaveTree(2),
            Ev::SaveToken(format!("{MINE}={}", lnk("D10")))
        ],
        "one tree and one token, tree first — round one's, once acknowledged"
    );
}

/// POSITIVE CONTROL. A provider that mistakes every subsequent call for a repeat
/// serves the same batch forever: the drive stops syncing after one round, with
/// `Ok` returned every time and nothing in any log to suggest a fault.
#[test]
fn positive_control_an_acknowledged_cursor_runs_the_next_round() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("D10"),
        ))],
    );
    rig.script(
        resume_req("D10"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01C", "c.txt", ROOT, 12, "c:{G},3")],
            &lnk("D11"),
        ))],
    );

    let mut d = rig.provider();
    let (_, c1) = d.changes(&Cursor::default()).expect("round one");
    // `hydration-sync.rs:493`: the pass applied cleanly, so `cursor = next`.
    let (b2, c2) = d.changes(&c1).expect("round two");

    assert_eq!(
        rig.journal.calls(),
        vec![resume_req("D9"), resume_req("D10")]
    );
    assert!(upserted(&b2).contains(&cloud(MINE, "01C")));
    assert_ne!(c2, c1);
    // Each round's pair lands on the call that acknowledges it: round two's
    // call wrote round one's D10, so round two's D11 needs one more.
    assert_eq!(rig.journal.token_writes().len(), 1);
    ack(&mut d, &c2);
    assert_eq!(rig.journal.token_writes().len(), 2);
    assert_eq!(
        rig.journal.token_writes().last().cloned(),
        Some(format!("{MINE}={}", lnk("D11")))
    );
}

/// Graph hands back the same deltaLink for two consecutive rounds when the feed
/// has not moved past that token. If two different batches can carry one cursor
/// value the discriminator above is gone: the provider either re-serves batch
/// one forever, so 01C never syncs, or reads a genuine retry as an
/// acknowledgement and drops the deferred work.
///
/// `Ok((changes, Cursor(Some(round.token.as_str().to_string()))))` — the cursor
/// and the token look like the same concept — yields `c1 == c2` here.
#[test]
fn two_batches_never_share_a_cursor_value_even_when_graph_repeats_its_delta_link() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("D10"),
        ))],
    );
    rig.script(
        resume_req("D10"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01C", "c.txt", ROOT, 12, "c:{G},3")],
            &lnk("D10"),
        ))],
    );

    let mut d = rig.provider();
    let (_, c1) = d.changes(&Cursor::default()).expect("round one");
    let (_, c2) = d.changes(&c1).expect("round two");

    assert!(c1.0.is_some() && c2.0.is_some());
    assert_ne!(
        c1, c2,
        "two batches sharing a cursor value make a repeat and an \
         acknowledgement indistinguishable"
    );
    assert_ne!(cursor_str(&c1), lnk("D10"));
    assert_ne!(cursor_str(&c2), lnk("D10"));
}

/// The stall guard. Three repeats of one cursor is the only evidence available
/// that the framework is wedged; without counting it, a path swap pins the
/// cursor silently forever.
///
/// The design's `StallDetector { passes, last_failed }` watches `Applied::failed`
/// — which the provider is never given. An implementation that keeps that field
/// and waits to be told compiles, is never called, and reports `None` here.
#[test]
fn three_repeats_of_one_cursor_are_reported_as_a_stall() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            file_item(MINE, "01X", ROOT, "x.txt", 12, "c:{G},3"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[tomb_json(MINE, "01X", "x.txt", ROOT)],
            &lnk("D10"),
        ))],
    );
    rig.script(
        resume_req("D10"),
        vec![Reply::ok(body_delta(&[], &lnk("D11")))],
    );

    let mut d = rig.provider();
    d.changes(&Cursor::default()).expect("round one");
    let mut last = None;
    for _ in 0..3 {
        last = Some(d.changes(&Cursor::default()).expect("a repeat"));
    }

    match d.last_escalation() {
        Some(Escalation::StalledRetryable { passes, .. }) => assert_eq!(passes, 3),
        other => panic!("three repeats must be reported as a stall, got {other:?}"),
    }
    // A stall is the case where the acknowledging call never comes, so nothing
    // has been written at all — which is the whole of the fix: the position
    // stays where the wedged batch was read from, and the tombstone in it is
    // still reachable from the token on disk after a restart.
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    let (b, c) = last.unwrap();
    assert_eq!(
        removed(&b),
        set(&[cloud(MINE, "01X")]),
        "the stall is reported, not resolved by quietly dropping the work"
    );
    // And when the framework does finally move on, the pair lands exactly once.
    ack(&mut d, &c);
    assert_eq!(rig.journal.token_writes().len(), 1);
    assert_eq!(
        rig.journal.writes(),
        vec![
            Ev::SaveTree(2),
            Ev::SaveToken(format!("{MINE}={}", lnk("D10")))
        ]
    );
}

/// POSITIVE CONTROL. Two objects swapping paths refuse each other on one pass
/// and succeed on the next — the exact scenario `Applied::retryable` exists for.
/// Escalating on the first repeat means the daemon prints "could not list the
/// cloud" and abandons a rename that was one pass from completing.
#[test]
fn positive_control_two_repeats_are_not_a_stall() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            file_item(MINE, "01X", ROOT, "x.txt", 12, "c:{G},3"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[tomb_json(MINE, "01X", "x.txt", ROOT)],
            &lnk("D10"),
        ))],
    );

    let mut d = rig.provider();
    let (_, c1) = d.changes(&Cursor::default()).expect("round one");
    for _ in 0..2 {
        let (b, c) = d.changes(&Cursor::default()).expect("a repeat");
        assert_eq!(removed(&b), set(&[cloud(MINE, "01X")]));
        assert_eq!(c, c1);
        assert_eq!(
            d.last_escalation(),
            None,
            "an ordinary retryable pass is not a fault"
        );
    }
    assert_eq!(rig.journal.calls(), vec![resume_req("D9")]);
}

/// The ordinary quiet round, which is most of them.
///
/// An empty batch paired with a new cursor is the exact shape
/// `hydration-sync.rs:527` had to be patched for: the empty-batch arm advanced
/// the cursor unconditionally, so a refusal deliberately held back was consumed
/// by silence. A provider whose quiet round is `(vec![], new_cursor)` is one
/// framework version away from that bug, and it independently breaks
/// PROVIDER.md:103.
#[test]
fn a_quiet_steady_state_round_reports_the_tree_rather_than_an_empty_batch() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            folder_item(MINE, "01W", ROOT, "Work"),
            file_item(MINE, "01B", "01W", "b.txt", 11, "c:{G},2"),
            file_item(MINE, "01C", "01W", "c.txt", 12, "c:{G},3"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},7")],
            &lnk("D10"),
        ))],
    );
    rig.script(
        resume_req("D10"),
        vec![Reply::ok(body_delta(&[], &lnk("D11")))],
    );

    let mut d = rig.provider();
    let (_, c1) = d.changes(&Cursor::default()).expect("round one");
    let (b2, c2) = d.changes(&c1).expect("the quiet round");

    assert!(!b2.is_empty(), "a quiet round still reports the tree");
    assert_eq!(
        upserted(&b2),
        set(&[
            cloud(MINE, "01A"),
            cloud(MINE, "01B"),
            cloud(MINE, "01C")
        ])
    );
    assert_eq!(
        paths(&b2),
        set(&[
            "a.txt".to_string(),
            "Work/b.txt".to_string(),
            "Work/c.txt".to_string()
        ])
    );
    assert_ne!(c2, c1);
    assert!(c2.0.is_some());
}

// ===========================================================================
// CLASS C — The two writes, and the order they go in
//
// PROVIDER.md:190-203. A tree newer than its token is harmless: the replayed
// items are no-ops. A token newer than its tree is unrecoverable: every move in
// between is lost, a delta feed never re-reports an unchanged item, and nothing
// self-corrects.
// ===========================================================================

/// The base case. Two live wrong implementations: token first (the token is what
/// the round produced and the tree feels like a cache), and right order with
/// stale content (snapshotting before the pages were fed). The content half of
/// the assertion is what catches the second.
#[test]
fn the_tree_written_is_this_rounds_tree_and_it_is_written_before_the_token() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
            ],
            &lnk("DELTA-1"),
        ))],
    );

    let mut d = rig.provider();
    let (_, cursor) = d.changes(&Cursor::default()).expect("a clean round");

    // Still this round's tree, still before the token — one call later. The
    // round derives the pair and writes neither; the call that proves the batch
    // was applied is the one that lands it.
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    ack(&mut d, &cursor);
    assert_eq!(
        rig.journal.writes(),
        vec![
            Ev::SaveTree(3),
            Ev::SaveToken(format!("{MINE}={}", lnk("DELTA-1")))
        ]
    );
    let tree = rig.store.trees_written().pop().expect("a tree was written");
    let ids = tree_ids(&tree);
    assert!(ids.contains(&cloud(MINE, "01A")) && ids.contains(&cloud(MINE, "01B")));
    let token = rig.store.tokens_written().pop().expect("a token was written");
    assert_eq!(token.get(&drive_id(MINE)), Some(lnk("DELTA-1").as_str()));
    assert!(cursor_str(&cursor).contains("DELTA-1"));
}

/// A full disk or an ENOSPC on the tree file is precisely when the token must
/// not move. `let _ = store.save_tree(&blob); store.save_token(&tok)?;` — the
/// tree write treated as best-effort because it is "only a cache of what the
/// service will tell us again" — is the false belief this ordering rule exists
/// to correct.
#[test]
fn a_tree_write_failure_writes_no_token_at_all() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
        ],
        Some("D9"),
    ));
    rig.store.fail_tree(io::ErrorKind::StorageFull);
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("D10"),
        ))],
    );

    let mut d = rig.provider();
    // The writes happen on the call that proves the batch was applied, so that
    // is where a full disk surfaces. Everything else about this test is
    // unchanged: the tree write fails and no token is written at all.
    let (_, c1) = d
        .changes(&Cursor::default())
        .expect("the round derives its state");
    assert!(
        d.changes(&c1).is_err(),
        "a round whose state could not be written did not complete"
    );
    assert_eq!(
        rig.journal.store_events(),
        vec![Ev::Load, Ev::SaveTreeFailed],
        "no save_token entry of any kind"
    );

    rig.store.clear_faults();
    rig.journal.clear();
    let (changes, _) = d.changes(&c1).expect("the retry");
    assert_eq!(rig.journal.calls().first(), Some(&resume_req("D9")));
    assert!(upserted(&changes).contains(&cloud(MINE, "01B")));
}

/// PROVIDER.md:198 — "on any doubt, discard the token and keep the tree".
/// Keeping D10 in memory after the write failed means the D9→D10 window is
/// consumed and never replayed: those files silently never sync, and after the
/// next restart the on-disk token and the provider's actual position disagree
/// with nothing to reconcile them.
#[test]
fn a_token_write_failure_does_not_advance_the_in_memory_token() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
        ],
        Some("D9"),
    ));
    rig.store.fail_token(io::ErrorKind::StorageFull);
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("D10"),
        ))],
    );
    rig.script(
        resume_req("D10"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01C", "c.txt", ROOT, 12, "c:{G},3")],
            &lnk("D11"),
        ))],
    );

    let mut d = rig.provider();
    // The pair lands on the call that proves the batch was applied, so the
    // token failure surfaces there — after the tree of the same round landed.
    let (_, c1) = d
        .changes(&Cursor::default())
        .expect("the round derives its state");
    let _ = d.changes(&c1);
    assert_eq!(
        rig.journal.writes(),
        vec![Ev::SaveTree(3), Ev::SaveTokenFailed],
        "the tree lands — root, 01A and the newly arrived 01B — and the token does not"
    );

    rig.store.clear_faults();
    rig.journal.clear();
    let (changes, _) = d.changes(&c1).expect("the retry");

    assert_eq!(
        rig.journal.calls().first(),
        Some(&resume_req("D9")),
        "the token only advances once it is on disk"
    );
    assert!(
        upserted(&changes).contains(&cloud(MINE, "01B")),
        "the change from the failed round is reported again"
    );
    assert!(
        !upserted(&changes).contains(&cloud(MINE, "01C")),
        "the D9→D10 window must not be skipped"
    );
}

/// The same rule from the other side: the old pair must survive intact, byte for
/// byte, so the next round starts from a state that is internally consistent.
#[test]
fn a_tree_write_failure_leaves_the_old_pair_intact() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("DELTA-1"),
        ))],
    );
    let mut one = rig.provider();
    let (_, c1) = one.changes(&Cursor::default()).expect("round one");
    // Round one's pair lands on the call that proves its batch was applied.
    ack(&mut one, &c1);
    let tree_before = rig.store.tree_bytes().expect("a tree");
    let token_before = rig.store.token_bytes().expect("a token");

    rig.journal.clear();
    rig.store.fail_tree(io::ErrorKind::StorageFull);
    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::ok(body_delta(
            &[
                folder_json(MINE, "01W", "Work", ROOT),
                file_json(MINE, "01A", "a.txt", "01W", 10, "c:{G},1"),
            ],
            &lnk("DELTA-2"),
        ))],
    );

    let mut two = rig.provider();
    // The failing write is on the acknowledging call, which is where both
    // writes now happen.
    let (_, c2) = two
        .changes(&Cursor::default())
        .expect("the round derives its state");
    let outcome = two.changes(&c2);

    assert!(
        !rig.journal
            .writes()
            .iter()
            .any(|e| matches!(e, Ev::SaveToken(_))),
        "no token may be written when the tree write failed: {:?}",
        rig.journal.writes()
    );
    assert_eq!(rig.store.tree_bytes(), Some(tree_before));
    assert_eq!(rig.store.token_bytes(), Some(token_before));
    assert!(
        outcome.is_err(),
        "a pair that could not be written is not a pass that completed"
    );
    // The position the round handed out was never durable, and the assertion
    // that used to say so — "no new position to hand out" — now says it where
    // it is actually observable: the next round starts from DELTA-1 again,
    // because nothing about DELTA-2 reached the disk.
    rig.journal.clear();
    let _ = two.changes(&c2);
    assert_eq!(
        rig.journal.calls().first(),
        Some(&resume_req("DELTA-1")),
        "the old pair is what the retry resumes: {:?}",
        rig.journal.calls()
    );
}

/// The harmless half of the ordering rule, proved harmless rather than assumed.
/// Replayed upserts are no-ops; what must not happen is that the replay is
/// treated as the whole world and the two files the replayed page never mentions
/// are dropped from the tree.
///
/// The page includes the root on purpose, so a provider that never calls
/// `Namespace::restore(stored_tree)` completes `Ok` with a shrunken tree instead
/// of failing loudly on a rootless namespace. Only the 01B/01C assertion sees it.
#[test]
fn a_crash_after_the_tree_write_replays_the_delta_and_keeps_the_rest_of_the_tree() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
                file_json(MINE, "01C", "c.txt", ROOT, 12, "c:{G},3"),
            ],
            &lnk("DELTA-1"),
        ))],
    );
    let mut one = rig.provider();
    let (_, c1) = one.changes(&Cursor::default()).expect("round one");
    // Round one's pair lands on the call that proves its batch was applied.
    ack(&mut one, &c1);

    // Round two: the tree lands, the token write is interrupted.
    rig.store.fail_token(io::ErrorKind::Interrupted);
    let renamed = body_delta(
        &[
            root_json(MINE, ROOT),
            file_json(MINE, "01A", "a2.txt", ROOT, 10, "c:{G},1"),
        ],
        &lnk("DELTA-2"),
    );
    rig.script(resume_req("DELTA-1"), vec![Reply::ok(renamed)]);
    let mut two = rig.provider();
    // Both writes are on the acknowledging call, so that is where round two's
    // interrupted token write happens.
    let (_, c2) = two
        .changes(&Cursor::default())
        .expect("round two derives its state");
    let _ = two.changes(&c2);

    let held = rig.store.stored_tree().expect("the tree landed");
    let ids = tree_ids(&held);
    assert!(ids.contains(&cloud(MINE, "01A")));
    assert!(ids.contains(&cloud(MINE, "01B")));
    assert!(ids.contains(&cloud(MINE, "01C")));
    assert_eq!(
        rig.store
            .stored_token()
            .and_then(|t| t.get(&drive_id(MINE)).map(str::to_string)),
        Some(lnk("DELTA-1")),
        "the token did not move"
    );

    // Round three: a delta link is replayable, so the same page arrives again.
    rig.store.clear_faults();
    rig.journal.clear();
    rig.script(
        resume_req("DELTA-2"),
        vec![Reply::ok(body_delta(&[], &lnk("DELTA-3")))],
    );
    let mut three = rig.provider();
    let (changes, _) = three.changes(&Cursor::default()).expect("round three");

    assert!(rig.journal.calls().contains(&resume_req("DELTA-1")));
    assert!(!rig.journal.calls().contains(&resume_req("DELTA-2")));
    assert!(!rig.journal.calls().contains(&first_req(MINE)));
    assert!(
        removed(&changes).is_empty(),
        "a replayed page is not a statement about what is absent from it"
    );
    let after = rig.store.stored_tree().unwrap();
    assert!(tree_ids(&after).contains(&cloud(MINE, "01B")));
    assert!(tree_ids(&after).contains(&cloud(MINE, "01C")));
    match tree_entry(&after, &cloud(MINE, "01A")) {
        Some(Item::Upsert { name, .. }) => assert_eq!(name, "a2.txt"),
        other => panic!("01A must still be in the tree, renamed: {other:?}"),
    }
}

/// The rule itself, measured in the only unit that matters.
///
/// Tree-first: the crash leaves the new tree with the old token, round three
/// resumes DELTA-1, the move arrives a second time and lands. Token-first: the
/// crash leaves the old tree with the new token, round three resumes DELTA-2,
/// Graph reports nothing, and `a.txt` stays at the sync root for the rest of the
/// installation's life.
///
/// `fail_after_n_writes` is deliberately method-agnostic: it kills the second
/// write whatever the implementation chose, which is what a power cut does.
#[test]
fn a_crash_between_the_two_writes_costs_a_move_only_when_the_token_is_written_first() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                folder_json(MINE, "01W", "Work", ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("DELTA-1"),
        ))],
    );
    let mut one = rig.provider();
    let (_, c1) = one.changes(&Cursor::default()).expect("round one");
    // Round one's pair lands on the call that proves its batch was applied, and
    // before the write counter below is armed.
    ack(&mut one, &c1);

    rig.store.fail_after_n_writes(1);
    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", "01W", 10, "c:{G},1"),
            ],
            &lnk("DELTA-2"),
        ))],
    );
    let mut two = rig.provider();
    // The two writes are on the acknowledging call, so that is the call the
    // power cut lands in the middle of.
    let (_, c2) = two
        .changes(&Cursor::default())
        .expect("round two derives its state");
    let _ = two.changes(&c2);

    // Round three. Every branch a correct or incorrect implementation could take
    // is scripted, so the failure is the outcome and not a missing fixture.
    rig.store.clear_faults();
    rig.journal.clear();
    rig.script(
        resume_req("DELTA-2"),
        vec![Reply::ok(body_delta(
            &[root_json(MINE, ROOT)],
            &lnk("DELTA-3"),
        ))],
    );
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                folder_json(MINE, "01W", "Work", ROOT),
                file_json(MINE, "01A", "a.txt", "01W", 10, "c:{G},1"),
            ],
            &lnk("DELTA-3"),
        ))],
    );
    let mut three = rig.provider();
    let (changes, _) = three.changes(&Cursor::default()).expect("round three");

    assert_eq!(
        path_of(&changes, &cloud(MINE, "01A")),
        Some("Work/a.txt"),
        "the move must survive the crash"
    );
    match tree_entry(&rig.store.stored_tree().unwrap(), &cloud(MINE, "01A")) {
        Some(Item::Upsert { parent, .. }) => assert_eq!(parent, cloud(MINE, "01W")),
        other => panic!("01A must be under Work in the persisted tree: {other:?}"),
    }
}

/// Correct write order is not sufficient on its own: two independently written
/// blobs can still end up mismatched when a write reports success and does not
/// land. Without something tying the token to the tree it was written after, the
/// mismatch is undetectable and costs the same move as writing them in the wrong
/// order.
///
/// The test does not prescribe the mechanism — a generation counter, a hash of
/// the tree bytes, or one combined file all pass.
#[test]
fn a_token_that_does_not_belong_to_the_stored_tree_is_discarded() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                folder_json(MINE, "01W", "Work", ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("DELTA-1"),
        ))],
    );
    let mut one = rig.provider();
    let (_, c1) = one.changes(&Cursor::default()).expect("round one");
    // Round one's pair lands on the call that proves its batch was applied.
    ack(&mut one, &c1);

    // A tree write that returned success and did not survive the power cut.
    rig.store.swallow_tree_write(true);
    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", "01W", 10, "c:{G},1"),
            ],
            &lnk("DELTA-2"),
        ))],
    );
    let mut two = rig.provider();
    // Both writes are on the acknowledging call, so that is where the swallowed
    // tree write and the token that outruns it happen.
    let (_, c2) = two
        .changes(&Cursor::default())
        .expect("round two derives its state");
    let _ = two.changes(&c2);

    rig.store.clear_faults();
    rig.journal.clear();
    rig.script(
        resume_req("DELTA-2"),
        vec![Reply::ok(body_delta(
            &[root_json(MINE, ROOT)],
            &lnk("DELTA-3"),
        ))],
    );
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                folder_json(MINE, "01W", "Work", ROOT),
                file_json(MINE, "01A", "a.txt", "01W", 10, "c:{G},1"),
            ],
            &lnk("DELTA-3"),
        ))],
    );
    let mut three = rig.provider();
    let (changes, _) = three.changes(&Cursor::default()).expect("round three");

    assert!(
        rig.journal.calls().contains(&first_req(MINE)),
        "a token ahead of its tree must be discarded, not resumed"
    );
    assert!(!rig.journal.calls().contains(&resume_req("DELTA-2")));
    assert_eq!(path_of(&changes, &cloud(MINE, "01A")), Some("Work/a.txt"));
    assert!(removed(&changes).is_empty());
}

/// An empty change batch does not mean an empty round.
///
/// Skipping the tree write here advances the token past the creation of `Work/`
/// while the tree has no record of it — and a delta feed never re-reports an
/// unchanged folder, so every file that ever arrives inside `Work` lands in
/// `Namespace::waiting` under a parent that will never come and blocks the token
/// forever. Sync stops permanently, on a folder.
#[test]
fn a_round_that_produced_no_changes_still_persists_its_tree() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[root_json(MINE, ROOT), folder_json(MINE, "01W", "Work", ROOT)],
            &lnk("DELTA-1"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("a clean round");

    assert!(changes.is_empty(), "a root and an empty folder are no files");
    // An empty batch is still acknowledged — `hydration-sync.rs` advances the
    // cursor on a quiet pass too — so the tree still reaches disk, one call
    // later and with the folder in it.
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    ack(&mut d, &cursor);
    assert_eq!(
        rig.journal.writes(),
        vec![
            Ev::SaveTree(2),
            Ev::SaveToken(format!("{MINE}={}", lnk("DELTA-1")))
        ]
    );
    let tree = rig.store.stored_tree().unwrap();
    match tree_entry(&tree, &cloud(MINE, "01W")) {
        Some(Item::Upsert { kind, .. }) => assert_eq!(kind, Kind::Folder),
        other => panic!("the folder must be in the tree: {other:?}"),
    }
}

/// A nextLink persisted as a token is a resume point in the middle of an
/// enumeration whose earlier pages were never applied. On restart the provider
/// resumes at page two, page one's items are never delivered and never
/// re-reported, and the cursor looks perfectly healthy. nextLinks also expire far
/// sooner than delta tokens, so the failure surfaces as an unexplained 400 days
/// later.
///
/// Checkpointing after each page is a sympathetic instinct for a 300-page
/// enumeration against a throttling endpoint, and it reads as more crash-safe,
/// not less.
#[test]
fn only_a_delta_link_is_ever_persisted_as_a_token() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("NEXT-1"),
        ))],
    );
    rig.script(
        next_req("NEXT-1"),
        vec![Reply::ok(body_next(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("NEXT-2"),
        ))],
    );
    rig.script(
        next_req("NEXT-2"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01C", "c.txt", ROOT, 12, "c:{G},3")],
            &lnk("DELTA-9"),
        ))],
    );

    let mut d = rig.provider();
    let (_, cursor) = d.changes(&Cursor::default()).expect("a three-page round");

    // Still one token per round and still after the tree — written on the call
    // that proves the round's batch was applied.
    ack(&mut d, &cursor);
    let tokens = rig.store.tokens_written();
    assert_eq!(tokens.len(), 1, "one token per round, at the end of it");
    let bytes = String::from_utf8(tokens[0].as_bytes()).expect("utf-8");
    assert!(bytes.contains("DELTA-9"));
    assert!(!bytes.contains("NEXT-1"), "a nextLink is not a resume point");
    assert!(!bytes.contains("NEXT-2"));
    let events = rig.journal.writes();
    let last_tree = events
        .iter()
        .rposition(|e| matches!(e, Ev::SaveTree(_)))
        .expect("a tree was written");
    let token_at = events
        .iter()
        .position(|e| matches!(e, Ev::SaveToken(_)))
        .expect("a token was written");
    assert!(last_tree < token_at);
    assert!(cursor_str(&cursor).contains("DELTA-9"));
}

/// PROVIDER.md is explicit that the daemon builds a separate provider instance
/// per role and runs three of them concurrently. An instance that read the store
/// once at construction holds a snapshot from before the delta thread's first
/// round and writes its empty tree back over three files' worth of state — with
/// the newer token still in place, which is the unrecoverable pair produced
/// without any crash at all, on an ordinary healthy machine.
///
/// The construction order here is the daemon's, not a contrived one.
#[test]
fn a_second_provider_instance_over_the_same_store_does_not_write_back_a_stale_tree() {
    let rig = Rig::new();
    // Both built up front, as hydration-sync.rs builds its instances at startup
    // before any of them runs.
    let mut one = rig.provider();
    let mut two = rig.provider();

    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
                file_json(MINE, "01C", "c.txt", ROOT, 12, "c:{G},3"),
            ],
            &lnk("DELTA-1"),
        ))],
    );
    let (_, c1) = one.changes(&Cursor::default()).expect("instance one syncs");
    // Instance one's pair lands on the call that proves its batch was applied;
    // that is the state instance two must not write back over.
    ack(&mut one, &c1);

    rig.journal.clear();
    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::ok(body_delta(
            &[root_json(MINE, ROOT)],
            &lnk("DELTA-2"),
        ))],
    );
    let (_, c2) = two
        .changes(&Cursor::default())
        .expect("instance two runs a round");
    // Instance two's own pair lands the same way, so what is on disk at the end
    // is a tree instance two derived — the thing under test.
    ack(&mut two, &c2);

    let events = rig.journal.store_events();
    assert_eq!(
        events.first(),
        Some(&Ev::Load),
        "an instance re-reads the store before it writes: {events:?}"
    );
    assert!(rig.journal.calls().contains(&resume_req("DELTA-1")));
    let ids = tree_ids(&rig.store.stored_tree().unwrap());
    for id in ["01A", "01B", "01C"] {
        assert!(
            ids.contains(&cloud(MINE, id)),
            "instance two wrote its own empty tree over the state: {ids:?}"
        );
    }
}

/// An escalation has no channel through `io::Result<(Vec<Change>, Cursor)>`, so
/// there is real pressure to log it and return `Ok((vec![], Cursor(Some(link))))`
/// to keep the daemon alive. Against the pre-fix driver — and any other host of
/// this trait — the empty batch advances the cursor unconditionally, and the
/// item that was never placed is never mentioned again.
#[test]
fn a_round_that_escalates_writes_no_token_and_returns_no_new_cursor() {
    let rig = Rig::new();
    rig.store
        .preload(primed(&[root_item(MINE, ROOT)], Some("D9")));
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01Y", "y.txt", "NOWHERE", 10, "c:{G},1")],
            &lnk("D10"),
        ))],
    );

    let mut d = rig.provider();
    assert!(
        d.changes(&Cursor::default()).is_err(),
        "an item that was never placed must not be advanced past"
    );
    assert!(
        !rig.journal
            .writes()
            .iter()
            .any(|e| matches!(e, Ev::SaveToken(_))),
        "{:?}",
        rig.journal.writes()
    );
    assert_eq!(
        d.last_escalation(),
        Some(Escalation::Incomplete {
            refusals: 0,
            pending: 1
        })
    );

    rig.journal.clear();
    let _ = d.changes(&Cursor::default());
    assert_eq!(
        rig.journal.calls().first(),
        Some(&resume_req("D9")),
        "the old token, never the one the escalating round reached"
    );
}

// ===========================================================================
// CLASS D — Paging, and the ways a round fails to end
//
// The delta thread in bin/hydration-sync.rs:446-533 is one spawned thread with
// no timeout around `cloud.changes(&cursor)`. Anything that pins that call pins
// the download direction forever, logs nothing, and leaves the daemon looking
// healthy.
// ===========================================================================

/// A self-referential nextLink. The natural driver keeps no memory of the links
/// it has issued and follows this one forever.
#[test]
fn a_next_link_identical_to_the_one_just_followed_ends_the_round() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("P1"),
        ))],
    );
    rig.script(
        next_req("P1"),
        vec![Reply::ok(body_next(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("P1"),
        ))],
    );

    let mut d = rig.provider();
    assert!(d.changes(&Cursor::default()).is_err());
    assert_eq!(
        rig.journal.calls(),
        vec![first_req(MINE), next_req("P1")],
        "the repeated link is never re-issued"
    );
    assert!(rig.journal.token_writes().is_empty());
    assert!(
        rig.journal.sleeps().is_empty(),
        "a repeated link is not a throttle"
    );
}

/// The same wedge reached through the fix a developer writes *after* the test
/// above. `if next == last_followed` is one-deep memory; only a per-round
/// visited set fails both.
#[test]
fn a_two_link_cycle_is_not_missed_by_a_previous_link_check() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("P1"),
        ))],
    );
    rig.script(
        next_req("P1"),
        vec![Reply::ok(body_next(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("P2"),
        ))],
    );
    rig.script(
        next_req("P2"),
        vec![Reply::ok(body_next(
            &[file_json(MINE, "01C", "c.txt", ROOT, 12, "c:{G},3")],
            &lnk("P1"),
        ))],
    );

    let mut d = rig.provider();
    assert!(d.changes(&Cursor::default()).is_err());
    assert_eq!(
        rig.journal.calls(),
        vec![first_req(MINE), next_req("P1"), next_req("P2")],
        "the second P1 is never issued"
    );
    assert!(rig.journal.token_writes().is_empty());
}

/// Every link distinct, so the visited set does not help. A chain that never
/// ends is also an OOM of the process that owns the upload queue and the control
/// socket, and killing it loses queued uploads that have no other copy.
#[test]
fn an_endless_chain_of_fresh_next_links_stops_at_the_page_budget() {
    let rig = Rig::with_cap(usize::MAX);
    let pages = GeneratedPages::endless(rig.journal.clone());
    let mut d = rig.generated(pages);

    assert!(d.changes(&Cursor::default()).is_err());
    let nexts = rig
        .journal
        .calls()
        .iter()
        .filter(|r| matches!(r, Req::Next(_)))
        .count();
    assert!(
        nexts <= MAX_PAGES_PER_ROUND,
        "{nexts} pages fetched with no budget"
    );
    assert!(rig.journal.writes().is_empty());
    assert!(rig.journal.sleeps().is_empty());
}

/// POSITIVE CONTROL for the budget. A cap set too low, or checked one page
/// early, makes a large drive permanently unsyncable: 100k items at Graph's
/// default 200 per page is about 500 pages, and every round would fail with an
/// error naming a limit the user cannot influence.
#[test]
fn a_long_finite_enumeration_completes_and_yields_exactly_one_token() {
    let rig = Rig::with_cap(usize::MAX);
    // A trivial second round is scripted only so the acknowledging call below
    // has something to resume; nothing about it is asserted on.
    let pages = GeneratedPages::bounded(rig.journal.clone(), vec![MAX_PAGES_PER_ROUND - 1, 1]);
    let mut d = rig.generated(pages);

    let (changes, cursor) = d
        .changes(&Cursor::default())
        .expect("a long enumeration is not a fault");

    assert_eq!(upsert_count(&changes), MAX_PAGES_PER_ROUND - 1);
    assert_eq!(
        upserted(&changes).len(),
        MAX_PAGES_PER_ROUND - 1,
        "no duplicates"
    );
    // Still exactly one token for the round, written on the call that proves
    // its batch was applied.
    ack(&mut d, &cursor);
    let tokens = rig.store.tokens_written();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].get(&drive_id(MINE)), Some(lnk("D0").as_str()));
    for t in &tokens {
        let bytes = String::from_utf8(t.as_bytes()).expect("utf-8");
        assert!(
            !bytes.contains("token=P"),
            "a nextLink was persisted as a token"
        );
    }
    assert!(cursor_str(&cursor).contains("D0"));
}

/// POSITIVE CONTROL. The counter written as a `GraphDiscover` field rather than
/// a local of the round is the natural place to put it when the budget is added
/// — the budget conceptually belongs to "the provider". The third round then
/// trips a limit the first two consumed, which looks like a flaky network and
/// clears on restart.
#[test]
fn the_page_budget_belongs_to_the_round_not_to_the_provider() {
    let rig = Rig::with_cap(usize::MAX);
    let per_round = MAX_PAGES_PER_ROUND - 2;
    // A fourth round is scripted only so the acknowledging call below has
    // something to resume; nothing about it is asserted on.
    let pages = GeneratedPages::bounded(rig.journal.clone(), vec![per_round; 4]);
    let mut d = rig.generated(pages);

    let (_, c1) = d.changes(&Cursor::default()).expect("round one");
    let (_, c2) = d.changes(&c1).expect("round two");
    let (_, c3) = d.changes(&c2).expect("round three");

    assert!(cursor_str(&c1).contains("D0"));
    assert!(cursor_str(&c2).contains("D1"));
    assert!(cursor_str(&c3).contains("D2"));
    // Each round's token is written by the call that acknowledges it, so three
    // acknowledged rounds are still three tokens — the third one call later.
    ack(&mut d, &c3);
    let tokens = rig.store.tokens_written();
    assert_eq!(tokens.len(), 3);
    for (i, t) in tokens.iter().enumerate() {
        assert_eq!(t.get(&drive_id(MINE)), Some(lnk(&format!("D{i}")).as_str()));
    }
}

/// Graph genuinely serves empty mid-enumeration pages — permission-trimmed
/// results and `$top` interacting with the change feed both produce them. A
/// driver that stops there ends the round early, and because the token it then
/// persists covers the whole feed as far as the service is concerned, every item
/// after the empty page is never mentioned again.
#[test]
fn an_empty_page_carrying_a_next_link_is_followed() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("P1"),
        ))],
    );
    rig.script(next_req("P1"), vec![Reply::ok(body_next(&[], &lnk("P2")))]);
    rig.script(
        next_req("P2"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("DELTA-1"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("three pages");

    assert_eq!(
        rig.journal.calls(),
        vec![first_req(MINE), next_req("P1"), next_req("P2")]
    );
    assert_eq!(
        upserted(&changes),
        set(&[cloud(MINE, "01A"), cloud(MINE, "01B")])
    );
    assert!(cursor_str(&cursor).contains("DELTA-1"));
    // The one token of the round, written on the call that proves its batch was
    // applied.
    ack(&mut d, &cursor);
    assert_eq!(
        rig.journal.token_writes(),
        vec![format!("{MINE}={}", lnk("DELTA-1"))]
    );
}

/// A do-while driver issues one unearned request. Here that request answers with
/// three tombstones, so the round deletes three of the user's files on a pass in
/// which the service reported no change at all.
///
/// The second half: `Cursor(None)` on an empty batch makes
/// `hydration-sync.rs:527` reset the cursor to empty, so the next pass is a full
/// tokenless enumeration — every five seconds, forever.
#[test]
fn a_delta_link_on_the_first_page_completes_the_round_and_nothing_further_is_fetched() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            file_item(MINE, "01B", ROOT, "b.txt", 11, "c:{G},2"),
            file_item(MINE, "01C", ROOT, "c.txt", 12, "c:{G},3"),
        ],
        Some("D9"),
    ));
    let quiet = body_delta(&[], &lnk("DELTA-1"));
    rig.script(resume_req("D9"), vec![Reply::ok(quiet)]);
    // Anything beyond the first request deletes files rather than merely
    // erroring.
    let massacre = body_delta(
        &[
            tomb_json(MINE, "01A", "a.txt", ROOT),
            tomb_json(MINE, "01B", "b.txt", ROOT),
            tomb_json(MINE, "01C", "c.txt", ROOT),
        ],
        &lnk("DELTA-2"),
    );
    for req in [
        next_req("DELTA-1"),
        resume_req("DELTA-1"),
        first_req(MINE),
        latest_req(MINE),
    ] {
        rig.script(req, vec![Reply::ok(massacre.clone())]);
    }

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("a quiet round");

    assert_eq!(rig.journal.calls().len(), 1, "one page, one request");
    assert!(
        removed(&changes).is_empty(),
        "a round that fetched one page too many deleted the user's files"
    );
    assert!(
        cursor.0.is_some(),
        "Cursor(None) makes the driver re-enumerate the whole drive next pass"
    );
    assert!(cursor_str(&cursor).contains("DELTA-1"));
    // The pair lands on the call that proves the batch was applied. Same two
    // writes, same order, same contents, one call later.
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    ack(&mut d, &cursor);
    assert_eq!(
        rig.journal.writes(),
        vec![
            Ev::SaveTree(4),
            Ev::SaveToken(format!("{MINE}={}", lnk("DELTA-1")))
        ]
    );
}

/// "Resume where we left off" is what the variable names invite and what a
/// paging loop over any ordinary REST collection would do. Here it stores a
/// skiptoken as the framework's cursor: the next call resumes from the middle of
/// an abandoned enumeration, and when that partial run reaches a deltaLink it is
/// persisted as a complete token.
#[test]
fn a_transport_failure_mid_chain_never_makes_a_next_link_a_cursor() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("P1"),
        ))],
    );
    rig.script(
        next_req("P1"),
        vec![Reply::fail(io::ErrorKind::ConnectionReset, "reset by peer")],
    );

    let mut d = rig.provider();
    assert!(d.changes(&Cursor::default()).is_err());
    assert!(rig.journal.writes().is_empty());

    rig.journal.clear();
    rig.script(
        next_req("P1"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("DELTA-1"),
        ))],
    );
    let (changes, _) = d.changes(&Cursor::default()).expect("the retry");

    assert_eq!(
        rig.journal.calls().first(),
        Some(&first_req(MINE)),
        "a Graph skiptoken is consumed on use; a retry starts the round again"
    );
    assert_eq!(
        changes
            .iter()
            .filter(|c| matches!(c, Change::Upserted { cloud_id, .. } if *cloud_id == cloud(MINE, "01A")))
            .count(),
        1
    );
}

/// The 200 items of page one are already inside the round's `Namespace`.
/// Returning them as `Ok` has the framework place 200 placeholders and treat the
/// pass as finished, while pages two onwards — including any tombstones on them
/// — are dropped. A blanket retry instead pins the thread on a body that is
/// deterministic and can never parse differently.
#[test]
fn a_page_that_fails_to_parse_loses_the_round_and_is_not_refetched() {
    let rig = Rig::new();
    let mut first = vec![root_json(MINE, ROOT)];
    for i in 0..200 {
        first.push(file_json(
            MINE,
            &format!("01P{i:03}"),
            &format!("p{i:03}.txt"),
            ROOT,
            1,
            &format!("c:{{G}},{i}"),
        ));
    }
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(&first, &lnk("P1")))],
    );
    // `DeltaPage::parse` refuses a page with a null element as a whole
    // (lib.rs:459-468).
    rig.script(
        next_req("P1"),
        vec![Reply::status(
            200,
            &format!(
                r#"{{"value":[{},null],"@odata.nextLink":"{}"}}"#,
                file_json(MINE, "01OK", "ok.txt", ROOT, 1, "c:{G},9"),
                lnk("P2")
            ),
        )],
    );
    rig.script(
        next_req("P2"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01NEVER", "never.txt", ROOT, 1, "c:{G},8")],
            &lnk("DELTA-1"),
        ))],
    );

    let mut d = rig.provider();
    assert!(d.changes(&Cursor::default()).is_err());
    assert_eq!(
        rig.journal.calls(),
        vec![first_req(MINE), next_req("P1")],
        "P1 issued once and only once, P2 never"
    );
    assert!(rig.journal.writes().is_empty());
    assert!(rig.journal.sleeps().is_empty());
}

/// POSITIVE CONTROL. Without it the repair for the test above can be "mark the
/// scope poisoned" or "never re-issue a link that failed", which turns one
/// transient bad response into a drive that never syncs again for the life of
/// the process.
///
/// The no-duplicates and no-removal assertions guard the other repair: keeping
/// the half-built `Round` from the failed attempt and feeding page one into it a
/// second time, which makes the tree disagree with itself.
#[test]
fn a_round_lost_to_a_bad_page_is_reissued_from_the_start_and_completes() {
    let rig = Rig::new();
    let mut first = vec![root_json(MINE, ROOT)];
    for i in 0..200 {
        first.push(file_json(
            MINE,
            &format!("01P{i:03}"),
            &format!("p{i:03}.txt"),
            ROOT,
            1,
            &format!("c:{{G}},{i}"),
        ));
    }
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(&first, &lnk("P1")))],
    );
    rig.script(
        next_req("P1"),
        vec![Reply::status(
            200,
            &format!(r#"{{"value":[null],"@odata.nextLink":"{}"}}"#, lnk("P2")),
        )],
    );

    let mut d = rig.provider();
    assert!(d.changes(&Cursor::default()).is_err());

    rig.journal.clear();
    rig.script(
        next_req("P1"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("DELTA-1"),
        ))],
    );
    let (changes, cursor) = d.changes(&Cursor::default()).expect("the retry completes");

    assert!(rig.journal.calls().contains(&next_req("P1")));
    assert_eq!(upsert_count(&changes), 201);
    assert_eq!(upserted(&changes).len(), 201, "no id twice");
    assert!(removed(&changes).is_empty());
    // One token for the one round that completed, written on the call that
    // proves its batch was applied — the lost round wrote nothing either way.
    ack(&mut d, &cursor);
    assert_eq!(rig.store.tokens_written().len(), 1);
}

/// Restarting the round from `first()` on every 429 means a throttled tenant
/// never finishes an enumeration: the daemon re-fetches page one forever and
/// generates exactly the request volume that caused the throttle. Ignoring the
/// delay earns a longer ban for the whole app registration, which affects every
/// user of the client.
///
/// Three wrong implementations, one assertion each: restart-on-throttle (`First`
/// twice), `std::thread::sleep` instead of the injected `Sleeper` (no recorded
/// sleep — and a seven-second floor under the suite), and reading the delay from
/// `EnvelopeError::Throttled`, which `DeltaPage::parse` hardcodes to `None` at
/// lib.rs:401-405.
#[test]
fn a_429_mid_chain_retries_the_same_link_and_honours_the_delay_the_page_carried() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("P1"),
        ))],
    );
    rig.script(
        next_req("P1"),
        vec![
            Reply::throttled(7),
            Reply::ok(body_delta(
                &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
                &lnk("DELTA-1"),
            )),
        ],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("the retry succeeds");

    assert_eq!(
        rig.journal.calls(),
        vec![first_req(MINE), next_req("P1"), next_req("P1")],
        "the same link is retried; the round is not restarted"
    );
    assert_eq!(
        rig.journal.sleeps(),
        vec![Duration::from_secs(7)],
        "the delay the page carried, through the injected clock"
    );
    assert_eq!(
        upserted(&changes),
        set(&[cloud(MINE, "01A"), cloud(MINE, "01B")])
    );
    assert!(cursor_str(&cursor).contains("DELTA-1"));
}

// ===========================================================================
// CLASS E — A link from the cloud is untrusted input
//
// `PageSource::next` is the seam the credential lives below (`http::HttpPages`
// holds `Arc<Auth>`), so following a cloud-supplied absolute URL hands a live
// OneDrive access token to whatever host the response names. Nothing validates a
// link today: `NextLink(String)` is built straight from the JSON value at
// lib.rs:446 and has no checking constructor.
// ===========================================================================

/// The double *is* scripted to answer the foreign URL successfully, so a driver
/// that follows it returns `Ok` and fails these assertions loudly rather than
/// erroring by accident.
#[test]
fn a_next_link_on_another_host_is_refused_before_it_is_fetched() {
    let rig = Rig::new();
    let evil = "https://evil.example.com/v1.0/drives/b!mine/root/delta?token=P1";
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            evil,
        ))],
    );
    rig.script(
        Req::Next(evil.to_string()),
        vec![Reply::ok(body_delta(&[], &lnk("DELTA-1")))],
    );

    let mut d = rig.provider();
    assert!(d.changes(&Cursor::default()).is_err());
    assert_eq!(
        rig.journal.calls(),
        vec![first_req(MINE)],
        "a bearer token must not be sent to a host the response named"
    );
    assert!(rig.journal.token_writes().is_empty());
    // The expected origin is a pure function of the scope, reachable without the
    // `http` feature — a check that lives below the seam fails this test, which
    // is the intent.
    assert!(delta_url(&primary(MINE)).starts_with("https://graph.microsoft.com/"));
}

/// Each case kills a different plausible check. `contains("graph.microsoft.com")`
/// follows (a), (b) and (c); `starts_with("https://graph.microsoft.com")` — the
/// obvious repair — follows (c), because the userinfo segment makes
/// `evil.example` the real host; a `Url::join(base, link)` check follows (d).
/// Only parsing the URL and comparing scheme, host and port passes all four.
#[test]
fn a_next_link_that_only_resembles_the_endpoint_is_refused() {
    let cases = [
        "http://graph.microsoft.com/v1.0/drives/b!mine/root/delta?token=P1",
        "https://graph.microsoft.com.evil.example/v1.0/drives/b!mine/root/delta?token=P1",
        "https://graph.microsoft.com@evil.example/v1.0/drives/b!mine/root/delta?token=P1",
        "//evil.example/v1.0/drives/b!mine/root/delta?token=P1",
    ];
    for (i, bad) in cases.iter().enumerate() {
        let rig = Rig::new();
        rig.script(
            first_req(MINE),
            vec![Reply::ok(body_next(
                &[
                    root_json(MINE, ROOT),
                    file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                ],
                bad,
            ))],
        );
        rig.script(
            Req::Next(bad.to_string()),
            vec![Reply::ok(body_delta(&[], &lnk("DELTA-1")))],
        );

        let mut d = rig.provider();
        assert!(
            d.changes(&Cursor::default()).is_err(),
            "case {i} ({bad}) was accepted"
        );
        assert_eq!(
            rig.journal.calls(),
            vec![first_req(MINE)],
            "case {i} ({bad}) was fetched"
        );
    }
}

/// POSITIVE CONTROL, taken at the seam because that is the side of it this layer
/// can observe.
///
/// A re-encoded or reconstructed link is a different skiptoken: Graph answers
/// 400, the round never reaches a deltaLink, and every pass restarts the
/// enumeration from scratch — the full `$select` payload for the whole drive,
/// every five seconds. An over-tight repair for the two tests above rebuilds the
/// URL from `delta_url(&scope)` plus an extracted `$skiptoken`, dropping
/// `$select` (which turns deletes into no-ops) and `$top`.
#[test]
fn a_legitimate_next_link_reaches_the_source_byte_for_byte() {
    let rig = Rig::new();
    // Same origin, a different path shape from `delta_url`, reordered query,
    // containing `%2B`, `%3D`, `,` and `$`.
    let legit = "https://graph.microsoft.com/v1.0/drives/b!mine/root/delta?$skiptoken=UDE7bT0x%2Bab%3D&$select=id,name,size,eTag,cTag,file,folder,package,deleted,root,remoteItem,parentReference,fileSystemInfo,lastModifiedDateTime&$top=200";
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
            ],
            legit,
        ))],
    );
    rig.script(
        Req::Next(legit.to_string()),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2")],
            &lnk("DELTA-1"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("a legitimate link");

    let nexts: Vec<Req> = rig
        .journal
        .calls()
        .into_iter()
        .filter(|r| matches!(r, Req::Next(_)))
        .collect();
    assert_eq!(nexts.len(), 1);
    match &nexts[0] {
        Req::Next(seen) => assert_eq!(
            seen, legit,
            "no percent decoding, no re-encoding, no normalisation"
        ),
        other => panic!("expected a Next, got {other:?}"),
    }
    assert_eq!(
        upserted(&changes),
        set(&[cloud(MINE, "01A"), cloud(MINE, "01B")])
    );
    assert!(cursor_str(&cursor).contains("DELTA-1"));
}

// ===========================================================================
// CLASS F — One round, several drives
//
// `Round` holds a single `token: Option<DeltaLink>` (lib.rs:1163) and `feed`
// overwrites it on every `PageEnd::Done` (lib.rs:1214-1216). Every existing
// round test in tests/mapping.rs feeds one scope to completion before starting
// the next, so nothing currently distinguishes "one token" from "one token per
// drive".
// ===========================================================================

const SHARE: &str = "01SH";
const FAR_ROOT: &str = "01FAR";

fn fan_out_primary_page(end_next: Option<&str>) -> String {
    let items = [
        root_json(MINE, ROOT),
        share_json(MINE, SHARE, "Team Files", ROOT, THEIRS, FAR_ROOT, "01FARROOT"),
    ];
    match end_next {
        Some(n) => body_next(&items, n),
        None => body_delta(&items, &link_on(MINE, "DM")),
    }
}

/// Resuming b!mine with b!theirs's token gets a 400 and a full re-enumeration
/// every round; if the service accepts it instead, the near drive is reconciled
/// against the far drive's change list and local files are removed on the
/// strength of a feed that never mentioned them.
///
/// The same item id is used on both drives on purpose.
#[test]
fn two_scopes_in_one_round_each_get_their_own_token() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(fan_out_primary_page(Some(&link_on(MINE, "PM1"))))],
    );
    rig.script(
        next_req_on(MINE, "PM1"),
        vec![Reply::ok(body_delta(
            &[file_json(MINE, "01X", "x.txt", ROOT, 10, "c:{G},1")],
            &link_on(MINE, "DM"),
        ))],
    );
    rig.script(
        first_req(THEIRS),
        vec![Reply::ok(body_next(
            &[file_json(THEIRS, "01X", "x.txt", FAR_ROOT, 20, "c:{H},1")],
            &link_on(THEIRS, "PT1"),
        ))],
    );
    rig.script(
        next_req_on(THEIRS, "PT1"),
        vec![Reply::ok(body_delta(
            &[file_json(THEIRS, "01Y", "y.txt", FAR_ROOT, 21, "c:{H},2")],
            &link_on(THEIRS, "DT"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("a fan-out round");

    assert!(upserted(&changes).contains(&cloud(MINE, "01X")));
    assert!(upserted(&changes).contains(&cloud(THEIRS, "01X")));
    // Still one token write for the whole fan-out, on the call that proves the
    // round's batch was applied.
    ack(&mut d, &cursor);
    let tokens = rig.store.tokens_written();
    assert_eq!(tokens.len(), 1, "one round, one token write");
    let blob = &tokens[0];
    assert_eq!(blob.get(&drive_id(MINE)), Some(link_on(MINE, "DM").as_str()));
    assert_eq!(
        blob.get(&drive_id(THEIRS)),
        Some(link_on(THEIRS, "DT").as_str())
    );
    assert_ne!(blob.get(&drive_id(MINE)), blob.get(&drive_id(THEIRS)));
}

/// A loop whose condition is "has this round got a token yet" stops as soon as
/// any scope reports `Done` — the natural reading given `Round`'s single `token`
/// field. The shared folder then syncs its first page and nothing else, and
/// because the primary token does advance, the missing items are never mentioned
/// again: a Team Files folder holding 200 of 3000 documents, permanently, with
/// no error anywhere.
#[test]
fn a_delta_link_for_one_scope_does_not_end_another_scopes_paging() {
    let rig = Rig::new();
    rig.script(first_req(MINE), vec![Reply::ok(fan_out_primary_page(None))]);
    rig.script(
        first_req(THEIRS),
        vec![Reply::ok(body_next(
            &[file_json(THEIRS, "01X", "x.txt", FAR_ROOT, 20, "c:{H},1")],
            &link_on(THEIRS, "PT1"),
        ))],
    );
    rig.script(
        next_req_on(THEIRS, "PT1"),
        vec![Reply::ok(body_delta(
            &[file_json(THEIRS, "01Y", "y.txt", FAR_ROOT, 21, "c:{H},2")],
            &link_on(THEIRS, "DT"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d.changes(&Cursor::default()).expect("a fan-out round");

    assert!(
        rig.journal.calls().contains(&next_req_on(THEIRS, "PT1")),
        "the mounted scope's paging is its own"
    );
    assert!(upserted(&changes).contains(&cloud(THEIRS, "01Y")));
    assert_eq!(
        path_of(&changes, &cloud(THEIRS, "01Y")),
        Some("Team Files/y.txt"),
        "the far side hangs from the near placeholder, not from a root of its own"
    );
    // The token is written by the call that proves the round's batch was
    // applied; it still carries both scopes' links.
    ack(&mut d, &cursor);
    let blob = rig.store.tokens_written().pop().expect("a token");
    assert_eq!(blob.get(&drive_id(MINE)), Some(link_on(MINE, "DM").as_str()));
    assert_eq!(
        blob.get(&drive_id(THEIRS)),
        Some(link_on(THEIRS, "DT").as_str())
    );
}

/// A deltaLink embeds the drive it enumerates, so resuming the wrong one
/// enumerates the wrong drive into the wrong scope. And a token blob holding one
/// link per store rather than one per drive silently discards a mount's token on
/// every primary round: the shared library is fully re-enumerated every pass
/// against a throttling endpoint.
#[test]
fn each_drives_token_is_stored_and_resumed_under_its_own_drive_id() {
    let rig = Rig::new();
    rig.script(first_req(MINE), vec![Reply::ok(fan_out_primary_page(None))]);
    rig.script(
        first_req(THEIRS),
        vec![Reply::ok(body_delta(
            &[file_json(THEIRS, "01X", "x.txt", FAR_ROOT, 20, "c:{H},1")],
            &link_on(THEIRS, "DT"),
        ))],
    );
    let mut one = rig.provider();
    let (_, c1) = one.changes(&Cursor::default()).expect("round one");
    // Round one's per-drive token blob lands on the call that proves its batch
    // was applied; it is what round two has to resume from.
    ack(&mut one, &c1);

    rig.journal.clear();
    rig.script(
        resume_req_on(MINE, "DM"),
        vec![Reply::ok(body_delta(&[], &link_on(MINE, "DM2")))],
    );
    rig.script(
        resume_req_on(THEIRS, "DT"),
        vec![Reply::ok(body_delta(&[], &link_on(THEIRS, "DT2")))],
    );

    let mut two = rig.provider();
    two.changes(&Cursor::default()).expect("round two resumes");

    let calls = rig.journal.calls();
    assert!(calls.contains(&resume_req_on(MINE, "DM")));
    assert!(calls.contains(&resume_req_on(THEIRS, "DT")));
    assert!(
        !calls.contains(&first_req(MINE)) && !calls.contains(&first_req(THEIRS)),
        "neither scope re-enumerates: {calls:?}"
    );
    let blob = rig.store.stored_token().expect("a token blob");
    assert!(blob.get(&drive_id(MINE)).is_some());
    assert!(blob.get(&drive_id(THEIRS)).is_some());
}

/// The user signed into a different account, or the site id changed.
///
/// If the old tree is kept and diffed, every file of the old account is reported
/// `Removed` — a mass local deletion driven by a sign-in. If it is kept and
/// merged, the new drive's root is refused as `Problem::ForeignRoot` and every
/// new item waits forever on a root that will never arrive.
#[test]
fn state_belonging_to_another_drive_is_discarded_whole_and_reports_no_deletions() {
    let rig = Rig::new();
    rig.script(
        first_req(OLD),
        vec![Reply::ok(body_delta(
            &[
                root_json(OLD, ROOT),
                file_json(OLD, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(OLD, "01B", "b.txt", ROOT, 11, "c:{G},2"),
                file_json(OLD, "01C", "c.txt", ROOT, 12, "c:{G},3"),
            ],
            &link_on(OLD, "DELTA-OLD-1"),
        ))],
    );
    let mut old = rig.provider_for(primary(OLD));
    let (_, c_old) = old.changes(&Cursor::default()).expect("the old account");
    // The old account's pair lands on the call that proves its batch was
    // applied — that is the state the new sign-in has to discard.
    ack(&mut old, &c_old);

    rig.journal.clear();
    rig.script(
        first_req(NEW),
        vec![Reply::ok(body_delta(
            &[
                root_json(NEW, "01ROOT2"),
                file_json(NEW, "01A2", "a2.txt", "01ROOT2", 10, "c:{G},9"),
            ],
            &link_on(NEW, "DELTA-NEW-1"),
        ))],
    );
    // Scripted so the wrong branch does not error for an unrelated reason.
    rig.script(
        resume_req_on(OLD, "DELTA-OLD-1"),
        vec![Reply::ok(body_delta(&[], &link_on(OLD, "DELTA-OLD-2")))],
    );

    let mut fresh = rig.provider_for(primary(NEW));
    let (changes, c_new) = fresh
        .changes(&Cursor::default())
        .expect("a new drive is not a fault");

    assert!(
        removed(&changes).is_empty(),
        "a sign-in change must not delete the old account's files locally"
    );
    for id in upserted(&changes) {
        assert!(id.starts_with(NEW), "{id} is not on the drive being synced");
    }
    assert!(rig.journal.calls().contains(&first_req(NEW)));
    assert!(!rig
        .journal
        .calls()
        .contains(&resume_req_on(OLD, "DELTA-OLD-1")));
    // The new drive's tree replaces the old one on the call that proves its
    // batch was applied.
    ack(&mut fresh, &c_new);
    let tree = rig.store.stored_tree().expect("a tree");
    assert!(tree_ids(&tree).iter().all(|id| id.starts_with(NEW)));
}

// ===========================================================================
// CLASS G — Recovery, and the deletions only a diff can find
//
// Graph tokens expire in days. PROVIDER.md calls a full listing plus a fresh
// cursor a supported outcome, not a failure — and `listing()` cannot express a
// deletion, so a provider recovering from one must diff.
// ===========================================================================

/// Mapping the 410 to an `io::Error` wedges the provider permanently: the
/// framework has no other way to ask, so the drive never syncs again and the
/// only symptom is a repeating log line. Recovering but discarding the tree
/// loses the 01C deletion silently.
#[test]
fn an_expired_token_re_enumerates_and_returns_a_fresh_cursor_rather_than_erroring_forever() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            file_item(MINE, "01B", ROOT, "b.txt", 11, "c:{G},2"),
            file_item(MINE, "01C", ROOT, "c.txt", 12, "c:{G},3"),
        ],
        Some("D9"),
    ));
    rig.script(
        resume_req("D9"),
        vec![Reply::status(410, r#"{"error":{"code":"resyncRequired"}}"#)],
    );
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
            ],
            &lnk("D20"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d
        .changes(&Cursor::default())
        .expect("an expired token is a supported outcome, not a failure");

    assert_eq!(rig.journal.calls(), vec![resume_req("D9"), first_req(MINE)]);
    assert_eq!(
        upserted(&changes),
        set(&[cloud(MINE, "01A"), cloud(MINE, "01B")])
    );
    assert_eq!(removed(&changes), set(&[cloud(MINE, "01C")]));
    assert!(cursor.0.is_some() && cursor_str(&cursor).contains("D20"));
    // The recovered pair lands on the call that proves the batch was applied.
    // Same two writes, same order, same contents, one call later.
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    ack(&mut d, &cursor);
    assert_eq!(
        rig.journal.writes(),
        vec![
            Ev::SaveTree(3),
            Ev::SaveToken(format!("{MINE}={}", lnk("D20")))
        ]
    );
}

/// POSITIVE CONTROL for the recovery path, and the one test that requires it to
/// complete *and* to delete.
///
/// The design's own wording, implemented literally — `Ok((self.namespace
/// .listing(), Cursor(Some(new_link))))` — returns two upserts and no removal:
/// the round completes, the cursor advances, and `c.txt` is a permanent orphan.
/// Calling `latest()` after the 410 skips the enumeration entirely and re-anchors
/// the token to a drive state it never read.
#[test]
fn the_expired_token_diff_removes_a_file_deleted_while_the_token_was_dead() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
                file_json(MINE, "01C", "c.txt", ROOT, 12, "c:{G},3"),
            ],
            &lnk("DELTA-1"),
        ))],
    );
    rig.script(
        latest_req(MINE),
        vec![Reply::ok(body_delta(&[], &lnk("DLATEST")))],
    );
    let mut one = rig.provider();
    let (_, c1) = one.changes(&Cursor::default()).expect("round one");
    // Round one's pair lands on the call that proves its batch was applied —
    // it is the tree the expired-token diff below is taken against.
    ack(&mut one, &c1);

    rig.journal.clear();
    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::status(
            410,
            r#"{"error":{"code":"resyncRequired","message":"Resync required."}}"#,
        )],
    );
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
            ],
            &lnk("DELTA-2"),
        ))],
    );

    let mut two = rig.provider();
    let (changes, cursor) = two.changes(&Cursor::default()).expect("recovery completes");

    assert_eq!(
        rig.journal.calls(),
        vec![resume_req("DELTA-1"), first_req(MINE)],
        "resume, then enumerate — and never ?token=latest"
    );
    assert_eq!(removed(&changes), set(&[cloud(MINE, "01C")]));
    assert!(upserted(&changes).contains(&cloud(MINE, "01A")));
    assert!(upserted(&changes).contains(&cloud(MINE, "01B")));
    assert!(cursor_str(&cursor).contains("DELTA-2"));
    // The recovered pair lands on the call that proves the batch was applied.
    // Same two writes, same order, same contents, one call later.
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    ack(&mut two, &cursor);
    assert_eq!(
        rig.journal.writes(),
        vec![
            Ev::SaveTree(3),
            Ev::SaveToken(format!("{MINE}={}", lnk("DELTA-2")))
        ]
    );
    assert!(!tree_ids(&rig.store.stored_tree().unwrap()).contains(&cloud(MINE, "01C")));
}

/// Three of the user's files deleted by a dropped TCP connection.
///
/// The blast-radius guard gives false confidence: three removals out of five
/// known is nowhere near `max(64, known / 10)`, so the guard passes it, and on a
/// real drive any truncated enumeration under 64 items short walks straight
/// through. Only a rule that says an unfinished enumeration is not evidence of
/// absence stops it.
#[test]
fn a_re_enumeration_that_did_not_finish_is_never_diffed_for_deletions() {
    let rig = Rig::new();
    let mut items = vec![root_item(MINE, ROOT)];
    for (i, id) in ["01A", "01B", "01C", "01D", "01E"].iter().enumerate() {
        items.push(file_item(
            MINE,
            id,
            ROOT,
            &format!("{id}.txt"),
            10,
            &format!("c:{{G}},{i}"),
        ));
    }
    rig.store.preload(primed(&items, Some("DELTA-1")));
    let tree_before = rig.store.tree_bytes().expect("a tree");
    let token_before = rig.store.token_bytes().expect("a token");

    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::status(410, r#"{"error":{"code":"resyncRequired"}}"#)],
    );
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_next(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "01A.txt", ROOT, 10, "c:{G},0"),
                file_json(MINE, "01B", "01B.txt", ROOT, 10, "c:{G},1"),
            ],
            &lnk("NEXT-1"),
        ))],
    );
    rig.script(
        next_req("NEXT-1"),
        vec![Reply::fail(io::ErrorKind::ConnectionReset, "reset by peer")],
    );

    let mut d = rig.provider();
    let outcome = d.changes(&Cursor::default());
    if let Ok((changes, _)) = &outcome {
        assert!(
            removed(changes).is_empty(),
            "an unfinished enumeration is not evidence of absence: {:?}",
            removed(changes)
        );
    }
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    assert_eq!(rig.store.tree_bytes(), Some(tree_before));
    assert_eq!(rig.store.token_bytes(), Some(token_before));
}

/// An escalation that overwrites its own evidence is a one-shot alarm.
///
/// Persisting the one-item tree before deciding to refuse means the next round
/// starts from a tree that agrees the drive is empty — the guard cannot fire a
/// second time because `known` is now 1, and the 500 placeholders are unknown to
/// the provider forever. "Write the tree first, then the token" read as "always
/// write the tree, then decide about the token" satisfies every call-order
/// assertion and destroys the state the refusal was protecting.
#[test]
fn a_round_the_blast_guard_refused_does_not_overwrite_the_tree_it_refused_to_trust() {
    let rig = Rig::new();
    let mut items = vec![root_item(MINE, ROOT)];
    for i in 0..500 {
        items.push(file_item(
            MINE,
            &format!("01F{i:03}"),
            ROOT,
            &format!("f{i:03}.txt"),
            1,
            &format!("c:{{G}},{i}"),
        ));
    }
    rig.store.preload(primed(&items, Some("DELTA-1")));
    let tree_before = rig.store.tree_bytes().expect("a tree");
    let token_before = rig.store.token_bytes().expect("a token");

    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::status(410, r#"{"error":{"code":"resyncRequired"}}"#)],
    );
    // A complete, well-formed enumeration that reports an empty drive — what a
    // revoked permission or a wrong `$select` produces.
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[root_json(MINE, ROOT)],
            &lnk("DELTA-2"),
        ))],
    );

    let mut d = rig.provider();
    assert!(
        d.changes(&Cursor::default()).is_err(),
        "500 removals in one batch is a bug, not an instruction"
    );
    assert!(d.last_escalation().is_some(), "the refusal must be nameable");
    assert!(rig.journal.writes().is_empty(), "{:?}", rig.journal.writes());
    assert_eq!(rig.store.tree_bytes(), Some(tree_before));
    assert_eq!(rig.store.token_bytes(), Some(token_before));
}

// ===========================================================================
// CLASS H — What the tree has to carry across a restart
//
// The restart is the only place these failures can enter: the mapping layer gets
// every one of them right on the round that first sees the item.
// ===========================================================================

/// An unreadable tree is a tree we do not have, and a token whose tree we do not
/// have is the unrecoverable pair.
///
/// `unwrap_or_default()` on the parse looks like a fresh install — but the token
/// is still there and gets resumed, so the drive is never enumerated.
/// `.expect("our own file")` kills the delta thread, which is spawned bare and
/// never restarted, so sync stops silently for the life of the process.
#[test]
fn a_tree_that_fails_to_deserialise_discards_the_token_with_it() {
    let rig = Rig::new();
    // Valid JSON prefix, truncated mid-key.
    let truncated = TreeBlob::from_bytes(
        br#"{"items":[{"Upsert":{"id":"b!mine|01A","parent":"b!mine|01ROOT","name":"a.txt","kin"#
            .to_vec(),
    );
    rig.store.preload_raw(
        Some(truncated),
        Some(TokenBlob::one(&drive_id(MINE), &lnk("DELTA-1"))),
    );
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
            ],
            &lnk("DELTA-2"),
        ))],
    );
    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G},2"),
            ],
            &lnk("DELTA-2"),
        ))],
    );

    let mut d = rig.provider();
    let (changes, cursor) = d
        .changes(&Cursor::default())
        .expect("a corrupt tree is recoverable, and no panic escapes");

    assert!(rig.journal.calls().contains(&first_req(MINE)));
    assert!(!rig.journal.calls().contains(&resume_req("DELTA-1")));
    assert!(removed(&changes).is_empty());
    // The replacement tree lands on the call that proves the batch was applied.
    ack(&mut d, &cursor);
    let tree = rig.store.stored_tree().expect("a tree was rewritten");
    let ids = tree_ids(&tree);
    assert!(ids.contains(&cloud(MINE, "01A")) && ids.contains(&cloud(MINE, "01B")));
}

/// `delta::is_current` byte-compares the etag and treats `(Some(remote), None)`
/// as not-current. A tree format that drops the tag makes every file on the
/// drive compare as changed after the first restart, and `apply` then calls
/// `place()` on each one — every hydrated file the user has is replaced by a
/// placeholder in a single pass, which on a laptop that is offline by evening is
/// their content gone.
///
/// Round two reports no content change on purpose, so a dropped tag surfaces as
/// a wrong etag rather than a legitimately refreshed one.
#[test]
fn the_content_tag_survives_the_tree_round_trip() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01A", "a.txt", ROOT, 10, "c:{G1},1"),
                file_json(MINE, "01B", "b.txt", ROOT, 11, "c:{G2},7"),
            ],
            &lnk("DELTA-1"),
        ))],
    );
    let mut one = rig.provider();
    let (b1, c1) = one.changes(&Cursor::default()).expect("round one");
    assert_eq!(etag_of(&b1, &cloud(MINE, "01A")), Some("ct:c:{G1},1"));
    // Round one's tree lands on the call that proves its batch was applied.
    // Without it the restart below finds an empty store and re-enumerates,
    // which would answer this test out of the page rather than out of the tree.
    ack(&mut one, &c1);

    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::ok(body_delta(
            &[root_json(MINE, ROOT)],
            &lnk("DELTA-2"),
        ))],
    );
    let mut two = rig.provider();
    let (b2, _) = two.changes(&Cursor::default()).expect("round two");

    assert_eq!(
        etag_of(&b2, &cloud(MINE, "01A")),
        Some("ct:c:{G1},1"),
        "the tag must survive the tree, byte for byte"
    );
    assert_eq!(etag_of(&b2, &cloud(MINE, "01B")), Some("ct:c:{G2},7"));
}

/// A OneNote notebook synced as an ordinary folder is corrupted piecemeal — its
/// sections are written out as separate files and the notebook is no longer
/// openable. `enum StoredKind { File { .. }, Dir }` collapses Folder and Opaque,
/// which is tempting because `Namespace` treats them identically for pathing.
#[test]
fn a_package_is_still_opaque_after_a_restart() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                package_json(MINE, "01NB", "Notes", ROOT),
            ],
            &lnk("DELTA-1"),
        ))],
    );
    let mut one = rig.provider();
    let (_, c1) = one.changes(&Cursor::default()).expect("round one");
    // Round one's tree lands on the call that proves its batch was applied.
    // Without it the restart below finds an empty store and re-enumerates,
    // which would never read the notebook back out of the tree at all.
    ack(&mut one, &c1);
    match tree_entry(&rig.store.stored_tree().unwrap(), &cloud(MINE, "01NB")) {
        Some(Item::Upsert { kind, .. }) => assert_eq!(kind, Kind::Opaque),
        other => panic!("the notebook must be stored as opaque: {other:?}"),
    }

    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                file_json(MINE, "01SEC", "Section.one", "01NB", 40960, "c:{G9},1"),
            ],
            &lnk("DELTA-2"),
        ))],
    );
    let mut two = rig.provider();
    let (changes, c2) = two.changes(&Cursor::default()).expect("round two");

    for p in paths(&changes) {
        assert!(!p.contains("Notes/"), "walked into a package: {p}");
        assert!(!p.ends_with(".one"), "emitted a notebook internal: {p}");
    }
    // Acknowledged too, so the tree checked below is the one round two wrote
    // back after reading the notebook out of round one's — not round one's own.
    ack(&mut two, &c2);
    match tree_entry(&rig.store.stored_tree().unwrap(), &cloud(MINE, "01NB")) {
        Some(Item::Upsert { kind, .. }) => assert_eq!(kind, Kind::Opaque),
        other => panic!("still opaque after the restart: {other:?}"),
    }
}

/// Every tag on the drive changing at once.
///
/// `is_current` compares byte for byte, so a source that flips from `qx:` to
/// `ct:` between two rounds makes every file look stale simultaneously and the
/// next pass re-places all of them — the same whole-drive dehydration as a
/// dropped tag, triggered by nothing more than a restart plus a service that
/// started reporting cTags. The prefixes exist precisely so this is visible, and
/// this is the test that makes them do work.
#[test]
fn the_pinned_tag_source_is_persisted_and_never_re_probed() {
    let rig = Rig::new();
    rig.script(
        first_req(MINE),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                qx_file_json(MINE, "01A", "a.txt", ROOT, 10, "QXAAA"),
                qx_file_json(MINE, "01B", "b.txt", ROOT, 11, "QXBBB"),
            ],
            &lnk("DELTA-1"),
        ))],
    );
    let mut one = rig.provider();
    let (b1, c1) = one.changes(&Cursor::default()).expect("round one");
    assert_eq!(
        etag_of(&b1, &cloud(MINE, "01A")),
        Some("qx:QXAAA"),
        "a drive with hashes and no cTags pins QuickXor"
    );
    // Round one's tree — and with it the pinned tag source — lands on the call
    // that proves its batch was applied. Without it the restart below finds an
    // empty store, re-probes from a fresh page, and the pin is never tested.
    ack(&mut one, &c1);

    rig.script(
        resume_req("DELTA-1"),
        vec![Reply::ok(body_delta(
            &[
                root_json(MINE, ROOT),
                qx_and_ctag_file_json(MINE, "01A", "a.txt", ROOT, 10, "QXAAA", "c:{G1},1"),
                qx_and_ctag_file_json(MINE, "01B", "b.txt", ROOT, 11, "QXBBB", "c:{G2},1"),
            ],
            &lnk("DELTA-2"),
        ))],
    );
    let mut two = rig.provider();
    let (b2, _) = two.changes(&Cursor::default()).expect("round two");

    assert_eq!(
        etag_of(&b2, &cloud(MINE, "01A")),
        Some("qx:QXAAA"),
        "the source is pinned once and persisted, never re-probed per page"
    );
    for c in &b2 {
        if let Change::Upserted { etag: Some(e), .. } = c {
            assert!(!e.starts_with("ct:"), "the tag source flipped: {e}");
        }
    }
}

// ===========================================================================
// CLASS I — An unacknowledged batch and a restart
//
// `a_removal_the_framework_could_not_apply_is_re_served_not_forgotten` proves
// the removal survives a repeat *within one process*. The copy it survives in is
// `self.served` — a `Vec<Change>` in RAM. This class asks the only question that
// is left: what happens when the process does not live long enough to be asked
// again.
// ===========================================================================

/// The delta thread is spawned bare (`hydration-sync.rs:446`), so a stalled
/// drive is one `SIGTERM`, one panic in a sibling thread or one laptop lid away
/// from a restart, and the daemon restarts on a five-second loop.
///
/// The window is exactly this: round one consumed 01X's tombstone from the D9
/// feed and returned the `Removed`. `hydration-sync.rs:483-490` held the cursor
/// because the pass was retryable, so `changes` is never called with the cursor
/// round one minted — the batch was never applied. Then the process dies.
///
/// Whether the removal is recoverable is decided entirely by which token is on
/// disk at that moment, and that is the whole of decision 3 in
/// `docs/GRAPH-DISCOVER-GROUNDWORK.md`:
///
///   * token still at **D9** — the position the batch was read from — and the
///     fresh instance re-asks Graph from there and is handed the tombstone
///     again;
///   * token already at **D10** and the tombstone is unreachable forever. Graph
///     does not replay a consumed tombstone, `Namespace::listing()` cannot
///     express a deletion, and the tree written alongside that token already
///     agrees 01X is gone — so no diff can rediscover it either. The user keeps
///     a placeholder for a deleted object, and an edit to it uploads content
///     back into that object.
///
/// Both branches are scripted to succeed, so the wrong one is quiet: a provider
/// that advanced to D10 resumes D10 and is answered with a well-formed, entirely
/// ordinary empty page. Nothing errors. The only thing that distinguishes right
/// from wrong is whether 01X is in the batch.
#[test]
fn a_removal_a_restart_interrupted_before_it_was_applied_is_still_reported() {
    let rig = Rig::new();
    rig.store.preload(primed(
        &[
            root_item(MINE, ROOT),
            file_item(MINE, "01A", ROOT, "a.txt", 10, "c:{G},1"),
            file_item(MINE, "01B", ROOT, "b.txt", 11, "c:{G},2"),
            file_item(MINE, "01X", ROOT, "x.txt", 12, "c:{G},3"),
        ],
        Some("D9"),
    ));
    // The tombstone lives on the D9 token and nowhere else. The last reply for a
    // key repeats forever, so this is also "Graph replays it for as long as D9 is
    // the position" — which is what makes the surviving-token branch recoverable.
    rig.script(
        resume_req("D9"),
        vec![Reply::ok(body_delta(
            &[tomb_json(MINE, "01X", "x.txt", ROOT)],
            &lnk("D10"),
        ))],
    );
    // Past the tombstone the feed is quiet: Graph has nothing further to say,
    // because it already said it once, on the earlier token.
    rig.script(
        resume_req("D10"),
        vec![Reply::ok(body_delta(&[], &lnk("D11")))],
    );

    let mut one = rig.provider();
    let (b1, _c1) = one.changes(&Cursor::default()).expect("round one");
    assert_eq!(
        removed(&b1),
        set(&[cloud(MINE, "01X")]),
        "round one consumed the tombstone and must report it"
    );

    // What the dying process left behind.
    let token_after_one = rig
        .store
        .stored_token()
        .map(|t| render_token(&t))
        .unwrap_or_else(|| "<none>".into());
    let tree_after_one_holds_x = rig
        .store
        .stored_tree()
        .map(|t| tree_ids(&t).contains(&cloud(MINE, "01X")))
        .unwrap_or(false);

    // The framework never applied the batch, so `changes` is never called again
    // with the cursor round one returned. The process dies here.
    drop(one);
    rig.journal.clear();

    // A restart: a fresh instance over the same state directory, handed the
    // empty cursor the framework hands after every restart.
    let mut two = rig.provider();
    let (b2, _c2) = two
        .changes(&Cursor::default())
        .expect("a restart with good state must not fail");

    assert_eq!(
        removed(&b2),
        set(&[cloud(MINE, "01X")]),
        "the only copy of this removal was a Vec<Change> in the dead process's \
         memory.\n  round one left the token at {token_after_one}\n  round one's \
         tree {} 01X\n  the restart issued {:?}\n  and got back removals {:?}",
        if tree_after_one_holds_x {
            "still holds"
        } else {
            "no longer holds"
        },
        rig.journal.calls(),
        removed(&b2),
    );
}

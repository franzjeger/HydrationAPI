//! Attack tests for the `hydration-graph` *write* half — everything between
//! `hydration_client::upload::Sink` and the `Transport` seam.
//!
//! `tests/discover.rs` covers the download direction. Nothing there can fail an
//! implementation that reads a drive perfectly and then addresses a content
//! write by path, retries a `412` without its precondition, commits a session
//! over an object another device moved on, or answers a `409` by replacing the
//! stranger's file that caused it. Those are the failures in this file, and
//! every one of them destroys data that exists nowhere else.
//!
//! Same three construction rules as `discover.rs`, and they matter more here
//! because the wrong branch on this side is usually the one the service is
//! happiest to serve:
//!
//!   * **The wrong branch is always scripted to succeed.** The path-addressed
//!     write returns `200`. The `DELETE` returns `204`. The
//!     `conflictBehavior=replace` retry returns `201`. Only the recorded log
//!     tells right from wrong.
//!   * **Every refusal has a positive control.** "Refuse every write that
//!     cannot be proven safe" satisfies most of this file and ships a client
//!     whose users' edits die with the laptop.
//!   * **Nothing sleeps, and nothing touches a socket.** The `Sleeper` is
//!     injected and records; files are real, under `CARGO_TARGET_TMPDIR`,
//!     because the bytes on the wire are half of what is being asserted.
//!
//! ## Why the seam is a whole request
//!
//! The read half's `PageSource` sends *typed* requests, because everything it
//! has to prove is about which page was asked for. Every rule below is instead
//! about the request itself — the URL an update was addressed at, the
//! `if-match` a conditional write carried, the `content-range` on a fragment,
//! the conflict behaviour a create declared, and whether the account credential
//! was attached at all. So `Transport` carries a `Request` and returns a
//! `Reply`, and the sink builds both.
//!
//! ## The addressing grammar these tests fix
//!
//! * update content: `PUT {BASE}/drives/{d}/items/{i}/content`
//! * create content: `PUT {BASE}/drives/{d}/root:/{rel}:/content?@microsoft.graph.conflictBehavior=…`
//! * update session: `POST {BASE}/drives/{d}/items/{i}/createUploadSession`
//! * create session: `POST {BASE}/drives/{d}/root:/{rel}:/createUploadSession`
//! * metadata: `GET {BASE}/drives/{d}/items/{i}?$select=…`
//! * rename: `PATCH {BASE}/drives/{d}/items/{i}`
//! * remove: `DELETE {BASE}/drives/{d}/items/{i}`
//! * fragments, status and cancel: the `uploadUrl` verbatim, **unauthorised**

#![allow(clippy::type_complexity)]

use std::collections::BTreeSet;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hydration_client::delta::Change;
use hydration_client::namespace::Namespace;
use hydration_client::store::{self, Store};
use hydration_client::upload::{run_upload, Known, Outcome as RunOutcome, Sink, Uploaded};
use hydration_graph::{
    DeltaPage, DriveId, DriveScope, GraphSink, ItemId, Method, ObjectKey, Reply, Request, Round,
    Sleeper, TagSource, Transport, UploadPolicy, FRAGMENT_QUANTUM, MAX_FRAGMENT_BYTES,
};
use hydration_protocol::{stamp, xattr, FileId};

// ===========================================================================
// Ids, URLs and wire fixtures
// ===========================================================================

const BASE: &str = "https://graph.microsoft.com/v1.0";
const MINE: &str = "b!mine";
const THEIRS: &str = "b!theirs";
const ROOT: &str = "01ROOT";

/// Graph's own expiry stamp. Never read by these tests; present because a
/// session response that lacks it is a different fixture.
const EXPIRES: &str = "2026-08-09T12:00:00Z";

fn drive_id(s: &str) -> DriveId {
    DriveId::parse(s).unwrap_or_else(|e| panic!("fixture drive id {s:?} must parse: {e:?}"))
}

fn item_id(s: &str) -> ItemId {
    ItemId::parse(s).unwrap_or_else(|e| panic!("fixture item id {s:?} must parse: {e:?}"))
}

/// The framework's `Known`, carrying an id and no tag.
///
/// No tag on purpose: these tests seed the sink's own memory with `record_tag`,
/// so they go on measuring the provider's recollection of a completed round.
/// The path where the *framework* supplies the tag — the one that had never run
/// outside a test — is covered separately, by the test that calls no
/// `record_tag` at all.
fn at(id: &str) -> Option<Known<'_>> {
    Some(Known {
        cloud_id: id,
        tag: None,
    })
}

/// The expected `cloud_id`, built the only way the crate permits one to be
/// built. Every identity assertion in this file goes through here rather than
/// through a hand-written `"b!mine|01X"`, so a change to the separator cannot
/// leave the tests agreeing with themselves and disagreeing with the crate.
fn cloud(drive: &str, item: &str) -> String {
    ObjectKey::new(drive_id(drive), item_id(item))
        .to_cloud_id()
        .into_inner()
}

fn primary(drive: &str) -> DriveScope {
    DriveScope::primary(drive_id(drive))
}

// --- URLs ------------------------------------------------------------------

/// `PUT`ting content at an object the sink knows the id of.
fn item_content(drive: &str, item: &str) -> String {
    format!("{BASE}/drives/{drive}/items/{item}/content")
}

/// Reading the metadata of whatever object holds a drive-root-relative path.
fn path_meta(drive: &str, rel: &str) -> String {
    format!("{BASE}/drives/{drive}/root:/{rel}")
}

/// `PUT`ting content at a drive-root-relative path. The create form.
fn path_content(drive: &str, rel: &str) -> String {
    format!("{BASE}/drives/{drive}/root:/{rel}:/content")
}

fn item_session(drive: &str, item: &str) -> String {
    format!("{BASE}/drives/{drive}/items/{item}/createUploadSession")
}

fn path_session(drive: &str, rel: &str) -> String {
    format!("{BASE}/drives/{drive}/root:/{rel}:/createUploadSession")
}

/// Metadata, and — with `DELETE` — the object itself.
fn item_url(drive: &str, item: &str) -> String {
    format!("{BASE}/drives/{drive}/items/{item}")
}

/// Creating a child beneath a folder addressed by its stable identity.
fn item_children(drive: &str, item: &str) -> String {
    format!("{BASE}/drives/{drive}/items/{item}/children")
}

/// An upload session URL. A different host, which is the whole point: it is
/// named by a response body and must never receive the Graph credential.
fn upload_url(tag: &str) -> String {
    format!("https://sn3302.up.1drv.com/up/{tag}")
}

// --- bodies ----------------------------------------------------------------

/// A drive item that also carries the QuickXorHash Graph reports for content.
///
/// `drive_item` deliberately has none — most of this file is about tags and
/// names, where a hash would be noise. The collision-reconciliation path is the
/// one place the hash is the whole answer.
fn hashed_item(id: &str, name: &str, body: &[u8], ctag: &str) -> String {
    serde_json::json!({
        "id": id,
        "name": name,
        "size": body.len(),
        "cTag": ctag,
        "eTag": ctag,
        "file": {
            "mimeType": "application/octet-stream",
            "hashes": {"quickXorHash": hydration_graph::quickxor_of(body)},
        },
        "parentReference": {"driveId": MINE, "id": ROOT},
    })
    .to_string()
}

fn drive_item(id: &str, name: &str, size: u64, ctag: &str) -> String {
    serde_json::json!({
        "id": id,
        "name": name,
        "size": size,
        "cTag": ctag,
        "eTag": ctag,
        "file": {"mimeType": "application/octet-stream"},
        "parentReference": {"driveId": MINE, "id": ROOT},
    })
    .to_string()
}

fn folder_item(id: &str, name: &str, etag: &str, parent: &str) -> String {
    serde_json::json!({
        "id": id,
        "name": name,
        "size": 0,
        "eTag": etag,
        "folder": {"childCount": 0},
        "parentReference": {"driveId": MINE, "id": parent},
    })
    .to_string()
}

/// The "default property set" truncation Graph is documented to send: an item
/// with no `cTag` and no hashes.
fn bare_item(id: &str, name: &str, size: u64) -> String {
    serde_json::json!({
        "id": id,
        "name": name,
        "size": size,
        "file": {"mimeType": "application/octet-stream"},
        "parentReference": {"driveId": MINE, "id": ROOT},
    })
    .to_string()
}

fn qx_item(id: &str, name: &str, size: u64, qx: &str) -> String {
    serde_json::json!({
        "id": id,
        "name": name,
        "size": size,
        "cTag": "c:{G},1",
        "file": {"mimeType": "application/octet-stream", "hashes": {"quickXorHash": qx}},
        "parentReference": {"driveId": MINE, "id": ROOT},
    })
    .to_string()
}

fn session(url: &str) -> String {
    serde_json::json!({"uploadUrl": url, "expirationDateTime": EXPIRES}).to_string()
}

fn accepted(ranges: &[&str]) -> String {
    serde_json::json!({"expirationDateTime": EXPIRES, "nextExpectedRanges": ranges}).to_string()
}

fn graph_error(code: &str) -> String {
    serde_json::json!({"error": {"code": code, "message": code}}).to_string()
}

// ===========================================================================
// The doubles
//
// One journal shared by the transport and the sleeper, so the interleaving of
// a request and a backoff is observable — "it re-read the item before the
// commit" is an ordering claim, not a presence one.
// ===========================================================================

/// A request as the seam saw it. `Debug` is hand-written: a fragment body is
/// ten megabytes and a failing assertion must stay readable.
#[derive(Clone, PartialEq, Eq)]
struct Rec {
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    authorize: bool,
}

impl std::fmt::Debug for Rec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} headers={:?} body={}B auth={}",
            self.method.as_str(),
            self.url,
            self.headers,
            self.body.len(),
            self.authorize
        )
    }
}

impl Rec {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The URL with its query removed.
    fn path(&self) -> &str {
        self.url.split('?').next().unwrap_or(&self.url)
    }

    fn query(&self) -> &str {
        self.url.split_once('?').map(|(_, q)| q).unwrap_or("")
    }

    fn range(&self) -> Option<&str> {
        self.header("content-range")
    }

    fn is_write(&self) -> bool {
        matches!(
            self.method,
            Method::Put | Method::Post | Method::Patch | Method::Delete
        )
    }

    /// The request body read as JSON, for the create-session assertions.
    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// Everything a `replace` could be hidden in: the query and the body.
    fn mentions(&self, needle: &str) -> bool {
        self.query().contains(needle) || String::from_utf8_lossy(&self.body).contains(needle)
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Ev {
    Call(Rec),
    Slept(Duration),
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

    fn calls(&self) -> Vec<Rec> {
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

    fn writes(&self) -> Vec<Rec> {
        self.calls().into_iter().filter(Rec::is_write).collect()
    }

    fn deletes(&self) -> Vec<Rec> {
        self.calls()
            .into_iter()
            .filter(|r| r.method == Method::Delete)
            .collect()
    }

    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

// --- the scripted transport ------------------------------------------------

type Effect = Arc<dyn Fn() + Send + Sync>;

fn effect(f: impl Fn() + Send + Sync + 'static) -> Effect {
    Arc::new(f)
}

#[derive(Clone)]
enum Outcome {
    Reply(u16, Vec<u8>),
    /// A reply that names its own retry interval. Kept separate from
    /// [`Outcome::Reply`] rather than adding a field to it, so that not one
    /// existing fixture changes shape.
    Throttled(u16, Vec<u8>, Duration),
    Fail(io::ErrorKind, String),
}

/// One scripted answer, and anything the world does at the moment it is given.
///
/// The effect is how "the user saved again mid-transfer" is expressed with no
/// thread and no sleep: it runs after the request has been recorded and before
/// the reply is returned, which is exactly the interleaving that produces a
/// spliced commit.
#[derive(Clone)]
struct Act {
    outcome: Outcome,
    effect: Option<Effect>,
}

fn reply(status: u16, body: impl Into<String>) -> Act {
    Act {
        outcome: Outcome::Reply(status, body.into().into_bytes()),
        effect: None,
    }
}

fn ok(body: impl Into<String>) -> Act {
    reply(200, body)
}

fn created(body: impl Into<String>) -> Act {
    reply(201, body)
}

fn no_content() -> Act {
    reply(204, "")
}

/// A refusal that names when to come back — `429` or `503` with `retry-after`.
///
/// The only way this suite can express a throttle, and the only thing that makes
/// the injected `Sleeper` say anything: every test written before this one
/// asserts `sleeps().is_empty()`, so the whole retry surface was scripted as
/// though the service never pushes back.
fn throttled(status: u16, body: impl Into<String>, after: Duration) -> Act {
    Act {
        outcome: Outcome::Throttled(status, body.into().into_bytes(), after),
        effect: None,
    }
}

fn boom(kind: io::ErrorKind, what: &str) -> Act {
    Act {
        outcome: Outcome::Fail(kind, what.to_string()),
        effect: None,
    }
}

impl Act {
    fn then(mut self, f: Effect) -> Act {
        self.effect = Some(f);
        self
    }
}

/// What a rule matches on. Every field is a constraint; the rule with the most
/// satisfied constraints wins, ties broken by insertion order, so a specific
/// rule cannot be shadowed by a catch-all written above it.
#[derive(Clone, Default, Debug)]
struct Match {
    method: Option<Method>,
    /// The URL with its query removed, compared exactly.
    url: Option<String>,
    /// Every pair must be present in the query.
    query: Vec<(String, String)>,
    /// A substring of the body.
    body_has: Option<String>,
    /// An exact `content-range`.
    range: Option<String>,
    /// Headers that must be present, optionally with a given value.
    has_header: Vec<(String, Option<String>)>,
    /// Headers that must be absent.
    no_header: Vec<String>,
}

fn on(method: Method, url: impl Into<String>) -> Match {
    Match {
        method: Some(method),
        url: Some(url.into()),
        ..Match::default()
    }
}

fn put(url: impl Into<String>) -> Match {
    on(Method::Put, url)
}
fn post(url: impl Into<String>) -> Match {
    on(Method::Post, url)
}
fn patch(url: impl Into<String>) -> Match {
    on(Method::Patch, url)
}
fn get(url: impl Into<String>) -> Match {
    on(Method::Get, url)
}
fn del(url: impl Into<String>) -> Match {
    on(Method::Delete, url)
}

impl Match {
    fn q(mut self, k: &str, v: &str) -> Self {
        self.query.push((k.to_string(), v.to_string()));
        self
    }
    fn body_has(mut self, s: &str) -> Self {
        self.body_has = Some(s.to_string());
        self
    }
    fn range(mut self, s: impl Into<String>) -> Self {
        self.range = Some(s.into());
        self
    }
    fn with(mut self, header: &str) -> Self {
        self.has_header.push((header.to_string(), None));
        self
    }
    fn without(mut self, header: &str) -> Self {
        self.no_header.push(header.to_string());
        self
    }

    fn score(&self) -> usize {
        self.method.is_some() as usize
            + self.url.is_some() as usize
            + self.query.len()
            + self.body_has.is_some() as usize
            + self.range.is_some() as usize
            + self.has_header.len()
            + self.no_header.len()
    }

    fn matches(&self, r: &Rec) -> bool {
        if let Some(m) = self.method {
            if m != r.method {
                return false;
            }
        }
        if let Some(u) = &self.url {
            if u != r.path() {
                return false;
            }
        }
        for (k, v) in &self.query {
            if !r.query().contains(&format!("{k}={v}")) {
                return false;
            }
        }
        if let Some(b) = &self.body_has {
            if !String::from_utf8_lossy(&r.body).contains(b.as_str()) {
                return false;
            }
        }
        if let Some(range) = &self.range {
            if r.range() != Some(range.as_str()) {
                return false;
            }
        }
        for (k, v) in &self.has_header {
            match (r.header(k), v) {
                (None, _) => return false,
                (Some(got), Some(want)) if got != want => return false,
                _ => {}
            }
        }
        for k in &self.no_header {
            if r.header(k).is_some() {
                return false;
            }
        }
        true
    }
}

struct Rule {
    m: Match,
    acts: Vec<Act>,
}

/// A `Transport` scripted by request shape.
///
/// The last act for a rule repeats forever, so `[a, b]` means "a once then b"
/// and `[a]` means "answerable as often as asked". An unscripted request is
/// *recorded* and then fails, so an attempt to take a path this test forbids is
/// visible in the log rather than silently satisfied. A hard call cap panics
/// with the journal attached: a sink that loops must fail deterministically in
/// milliseconds, not hang the suite.
#[derive(Clone)]
struct Wire {
    journal: Journal,
    rules: Arc<Mutex<Vec<Rule>>>,
    calls: Arc<Mutex<usize>>,
    cap: usize,
}

impl Wire {
    fn new(journal: Journal, cap: usize) -> Self {
        Self {
            journal,
            rules: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(Mutex::new(0)),
            cap,
        }
    }

    fn script(&self, m: Match, acts: Vec<Act>) {
        self.rules.lock().unwrap().push(Rule { m, acts });
    }
}

impl Transport for Wire {
    fn send(&mut self, request: &Request) -> io::Result<Reply> {
        let rec = Rec {
            method: request.method,
            url: request.url.clone(),
            headers: request.headers.clone(),
            body: request.body.clone(),
            authorize: request.authorize,
        };
        self.journal.push(Ev::Call(rec.clone()));

        let n = {
            let mut c = self.calls.lock().unwrap();
            *c += 1;
            *c
        };
        assert!(
            n <= self.cap,
            "the transport was called {n} times (cap {}); the sink is looping.\n{:#?}",
            self.cap,
            self.journal.all()
        );

        let act = {
            let mut rules = self.rules.lock().unwrap();
            let best = rules
                .iter()
                .enumerate()
                .filter(|(_, rule)| rule.m.matches(&rec))
                .max_by_key(|(i, rule)| (rule.m.score(), usize::MAX - *i))
                .map(|(i, _)| i);
            match best {
                None => return Err(io::Error::other(format!("unscripted request: {rec:?}"))),
                Some(i) => {
                    let acts = &mut rules[i].acts;
                    if acts.len() > 1 {
                        acts.remove(0)
                    } else {
                        acts[0].clone()
                    }
                }
            }
        };

        if let Some(f) = &act.effect {
            f();
        }
        match act.outcome {
            Outcome::Reply(status, body) => Ok(Reply {
                status,
                retry_after: None,
                body,
            }),
            Outcome::Throttled(status, body, after) => Ok(Reply {
                status,
                retry_after: Some(after),
                body,
            }),
            Outcome::Fail(kind, what) => Err(io::Error::new(kind, what)),
        }
    }
}

// --- the clock -------------------------------------------------------------

/// Records what it was asked for and returns immediately. Nothing in this suite
/// spends a second of wall time on a backoff policy.
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

/// A sync root of this test's own, under the target directory. Real files,
/// because half of what is being asserted is the bytes that went out.
fn scratch(name: &str) -> PathBuf {
    // `HYDRATION_TEST_DIR` overrides this at run time, so the suite can be
    // pointed at a btrfs, ext4 or xfs mount without rebuilding.
    test_scratch::scratch(env!("CARGO_TARGET_TMPDIR"), &format!("upload/{name}"))
}

/// A fragment policy small enough to make a 960 KiB file take three fragments.
fn session_policy() -> UploadPolicy {
    UploadPolicy {
        fragment_bytes: FRAGMENT_QUANTUM,
        simple_upload_max: 4096,
    }
}

struct Rig {
    journal: Journal,
    wire: Wire,
    root: PathBuf,
}

impl Rig {
    fn new(name: &str) -> Self {
        Self::with_cap(name, 24)
    }

    fn with_cap(name: &str, cap: usize) -> Self {
        let journal = Journal::default();
        Self {
            wire: Wire::new(journal.clone(), cap),
            journal,
            root: scratch(name),
        }
    }

    fn script(&self, m: Match, acts: Vec<Act>) {
        self.wire.script(m, acts);
    }

    fn sink(&self) -> GraphSink<Wire, RecordingSleeper> {
        self.sink_with(MINE, TagSource::CTag, UploadPolicy::default())
    }

    fn sink_policy(&self, policy: UploadPolicy) -> GraphSink<Wire, RecordingSleeper> {
        self.sink_with(MINE, TagSource::CTag, policy)
    }

    fn sink_with(
        &self,
        drive: &str,
        tags: TagSource,
        policy: UploadPolicy,
    ) -> GraphSink<Wire, RecordingSleeper> {
        GraphSink::new(
            primary(drive),
            self.root.clone(),
            tags,
            self.wire.clone(),
            RecordingSleeper {
                journal: self.journal.clone(),
            },
        )
        .with_policy(policy)
    }

    /// A file under the sync root, with its parent directories.
    fn file(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = self.root.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).expect("a directory for the fixture");
        }
        std::fs::write(&p, bytes).expect("a fixture file");
        p
    }
}

/// Content byte `i = (i * 31 + 7) % 251` — position-dependent, so a fragment
/// resent from the wrong offset does not compare equal to the right one.
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) % 251) as u8).collect()
}

// --- assertion helpers -----------------------------------------------------

fn only_call(j: &Journal) -> Rec {
    let calls = j.calls();
    assert_eq!(
        calls.len(),
        1,
        "expected exactly one request; got {:#?}",
        calls
    );
    calls.into_iter().next().unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Frag {
    start: u64,
    end: u64,
    total: u64,
    len: usize,
}

fn parse_range(raw: &str) -> (u64, u64, u64) {
    let rest = raw
        .strip_prefix("bytes ")
        .unwrap_or_else(|| panic!("a content-range must start with `bytes `, got {raw:?}"));
    let (span, total) = rest
        .split_once('/')
        .unwrap_or_else(|| panic!("a content-range must declare a total, got {raw:?}"));
    let (start, end) = span
        .split_once('-')
        .unwrap_or_else(|| panic!("a content-range must be a span, got {raw:?}"));
    (
        start.parse().expect("a start offset"),
        end.parse().expect("an end offset"),
        total.parse().expect("a total size"),
    )
}

/// Every fragment sent to `url`, in order, with its declared range.
fn fragments(j: &Journal, url: &str) -> Vec<(Frag, Vec<u8>)> {
    j.calls()
        .into_iter()
        .filter(|r| r.method == Method::Put && r.url == url)
        .map(|r| {
            let raw = r
                .range()
                .unwrap_or_else(|| panic!("a session fragment must carry a content-range: {r:?}"))
                .to_string();
            let (start, end, total) = parse_range(&raw);
            (
                Frag {
                    start,
                    end,
                    total,
                    len: r.body.len(),
                },
                r.body,
            )
        })
        .collect()
}

/// Every byte the whole error chain renders to, both ways.
fn rendered(e: &io::Error) -> String {
    let mut out = format!("{e}|{e:?}");
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(s) = src {
        out.push_str(&format!("|{s}|{s:?}"));
        src = std::error::Error::source(s);
    }
    out
}

fn upserted_id(cs: &[Change], name: &str) -> String {
    cs.iter()
        .find_map(|c| match c {
            Change::Upserted { cloud_id, path, .. } if path.ends_with(name) => {
                Some(cloud_id.clone())
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("the delta half produced no change for {name}: {cs:#?}"))
}

fn upserted_etag(cs: &[Change], id: &str) -> Option<String> {
    cs.iter().find_map(|c| match c {
        Change::Upserted { cloud_id, etag, .. } if cloud_id == id => etag.clone(),
        _ => None,
    })
}

// ===========================================================================
// CLASS A — An update is addressed by identity, never by name
//
// The delta pass renames local files itself whenever an object moves in the
// cloud, and users `mv` files constantly, so the path a local inode sits at
// routinely stops naming the object that inode claims. A path-addressed content
// write lands on whichever object now occupies that name.
// ===========================================================================

#[test]
fn a_local_folder_create_is_addressed_to_the_parent_identity() {
    let rig = Rig::new("create_folder_parent_identity");
    let parent = rig.root.join("Projects");
    let folder = parent.join("New");
    std::fs::create_dir_all(&folder).unwrap();
    store::set_xattr(&parent, store::XATTR_ID, cloud(MINE, "01PARENT").as_bytes()).unwrap();
    rig.script(
        post(item_children(MINE, "01PARENT")).body_has("conflictBehavior"),
        vec![ok(folder_item(
            "01NEW",
            "New",
            "\"{FOLDER},1\"",
            "01PARENT",
        ))],
    );

    let created = rig.sink().create_folder(&folder).unwrap();

    assert_eq!(created.cloud_id, cloud(MINE, "01NEW"));
    assert_eq!(created.etag.as_deref(), Some("et:\"{FOLDER},1\""));
    let call = only_call(&rig.journal);
    assert_eq!(call.path(), item_children(MINE, "01PARENT"));
    assert_eq!(call.json()["name"], "New");
    assert!(call.json()["folder"].is_object());
    assert_eq!(call.json()["@microsoft.graph.conflictBehavior"], "fail");
}

#[test]
fn a_local_folder_create_without_parent_identity_is_refused_before_graph() {
    let rig = Rig::new("create_folder_unknown_parent");
    let folder = rig.root.join("Projects/New");
    std::fs::create_dir_all(&folder).unwrap();

    let err = rig.sink().create_folder(&folder).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("parent folder"));
    assert!(rig.journal.calls().is_empty());
}

#[test]
fn a_retried_folder_create_adopts_the_exact_existing_folder() {
    let rig = Rig::new("create_folder_reconcile");
    let parent = rig.root.join("Projects");
    let folder = parent.join("New");
    std::fs::create_dir_all(&folder).unwrap();
    store::set_xattr(&parent, store::XATTR_ID, cloud(MINE, "01PARENT").as_bytes()).unwrap();
    rig.script(
        post(item_children(MINE, "01PARENT")),
        vec![reply(409, graph_error("nameAlreadyExists"))],
    );
    rig.script(
        get(path_meta(MINE, "Projects/New")),
        vec![ok(folder_item(
            "01EXISTING",
            "New",
            "\"{FOLDER},4\"",
            "01PARENT",
        ))],
    );

    let created = rig.sink().create_folder(&folder).unwrap();

    assert_eq!(created.cloud_id, cloud(MINE, "01EXISTING"));
    assert_eq!(created.etag.as_deref(), Some("et:\"{FOLDER},4\""));
    let calls = rig.journal.calls();
    assert_eq!(calls.len(), 2, "collision reconciliation made extra calls");
    assert_eq!(calls[0].method, Method::Post);
    assert_eq!(calls[1].method, Method::Get);
}

#[test]
fn a_folder_create_never_adopts_a_file_that_occupies_the_name() {
    let rig = Rig::new("create_folder_file_collision");
    let parent = rig.root.join("Projects");
    let folder = parent.join("New");
    std::fs::create_dir_all(&folder).unwrap();
    store::set_xattr(&parent, store::XATTR_ID, cloud(MINE, "01PARENT").as_bytes()).unwrap();
    rig.script(
        post(item_children(MINE, "01PARENT")),
        vec![reply(409, graph_error("nameAlreadyExists"))],
    );
    rig.script(
        get(path_meta(MINE, "Projects/New")),
        vec![ok(drive_item("01FILE", "New", 3, "c:{FILE},1"))],
    );

    let err = rig.sink().create_folder(&folder).unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("different object"));
}

#[test]
fn a_local_folder_rename_uses_the_folders_metadata_version() {
    let rig = Rig::new("rename_folder");
    let from = rig.root.join("before");
    let to = rig.root.join("after");
    std::fs::create_dir_all(&from).unwrap();
    std::fs::rename(&from, &to).unwrap();
    let id = cloud(MINE, "01FOLDER");
    rig.script(
        patch(item_url(MINE, "01FOLDER"))
            .body_has("after")
            .with("if-match"),
        vec![ok(folder_item("01FOLDER", "after", "\"{FOLDER},2\"", ROOT))],
    );

    let moved = rig
        .sink()
        .move_item(
            &from,
            &to,
            Known {
                cloud_id: &id,
                tag: Some("et:\"{FOLDER},1\""),
            },
        )
        .unwrap();

    assert_eq!(moved.cloud_id, id);
    assert_eq!(moved.etag.as_deref(), Some("et:\"{FOLDER},2\""));
    let call = only_call(&rig.journal);
    assert_eq!(call.header("if-match"), Some("\"{FOLDER},1\""));
    assert_eq!(call.json()["name"], "after");
}

#[test]
fn a_local_rename_is_a_conditional_patch_of_the_object() {
    let rig = Rig::new("rename_same_parent");
    let from = rig.file("before.txt", b"content");
    let to = rig.root.join("after.txt");
    std::fs::rename(&from, &to).unwrap();
    let id = cloud(MINE, "01REPORT");
    rig.script(
        patch(item_url(MINE, "01REPORT"))
            .body_has("after.txt")
            .with("if-match"),
        vec![ok(drive_item("01REPORT", "after.txt", 7, "c:{G},2"))],
    );

    let moved = rig
        .sink()
        .move_item(
            &from,
            &to,
            Known {
                cloud_id: &id,
                tag: Some("ct:c:{G},1"),
            },
        )
        .unwrap();

    assert_eq!(moved.cloud_id, id);
    assert_eq!(moved.etag.as_deref(), Some("ct:c:{G},2"));
    let calls = rig.journal.calls();
    assert_eq!(calls.len(), 1, "rename made extra requests: {calls:#?}");
    assert_eq!(calls[0].method, Method::Patch);
    assert_eq!(calls[0].header("if-match"), Some("c:{G},1"));
    assert_eq!(calls[0].json()["name"], "after.txt");
}

#[test]
fn a_cross_folder_move_uses_the_destination_folders_recorded_identity() {
    let rig = Rig::new("move_cross_parent");
    let from = rig.file("one/report.txt", b"content");
    let to = rig.root.join("two/report.txt");
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    hydration_client::store::set_xattr(
        to.parent().unwrap(),
        hydration_client::store::XATTR_ID,
        cloud(MINE, "01FOLDER").as_bytes(),
    )
    .unwrap();
    std::fs::rename(&from, &to).unwrap();
    let id = cloud(MINE, "01REPORT");
    rig.script(
        patch(item_url(MINE, "01REPORT"))
            .body_has("01FOLDER")
            .with("if-match"),
        vec![ok(drive_item("01REPORT", "report.txt", 7, "c:{G},2"))],
    );

    rig.sink()
        .move_item(
            &from,
            &to,
            Known {
                cloud_id: &id,
                tag: Some("ct:c:{G},1"),
            },
        )
        .unwrap();

    let call = only_call(&rig.journal);
    assert_eq!(call.json()["name"], "report.txt");
    assert_eq!(call.json()["parentReference"]["id"], "01FOLDER");
    assert_eq!(call.header("if-match"), Some("c:{G},1"));
}

#[test]
fn a_cross_folder_move_without_destination_identity_is_refused_before_graph() {
    let rig = Rig::new("move_cross_parent_unknown");
    let from = rig.file("one/report.txt", b"content");
    let to = rig.root.join("two/report.txt");
    std::fs::create_dir_all(to.parent().unwrap()).unwrap();
    std::fs::rename(&from, &to).unwrap();
    let id = cloud(MINE, "01REPORT");

    let err = rig
        .sink()
        .move_item(
            &from,
            &to,
            Known {
                cloud_id: &id,
                tag: Some("ct:c:{G},1"),
            },
        )
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("destination folder"));
    assert!(rig.journal.calls().is_empty());
}

/// The first implementation derives the URL from the one thing it was handed —
/// the path — and uses `existing` only to decide whether to attach `if-match`.
/// Both branches return `200` here; only the log separates them.
#[test]
fn an_update_writes_to_the_item_id_never_to_the_path() {
    let rig = Rig::new("update_addresses_the_item");
    let path = rig.file("Work/report.docx", b"hello world!");

    rig.script(
        put(item_content(MINE, "01REPORT")),
        vec![ok(drive_item("01REPORT", "report.docx", 12, "c:{G},2"))],
    );
    // The wrong branch, scripted to succeed and to squat on a different object.
    rig.script(
        put(path_content(MINE, "Work/report.docx")),
        vec![ok(drive_item("01SQUATTER", "report.docx", 12, "c:{H},9"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01REPORT")));

    let call = only_call(&rig.journal);
    assert_eq!(
        call.path(),
        item_content(MINE, "01REPORT"),
        "an update addresses the id the local file claims"
    );
    assert!(
        !call.url.contains("root:/"),
        "no write may use the path-addressing delimiter: {}",
        call.url
    );
    assert_eq!(
        out.expect("the update must succeed").cloud_id,
        cloud(MINE, "01REPORT"),
        "the object written is the object claimed"
    );
}

/// The same rule one level down. `upload.rs:295-321` resends after a
/// rename-mid-upload with `existing = Some(the id it just created)` and relies
/// entirely on that second call *updating* that object; a path-addressed
/// session orphans the first object under its temp name forever.
#[test]
fn an_update_creates_an_item_addressed_session_never_a_path_addressed_one() {
    let rig = Rig::new("session_addresses_the_item");
    let bytes = pattern(655_360);
    let path = rig.file("Work/report.pdf", &bytes);
    let u1 = upload_url("S1");
    let u2 = upload_url("S2");

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u1))]);
    // The pre-commit re-read `a_session_does_not_commit_after_the_item_changed_
    // under_it` requires, answered with the version the upload is based on.
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u1.clone()).range("bytes 0-327679/655360"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u1.clone()).range("bytes 327680-655359/655360"),
        vec![created(drive_item("01A", "report.pdf", 655_360, "c:{G},9"))],
    );
    // The path-addressed session, scripted to succeed end to end.
    rig.script(
        post(path_session(MINE, "Work/report.pdf")),
        vec![ok(session(&u2))],
    );
    rig.script(
        put(u2.clone()),
        vec![
            reply(202, accepted(&["327680-"])),
            created(drive_item("01NEW", "report.pdf", 655_360, "c:{G},9")),
        ],
    );

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    let sessions: Vec<Rec> = rig
        .journal
        .calls()
        .into_iter()
        .filter(|r| r.path().ends_with("/createUploadSession"))
        .collect();
    assert_eq!(sessions.len(), 1, "exactly one session: {sessions:#?}");
    assert_eq!(
        sessions[0].path(),
        item_session(MINE, "01A"),
        "an update's session is created at the item"
    );
    assert_eq!(
        out.expect("the session must commit").cloud_id,
        cloud(MINE, "01A")
    );
}

// ===========================================================================
// CLASS B — Nothing this crate does may delete an object it did not create
// ===========================================================================

/// "Update in place is fiddly; delete plus create is one code path for both
/// cases" is a real simplification, and it throws away the item's whole version
/// history — the only overwrite recovery that works, and on a business drive
/// the only one that exists.
#[test]
fn content_replacement_never_deletes_first() {
    let rig = Rig::new("replace_never_deletes");
    let path = rig.file("Work/report.docx", b"hello world!");

    rig.script(del(item_url(MINE, "01REPORT")), vec![no_content()]);
    rig.script(
        put(path_content(MINE, "Work/report.docx")),
        vec![created(drive_item("01FRESH", "report.docx", 12, "c:{H},1"))],
    );
    rig.script(
        put(item_content(MINE, "01REPORT")),
        vec![ok(drive_item("01REPORT", "report.docx", 12, "c:{G},2"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01REPORT")));

    assert!(
        rig.journal.deletes().is_empty(),
        "a content replacement never deletes: {:#?}",
        rig.journal.calls()
    );
    assert_eq!(
        out.expect("the update must succeed").cloud_id,
        cloud(MINE, "01REPORT"),
        "the id did not change, so nothing became garbage"
    );
}

/// Cleanup-on-failure is idiomatic everywhere except where the resource
/// predates the operation — and an upload's destination always does. A `500`
/// leaves the previous version perfectly intact; rolling back destroys it.
#[test]
fn a_failed_write_never_deletes_the_destination() {
    let rig = Rig::new("failed_write_never_deletes");
    let path = rig.file("Work/report.docx", b"hello world!");

    rig.script(
        put(item_content(MINE, "01REPORT")),
        vec![reply(500, graph_error("generalException"))],
    );
    rig.script(del(item_url(MINE, "01REPORT")), vec![no_content()]);

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01REPORT")));

    assert!(out.is_err(), "a 500 is a failure, not a success");
    assert!(
        rig.journal.deletes().is_empty(),
        "a failed write leaves the destination alone: {:#?}",
        rig.journal.calls()
    );
    let calls = rig.journal.calls();
    // Without this the `all` below is vacuously true of a sink that sent
    // nothing, and the 500 this test is about was never received.
    assert!(
        !calls.is_empty(),
        "the write was attempted, so the 500 was answered rather than avoided"
    );
    assert!(
        calls
            .iter()
            .all(|r| r.method == Method::Put && r.path() == item_content(MINE, "01REPORT")),
        "only the write itself was retried: {calls:#?}"
    );
    assert!(
        calls.len() <= 5,
        "the retry must terminate; it made {} attempts",
        calls.len()
    );
}

/// The compound failure. Adopting `01THEIRS` writes a stranger's item id onto
/// the local inode; reclaim may then evict the local file, the next read
/// fetches their document, and when the user deletes their own file
/// `run_upload` calls `sink.remove` on the stranger's object.
#[test]
fn a_409_on_a_create_is_an_error_and_never_adopts_the_other_objects_id() {
    let rig = Rig::new("create_409_is_terminal");
    let path = rig.file("Work/plan.md", b"a plan, then");

    rig.script(
        put(path_content(MINE, "Work/plan.md")).q("@microsoft.graph.conflictBehavior", "fail"),
        vec![reply(409, graph_error("nameAlreadyExists"))],
    );
    // Every recovery route, scripted to succeed.
    rig.script(
        get(format!("{BASE}/drives/{MINE}/root:/Work/plan.md")),
        vec![ok(drive_item("01THEIRS", "plan.md", 88_000, "c:{Z},3"))],
    );
    rig.script(
        put(path_content(MINE, "Work/plan.md")).q("@microsoft.graph.conflictBehavior", "replace"),
        vec![created(drive_item("01THEIRS", "plan.md", 12, "c:{Z},4"))],
    );
    rig.script(
        put(path_content(MINE, "Work/plan.md")).q("@microsoft.graph.conflictBehavior", "rename"),
        vec![created(drive_item("01REN", "plan 1.md", 12, "c:{Z},1"))],
    );
    rig.script(
        put(item_content(MINE, "01THEIRS")),
        vec![ok(drive_item("01THEIRS", "plan.md", 12, "c:{Z},4"))],
    );

    let mut sink = rig.sink();
    let out = sink.upload(&path, None);

    assert!(
        out.is_err(),
        "a name collision is a conflict, not a success"
    );
    let calls = rig.journal.calls();
    // Every other assertion here is a negative, and all of them hold of a sink
    // that never sent the create at all — in which case the 409 under test
    // never happened.
    assert!(
        calls.iter().any(|r| {
            r.method == Method::Put
                && r.path() == path_content(MINE, "Work/plan.md")
                && r.query().contains("@microsoft.graph.conflictBehavior=fail")
        }),
        "the create was sent, so the collision was answered: {calls:#?}"
    );
    assert!(
        !calls.iter().any(|r| r.mentions("replace")),
        "a collision is never resolved by replacing the other object: {calls:#?}"
    );
    assert!(
        !calls.iter().any(|r| r.mentions("rename")),
        "a rename retry adopts a name the user never chose: {calls:#?}"
    );
    assert!(
        !calls
            .iter()
            .any(|r| r.path() == item_content(MINE, "01THEIRS")),
        "nothing is written to an object this call did not create: {calls:#?}"
    );
}

/// Item ids are unique per drive, not globally. A shared-drive delete sent to
/// the user's own drive either 404s — so the object resurrects the local file
/// through the delta feed — or deletes an unrelated object.
#[test]
fn remove_deletes_on_the_drive_named_in_the_id() {
    let rig = Rig::new("remove_uses_the_ids_drive");
    rig.script(del(item_url(THEIRS, "01SHARED")), vec![no_content()]);
    rig.script(del(item_url(MINE, "01SHARED")), vec![no_content()]);

    let mut sink = rig.sink();
    let out = sink.remove(&cloud(THEIRS, "01SHARED"));

    assert!(out.is_ok(), "a 204 is a successful removal");
    let call = only_call(&rig.journal);
    assert_eq!(call.method, Method::Delete);
    assert_eq!(
        call.path(),
        item_url(THEIRS, "01SHARED"),
        "the delete goes to the drive the id names, not the drive the sink was configured with"
    );
}

#[test]
fn a_known_local_delete_carries_the_version_recorded_on_disk() {
    let rig = Rig::new("known_remove_uses_recorded_version");
    rig.script(
        del(item_url(MINE, "01KNOWN")).with("if-match"),
        vec![no_content()],
    );

    let id = cloud(MINE, "01KNOWN");
    let mut sink = rig.sink();
    sink.remove_known(Known {
        cloud_id: &id,
        tag: Some("ct:c:{G},7"),
    })
    .expect("the recorded version is a valid delete precondition");

    let call = only_call(&rig.journal);
    assert_eq!(call.header("if-match"), Some("c:{G},7"));
}

/// `rsplit('|').next().unwrap_or(cloud_id)` turns junk in an extended attribute
/// — an xattr written by an older build, or another provider — into a live
/// `DELETE` against a real endpoint.
#[test]
fn remove_refuses_a_malformed_cloud_id_without_a_request() {
    let rig = Rig::new("remove_refuses_junk");
    rig.script(del(item_url(MINE, "01LOOSE")), vec![no_content()]);

    let mut sink = rig.sink();
    let out = sink.remove("01LOOSE");

    assert!(out.is_err(), "an id with no drive half is not addressable");
    assert!(
        rig.journal.calls().is_empty(),
        "the refusal happens before a request, not after a response: {:#?}",
        rig.journal.calls()
    );
}

/// `permanentDelete` needs no permission beyond an ordinary delete and has no
/// undo; `prefer: bypass-shared-lock` deletes a document out from under someone
/// who has it open. Both are one line away, both take the same token, and both
/// are scripted to succeed here.
#[test]
fn a_delete_never_escalates_to_permanent_delete_or_a_lock_bypass() {
    let rig = Rig::new("delete_never_escalates");
    rig.script(
        del(item_url(MINE, "01LOCKED")),
        vec![reply(423, graph_error("resourceLocked"))],
    );
    rig.script(
        post(format!(
            "{BASE}/drives/{MINE}/items/01LOCKED/permanentDelete"
        )),
        vec![no_content()],
    );
    rig.script(
        del(item_url(MINE, "01LOCKED")).with("prefer"),
        vec![no_content()],
    );

    let mut sink = rig.sink();
    let out = sink.remove(&cloud(MINE, "01LOCKED"));

    assert!(out.is_err(), "a locked object was not removed");
    let calls = rig.journal.calls();
    assert!(
        calls.iter().any(|r| {
            r.method == Method::Delete
                && r.path() == item_url(MINE, "01LOCKED")
                && r.header("prefer").is_none()
        }),
        "the ordinary delete was sent, so the 423 was answered rather than \
         avoided — everything below this line holds of a sink that sent \
         nothing: {calls:#?}"
    );
    assert!(
        !calls.iter().any(|r| r.path().ends_with("/permanentDelete")),
        "the recycle bin is the only recovery a business drive has: {calls:#?}"
    );
    assert!(
        !calls.iter().any(|r| r.header("prefer").is_some()),
        "a coauthoring lock is not ours to bypass: {calls:#?}"
    );
    assert!(
        calls.len() <= 5,
        "the retry must terminate; it made {} attempts",
        calls.len()
    );
}

// ===========================================================================
// CLASS C — A precondition is a guard, not decoration
// ===========================================================================

/// Two compounding losses. Retrying without the precondition destroys the
/// remote edit that caused the `412`. Returning `Ok` is worse in the other
/// direction: `run_upload` stamps the file Clean, reclaim may discard it, and
/// a delete-mid-upload then calls `sink.remove` on the object that won the race.
#[test]
fn a_412_is_terminal_and_never_retries_unconditionally_creates_or_returns_ok() {
    let rig = Rig::new("412_is_terminal");
    let path = rig.file("Work/report.docx", b"hello world!");

    rig.script(
        put(item_content(MINE, "01REPORT")).with("if-match"),
        vec![reply(412, graph_error("resourceModified"))],
    );
    // Every escape, scripted to succeed.
    rig.script(
        put(item_content(MINE, "01REPORT")).without("if-match"),
        vec![ok(drive_item("01REPORT", "report.docx", 12, "c:{G},9"))],
    );
    rig.script(
        put(path_content(MINE, "Work/report.docx")),
        vec![created(drive_item("01OOPS", "report.docx", 12, "c:{G},9"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01REPORT")));

    assert!(
        out.is_err(),
        "a 412 is somebody else's change; it is not an upload that happened"
    );
    let call = only_call(&rig.journal);
    assert_eq!(call.path(), item_content(MINE, "01REPORT"));
    assert_eq!(
        call.header("if-match"),
        Some("c:{G},1"),
        "the one write carried the precondition it was based on"
    );
}

/// `if let Some(tag) = … { req.header("if-match", tag) }` with no `else` is the
/// single most common shape in this surface, and on a quickXor drive it takes
/// the no-precondition branch on every file, every time. Every test on a cTag
/// drive passes.
#[test]
fn an_update_with_no_usable_precondition_is_refused_rather_than_written_blind() {
    let rig = Rig::new("no_precondition_no_write");
    let path = rig.file("notes.txt", b"nine byte");

    rig.script(
        put(item_content(MINE, "01NOTES")),
        vec![ok(drive_item("01NOTES", "notes.txt", 9, "c:{G},4"))],
    );
    rig.script(
        get(item_url(MINE, "01NOTES")),
        vec![ok(drive_item("01NOTES", "notes.txt", 9, "c:{G},4"))],
    );

    let mut sink = rig.sink_with(MINE, TagSource::QuickXor, UploadPolicy::default());
    // A quickXor tree records a hash. Nothing here is a valid `if-match`.
    sink.record_tag(&cloud(MINE, "01NOTES"), "qx:BAJk9sAAAAAAAAAAAAAAAAAAAAA=");
    let out = sink.upload(&path, at(&cloud(MINE, "01NOTES")));

    // Not "every write carries some if-match": `if-match: *` and `if-match:
    // qx:BAJk9s…` are both headers, both pass such a check, and both are the
    // blind overwrite this test exists to forbid — `*` matches any version and
    // a hash matches none, so the service either ignores the guard or rejects
    // every attempt forever. There is no precondition this drive can offer, so
    // the only correct number of conditional updates is zero.
    assert!(
        rig.journal.writes().is_empty(),
        "a drive whose tags are hashes has no value Graph accepts as a \
         precondition, so the update is refused rather than sent: {:#?}",
        rig.journal.calls()
    );
    assert!(
        !rig.journal
            .calls()
            .iter()
            .any(|r| r.header("if-match").is_some()),
        "and nothing is invented to fill the header with: {:#?}",
        rig.journal.calls()
    );
    assert!(
        out.is_err(),
        "failing closed is an error, never a fabricated Ok"
    );
}

/// A precondition read back from the service immediately before the write is a
/// precondition that can never fail. It converts `if-match` from a guard into
/// decoration and silently overwrites the newer version it has just read.
#[test]
fn the_precondition_is_the_tag_the_upload_is_based_on_not_one_just_read_back() {
    let rig = Rig::new("precondition_is_the_based_on_tag");
    let path = rig.file("Work/report.docx", b"hello world!");

    rig.script(
        get(item_url(MINE, "01REPORT")),
        vec![ok(drive_item("01REPORT", "report.docx", 900, "c:{G},7"))],
    );
    rig.script(
        put(item_content(MINE, "01REPORT")),
        vec![ok(drive_item("01REPORT", "report.docx", 12, "c:{G},8"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01REPORT")));

    let writes = rig.journal.writes();
    match writes.first() {
        Some(w) => assert_eq!(
            w.header("if-match"),
            Some("c:{G},1"),
            "the precondition is the tag the local file was last synchronised at, \
             not one fetched to make the guard pass"
        ),
        // Refusing outright, having seen {G},7 differ from {G},1, is also correct.
        None => assert!(out.is_err(), "no write means the call refused"),
    }
}

/// `Ok(Uploaded { cloud_id: item.id, .. })` is the most natural line to write
/// here, and the crate's whole identity discipline exists because it is wrong.
/// Deleting the old id is the second half of the same instinct.
#[test]
fn a_renumbered_update_returns_the_new_composed_id_and_removes_nothing() {
    let rig = Rig::new("renumbered_update");
    let path = rig.file("Work/report.docx", b"hello world!");

    rig.script(
        put(item_content(MINE, "01OLD")),
        vec![created(drive_item("01NEW", "report.docx", 12, "c:{H},1"))],
    );
    rig.script(del(item_url(MINE, "01OLD")), vec![no_content()]);

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01OLD"), "ct:c:{G},1");
    let out = sink
        .upload(&path, at(&cloud(MINE, "01OLD")))
        .expect("the write succeeded");

    assert_eq!(
        out,
        Uploaded {
            cloud_id: cloud(MINE, "01NEW"),
            etag: Some("ct:c:{H},1".into()),
        },
        "the id is the one the service actually used, drive-qualified"
    );
    assert!(
        rig.journal.deletes().is_empty(),
        "an id we no longer reference is not garbage: {:#?}",
        rig.journal.calls()
    );
}

// ===========================================================================
// CLASS D — A create states what it will do about a collision
//
// The two v1.0 pages disagree about the default — `driveItem` says `replace`
// for PUT, `createUploadSession` says `fail` — so an implementation that omits
// the parameter is destructive on one path and safe on the other, and which is
// which is not knowable from the documentation.
// ===========================================================================

/// `201 Created` comes back for a create and for a replace alike, so the status
/// code cannot tell you which happened. Both branches are scripted to succeed.
#[test]
fn a_create_states_its_conflict_behaviour_in_the_url_and_it_is_never_replace() {
    let rig = Rig::new("create_declares_conflict_behaviour");
    let path = rig.file("notes.txt", b"abc");

    rig.script(
        put(path_content(MINE, "notes.txt")).q("@microsoft.graph.conflictBehavior", "fail"),
        vec![created(drive_item("01NEW", "notes.txt", 3, "c:{G},1"))],
    );
    // A bare URL, and an explicit replace, both scripted to succeed.
    rig.script(
        put(path_content(MINE, "notes.txt")),
        vec![created(drive_item("01CLOBBER", "notes.txt", 3, "c:{G},1"))],
    );

    let mut sink = rig.sink();
    let out = sink.upload(&path, None);

    let call = only_call(&rig.journal);
    // The value, not merely the parameter: `=rename` also "states a conflict
    // behaviour", and it answers a collision by inventing `notes 1.txt` — an
    // object no local file claims, stamped onto the inode that asked for
    // `notes.txt`.
    assert!(
        call.query()
            .contains("@microsoft.graph.conflictBehavior=fail"),
        "a create declares that a collision is an error: {}",
        call.url
    );
    assert!(
        !call.mentions("replace"),
        "a create never replaces an object it knows nothing about: {}",
        call.url
    );
    assert!(
        !call.mentions("rename"),
        "and never accepts a name the user did not choose: {}",
        call.url
    );
    assert_eq!(
        out.expect("the create must succeed").cloud_id,
        cloud(MINE, "01NEW")
    );
}

/// The body form is a second, independent chance to get it wrong: for
/// `PUT /content` the body is the file bytes so the parameter vanishes, and for
/// `createUploadSession` the body is JSON the service does read.
#[test]
fn every_create_session_states_its_conflict_behaviour_and_never_replaces_without_an_id() {
    let rig = Rig::with_cap("session_declares_conflict_behaviour", 40);
    let bytes = pattern(655_360);
    let update = rig.file("Work/report.pdf", &bytes);
    let create = rig.file("Work/new.bin", &bytes);
    let u1 = upload_url("SA");
    let u2 = upload_url("SB");

    // Every conflict behaviour, and a body-less create, all answerable.
    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u1))]);
    rig.script(
        post(path_session(MINE, "Work/new.bin")),
        vec![ok(session(&u2))],
    );
    // The update's pre-commit re-read, answered with the version it is based on.
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    for (u, id) in [(&u1, "01A"), (&u2, "01NEW")] {
        rig.script(
            put(u.clone()),
            vec![
                reply(202, accepted(&["327680-"])),
                created(drive_item(id, "x", 655_360, "c:{G},9")),
            ],
        );
    }

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let updated = sink.upload(&update, at(&cloud(MINE, "01A")));
    let made = sink.upload(&create, None);

    // Both are scripted end to end. Discarding the results let a sink that
    // creates a session and then abandons it satisfy every assertion below.
    assert!(updated.is_ok(), "the update must commit: {updated:?}");
    assert!(made.is_ok(), "the create must commit: {made:?}");

    let sessions: Vec<Rec> = rig
        .journal
        .calls()
        .into_iter()
        .filter(|r| r.path().ends_with("/createUploadSession"))
        .collect();
    assert_eq!(sessions.len(), 2, "one session per call: {sessions:#?}");
    for s in &sessions {
        let behaviour = s.json()["item"]["@microsoft.graph.conflictBehavior"]
            .as_str()
            .map(str::to_string);
        assert!(
            behaviour.is_some(),
            "a session body states its conflict behaviour: {}",
            String::from_utf8_lossy(&s.body)
        );
        assert_ne!(
            behaviour.as_deref(),
            Some("rename"),
            "and never `rename`, which commits the transfer to an object under a \
             name no local file holds and leaves the original untouched: {}",
            String::from_utf8_lossy(&s.body)
        );
    }
    let create_session = sessions
        .iter()
        .find(|s| s.path() == path_session(MINE, "Work/new.bin"))
        .expect("the create's session");
    assert_eq!(
        create_session.json()["item"]["@microsoft.graph.conflictBehavior"].as_str(),
        Some("fail"),
        "a sink with no id has never seen the object it would be replacing: {}",
        String::from_utf8_lossy(&create_session.body)
    );
}

// ===========================================================================
// CLASS E — A session is not committed until the service says it is
// ===========================================================================

/// `if (200..300).contains(&status) { return Ok(..) }` covers `202`. The moment
/// `Ok` is returned the framework stamps the file Clean and reclaim may replace
/// the user's only copy with a placeholder pointing at an object that was never
/// committed.
#[test]
fn a_202_on_the_last_fragment_is_not_a_successful_upload() {
    // The cap is the anti-loop backstop and has to sit above the bound this
    // test asserts, or the assertion is one the harness already guarantees.
    let rig = Rig::with_cap("202_is_not_a_commit", 20);
    let bytes = pattern(12_582_912);
    let path = rig.file("big.bin", &bytes);
    let u = upload_url("S3");

    rig.script(post(item_session(MINE, "01BIG")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01BIG")),
        vec![ok(drive_item("01BIG", "big.bin", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-10485759/12582912"),
        vec![reply(202, accepted(&["10485760-"]))],
    );
    // The last fragment, and everything after it: a service that never
    // finishes assembling.
    rig.script(
        put(u.clone()),
        vec![reply(202, accepted(&["12000000-12582911"]))],
    );
    rig.script(
        get(u.clone()),
        vec![reply(200, accepted(&["12000000-12582911"]))],
    );
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01BIG"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01BIG")));

    assert!(
        out.is_err(),
        "Ok is a claim about durability, not about having sent bytes"
    );
    // Otherwise a sink that stopped before the last fragment passes a test
    // about what the last fragment's answer means.
    let frags = fragments(&rig.journal, &u);
    assert!(
        frags.iter().any(|(f, _)| f.end + 1 == f.total),
        "the fragment that completes the file was sent, so the 202 under test \
         was received: {frags:#?}"
    );
    assert!(
        rig.journal.calls().len() <= 12,
        "the session must give up, not spin: {} calls",
        rig.journal.calls().len()
    );
}

/// The worst failure in the class: `202` is a success status to every HTTP
/// client library, so an early return after fragment one leaves two thirds of
/// the file unsent and reports success.
#[test]
fn a_202_on_a_fragment_is_progress_and_is_never_a_completed_upload() {
    let rig = Rig::with_cap("202_is_progress", 24);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("SP");

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    // The pre-commit re-read, answered with the version the upload is based on.
    // Without it the final fragment can never be reached and the coverage
    // assertion below is one no correct sink can satisfy.
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(202, accepted(&["655360-"]))],
    );
    // The service claims the last five bytes are missing, forever.
    rig.script(put(u.clone()), vec![reply(202, accepted(&["983035-"]))]);
    rig.script(get(u.clone()), vec![reply(200, accepted(&["983035-"]))]);
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    assert!(out.is_err(), "no fragment was ever answered 200 or 201");
    let frags = fragments(&rig.journal, &u);
    assert!(
        frags.len() >= 3,
        "every declared byte must have been sent at least once: {frags:#?}"
    );
    let covered: u64 = {
        let mut high = 0u64;
        for (f, _) in &frags {
            if f.start <= high {
                high = high.max(f.end + 1);
            }
        }
        high
    };
    assert_eq!(
        covered, 983_040,
        "the whole file was offered before the call gave up"
    );
}

/// A committed object made of 10 MiB of the old file and 2 MiB of the new one
/// is a version that has never existed on any machine, and it replaces the good
/// remote copy.
#[test]
fn a_file_that_changed_during_a_session_is_not_committed_as_a_splice() {
    let rig = Rig::with_cap("no_spliced_commit", 16);
    let mut bytes = vec![0xAAu8; 10_485_760];
    bytes.extend(std::iter::repeat_n(0xBBu8, 2_097_152));
    let path = rig.file("big.bin", &bytes);
    let u = upload_url("S4");

    let rewrite_to = path.clone();
    rig.script(post(item_session(MINE, "01BIG")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01BIG")),
        vec![ok(drive_item("01BIG", "big.bin", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-10485759/12582912"),
        vec![reply(202, accepted(&["10485760-"])).then(effect(move || {
            std::fs::write(&rewrite_to, vec![0xCCu8; 12_582_912]).expect("the user saved again");
        }))],
    );
    // The commit is scripted to succeed, so only the assertion catches it.
    rig.script(
        put(u.clone()),
        vec![created(drive_item(
            "01BIG", "big.bin", 12_582_912, "c:{G},2",
        ))],
    );
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01BIG"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01BIG")));

    let frags = fragments(&rig.journal, &u);
    // The `<= 1` and the loop below are both true of an empty log, and the
    // rewrite this test turns on only happens once a fragment has been sent.
    assert!(
        !frags.is_empty(),
        "the first fragment was sent, so the save mid-transfer happened: {:#?}",
        rig.journal.calls()
    );
    let totals: BTreeSet<u64> = frags.iter().map(|(f, _)| f.total).collect();
    assert!(
        totals.len() <= 1,
        "every fragment declares the same total: {totals:?}"
    );
    for (f, body) in &frags {
        assert!(
            !body.iter().all(|b| *b == 0xCC),
            "fragment {}-{} carries content from after the snapshot",
            f.start,
            f.end
        );
    }
    let committed = frags.iter().any(|(f, _)| f.end + 1 == f.total);
    if committed {
        let tail = frags
            .iter()
            .find(|(f, _)| f.end + 1 == f.total)
            .expect("the final fragment");
        assert!(
            tail.1.iter().all(|b| *b == 0xBB),
            "the tail committed is the one snapshot's tail"
        );
    } else {
        assert!(out.is_err(), "nothing committed, so nothing succeeded");
    }
}

/// `if-match` on an upload session is evaluated once, when the session is
/// created, and never re-evaluated when the bytes commit. A 12 MiB file is
/// seconds; a 2 GB file is an hour, and every remote edit made during that hour
/// is destroyed by the commit.
#[test]
fn a_session_does_not_commit_after_the_item_changed_under_it() {
    let rig = Rig::with_cap("session_rechecks_before_commit", 16);
    let bytes = pattern(12_582_912);
    let path = rig.file("big.bin", &bytes);
    let u = upload_url("S1");

    rig.script(post(item_session(MINE, "01BIG")), vec![ok(session(&u))]);
    rig.script(
        put(u.clone()).range("bytes 0-10485759/12582912"),
        vec![reply(202, accepted(&["10485760-"]))],
    );
    // The commit is scripted to succeed. Only the re-check stops it.
    rig.script(
        put(u.clone()).range("bytes 10485760-12582911/12582912"),
        vec![created(drive_item(
            "01BIG", "big.bin", 12_582_912, "c:{G},2",
        ))],
    );
    // Another device committed while the transfer ran.
    rig.script(
        get(item_url(MINE, "01BIG")),
        vec![ok(drive_item("01BIG", "big.bin", 900_123, "c:{G},5"))],
    );
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01BIG"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01BIG")));

    assert!(out.is_err(), "the object moved on under the session");
    let calls = rig.journal.calls();
    let commit_at = calls
        .iter()
        .position(|r| r.range() == Some("bytes 10485760-12582911/12582912"));
    assert!(
        commit_at.is_none(),
        "the final fragment is the commit and must not be sent: {calls:#?}"
    );
    let recheck_at = calls
        .iter()
        .position(|r| r.method == Method::Get && r.path() == item_url(MINE, "01BIG"));
    assert!(
        recheck_at.is_some(),
        "the item is re-read before the commit: {calls:#?}"
    );
    assert!(
        calls
            .iter()
            .any(|r| r.method == Method::Delete && r.url == u),
        "the staged bytes are released rather than left against quota: {calls:#?}"
    );
}

/// A `409` arrives after the entire file has been transferred — exactly when
/// forcing it is most tempting and re-uploading is most expensive. The object
/// it would replace is the newest thing on the drive.
#[test]
fn a_name_conflict_at_commit_is_never_resolved_by_replacing_the_other_object() {
    let rig = Rig::with_cap("commit_409_never_forces", 24);
    let bytes = pattern(655_360);
    let path = rig.file("Work/report.pdf", &bytes);
    let u = upload_url("SC1");
    let u2 = upload_url("SC2");

    rig.script(
        post(path_session(MINE, "Work/report.pdf")).body_has("fail"),
        vec![ok(session(&u))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/655360"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u.clone()),
        vec![reply(409, graph_error("nameAlreadyExists"))],
    );
    // Every forcing route, scripted to succeed.
    rig.script(
        post(path_session(MINE, "Work/report.pdf")).body_has("replace"),
        vec![ok(session(&u2))],
    );
    rig.script(
        put(u2.clone()),
        vec![
            reply(202, accepted(&["327680-"])),
            created(drive_item("01OTHER", "report.pdf", 655_360, "c:{G},1")),
        ],
    );
    rig.script(
        put(path_content(MINE, "Work/report.pdf")),
        vec![created(drive_item(
            "01OTHER",
            "report.pdf",
            655_360,
            "c:{G},1",
        ))],
    );
    rig.script(del(item_url(MINE, "01OTHER")), vec![no_content()]);
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    let out = sink.upload(&path, None);

    assert!(out.is_err(), "somebody else got there first");
    let calls = rig.journal.calls();
    // The 409 arrives on the fragment that completes the file. A sink that
    // never got that far satisfies every negative below without ever meeting
    // the conflict.
    let frags = fragments(&rig.journal, &u);
    assert!(
        frags.iter().any(|(f, _)| f.end + 1 == f.total),
        "the whole file crossed the wire and the commit collided: {frags:#?}"
    );
    assert!(
        !calls.iter().any(|r| r.mentions("replace")),
        "the value `replace` appears in no query and no body: {calls:#?}"
    );
    assert!(
        !calls
            .iter()
            .any(|r| r.method == Method::Put && r.path() == path_content(MINE, "Work/report.pdf")),
        "a simple PUT on the path defaults to replace and achieves the same thing \
         without the word appearing: {calls:#?}"
    );
    assert!(
        rig.journal
            .deletes()
            .iter()
            .all(|r| r.url == u || r.url == u2),
        "nothing is deleted but the session itself: {calls:#?}"
    );
}

/// `Ok(Uploaded { cloud_id: existing… })` is the natural shape when you think
/// of an update as in-place, and it passes every test where the id does not
/// change. A cloud id naming an object the service has replaced can never be
/// fetched again.
#[test]
fn the_cloud_id_comes_from_the_commit_response_not_from_the_existing_id() {
    let rig = Rig::with_cap("session_id_from_the_commit", 16);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("SR");

    rig.script(post(item_session(MINE, "01OLD")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01OLD")),
        vec![ok(drive_item("01OLD", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(202, accepted(&["655360-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 655360-983039/983040"),
        vec![created(drive_item(
            "01NEW",
            "report.pdf",
            983_040,
            "c:{G},9",
        ))],
    );

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01OLD"), "ct:c:{G},1");
    let out = sink
        .upload(&path, at(&cloud(MINE, "01OLD")))
        .expect("the session committed");

    assert_eq!(
        out.cloud_id,
        cloud(MINE, "01NEW"),
        "the service renumbered the item and said so"
    );
}

/// `store::adopt_cloud_id` writes the etag only when it is `Some` and never
/// clears a stale one, so `None` on an update leaves version 1's tag on a file
/// that now holds version 2 and the next delta pass places a placeholder over
/// content the user just successfully uploaded.
#[test]
fn a_commit_response_without_a_content_tag_never_yields_ok_with_no_etag() {
    let rig = Rig::with_cap("commit_without_a_tag", 16);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("SN");

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(202, accepted(&["655360-"]))],
    );
    // The documented default property set: no cTag, no hashes.
    rig.script(
        put(u.clone()).range("bytes 655360-983039/983040"),
        vec![created(bare_item("01A", "report.pdf", 983_040))],
    );
    // Two answers, in order: the pre-commit re-read sees the version this
    // upload is based on, so the commit is allowed to proceed; the read after
    // the commit sees the version it produced. One answer of `{G},9` made the
    // re-check fail, which made `Err` the only reachable outcome and left the
    // whole test satisfied by the empty arm below.
    rig.script(
        get(item_url(MINE, "01A")),
        vec![
            ok(drive_item("01A", "report.pdf", 900, "c:{G},1")),
            ok(drive_item("01A", "report.pdf", 983_040, "c:{G},9")),
        ],
    );

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    // The service committed the content. Reporting failure here re-queues an
    // upload that already happened, forever, so `Err` is not an acceptable way
    // to avoid inventing a tag — reading the tag back is.
    let out = sink
        .upload(&path, at(&cloud(MINE, "01A")))
        .expect("the commit succeeded, so the call succeeded");

    assert_eq!(
        out.etag.as_deref(),
        Some("ct:c:{G},9"),
        "a tag the delta half would also produce, fetched rather than punted"
    );
    let calls = rig.journal.calls();
    let commit = calls
        .iter()
        .position(|r| r.range() == Some("bytes 655360-983039/983040"))
        .expect("the commit");
    let meta = calls
        .iter()
        .rposition(|r| r.method == Method::Get && r.path() == item_url(MINE, "01A"))
        .expect("a follow-up metadata read");
    assert!(
        meta > commit,
        "the tag is read back after the commit, not before it: {calls:#?}"
    );
}

/// The destination item is untouched until commit, so a failed session has
/// nothing of its own to clean up — but "undo the half-finished upload" reads
/// naturally as "delete the item I was writing to", which recycle-bins the
/// user's complete previous version.
#[test]
fn abandoning_a_session_never_deletes_the_drive_item() {
    let rig = Rig::with_cap("abandon_never_deletes_the_item", 16);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("SX");

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(400, graph_error("invalidRequest"))],
    );
    // Every destructive branch, scripted quiet.
    rig.script(del(u.clone()), vec![no_content()]);
    rig.script(del(item_url(MINE, "01A")), vec![no_content()]);
    rig.script(
        put(path_content(MINE, "report.pdf")),
        vec![created(drive_item("01A", "report.pdf", 983_040, "c:{G},9"))],
    );

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    assert!(out.is_err(), "a 400 mid-session is a failure");
    let calls = rig.journal.calls();
    assert!(
        fragments(&rig.journal, &u).len() >= 2,
        "the session reached the fragment that 400s, so there was something to \
         abandon: {calls:#?}"
    );
    assert!(
        !calls
            .iter()
            .any(|r| r.method == Method::Delete && r.path() == item_url(MINE, "01A")),
        "the previous version is not ours to recycle: {calls:#?}"
    );
    assert!(
        !calls
            .iter()
            .any(|r| r.method == Method::Put && r.path() == path_content(MINE, "report.pdf")),
        "a session failure does not fall back to a path-addressed create: {calls:#?}"
    );
}

/// POSITIVE CONTROL for the rule above. "Never DELETE anything" passes it while
/// leaking a quota-consuming temp file per attempt; on OneDrive Personal staged
/// fragments count against quota until expiry, so repeated failures fill the
/// drive with invisible partial copies and unrelated uploads start failing 507.
#[test]
fn positive_control_an_abandoned_session_is_cancelled_at_the_upload_url() {
    let rig = Rig::with_cap("abandon_cancels_the_session", 16);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("SY");

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(400, graph_error("invalidRequest"))],
    );
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    assert!(out.is_err(), "the call still fails");
    let cancels: Vec<Rec> = rig
        .journal
        .deletes()
        .into_iter()
        .filter(|r| r.url == u)
        .collect();
    assert_eq!(
        cancels.len(),
        1,
        "exactly one cancel, at the uploadUrl byte for byte: {:#?}",
        rig.journal.calls()
    );
    assert!(
        !cancels[0].authorize,
        "the uploadUrl carries its own authorisation and never ours"
    );
}

// ===========================================================================
// CLASS F — Fragments are a protocol, not a loop
// ===========================================================================

/// The only silent-corruption path in this class that survives every integrity
/// check the framework has. A retry that re-reads from an already-advanced
/// cursor sends the file's second half labelled as its first; the size matches,
/// so the length check that guards both halves of the framework passes forever.
#[test]
fn a_retried_fragment_resends_the_same_bytes_from_the_same_offset() {
    let rig = Rig::with_cap("retry_resends_the_same_bytes", 16);
    let bytes = pattern(655_360);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("SRT");
    let d0 = bytes[0..327_680].to_vec();
    let d1 = bytes[327_680..655_360].to_vec();

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/655360"),
        vec![
            boom(io::ErrorKind::ConnectionReset, "reset by peer"),
            reply(202, accepted(&["327680-"])),
        ],
    );
    rig.script(get(u.clone()), vec![reply(202, accepted(&["0-"]))]);
    rig.script(
        put(u.clone()).range("bytes 327680-655359/655360"),
        vec![created(drive_item("01A", "report.pdf", 655_360, "c:{G},9"))],
    );

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    assert!(out.is_ok(), "a retried fragment is recoverable: {out:?}");
    let frags = fragments(&rig.journal, &u);
    for (f, body) in &frags {
        let expect = if f.start == 0 { &d0 } else { &d1 };
        assert_eq!(
            body, expect,
            "the bytes at {}-{} are the bytes at that offset in the file",
            f.start, f.end
        );
    }
    assert!(
        frags.iter().filter(|(f, _)| f.start == 0).count() >= 2,
        "the failed fragment was resent from offset zero: {frags:#?}"
    );
}

/// Three wrong answers. `416` read as fatal makes every lost fragment response
/// a permanently failing upload; read as "restart" it re-transfers gigabytes on
/// a blip; read as "the server already has it, so we're done" it returns `Ok`
/// with no commit at all.
#[test]
fn a_416_is_resolved_by_asking_the_server_where_it_is() {
    let rig = Rig::with_cap("416_asks_for_status", 16);
    let bytes = pattern(655_360);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("S416");
    let u2 = upload_url("S416B");

    rig.script(
        post(item_session(MINE, "01A")),
        vec![ok(session(&u)), ok(session(&u2))],
    );
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/655360"),
        vec![
            boom(io::ErrorKind::ConnectionReset, "reset by peer"),
            reply(416, graph_error("invalidRange")),
        ],
    );
    rig.script(get(u.clone()), vec![reply(202, accepted(&["327680-"]))]);
    rig.script(
        put(u.clone()).range("bytes 327680-655359/655360"),
        vec![created(drive_item("01A", "report.pdf", 655_360, "c:{G},9"))],
    );
    // A full restart, scripted to succeed quietly.
    rig.script(
        put(u2.clone()),
        vec![
            reply(202, accepted(&["327680-"])),
            created(drive_item("01A", "report.pdf", 655_360, "c:{G},9")),
        ],
    );
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    assert_eq!(
        out.expect("the session recovered").cloud_id,
        cloud(MINE, "01A")
    );
    let calls = rig.journal.calls();
    let sessions = calls
        .iter()
        .filter(|r| r.path() == item_session(MINE, "01A"))
        .count();
    assert_eq!(
        sessions, 1,
        "the session was resumed, not restarted: {calls:#?}"
    );
    // `any PUT at bytes 0-327679` is the *first* fragment, sent before the
    // reset and before the 416 — the flow guarantees it, so asserting it
    // asserts nothing. What the 416 has to produce is a probe, and then a
    // transfer that continues from what the probe said rather than from where
    // the sink thought it was.
    let first_frag = "bytes 0-327679/655360";
    let status_at = calls
        .iter()
        .position(|r| r.method == Method::Get && r.url == u)
        .unwrap_or_else(|| {
            panic!("a 416 is resolved by asking the server where it is: {calls:#?}")
        });
    assert!(
        calls[status_at + 1..]
            .iter()
            .any(|r| r.range() == Some("bytes 327680-655359/655360")),
        "and the transfer continues at the offset the answer named: {calls:#?}"
    );
    assert!(
        !calls[status_at + 1..]
            .iter()
            .any(|r| r.method == Method::Put && r.range() == Some(first_frag)),
        "a range the server has just said it already holds is not sent again: {calls:#?}"
    );
    assert!(
        !calls.iter().any(|r| r.url == u2),
        "the session was not discarded and started over: {calls:#?}"
    );
    assert!(
        rig.journal.deletes().is_empty(),
        "and it was not cancelled either: {calls:#?}"
    );
}

/// The server's view is the only authoritative one. `offset = offset.max(…)` is
/// a one-word defensive clamp that silently discards the only signal a chunk
/// was lost, and the session can then never commit.
#[test]
fn the_servers_next_expected_ranges_outrank_the_local_byte_counter() {
    let rig = Rig::with_cap("server_ranges_win", 20);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("SB1");

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![
            reply(202, accepted(&["327680-"])),
            reply(202, accepted(&["655360-"])),
        ],
    );
    // The service says the FIRST chunk never landed — behind the sink's own
    // high-water mark.
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(202, accepted(&["0-327679"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 655360-983039/983040"),
        vec![
            // Issued directly after the backwards range, this never converges.
            reply(202, accepted(&["0-327679"])),
            created(drive_item("01A", "report.pdf", 983_040, "c:{G},9")),
        ],
    );

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    let frags = fragments(&rig.journal, &u);
    let backwards = frags
        .iter()
        .position(|(f, _)| f.start == 327_680)
        .expect("the second fragment");
    let next = frags
        .get(backwards + 1)
        .unwrap_or_else(|| panic!("a fragment after the backwards range: {frags:#?}"));
    assert_eq!(
        next.0.start, 0,
        "the server's outstanding range is honoured even when it goes backwards: {frags:#?}"
    );
    if out.is_ok() {
        assert!(
            frags.iter().any(|(f, _)| f.end + 1 == f.total),
            "Ok requires a fragment the service answered as a commit"
        );
    }
}

/// "Using a fragment size that doesn't divide evenly by 320 KiB results in
/// errors committing some files" — and the error arrives at commit, after the
/// entire file has crossed the wire. The docs carry an explicit warning against
/// reading a `nextExpectedRanges` entry as a size, because it is the obvious
/// implementation.
#[test]
fn a_next_expected_range_is_a_starting_point_not_a_fragment_size() {
    let rig = Rig::with_cap("ranges_are_not_sizes", 20);
    let bytes = pattern(1_638_400);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("SNR");

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/1638400"),
        vec![reply(202, accepted(&["327680-400000"]))],
    );
    // Both continuations scripted, so neither errors.
    rig.script(
        put(u.clone()).range("bytes 327680-400000/1638400"),
        vec![reply(202, accepted(&["400001-"]))],
    );
    rig.script(
        put(u.clone()),
        vec![
            reply(202, accepted(&["655360-"])),
            reply(202, accepted(&["983040-"])),
            reply(202, accepted(&["1310720-"])),
            created(drive_item("01A", "report.pdf", 1_638_400, "c:{G},9")),
        ],
    );

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    // Every continuation is scripted through to a commit, so a discarded result
    // hid the case where the sink gives up after the odd range.
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));
    assert!(
        out.is_ok(),
        "a `nextExpectedRanges` entry with an end is not an error: {out:?}"
    );

    let frags = fragments(&rig.journal, &u);
    let second = frags
        .get(1)
        .unwrap_or_else(|| panic!("a second fragment: {frags:#?}"));
    assert_eq!(second.0.start, 327_680, "resume where the server said");
    assert_eq!(
        second.0.len, 327_680,
        "with our own fragment size, not the server's range length: {frags:#?}"
    );
    for (f, _) in &frags {
        assert_ne!(f.len, 72_321, "no fragment adopts the range's length");
        assert!(
            f.len % FRAGMENT_QUANTUM == 0 || f.end + 1 == f.total,
            "every fragment but the last is a whole number of quanta: {f:?}"
        );
    }
}

/// "Your app must ensure the total file size specified in the Content-Range
/// header is the same for all requests." A `metadata()` call inside the
/// fragment loop turns any save during a long upload into a wasted whole-file
/// transfer.
#[test]
fn every_fragment_declares_the_total_size_fixed_when_the_session_was_created() {
    let rig = Rig::with_cap("total_is_fixed_once", 20);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("STT");

    let grow = path.clone();
    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"])).then(effect(move || {
            let mut more = std::fs::read(&grow).expect("the fixture");
            more.extend(pattern(327_680));
            std::fs::write(&grow, more).expect("the user appended");
        }))],
    );
    // Both continuations scripted, so neither errors.
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(202, accepted(&["655360-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 655360-983039/983040"),
        vec![created(drive_item("01A", "report.pdf", 983_040, "c:{G},9"))],
    );
    rig.script(
        put(u.clone()).range("bytes 327680-655359/1310720"),
        vec![reply(202, accepted(&["655360-"]))],
    );
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let _ = sink.upload(&path, at(&cloud(MINE, "01A")));

    let frags = fragments(&rig.journal, &u);
    assert!(!frags.is_empty(), "at least one fragment was sent");
    for (f, _) in &frags {
        assert_eq!(
            f.total, 983_040,
            "the total is the size observed once, before the first byte was read: {f:?}"
        );
        assert!(
            f.end < 983_040,
            "nothing is sent past the declared end: {f:?}"
        );
    }
    let sessions = rig
        .journal
        .calls()
        .iter()
        .filter(|r| r.path() == item_session(MINE, "01A"))
        .count();
    assert_eq!(sessions, 1, "the session is not torn down and recreated");
}

/// `let mut buf = vec![0u8; frag]; file.read(&mut buf)?;` — `read` is allowed
/// to return short and its return value is discarded, so the untouched tail of
/// the buffer goes on the wire as the user's data and the service commits it.
#[test]
fn a_file_that_shrinks_mid_session_is_never_padded() {
    let rig = Rig::with_cap("shrink_is_never_padded", 20);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("SSH");

    let shrink = path.clone();
    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"])).then(effect(move || {
            let head = std::fs::read(&shrink).expect("the fixture")[..393_216].to_vec();
            std::fs::write(&shrink, head).expect("the user truncated");
        }))],
    );
    // The padded continuation is scripted to SUCCEED, so only the assertion
    // catches it.
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(202, accepted(&["655360-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 655360-983039/983040"),
        vec![created(drive_item("01A", "report.pdf", 983_040, "c:{G},9"))],
    );
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    let frags = fragments(&rig.journal, &u);
    for (f, body) in &frags {
        if f.start == 327_680 {
            assert!(
                body.len() <= 65_536,
                "only the bytes that were readable at that offset went out: {f:?}"
            );
        }
        assert!(
            !(body.len() > 16 && body[body.len() - 16..].iter().all(|b| *b == 0)),
            "a fragment tail of NULs is an unread buffer, not the user's data: {f:?}"
        );
    }
    assert!(
        !frags.iter().any(|(f, _)| f.end + 1 == f.total),
        "nothing commits over a file that changed under the session: {frags:#?}"
    );
    assert!(
        out.is_err(),
        "the transfer describes a file that no longer exists"
    );
}

/// A non-multiple fragment size fails at the *commit*, after the whole file has
/// crossed the wire. `4 * 1024 * 1024` is an ordinary-looking choice inside the
/// recommended 5–10 MiB band and `4194304 / 327680` is 12.8.
#[test]
fn the_default_fragment_size_is_a_multiple_of_320_kib_and_under_60_mib() {
    let rig = Rig::with_cap("default_fragment_size", 20);
    let path = rig.root.join("big.bin");
    {
        let f = std::fs::File::create(&path).expect("a sparse fixture");
        f.set_len(26_214_400).expect("25 MiB, sparse");
    }
    let u = upload_url("SD");

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "big.bin", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 20971520-26214399/26214400"),
        vec![created(drive_item("01A", "big.bin", 26_214_400, "c:{G},9"))],
    );
    rig.script(
        put(u.clone()),
        vec![
            reply(202, accepted(&["10485760-"])),
            reply(202, accepted(&["20971520-"])),
            reply(202, accepted(&["26214400-"])),
        ],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    assert!(
        out.is_ok(),
        "the default policy must be able to commit: {out:?}"
    );
    let frags = fragments(&rig.journal, &u);
    let last = frags.len() - 1;
    for (i, (f, _)) in frags.iter().enumerate() {
        if i != last {
            assert_eq!(
                f.len % FRAGMENT_QUANTUM,
                0,
                "fragment {i} is not a whole number of 320 KiB quanta: {f:?}"
            );
        }
        assert!(
            f.len < MAX_FRAGMENT_BYTES,
            "fragment {i} exceeds the service's ceiling: {f:?}"
        );
    }
    assert_eq!(
        frags[last].0.end, 26_214_399,
        "the last fragment ends at the last byte"
    );
}

/// A session vanishes on expiry, on `DELETE` **and** on successful completion,
/// so a `404` after a lost response to the last fragment is genuinely
/// ambiguous. Resolving it optimistically returns `Ok` for content that never
/// committed; resolving it by deleting the item destroys the good version too.
#[test]
fn a_404_on_the_final_fragment_is_not_evidence_that_the_commit_happened() {
    let rig = Rig::with_cap("404_is_not_a_commit", 20);
    let bytes = pattern(655_360);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("S404");
    let u2 = upload_url("S404B");

    rig.script(
        post(item_session(MINE, "01A")),
        vec![ok(session(&u)), ok(session(&u2))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/655360"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 327680-655359/655360"),
        vec![reply(404, graph_error("itemNotFound"))],
    );
    rig.script(
        get(u.clone()),
        vec![reply(404, graph_error("itemNotFound"))],
    );
    // The pre-upload state, so a probe that reads it as confirmation is caught.
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 100, "c:{G},1"))],
    );
    rig.script(
        put(u2.clone()),
        vec![
            reply(202, accepted(&["327680-"])),
            created(drive_item("01A", "report.pdf", 655_360, "c:{G},9")),
        ],
    );
    rig.script(del(item_url(MINE, "01A")), vec![no_content()]);
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01A")));

    let calls = rig.journal.calls();
    assert!(
        calls
            .iter()
            .any(|r| r.url == u && r.range() == Some("bytes 327680-655359/655360")),
        "the final fragment of the first session was sent, so the ambiguous 404 \
         was actually received: {calls:#?}"
    );
    assert!(
        !calls
            .iter()
            .any(|r| r.method == Method::Delete && r.path() == item_url(MINE, "01A")),
        "starting clean is not a licence to delete the good version: {calls:#?}"
    );
    if let Ok(u) = &out {
        assert!(
            calls.iter().any(|r| {
                r.method == Method::Put
                    && r.url.starts_with("https://sn3302.up.1drv.com/")
                    && r.range().map(|s| s.ends_with("/655360")).unwrap_or(false)
                    && r.body.len() == 327_680
                    && r.url == u2
            }),
            "Ok requires a fragment that was actually answered as a commit: {calls:#?}"
        );
        assert_eq!(
            u.etag.as_deref(),
            Some("ct:c:{G},9"),
            "and the tag of the new version, not the pre-upload one"
        );
    }
}

/// The `uploadUrl` is a bearer credential — the documentation says to strip
/// `Authorization` when using it precisely because it carries its own.
/// `run_upload` turns any `Err` into `Outcome::Failed(e.to_string())`, which the
/// daemon logs and shows in status output.
#[test]
fn the_upload_url_never_reaches_the_framework_in_an_error_string() {
    let rig = Rig::with_cap("upload_url_is_a_secret", 20);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = "https://sn3302.up.1drv.com/up/f00bar?tempauth=SECRET-TOKEN-9".to_string();

    rig.script(post(item_session(MINE, "01A")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()),
        vec![boom(io::ErrorKind::ConnectionReset, "reset by peer")],
    );
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let err = sink
        .upload(&path, at(&cloud(MINE, "01A")))
        .expect_err("the transport failed");

    // A sink that refused this upload before ever creating a session never held
    // the secret, and passes a leak test by never having anything to leak.
    assert!(
        rig.journal.calls().iter().any(|r| r.url == u),
        "the sink held the pre-authenticated URL and used it: {:#?}",
        rig.journal.calls()
    );

    let text = rendered(&err);
    for secret in ["SECRET-TOKEN-9", "sn3302.up.1drv.com", "/up/f00bar"] {
        assert!(
            !text.contains(secret),
            "a pre-authenticated write handle to the drive reached a log line: {text}"
        );
    }
}

/// `sessions: HashMap<PathBuf, UploadSession>` kept on the sink so the
/// framework's re-queue "resumes efficiently instead of re-uploading gigabytes"
/// is a genuinely attractive optimisation, and it is unsound: mtime and size
/// cannot distinguish "same file, retry" from "the user saved again", which is
/// the common case a 900-second debounce exists to create.
#[test]
fn a_second_upload_call_never_resumes_a_session_from_the_first() {
    let rig = Rig::with_cap("no_session_carried_between_calls", 24);
    let first = pattern(983_040);
    let path = rig.file("report.pdf", &first);
    let u1 = upload_url("SS1");
    let u2 = upload_url("SS2");

    rig.script(
        post(item_session(MINE, "01A")),
        vec![ok(session(&u1)), ok(session(&u2))],
    );
    rig.script(
        get(item_url(MINE, "01A")),
        vec![ok(drive_item("01A", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u1.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u1.clone()).range("bytes 327680-655359/983040"),
        vec![boom(io::ErrorKind::ConnectionReset, "reset by peer")],
    );
    // The rest of session one, scripted so a sink that resumes succeeds quietly.
    rig.script(
        put(u1.clone()),
        vec![
            reply(202, accepted(&["655360-"])),
            created(drive_item("01A", "report.pdf", 983_040, "c:{G},9")),
        ],
    );
    rig.script(
        put(u2.clone()).range("bytes 0-327679/655360"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u2.clone()).range("bytes 327680-655359/655360"),
        vec![created(drive_item("01A", "report.pdf", 655_360, "c:{G},9"))],
    );
    rig.script(del(u1.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01A"), "ct:c:{G},1");
    let one = sink.upload(&path, at(&cloud(MINE, "01A")));
    assert!(one.is_err(), "the first call lost its connection");

    // The user saved again: different length, different content.
    let second = pattern(655_360)
        .into_iter()
        .map(|b| b ^ 0x5A)
        .collect::<Vec<u8>>();
    std::fs::write(&path, &second).expect("the second save");
    rig.journal.clear();

    let two = sink.upload(&path, at(&cloud(MINE, "01A")));
    assert!(
        two.is_ok(),
        "the second call must be able to succeed: {two:?}"
    );

    let calls = rig.journal.calls();
    assert!(
        calls.iter().any(|r| r.path() == item_session(MINE, "01A")),
        "the second call creates its own session: {calls:#?}"
    );
    assert!(
        !calls.iter().any(|r| r.url == u1),
        "and never touches the first one's: {calls:#?}"
    );
    let frags = fragments(&rig.journal, &u2);
    for (f, _) in &frags {
        assert_eq!(
            f.total, 655_360,
            "the total is the file as it is now: {f:?}"
        );
    }
    let sent: Vec<u8> = frags.iter().flat_map(|(_, b)| b.clone()).collect();
    assert_eq!(sent, second, "the bytes sent are the file as it is now");
}

// ===========================================================================
// CLASS G — Identity crosses the two halves of the crate unchanged
// ===========================================================================

/// The common case is editing a file that came down from the cloud, and on that
/// path `existing` is the service's id, not a receipt from this process. A sink
/// keying `existing` into its own map of ids it handed out passes every
/// same-session test and misses on every restart.
#[test]
fn a_fresh_sink_honours_an_existing_id_it_never_minted() {
    let rig = Rig::new("fresh_sink_honours_existing");
    let path = rig.file("notes.txt", b"nine byte");

    rig.script(
        put(item_content(MINE, "01OLD")),
        vec![ok(drive_item("01OLD", "notes.txt", 9, "c:{G},2"))],
    );
    rig.script(
        put(path_content(MINE, "notes.txt")),
        vec![created(drive_item("01DUP", "notes.txt", 9, "c:{G},1"))],
    );

    // Brand new: this instance has returned no id in its lifetime.
    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01OLD"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01OLD")));

    let call = only_call(&rig.journal);
    assert_eq!(
        call.path(),
        item_content(MINE, "01OLD"),
        "an id from the delta half is as good as one this sink minted"
    );
    assert_eq!(
        out.expect("the update must succeed").cloud_id,
        cloud(MINE, "01OLD")
    );
}

/// The two halves must agree on identity or the framework holds two names for
/// one object: a bare `01NEW` on the inode means the next delta round reports
/// `b!mine|01NEW`, `delta::apply` finds no local claimant, and a second local
/// file starts claiming the same object.
#[test]
fn the_cloud_id_returned_by_upload_is_the_one_the_delta_half_produces() {
    let rig = Rig::new("cloud_id_round_trips");
    let path = rig.file("notes.txt", b"abc");
    let item = drive_item("01NEW", "notes.txt", 3, "c:{G},1");

    rig.script(
        put(path_content(MINE, "notes.txt")),
        vec![created(item.clone())],
    );

    let mut sink = rig.sink();
    let uploaded = sink.upload(&path, None).expect("the create must succeed");

    // The same JSON, through the read half.
    let body = serde_json::json!({
        "value": [
            serde_json::from_str::<serde_json::Value>(&root_item_json()).unwrap(),
            serde_json::from_str::<serde_json::Value>(&item).unwrap(),
        ],
        "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/b!mine/root/delta?token=D1",
    })
    .to_string();
    let page = DeltaPage::parse(200, body.as_bytes()).expect("a well-formed page");
    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(&primary(MINE), &page);
    let done = round
        .finish()
        .map_err(|(e, _)| e)
        .expect("a complete round");

    assert_eq!(
        uploaded.cloud_id,
        upserted_id(&done.changes, "notes.txt"),
        "the write half and the read half name the object identically"
    );
}

/// `delta::is_current` compares the stored tag to the cloud's byte for byte, so
/// a differently shaped tag is never current and the next delta pass places a
/// placeholder over the file that was just correctly uploaded.
#[test]
fn the_etag_returned_by_upload_is_the_tag_the_delta_half_produces() {
    let rig = Rig::new("etag_round_trips");
    let path = rig.file("notes.txt", b"abc");
    let item = drive_item("01NEW", "notes.txt", 3, "c:{G},1");

    rig.script(
        put(path_content(MINE, "notes.txt")),
        vec![created(item.clone())],
    );

    let mut sink = rig.sink();
    let uploaded = sink.upload(&path, None).expect("the create must succeed");

    let body = serde_json::json!({
        "value": [
            serde_json::from_str::<serde_json::Value>(&root_item_json()).unwrap(),
            serde_json::from_str::<serde_json::Value>(&item).unwrap(),
        ],
        "@odata.deltaLink": "https://graph.microsoft.com/v1.0/drives/b!mine/root/delta?token=D1",
    })
    .to_string();
    let page = DeltaPage::parse(200, body.as_bytes()).expect("a well-formed page");
    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(&primary(MINE), &page);
    let done = round
        .finish()
        .map_err(|(e, _)| e)
        .expect("a complete round");
    let id = upserted_id(&done.changes, "notes.txt");

    assert_eq!(
        uploaded.etag,
        upserted_etag(&done.changes, &id),
        "not the raw eTag, and not an unprefixed cTag"
    );
    assert_eq!(uploaded.etag.as_deref(), Some("ct:c:{G},1"));
}

/// The field is an `Option`, so punting it compiles and the upload genuinely
/// succeeded — the failure surfaces one delta round later, in another module,
/// as a placeholder over freshly uploaded content.
#[test]
fn an_update_never_returns_a_none_etag_when_the_response_carries_a_tag() {
    let rig = Rig::new("update_returns_its_tag");
    let path = rig.file("notes.txt", b"nine byte");

    rig.script(
        put(item_content(MINE, "01OLD")),
        vec![ok(drive_item("01OLD", "notes.txt", 9, "c:{G},2"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01OLD"), "ct:c:{G},1");
    let out = sink
        .upload(&path, at(&cloud(MINE, "01OLD")))
        .expect("the update must succeed");

    assert_eq!(
        out.etag.as_deref(),
        Some("ct:c:{G},2"),
        "the tag of the version that was just written, not the one it replaced"
    );
}

/// "Missing is an error; wrong is a catastrophe", applied to the write half. A
/// `ct:`-shaped tag on a quickXor drive is not one wrong file: every file this
/// sink uploads gets a tag the read half will never produce, so `is_current` is
/// false drive-wide and the next pass dehydrates everything the user edited.
#[test]
fn a_quickxor_drive_is_never_given_a_ctag_shaped_tag() {
    let rig = Rig::new("quickxor_tags_stay_quickxor");
    let path = rig.file("notes.txt", b"abc");

    // The commit body carries a cTag and no hashes — the documented default
    // property set, and the normal state while hashes lag a write.
    rig.script(
        put(path_content(MINE, "notes.txt")),
        vec![created(drive_item("01NEW", "notes.txt", 3, "c:{G},1"))],
    );
    rig.script(
        get(item_url(MINE, "01NEW")),
        vec![ok(qx_item("01NEW", "notes.txt", 3, "QX2"))],
    );

    let mut sink = rig.sink_with(MINE, TagSource::QuickXor, UploadPolicy::default());
    let out = sink.upload(&path, None).expect("the create must succeed");

    assert_eq!(
        out.etag.as_deref(),
        Some("qx:QX2"),
        "the tag comes from the source this drive is pinned to"
    );
    let calls = rig.journal.calls();
    assert_eq!(calls.len(), 2, "a create and a follow-up read: {calls:#?}");
    assert_eq!(calls[0].method, Method::Put);
    assert_eq!(calls[1].method, Method::Get);
    assert_eq!(calls[1].path(), item_url(MINE, "01NEW"));
}

/// `by_name.entry(name.to_lowercase())` is a cache added to skip a lookup per
/// upload: correct on every case-consistent drive, and wrong in the one
/// directory where it matters. Two local files then claim one object, both read
/// Clean, and deleting either removes the object the other depends on.
#[test]
fn two_local_names_differing_only_in_case_stay_two_objects() {
    let rig = Rig::new("case_is_not_folded");
    let upper = rig.file("Report.txt", b"upper");
    let lower = rig.file("report.txt", b"lower");

    rig.script(
        put(path_content(MINE, "Report.txt")).q("@microsoft.graph.conflictBehavior", "fail"),
        vec![created(drive_item("01A", "Report.txt", 5, "c:{G},1"))],
    );
    rig.script(
        put(path_content(MINE, "report.txt")).q("@microsoft.graph.conflictBehavior", "fail"),
        vec![reply(409, graph_error("nameAlreadyExists"))],
    );
    // The wrong branch, scripted to succeed.
    rig.script(
        put(item_content(MINE, "01A")),
        vec![ok(drive_item("01A", "Report.txt", 5, "c:{G},2"))],
    );

    let mut sink = rig.sink();
    let first = sink
        .upload(&upper, None)
        .expect("the first create succeeds");
    assert_eq!(first.cloud_id, cloud(MINE, "01A"));
    rig.journal.clear();

    let second = sink.upload(&lower, None);
    assert!(second.is_err(), "the service will not hold both names");

    // Two calls now, not one: the collision is followed by a metadata read that
    // asks whether the object already at this name is this same document. It is
    // not — Graph resolved the path case-insensitively and answered with
    // `Report.txt` — so nothing is adopted and nothing is written. The count was
    // only ever a proxy for "no second write"; that is asserted directly here,
    // across every call rather than the one.
    let calls = rig.journal.calls();
    assert!(
        calls.iter().any(|c| c.url.contains("root:/report.txt:")),
        "the name is sent as it is on disk, case preserved: {calls:#?}"
    );
    assert!(
        !calls
            .iter()
            .any(|c| c.method == Method::Put && c.path() == item_content(MINE, "01A")),
        "the second file was written over the first: {calls:#?}"
    );
}

/// The local file is now the only copy. `Err` makes `run_upload` return
/// `Failed`, the driver re-queues, the next attempt reads the same id and takes
/// the same `404` — forever, with nothing raising an alarm.
#[test]
fn an_existing_id_the_service_no_longer_has_becomes_a_create() {
    let rig = Rig::new("stale_id_becomes_a_create");
    let path = rig.file("notes.txt", b"nine byte");

    rig.script(
        put(item_content(MINE, "01GONE")),
        vec![reply(404, graph_error("itemNotFound"))],
    );
    rig.script(
        put(path_content(MINE, "notes.txt")).q("@microsoft.graph.conflictBehavior", "fail"),
        vec![created(drive_item("01FRESH", "notes.txt", 9, "c:{G},1"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01GONE"), "ct:c:{G},1");
    let out = sink
        .upload(&path, at(&cloud(MINE, "01GONE")))
        .expect("a stale id is recoverable");

    assert_eq!(out.cloud_id, cloud(MINE, "01FRESH"));
    let calls = rig.journal.calls();
    assert_eq!(calls.len(), 2, "the update, then the create: {calls:#?}");
    assert_eq!(calls[0].path(), item_content(MINE, "01GONE"));
    assert_eq!(calls[1].path(), path_content(MINE, "notes.txt"));
}

// ===========================================================================
// CLASS H — A name the service cannot hold is refused before any bytes move
// ===========================================================================

/// Two failures at once. Sending it spends a whole transfer that can only fail,
/// and on a resumable upload the rejection surfaces at the *last* fragment — a
/// 2 GB file transfers 2 GB and then 400s, on every retry, forever. Sanitising
/// is worse: the object is created under a name no local file has.
#[test]
fn a_name_the_service_would_reject_is_refused_before_any_request() {
    let rig = Rig::new("illegal_names_never_reach_the_wire");
    // Nothing is scripted at all, so any attempt is visible in the journal
    // rather than quietly satisfied.

    // 4 directories of 80 characters and an 88-character name: the decoded path
    // from the drive root is 412 characters, and every segment is legal.
    let deep = format!(
        "{}/{}/{}/{}/{}",
        "d".repeat(80),
        "e".repeat(80),
        "f".repeat(80),
        "g".repeat(80),
        "h".repeat(88)
    );
    assert_eq!(deep.chars().count(), 412);

    let cases: Vec<String> = vec![
        "notes.txt ".into(),
        "~$draft.docx".into(),
        ".lock".into(),
        "CON".into(),
        "report_vti_final.docx".into(),
        "a:b.txt".into(),
        deep,
    ];

    let mut sink = rig.sink();
    for rel in &cases {
        let path = rig.file(rel, b"twelve bytes");
        let out = sink.upload(&path, None);
        assert!(out.is_err(), "{rel:?} is not a name this service can hold");
        assert!(
            rig.journal.calls().is_empty(),
            "{rel:?} was refused after a request rather than before one: {:#?}",
            rig.journal.calls()
        );
        rig.journal.clear();
    }
}

/// Leading and trailing spaces are documented as not allowed; a trailing period
/// is not addressed at all, so the service may reject it or may trim it. If it
/// trims, the created object is named `report`, the local file is `report. `,
/// and the id gets stamped onto a file whose name the cloud does not have.
#[test]
fn a_name_the_service_would_silently_trim_is_refused_not_sent() {
    let rig = Rig::new("trimmable_names_never_reach_the_wire");

    // The normalising branch, scripted to succeed.
    for url in [
        path_content(MINE, "report"),
        path_content(MINE, "report. "),
        path_content(MINE, "report."),
    ] {
        rig.script(
            put(url),
            vec![created(drive_item("01TRIM", "report", 3, "c:{G},1"))],
        );
    }

    let mut sink = rig.sink();
    for rel in ["report. ", "report."] {
        let path = rig.file(rel, b"abc");
        let out = sink.upload(&path, None);
        assert!(
            out.is_err(),
            "{rel:?} names one thing locally and another in the cloud"
        );
        assert!(
            rig.journal.calls().is_empty(),
            "{rel:?} reached the wire: {:#?}",
            rig.journal.calls()
        );
        rig.journal.clear();
    }
}

// ===========================================================================
// CLASS I — Positive controls
//
// "Refuse every write that cannot be proven safe" satisfies most of this file
// and ships a client that never uploads anything — which destroys data in the
// other direction, because an edit that never leaves the laptop dies with the
// laptop and `Outcome::Failed` re-queues forever so `pending()` never falls.
// ===========================================================================

#[test]
fn positive_control_an_ordinary_update_is_one_conditional_put_and_returns_the_new_tag() {
    let rig = Rig::new("control_ordinary_update");
    let path = rig.file("Work/report.docx", b"hello world!");

    // Nothing else is scripted, so any extra request shows in the journal as an
    // error rather than being quietly satisfied.
    rig.script(
        put(item_content(MINE, "01REPORT")),
        vec![ok(drive_item("01REPORT", "report.docx", 12, "c:{G},2"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink
        .upload(&path, at(&cloud(MINE, "01REPORT")))
        .expect("an ordinary update must succeed");

    assert_eq!(
        out,
        Uploaded {
            cloud_id: cloud(MINE, "01REPORT"),
            etag: Some("ct:c:{G},2".into()),
        }
    );
    let call = only_call(&rig.journal);
    assert_eq!(call.method, Method::Put);
    assert_eq!(call.header("if-match"), Some("c:{G},1"));
    assert_eq!(
        call.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(call.body, b"hello world!".to_vec());
    assert!(call.authorize, "a Graph URL takes the account credential");
    assert!(rig.journal.sleeps().is_empty(), "nothing was throttled");
}

#[test]
fn positive_control_a_new_file_creates_once_and_returns_a_composed_id() {
    let rig = Rig::new("control_new_file");
    let path = rig.file("Work/plan.md", b"a plan, then!!");

    rig.script(
        put(path_content(MINE, "Work/plan.md")).q("@microsoft.graph.conflictBehavior", "fail"),
        vec![created(drive_item("01PLAN", "plan.md", 14, "c:{G},1"))],
    );

    let mut sink = rig.sink();
    let out = sink.upload(&path, None).expect("a create must succeed");

    assert_eq!(
        out,
        Uploaded {
            cloud_id: cloud(MINE, "01PLAN"),
            etag: Some("ct:c:{G},1".into()),
        }
    );
    let call = only_call(&rig.journal);
    assert_eq!(
        call.path(),
        path_content(MINE, "Work/plan.md"),
        "the folder structure below the sync root is preserved, and the slash is a slash"
    );
    assert_eq!(call.body, b"a plan, then!!".to_vec());
}

#[test]
fn positive_control_remove_deletes_once_and_an_already_gone_object_is_success() {
    // (a) 204: an ordinary removal.
    let a = Rig::new("control_remove_204");
    a.script(del(item_url(MINE, "01GONE")), vec![no_content()]);
    let mut sink = a.sink();
    assert!(sink.remove(&cloud(MINE, "01GONE")).is_ok());
    let call = only_call(&a.journal);
    assert_eq!(call.method, Method::Delete);
    assert_eq!(call.path(), item_url(MINE, "01GONE"));

    // (b) 404: already gone is the state that was wanted. An Err here makes
    // `run_upload` return Failed, the driver re-queue, and the next pass answer
    // NothingToDo — so the object is never removed and comes back down the
    // delta feed to resurrect the file the user deleted.
    let b = Rig::new("control_remove_404");
    b.script(
        del(item_url(MINE, "01GONE")),
        vec![reply(404, graph_error("itemNotFound"))],
    );
    let mut sink = b.sink();
    assert!(
        sink.remove(&cloud(MINE, "01GONE")).is_ok(),
        "already gone is success"
    );
    let calls = b.journal.calls();
    assert_eq!(calls.len(), 1);
    assert!(!calls[0].path().ends_with("/permanentDelete"));

    // (c) 403: still there, and `run_upload` would report DeletedInstead over it.
    let c = Rig::new("control_remove_403");
    c.script(
        del(item_url(MINE, "01GONE")),
        vec![reply(403, graph_error("accessDenied"))],
    );
    let mut sink = c.sink();
    assert!(
        sink.remove(&cloud(MINE, "01GONE")).is_err(),
        "a refusal is not a removal"
    );
}

#[test]
fn an_empty_folder_is_checked_then_deleted_with_its_metadata_version() {
    let rig = Rig::new("remove_empty_folder");
    rig.script(
        get(item_children(MINE, "01EMPTY"))
            .q("$top", "1")
            .q("$select", "id"),
        vec![ok(serde_json::json!({"value": []}).to_string())],
    );
    rig.script(
        get(item_url(MINE, "01EMPTY")),
        vec![ok(folder_item("01EMPTY", "Empty", "\"{FOLDER},8\"", ROOT))],
    );
    rig.script(
        del(item_url(MINE, "01EMPTY")).with("if-match"),
        vec![no_content()],
    );

    rig.sink()
        .remove_folder(Known {
            cloud_id: &cloud(MINE, "01EMPTY"),
            tag: Some("et:\"{FOLDER},7\""),
        })
        .unwrap();

    let calls = rig.journal.calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[0].method, Method::Get);
    assert_eq!(calls[1].method, Method::Get);
    assert!(
        calls[1].query().contains("folder"),
        "the metadata read must request the facet that proves this is a folder"
    );
    assert_eq!(calls[2].method, Method::Delete);
    assert_eq!(
        calls[2].header("if-match"),
        Some("\"{FOLDER},8\""),
        "the delete is bound to the empty-folder check, after child deletion changed the old tag"
    );
    assert!(!calls[2].path().ends_with("/permanentDelete"));
}

#[test]
fn a_nonempty_folder_is_never_recursively_deleted() {
    let rig = Rig::new("refuse_nonempty_folder");
    rig.script(
        get(item_children(MINE, "01FOLDER")),
        vec![ok(
            serde_json::json!({"value": [{"id": "01CHILD"}]}).to_string()
        )],
    );

    let err = rig
        .sink()
        .remove_folder(Known {
            cloud_id: &cloud(MINE, "01FOLDER"),
            tag: Some("et:\"{FOLDER},7\""),
        })
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("not empty"));
    assert!(rig.journal.deletes().is_empty());
}

#[test]
fn an_item_without_the_folder_facet_is_never_deleted_as_a_folder() {
    let rig = Rig::new("refuse_file_as_folder");
    rig.script(
        get(item_children(MINE, "01FILE")),
        vec![ok(serde_json::json!({"value": []}).to_string())],
    );
    rig.script(
        get(item_url(MINE, "01FILE")),
        vec![ok(drive_item("01FILE", "file.txt", 12, "c:{FILE},8"))],
    );

    let err = rig
        .sink()
        .remove_folder(Known {
            cloud_id: &cloud(MINE, "01FILE"),
            tag: Some("et:\"{FILE},7\""),
        })
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(err.to_string().contains("expected folder"));
    assert!(rig.journal.deletes().is_empty());
}

#[test]
fn a_folder_without_a_metadata_etag_is_refused_before_graph() {
    let rig = Rig::new("refuse_unguarded_folder_remove");

    for tag in [None, Some("ct:c:{FILE},1"), Some("qx:HASH")] {
        assert!(rig
            .sink()
            .remove_folder(Known {
                cloud_id: &cloud(MINE, "01FOLDER"),
                tag,
            })
            .is_err());
    }
    assert!(rig.journal.calls().is_empty());
}

#[test]
fn the_sync_root_is_never_removed_even_with_a_valid_identity_and_etag() {
    let rig = Rig::new("refuse_root_folder_remove");
    let root_id = cloud(MINE, ROOT);
    store::set_xattr(&rig.root, store::XATTR_ID, root_id.as_bytes()).unwrap();

    let err = rig
        .sink()
        .remove_folder(Known {
            cloud_id: &root_id,
            tag: Some("et:\"{ROOT},7\""),
        })
        .unwrap_err();

    assert!(err.to_string().contains("sync root"));
    assert!(rig.journal.calls().is_empty());
}

#[test]
fn a_folder_that_gains_a_child_during_delete_is_kept() {
    let rig = Rig::new("folder_delete_race");
    rig.script(
        get(item_children(MINE, "01FOLDER")),
        vec![ok(serde_json::json!({"value": []}).to_string())],
    );
    rig.script(
        get(item_url(MINE, "01FOLDER")),
        vec![ok(folder_item(
            "01FOLDER",
            "Folder",
            "\"{FOLDER},8\"",
            ROOT,
        ))],
    );
    rig.script(
        del(item_url(MINE, "01FOLDER")).with("if-match"),
        vec![reply(412, graph_error("resourceModified"))],
    );
    rig.script(
        del(item_url(MINE, "01FOLDER")).without("if-match"),
        vec![no_content()],
    );

    let err = rig
        .sink()
        .remove_folder(Known {
            cloud_id: &cloud(MINE, "01FOLDER"),
            tag: Some("et:\"{FOLDER},7\""),
        })
        .unwrap_err();

    assert!(rendered(&err).contains("412"));
    assert_eq!(rig.journal.deletes().len(), 1);
    assert_eq!(
        rig.journal.deletes()[0].header("if-match"),
        Some("\"{FOLDER},8\"")
    );
}

#[test]
fn positive_control_a_large_file_commits_through_a_session_with_conforming_fragments() {
    let rig = Rig::with_cap("control_large_file", 16);
    let bytes = pattern(12_582_912);
    let path = rig.file("big.bin", &bytes);
    let u = upload_url("S5");

    rig.script(post(item_session(MINE, "01BIG")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01BIG")),
        vec![ok(drive_item("01BIG", "big.bin", 900, "c:{G},7"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-10485759/12582912"),
        vec![reply(202, accepted(&["10485760-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 10485760-12582911/12582912"),
        vec![created(drive_item(
            "01BIG", "big.bin", 12_582_912, "c:{G},8",
        ))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01BIG"), "ct:c:{G},7");
    let out = sink
        .upload(&path, at(&cloud(MINE, "01BIG")))
        .expect("a large file must commit");

    assert_eq!(
        out,
        Uploaded {
            cloud_id: cloud(MINE, "01BIG"),
            etag: Some("ct:c:{G},8".into()),
        }
    );

    let frags = fragments(&rig.journal, &u);
    let last = frags.len() - 1;
    let mut expect_at = 0u64;
    for (i, (f, body)) in frags.iter().enumerate() {
        assert_eq!(f.start, expect_at, "fragments are contiguous: {f:?}");
        assert_eq!(f.total, 12_582_912, "one declared total throughout: {f:?}");
        assert_eq!(
            f.len as u64,
            f.end - f.start + 1,
            "the body fills the range"
        );
        if i != last {
            assert_eq!(
                f.len % FRAGMENT_QUANTUM,
                0,
                "a whole number of quanta: {f:?}"
            );
            assert!(f.len < MAX_FRAGMENT_BYTES, "under the ceiling: {f:?}");
        }
        assert_eq!(
            body.as_slice(),
            &bytes[f.start as usize..=f.end as usize],
            "fragment {i} carries the file's own bytes"
        );
        expect_at = f.end + 1;
    }
    assert_eq!(expect_at, 12_582_912, "the whole file went out");

    for call in rig.journal.calls() {
        if call.url.starts_with("https://sn3302.up.1drv.com/") {
            assert!(
                !call.authorize,
                "the Graph credential never goes to a host a response body named: {call:?}"
            );
            assert!(call.header("authorization").is_none());
        }
    }
    assert!(rig.journal.sleeps().is_empty(), "nothing was throttled");
}

#[test]
fn positive_control_a_three_fragment_session_completes_in_one_pass() {
    let rig = Rig::with_cap("control_three_fragments", 12);
    let bytes = pattern(983_040);
    let path = rig.file("report.pdf", &bytes);
    let u = upload_url("S3F");

    rig.script(post(item_session(MINE, "01OLD")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01OLD")),
        vec![ok(drive_item("01OLD", "report.pdf", 900, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(202, accepted(&["655360-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 655360-983039/983040"),
        vec![created(drive_item(
            "01OLD",
            "report.pdf",
            983_040,
            "c:{G},9",
        ))],
    );

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01OLD"), "ct:c:{G},1");
    let out = sink
        .upload(&path, at(&cloud(MINE, "01OLD")))
        .expect("three fragments must commit");

    assert_eq!(
        out,
        Uploaded {
            cloud_id: cloud(MINE, "01OLD"),
            etag: Some("ct:c:{G},9".into()),
        }
    );

    let frags = fragments(&rig.journal, &u);
    assert_eq!(
        frags
            .iter()
            .map(|(f, _)| (f.start, f.end))
            .collect::<Vec<_>>(),
        vec![(0, 327_679), (327_680, 655_359), (655_360, 983_039)],
        "strictly ascending, contiguous, no gap and no overlap"
    );
    assert!(
        !rig.journal
            .calls()
            .iter()
            .any(|r| r.method == Method::Get && r.url == u),
        "no status poll per fragment against a throttling endpoint"
    );
    assert!(rig.journal.deletes().is_empty(), "and no cancel");
    assert!(rig.journal.sleeps().is_empty(), "and no backoff");
}

/// The drive root, for the two round-trip tests that feed a page to the read
/// half. Kept here rather than in the fixtures block because it is the only
/// thing in this file that describes a *page* rather than a request.
fn root_item_json() -> String {
    serde_json::json!({
        "id": ROOT,
        "name": "root",
        "root": {},
        "folder": {"childCount": 1},
        "parentReference": {"driveId": MINE},
    })
    .to_string()
}

/// Compile-time proof that a `GraphSink` is usable everywhere the framework
/// asks for a `Sink` — including behind `ProviderSink`, which requires `Send`.
#[allow(dead_code)]
fn sink_is_a_framework_sink<T: Transport + 'static, K: Sleeper + 'static>(
    s: GraphSink<T, K>,
) -> Box<dyn Sink> {
    Box::new(s)
}

// ===========================================================================
// CLASS J — A placeholder is not content
//
// `reclaim::evict` does not truncate in place. It builds a fresh inode, sparse
// to the object's full size, marks it `user.hydration.dehydrated`, stamps it
// while still anonymous, and renames it over the path (`place::TmpfilePlacer`).
// So a dehydrated file is a file of NULs *at the original size*, under the
// original name, reading as `stamp::State::Clean`.
//
// Nothing in the file distinguishes it from real content. Reclaim closes the
// race from its own side — it answers `Refused::UploadPending` for any inode in
// `Queue::waiting_set` or `Queue::sending_set` — but that guard is read outside
// the transfer, and a large upload is minutes long. The sink is the last thing
// between a placeholder and a commit that replaces the user's document with
// holes, and that commit is silent: the length matches, so the size check that
// guards both halves of the framework passes forever.
// ===========================================================================

/// The whole-file case, which needs no race at all — a resync walk queueing a
/// placeholder whose stamp went missing is enough. Both writes are scripted to
/// succeed; only the mark on the file separates them.
#[test]
fn a_dehydrated_placeholder_is_never_uploaded_as_content() {
    let rig = Rig::new("placeholder_is_not_content");
    let path = rig.file("Work/report.docx", &vec![0u8; 4096]);
    store::set_xattr(&path, xattr::DEHYDRATED, b"1").expect("the eviction mark");

    rig.script(
        put(item_content(MINE, "01REPORT")),
        vec![ok(drive_item("01REPORT", "report.docx", 4096, "c:{G},2"))],
    );
    rig.script(
        put(path_content(MINE, "Work/report.docx")),
        vec![created(drive_item(
            "01FRESH",
            "report.docx",
            4096,
            "c:{G},1",
        ))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01REPORT")));

    assert!(
        out.is_err(),
        "a placeholder's holes are not the user's document"
    );
    assert!(
        rig.journal.calls().is_empty(),
        "the mark is on the file, so the refusal costs no request: {:#?}",
        rig.journal.calls()
    );
}

/// POSITIVE CONTROL for the rule above. "Refuse a body of zeros" and "refuse a
/// sparse file" both satisfy it, and both silently stop syncing real files: a
/// freshly `truncate`d database, a disk image, a zeroed test fixture. The mark
/// is the evidence — the bytes never are, which is exactly why
/// `xattr::DEHYDRATED` exists rather than an `st_blocks` test.
#[test]
fn positive_control_a_file_of_real_zeros_with_no_eviction_mark_uploads() {
    let rig = Rig::new("real_zeros_still_upload");
    let path = rig.file("Work/disk.img", &vec![0u8; 4096]);

    rig.script(
        put(item_content(MINE, "01IMG")),
        vec![ok(drive_item("01IMG", "disk.img", 4096, "c:{G},2"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01IMG"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01IMG")));

    assert_eq!(
        out.expect("a file of zeros is still a file").cloud_id,
        cloud(MINE, "01IMG")
    );
    let call = only_call(&rig.journal);
    assert_eq!(
        call.body,
        vec![0u8; 4096],
        "and its bytes went out unchanged"
    );
}

/// The race itself. The eviction lands between two fragments, so the session
/// began on the user's document and continues on a hole — and every guard the
/// sink could be carrying agrees the file is unchanged, because the placeholder
/// has the same size and the same name and its own fresh stamp.
///
/// The commit is scripted to succeed. What it would commit is 320 KiB of the
/// user's report followed by 640 KiB of nothing.
#[test]
fn an_eviction_that_lands_mid_session_never_commits_the_placeholders_zeros() {
    let rig = Rig::with_cap("eviction_mid_session", 20);
    let bytes = pattern(983_040);
    let path = rig.file("big.bin", &bytes);
    let u = upload_url("SEV");

    let evict_at = path.clone();
    let evict_via = rig.root.join(".big.bin.hydration-1");
    rig.script(post(item_session(MINE, "01BIG")), vec![ok(session(&u))]);
    rig.script(
        get(item_url(MINE, "01BIG")),
        vec![ok(drive_item("01BIG", "big.bin", 983_040, "c:{G},1"))],
    );
    rig.script(
        put(u.clone()).range("bytes 0-327679/983040"),
        vec![reply(202, accepted(&["327680-"])).then(effect(move || {
            // `TmpfilePlacer::place` in miniature: a new inode, sparse to the
            // object's size, marked before it is sized, swapped in by rename.
            let f = std::fs::File::create(&evict_via).expect("a placeholder inode");
            f.set_len(983_040).expect("sparse to the object's size");
            drop(f);
            store::set_xattr(&evict_via, xattr::DEHYDRATED, b"1").expect("the mark");
            let _ = hydration_protocol::stamp::write(&evict_via);
            std::fs::rename(&evict_via, &evict_at).expect("reclaim swaps the placeholder in");
        }))],
    );
    // Both continuations and the commit, scripted to succeed.
    rig.script(
        put(u.clone()).range("bytes 327680-655359/983040"),
        vec![reply(202, accepted(&["655360-"]))],
    );
    rig.script(
        put(u.clone()).range("bytes 655360-983039/983040"),
        vec![created(drive_item("01BIG", "big.bin", 983_040, "c:{G},9"))],
    );
    rig.script(del(u.clone()), vec![no_content()]);

    let mut sink = rig.sink_policy(session_policy());
    sink.record_tag(&cloud(MINE, "01BIG"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01BIG")));

    let frags = fragments(&rig.journal, &u);
    for (f, body) in &frags {
        assert!(
            !(body.len() > 16 && body.iter().all(|b| *b == 0)),
            "the fragment at {}-{} is the placeholder's hole, not the file: {f:?}",
            f.start,
            f.end
        );
    }
    assert!(
        !frags.iter().any(|(f, _)| f.end + 1 == f.total),
        "nothing commits over a file that became a placeholder under it: {frags:#?}"
    );
    assert!(
        out.is_err(),
        "the content this session described no longer exists on this machine"
    );
}

// ===========================================================================
// CLASS K — §5.5, at the moment the upload *starts*
//
// §5.5 states the absence rule about the moment an upload finishes, and
// `run_upload` implements it there. The moment it starts is the same fact and is
// specified nowhere: `run_upload` resolves the path, takes
// `std::fs::metadata(&path).ok()` — which folds `ENOENT` into `None` — and calls
// `sink.upload` anyway. So the sink is routinely handed a path that no longer
// exists, and the two shortest ways to write the read each turn that into a
// commit. `fs::read(path).unwrap_or_default()` replaces the user's document with
// an empty object; a per-path cache of what the last call sent restores the file
// they just deleted, which is bug #51 moved one layer down.
// ===========================================================================

#[test]
fn a_file_that_is_gone_is_never_uploaded_as_an_empty_object_or_from_a_remembered_copy() {
    // (a) The path never existed. Every write is scripted to succeed.
    let a = Rig::new("gone_never_existed");
    a.script(
        put(item_content(MINE, "01REPORT")),
        vec![ok(drive_item("01REPORT", "report.docx", 0, "c:{G},2"))],
    );
    a.script(
        put(path_content(MINE, "Work/report.docx")),
        vec![created(drive_item("01FRESH", "report.docx", 0, "c:{G},1"))],
    );

    let mut sink = a.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink.upload(
        &a.root.join("Work/report.docx"),
        at(&cloud(MINE, "01REPORT")),
    );

    assert!(
        out.is_err(),
        "a file that is not there has no content to send"
    );
    assert!(
        a.journal.calls().is_empty(),
        "the absence is local, and is discovered before a request rather than \
         after a response: {:#?}",
        a.journal.calls()
    );

    // (b) The path existed and was sent once, then deleted. A sink holding the
    // bytes of the first call answers the second from memory, and the file the
    // user deleted is back in the cloud with its contents.
    let b = Rig::new("gone_after_a_send");
    let path = b.file("Work/report.docx", b"the document");
    b.script(
        put(item_content(MINE, "01REPORT")),
        vec![
            ok(drive_item("01REPORT", "report.docx", 12, "c:{G},2")),
            ok(drive_item("01REPORT", "report.docx", 12, "c:{G},3")),
        ],
    );

    let mut sink = b.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    sink.upload(&path, at(&cloud(MINE, "01REPORT")))
        .expect("the first send succeeds");
    std::fs::remove_file(&path).expect("the user deletes the file");
    b.journal.clear();

    let again = sink.upload(&path, at(&cloud(MINE, "01REPORT")));
    assert!(again.is_err(), "the file is gone; there is nothing to send");
    assert!(
        b.journal.calls().is_empty(),
        "not one byte of a remembered copy reached the wire: {:#?}",
        b.journal.calls()
    );

    // (c) POSITIVE CONTROL. An empty file that *exists* is content. Refusing it
    // leaves the pre-truncation version in the cloud permanently, and the next
    // delta pass puts it back over the user's now-empty file.
    let c = Rig::new("empty_file_still_uploads");
    let empty = c.file("Work/notes.txt", b"");
    c.script(
        put(item_content(MINE, "01NOTES")),
        vec![ok(drive_item("01NOTES", "notes.txt", 0, "c:{G},2"))],
    );

    let mut sink = c.sink();
    sink.record_tag(&cloud(MINE, "01NOTES"), "ct:c:{G},1");
    let out = sink
        .upload(&empty, at(&cloud(MINE, "01NOTES")))
        .expect("an empty file is a file");

    assert_eq!(out.cloud_id, cloud(MINE, "01NOTES"));
    let call = only_call(&c.journal);
    assert!(call.body.is_empty(), "and it is sent as zero bytes");
}

// ===========================================================================
// CLASS L — A throttle is not a verdict
//
// The `Sleeper` is injected and recording and `Reply` carries `retry_after`, and
// until this class nothing made either of them say anything: every test above
// asserts `sleeps().is_empty()`. So the whole retry path was unspecified — and
// the retry is where a precondition goes missing, because the first attempt is
// built from the recorded tag and the natural loop rebuilds the request from
// whatever is still in scope.
// ===========================================================================

/// `429 activityLimitReached` is the single most common thing a busy drive
/// answers, so a retry that drops `if-match` is not a rare path — it is most
/// writes, and each one destroys the remote edit the precondition existed to
/// catch. The unconditional retry is scripted to succeed.
#[test]
fn a_throttled_write_is_retried_with_its_precondition_and_after_the_advertised_delay() {
    let rig = Rig::new("throttle_keeps_the_precondition");
    let path = rig.file("Work/report.docx", b"hello world!");

    rig.script(
        put(item_content(MINE, "01REPORT")).with("if-match"),
        vec![
            throttled(
                429,
                graph_error("activityLimitReached"),
                Duration::from_secs(7),
            ),
            ok(drive_item("01REPORT", "report.docx", 12, "c:{G},2")),
        ],
    );
    rig.script(
        put(item_content(MINE, "01REPORT")).without("if-match"),
        vec![ok(drive_item("01REPORT", "report.docx", 12, "c:{G},9"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01REPORT")));

    assert_eq!(
        out.expect("a 429 is the service asking for a moment, not refusing")
            .etag
            .as_deref(),
        Some("ct:c:{G},2"),
        "and the version that landed is the conditional write's"
    );
    let blind: Vec<Rec> = rig
        .journal
        .writes()
        .into_iter()
        .filter(|r| r.header("if-match").is_none())
        .collect();
    assert!(
        blind.is_empty(),
        "a retry carries the precondition its first attempt did: {blind:#?}"
    );

    let sleeps = rig.journal.sleeps();
    assert_eq!(sleeps.len(), 1, "one backoff for one throttle: {sleeps:?}");
    assert!(
        sleeps[0] >= Duration::from_secs(7),
        "the service named its interval, and it is not ours to shorten: {sleeps:?}"
    );

    // The shared journal is what makes this an ordering claim rather than a
    // presence one: a sink that sleeps *after* its last attempt has honoured
    // nothing.
    let events = rig.journal.all();
    let first = events
        .iter()
        .position(|e| matches!(e, Ev::Call(_)))
        .expect("a first attempt");
    let slept = events
        .iter()
        .position(|e| matches!(e, Ev::Slept(_)))
        .expect("a backoff");
    let retry = events
        .iter()
        .rposition(|e| matches!(e, Ev::Call(_)))
        .expect("a retry");
    assert!(
        first < slept && slept < retry,
        "the wait falls between the attempts: {events:#?}"
    );
}

/// `an_existing_id_the_service_no_longer_has_becomes_a_create` makes a `404` on
/// an update become a create, and it is the only place in this file where a
/// failed update is allowed to become one. The dangerous generalisation is one
/// token wide — `if !reply.ok()` where `if reply.status == 404` was meant — and
/// it passes every test written before this one. A throttle answered by a create
/// mints a second object holding the same document under the same name; the two
/// then chase each other, and whichever loses a pass is overwritten.
#[test]
fn a_transient_failure_on_an_update_never_becomes_a_create() {
    let rig = Rig::with_cap("transient_is_not_a_missing_item", 12);
    let path = rig.file("Work/report.docx", b"hello world!");

    rig.script(
        put(item_content(MINE, "01REPORT")),
        vec![throttled(
            503,
            graph_error("serviceNotAvailable"),
            Duration::from_secs(2),
        )],
    );
    // The create, scripted to succeed and to mint the duplicate.
    rig.script(
        put(path_content(MINE, "Work/report.docx")),
        vec![created(drive_item("01DUP", "report.docx", 12, "c:{G},1"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01REPORT"), "ct:c:{G},1");
    let out = sink.upload(&path, at(&cloud(MINE, "01REPORT")));

    assert!(out.is_err(), "the service never accepted the write");
    let calls = rig.journal.calls();
    assert!(
        !calls
            .iter()
            .any(|r| r.path() == path_content(MINE, "Work/report.docx")),
        "`the service is busy` is not `the object is gone`: {calls:#?}"
    );
    assert!(
        calls
            .iter()
            .all(|r| r.path() == item_content(MINE, "01REPORT")),
        "only the update itself was retried: {calls:#?}"
    );
    assert!(
        calls.len() <= 6,
        "the retry must terminate; it made {} attempts",
        calls.len()
    );
    assert!(
        !rig.journal.sleeps().is_empty(),
        "and it waited between them rather than spinning: {:#?}",
        rig.journal.all()
    );
}

// ===========================================================================
// CLASS M — The one call whose whole purpose is destruction
// ===========================================================================

/// `remove` sends `DELETE /items/{id}` and nothing else. §5.5 makes the local
/// delete win, and it is right about the *file* it was told about; it says
/// nothing about the *version* the object holds. The two meet on `run_upload`'s
/// delete-during-upload path, which removes `uploaded.cloud_id` — an id this
/// sink wrote seconds earlier and whose tag it therefore knows. If another
/// device committed in between, an unconditional `DELETE` recycle-bins work that
/// was never on this machine at all.
///
/// The positive control already exists:
/// `positive_control_remove_deletes_once_and_an_already_gone_object_is_success`
/// removes an id this sink has no tag for and must still succeed. A precondition
/// the sink cannot supply is not a reason to strand the user's delete.
#[test]
fn remove_carries_the_tag_it_recorded_rather_than_deleting_a_version_it_never_saw() {
    let rig = Rig::new("remove_is_conditional_when_it_can_be");
    // The unconditional form, scripted to succeed.
    rig.script(
        del(item_url(MINE, "01DOOMED")).without("if-match"),
        vec![no_content()],
    );
    rig.script(
        del(item_url(MINE, "01DOOMED")).with("if-match"),
        vec![no_content()],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01DOOMED"), "ct:c:{G},9");
    let out = sink.remove(&cloud(MINE, "01DOOMED"));

    assert!(out.is_ok(), "the object was removed");
    let call = only_call(&rig.journal);
    assert_eq!(
        call.header("if-match"),
        Some("c:{G},9"),
        "the delete is conditional on the version this sink last wrote"
    );
}

/// The other half. A `412` on that delete is another device's newer version
/// saying so, and re-issuing without the precondition is the same instinct as
/// retrying a `412` on a write — except that a `DELETE` has no version history
/// behind it to recover from. Re-reading and deleting again *conditionally* is a
/// defensible answer and passes; dropping the guard is not and does not.
#[test]
fn a_412_on_a_conditional_remove_is_never_retried_unconditionally() {
    let rig = Rig::with_cap("remove_412_keeps_its_guard", 8);
    rig.script(
        del(item_url(MINE, "01DOOMED")).with("if-match"),
        vec![reply(412, graph_error("resourceModified"))],
    );
    // The escape, scripted to succeed.
    rig.script(
        del(item_url(MINE, "01DOOMED")).without("if-match"),
        vec![no_content()],
    );
    rig.script(
        get(item_url(MINE, "01DOOMED")),
        vec![ok(drive_item("01DOOMED", "report.docx", 12, "c:{G},12"))],
    );

    let mut sink = rig.sink();
    sink.record_tag(&cloud(MINE, "01DOOMED"), "ct:c:{G},9");
    let _ = sink.remove(&cloud(MINE, "01DOOMED"));

    let unconditional: Vec<Rec> = rig
        .journal
        .deletes()
        .into_iter()
        .filter(|r| r.header("if-match").is_none())
        .collect();
    assert!(
        unconditional.is_empty(),
        "a delete that lost its race went out again with no guard at all: \
         {unconditional:#?}"
    );
    assert!(
        rig.journal.calls().len() <= 4,
        "and it terminated; it made {} attempts",
        rig.journal.calls().len()
    );
}

// ===========================================================================
// CLASS N — The framework side of the same seam
//
// Everything above drives `GraphSink` and reads the wire. These two drive
// `run_upload` and read the *file*, because the two rules they check are ones no
// `Sink` can keep on its own: what the framework asks the sink to do about a
// rename, and what it records as sent afterwards. They live here because the
// contract they check is this file's subject seen from the other side — the
// double below is a `Sink`, and the only thing it adds is the one property the
// real service has and `Uploaded` does not carry: an object has a *name*.
// ===========================================================================

/// A `Sink` that models object naming exactly as Class A requires a real one to
/// behave: a create takes its name from the path, and an update addressed by id
/// writes content and leaves the name alone.
#[derive(Clone, Default)]
struct FakeCloud {
    /// `(cloud_id, name)`, in creation order.
    objects: Arc<Mutex<Vec<(String, String)>>>,
    calls: Arc<Mutex<Vec<(PathBuf, Option<String>)>>>,
    removed: Arc<Mutex<Vec<String>>>,
    /// Run as each call returns — the same "the world moved while the bytes
    /// were in flight" device `Wire` uses, one per call, in order.
    on_return: Arc<Mutex<Vec<Effect>>>,
}

impl FakeCloud {
    fn arrange(&self, f: Effect) {
        self.on_return.lock().unwrap().push(f);
    }

    fn name_of(&self, cloud_id: &str) -> Option<String> {
        self.objects
            .lock()
            .unwrap()
            .iter()
            .find(|(id, _)| id == cloud_id)
            .map(|(_, name)| name.clone())
    }
}

impl Sink for FakeCloud {
    fn upload(
        &mut self,
        path: &std::path::Path,
        existing: Option<Known<'_>>,
    ) -> io::Result<Uploaded> {
        let existing = existing.map(|k| k.cloud_id);
        self.calls
            .lock()
            .unwrap()
            .push((path.to_path_buf(), existing.map(str::to_string)));

        let cloud_id = match existing {
            // An update addresses the id (Class A). The service writes the
            // content; the object keeps the name it already had.
            Some(id) => id.to_string(),
            None => {
                let name = path
                    .file_name()
                    .expect("a create is addressed by path")
                    .to_string_lossy()
                    .into_owned();
                let id = {
                    let mut objects = self.objects.lock().unwrap();
                    let id = format!("b!mine|01OBJ{}", objects.len());
                    objects.push((id.clone(), name));
                    id
                };
                id
            }
        };

        let effect = {
            let mut queue = self.on_return.lock().unwrap();
            (!queue.is_empty()).then(|| queue.remove(0))
        };
        if let Some(f) = effect {
            f();
        }

        Ok(Uploaded {
            cloud_id,
            etag: Some("ct:c:{G},9".into()),
        })
    }

    fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
        self.removed.lock().unwrap().push(cloud_id.to_string());
        self.objects
            .lock()
            .unwrap()
            .retain(|(id, _)| id != cloud_id);
        Ok(())
    }
}

/// §5.4's guarantee is that no upload can succeed under a name the file does not
/// have when the bytes are sent, and the framework's own repair path is where it
/// is lost. `run_upload` answers a rename-mid-upload by calling
/// `sink.upload(&moved.path, at(&uploaded.cloud_id))`, and Class A requires
/// that an update address the id. Both rules kept literally leave the object
/// named whatever the atomic save's temp file was called — the bytes are right,
/// the name is `report.docx.tmp.194149`, and bug #52 is back, reached through
/// the code written to prevent it.
///
/// The sink cannot fix this on its own: `positive_control_an_ordinary_update_..`
/// pins an update at exactly one request, so `GraphSink` never learns the remote
/// name and has nothing to compare. The decision belongs to `run_upload`, which
/// is the only layer that knows the name changed.
#[test]
fn the_object_that_ends_up_holding_the_bytes_is_named_what_the_file_is_named() {
    use std::os::unix::fs::MetadataExt;

    let root = scratch("rename_mid_upload_names_the_object");
    let temp = root.join("report.docx.tmp.194149");
    let real = root.join("report.docx");
    std::fs::write(&temp, b"the document, saved atomically").expect("the temp file");

    let md = std::fs::metadata(&temp).expect("the temp file");
    let file = FileId {
        fsid: md.dev(),
        ino: md.ino(),
    };

    let mut store = Store::new();
    store.scan(&root).expect("a scan of the sync root");

    let service = FakeCloud::default();
    // The rename lands while the first upload is in flight. §5.4's normal case,
    // and what `run_upload`'s second `lookup` is there to notice.
    let (from, to) = (temp.clone(), real.clone());
    service.arrange(effect(move || {
        std::fs::rename(&from, &to).expect("the atomic save completes");
    }));

    let mut sink = service.clone();
    let outcome = run_upload(file, &mut store, &mut sink);

    let RunOutcome::Sent { cloud_id } = &outcome else {
        panic!("the resend must land the bytes somewhere: {outcome:?}");
    };
    assert_eq!(
        service.name_of(cloud_id).as_deref(),
        Some("report.docx"),
        "the object holding the user's document is named after the temp file the \
         save used, so every other device downloads `report.docx.tmp.194149` and \
         `report.docx` exists nowhere in the cloud. calls: {:#?}",
        service.calls.lock().unwrap()
    );
}

/// The main path stamps from `sent_state`, captured before the sink read a byte,
/// and its comment explains at length why anything else destroys an edit made
/// during the transfer. The rename path four lines above it does the opposite:
/// `std::fs::metadata(&moved.path)` *after* the resend returned. So an edit that
/// lands during the resend is stamped as sent — it is never re-queued, reclaim
/// reads it as `Clean` and is free to evict it, and the next remote change
/// overwrites it. `stamp::write_as` documents this exact hazard in its own
/// doc comment.
#[test]
fn the_stamp_written_after_a_rename_never_blesses_an_edit_that_was_not_sent() {
    use std::os::unix::fs::MetadataExt;

    let root = scratch("stamp_after_a_rename");
    let temp = root.join("notes.txt.tmp.5089");
    let real = root.join("notes.txt");
    std::fs::write(&temp, b"the note as it was sent").expect("the temp file");

    let md = std::fs::metadata(&temp).expect("the temp file");
    let file = FileId {
        fsid: md.dev(),
        ino: md.ino(),
    };

    let mut store = Store::new();
    store.scan(&root).expect("a scan of the sync root");

    let service = FakeCloud::default();
    let (from, to) = (temp.clone(), real.clone());
    service.arrange(effect(move || {
        std::fs::rename(&from, &to).expect("the atomic save completes");
    }));
    // The user saves again while the *resend* is in flight. A longer document,
    // so the stamp cannot compare equal by accident at any mtime granularity.
    let edited = real.clone();
    service.arrange(effect(move || {
        std::fs::write(
            &edited,
            b"the note, with a paragraph added while the resend was still in flight",
        )
        .expect("the user saved again");
    }));

    let mut sink = service.clone();
    let outcome = run_upload(file, &mut store, &mut sink);
    assert!(
        matches!(outcome, RunOutcome::Sent { .. }),
        "the resend path was taken: {outcome:?}"
    );

    assert_ne!(
        stamp::state(&real).expect("a stamp state"),
        stamp::State::Clean,
        "the file reads as already sent over a paragraph that never left the \
         machine: it is not re-queued, reclaim may evict it, and the next delta \
         pass replaces it with a placeholder for the version without it"
    );
}

/// The one this suite could not see, and the reason it could not.
///
/// `GraphSink::precondition` reads `self.known`, and `record_tag` is the only
/// thing that fills it. `record_tag` is called forty-three times in this file
/// and *nowhere else in either repository* — so every test above seeds by hand
/// a map that a running daemon never populates. On a live account `precondition`
/// therefore always answered `None`, `put_at_item` always returned
/// `no_precondition`, and no update to an object that already existed had ever
/// succeeded outside this file.
///
/// Measured 2026-08-13: six edited files unsent for hours, retried in a loop,
/// each one holding in its own `user.hydration.etag` the very tag the write
/// needed. The framework read it — `Store::lookup` fills `Entry::etag` — and
/// then dropped it at the `Sink` boundary, which carried the id and not the
/// version.
///
/// So this test calls no `record_tag`. It goes the way the daemon goes:
/// `run_upload` reads the file's extended attributes through `Store`, passes
/// them as `Known`, and the write is conditional on what was on disk all along.
/// The request is scripted `.with("if-match")`, so an unconditional write does
/// not merely assert wrongly — it finds no scripted reply at all.
#[test]
fn an_update_is_conditional_on_the_tag_recorded_on_the_file_with_no_help_from_the_sink() {
    use std::os::unix::fs::MetadataExt;

    let rig = Rig::new("durable_tag_reaches_the_wire");
    let path = rig.file("Work/report.docx", b"edited on this machine");
    store::set_xattr(&path, xattr::ID, cloud(MINE, "01REPORT").as_bytes())
        .expect("the cloud id the delta pass would have written");
    store::set_xattr(&path, xattr::ETAG, b"ct:c:{G},1")
        .expect("the tag of the version this edit is based on");

    rig.script(
        put(item_content(MINE, "01REPORT")).with("if-match"),
        vec![ok(drive_item("01REPORT", "report.docx", 22, "c:{G},2"))],
    );

    let md = std::fs::metadata(&path).expect("the fixture");
    let file = FileId {
        fsid: md.dev(),
        ino: md.ino(),
    };
    let mut store = Store::new();
    store.scan(&rig.root).expect("a scan of the sync root");

    // No `record_tag`. That is the whole point.
    let mut sink = rig.sink();
    let outcome = run_upload(file, &mut store, &mut sink);

    let call = only_call(&rig.journal);
    assert_eq!(
        call.header("if-match"),
        Some("c:{G},1"),
        "the update went out with no precondition, or with one that is not the \
         version the file says it is based on: {call:?}"
    );
    assert!(
        matches!(outcome, RunOutcome::Sent { .. }),
        "an edit to a file the cloud already holds was not sent: {outcome:?}"
    );
}

/// The other half of what was measured on 2026-08-13, and the harder one.
///
/// Git writes its index by creating a lock file and renaming it into place.
/// Most editors save the same way, and §5.4 is about exactly this shape. What
/// survives the rename is a *different inode*, and extended attributes do not
/// travel across one — so the file loses `user.hydration.id` and
/// `user.hydration.etag` at the instant of the save.
///
/// Read from the file alone, it is then indistinguishable from a document the
/// cloud has never heard of. The upload became a create, the service answered
/// `409 nameAlreadyExists`, the failure was re-queued, and it repeated for as
/// long as the daemon ran: six files, hours, edits that existed on one machine.
///
/// The lineage record is what bridges it. Nothing here calls `record_tag` and
/// nothing re-attaches the attributes by hand — the scan wrote down what the
/// file said while it still said it, and the save that destroyed the attributes
/// did not destroy that.
///
/// Scripted `.with("if-match")` for the same reason as the test above: an
/// unconditional write, or a create, finds no reply at all rather than failing
/// an assertion about one.
#[test]
fn a_file_saved_atomically_is_still_an_update_of_the_object_it_came_from() {
    use std::os::unix::fs::MetadataExt;

    let rig = Rig::new("atomic_save_keeps_its_lineage");
    let path = rig.file("Work/report.docx", b"the version that came down");
    store::set_xattr(&path, xattr::ID, cloud(MINE, "01REPORT").as_bytes())
        .expect("the cloud id the delta pass wrote");
    store::set_xattr(&path, xattr::ETAG, b"ct:c:{G},1").expect("the tag it was placed at");

    // The scan that runs before every upload batch, while the file still has
    // something to say for itself.
    let mut store = Store::new().remembering();
    store
        .scan(&rig.root)
        .expect("the scan that records the lineage");

    // The atomic save. A new inode, no extended attributes, renamed over the
    // name the old one had — which is all git does, and all most editors do.
    let tmp = rig.root.join("Work/.report.docx.swp");
    std::fs::write(&tmp, b"the paragraph the user just wrote").expect("the temp file");
    std::fs::rename(&tmp, &path).expect("the atomic save");
    let md = std::fs::metadata(&path).expect("the saved file");
    let file = FileId {
        fsid: md.dev(),
        ino: md.ino(),
    };
    {
        // Asserted through the same call the daemon makes, on a store that
        // remembers nothing: this is the file as it now is. Without it the test
        // would pass on a filesystem where the attributes somehow survived, which
        // is to say it would pass without testing anything.
        let mut bare = Store::new();
        bare.scan(&rig.root).expect("a scan with no memory");
        assert!(
            bare.lookup(&file).and_then(|e| e.cloud_id).is_none(),
            "the fixture did not reproduce the failure: the save kept the file's \
             identity, so nothing here needed recovering"
        );
    }
    store.scan(&rig.root).expect("the scan after the save");

    rig.script(
        put(item_content(MINE, "01REPORT")).with("if-match"),
        vec![ok(drive_item("01REPORT", "report.docx", 33, "c:{G},2"))],
    );

    let mut sink = rig.sink();
    let outcome = run_upload(file, &mut store, &mut sink);

    let call = only_call(&rig.journal);
    assert_eq!(
        call.path(),
        item_content(MINE, "01REPORT"),
        "the edit was sent as a create, which the service answers 409 \
         nameAlreadyExists for as long as the daemon runs: {call:?}"
    );
    assert_eq!(
        call.header("if-match"),
        Some("c:{G},1"),
        "the update carried no precondition, or not the version the file was \
         placed at: {call:?}"
    );
    assert!(
        matches!(outcome, RunOutcome::Sent { .. }),
        "an edit saved the way every editor saves never left the machine: {outcome:?}"
    );
}

/// And the record does not outlive the truth it was written from.
///
/// A path-keyed record is only safe while an object is at one path. If the cloud
/// renames `01REPORT` away and something unrelated is created at the old name,
/// a surviving record would send the new file's contents into the renamed
/// object — past the `if-match`, which guards the version and not the identity.
///
/// `Lineage::absorb` evicts on the object rather than on the path, so the scan
/// that finds `01REPORT` living somewhere else drops the stale claim in the same
/// pass. This is the assertion that the eviction reaches all the way through
/// `Store::lookup`.
#[test]
fn a_new_file_does_not_inherit_the_identity_of_an_object_renamed_away_from_its_path() {
    use std::os::unix::fs::MetadataExt;

    let rig = Rig::new("atomic_save_does_not_inherit");
    let old = rig.file("Work/report.docx", b"the version that came down");
    store::set_xattr(&old, xattr::ID, cloud(MINE, "01REPORT").as_bytes()).expect("id");
    store::set_xattr(&old, xattr::ETAG, b"ct:c:{G},1").expect("tag");

    let mut store = Store::new().remembering();
    store
        .scan(&rig.root)
        .expect("the scan that records the lineage");

    // The cloud renamed it; the delta pass renamed the file to match.
    let moved = rig.root.join("Work/quarterly.docx");
    std::fs::rename(&old, &moved).expect("the delta pass rename");
    // And something entirely unrelated is created at the name it used to have.
    std::fs::write(&old, b"a different document that happens to share a name").expect("new file");

    let md = std::fs::metadata(&old).expect("the new file");
    let file = FileId {
        fsid: md.dev(),
        ino: md.ino(),
    };
    store.scan(&rig.root).expect("the scan after the rename");

    let entry = store.lookup(&file).expect("the new file is indexed");
    assert_eq!(
        entry.cloud_id, None,
        "a new local file inherited the identity of an object that had been \
         renamed away from its path; its contents would have been written into \
         Work/quarterly.docx"
    );
}

/// The five that were stuck, and why they were.
///
/// A file whose extended attributes were destroyed by an atomic save before
/// anything recorded them has no id, so its upload is a create, and the create
/// collides with the object already at that name. Until now the answer was to
/// fail, and to keep failing: measured on a live account on 2026-08-13, five
/// files retried in a loop for hours, three of them git pack files whose names
/// are content-addressed and which therefore could not possibly have differed
/// from what was already there.
///
/// Stopping was right for the reason `put_at_path` gives — adopting a
/// stranger's object id would let reclaim evict the local file, the next read
/// fetch their document, and a local delete remove their object. Every one of
/// those rests on it being a *stranger's*. When the bytes already at the name
/// are the bytes being sent, it is this document, and taking its id is not a
/// write at all.
#[test]
fn a_create_that_collides_with_its_own_content_adopts_it_instead_of_failing() {
    let rig = Rig::new("collide_same_content");
    let body = b"the pack file, which is named after its own contents";
    let path = rig.file("Work/pack.pack", body);

    rig.script(
        put(path_content(MINE, "Work/pack.pack")),
        vec![reply(409, graph_error("nameAlreadyExists"))],
    );
    rig.script(
        get(path_meta(MINE, "Work/pack.pack")),
        vec![ok(hashed_item("01PACK", "pack.pack", body, "c:{G},1"))],
    );

    let mut sink = rig.sink();
    let out = sink.upload(&path, None).expect(
        "a create that collided with a byte-identical object left the file stranded, which \
         is the state five files were measured in",
    );

    assert_eq!(
        out.cloud_id,
        cloud(MINE, "01PACK"),
        "the identity recovered is not the object that holds the bytes"
    );
    let calls = rig.journal.calls().len();
    assert_eq!(
        calls, 2,
        "expected the create and one metadata read, got {calls} requests — anything more \
         means a second write was attempted"
    );
}

/// And when it is genuinely a different document, nothing is written.
#[test]
fn a_create_that_collides_with_different_content_is_still_refused() {
    let rig = Rig::new("collide_other_content");
    let path = rig.file("Work/notes.txt", b"what this machine has");

    rig.script(
        put(path_content(MINE, "Work/notes.txt")),
        vec![reply(409, graph_error("nameAlreadyExists"))],
    );
    rig.script(
        get(path_meta(MINE, "Work/notes.txt")),
        vec![ok(hashed_item(
            "01NOTES",
            "notes.txt",
            b"what somebody else has",
            "c:{G},1",
        ))],
    );

    let mut sink = rig.sink();
    let err = sink
        .upload(&path, None)
        .expect_err("a stranger's document was overwritten, or its id adopted");
    let said = err.to_string();
    assert!(
        said.contains("overwriting that one blind"),
        "the refusal did not say why it refused: {said}"
    );
}

/// A 409 that is not about the name is not sent looking for content.
///
/// Graph answers 409 for quota and for locking too. Treating those as a name
/// collision would spend a metadata read answering a question nobody asked, and
/// would report the wrong reason for the failure.
#[test]
fn a_collision_on_something_other_than_the_name_is_not_reconciled() {
    let rig = Rig::new("collide_not_name");
    let path = rig.file("Work/notes.txt", b"x");
    rig.script(
        put(path_content(MINE, "Work/notes.txt")),
        vec![reply(409, graph_error("quotaLimitReached"))],
    );

    let mut sink = rig.sink();
    let err = sink
        .upload(&path, None)
        .expect_err("a quota refusal was accepted");
    assert!(
        err.to_string().contains("quotaLimitReached"),
        "the quota refusal was reported as something else: {err}"
    );
    assert_eq!(
        rig.journal.calls().len(),
        1,
        "a quota refusal sent the sink looking for content that was never in question"
    );
}

/// The hazard the content check opens, and the name check closes.
///
/// Graph resolves a path case-insensitively, so a create at `report.txt` collides
/// with an object named `Report.txt`. If the two hold the same bytes — an
/// ordinary thing for a copy — then reconciling on content *alone* would give
/// two distinct local files one object id. Both would read Clean, and deleting
/// either would remove the object the other depends on.
///
/// `two_local_names_differing_only_in_case_stay_two_objects` caught this when the
/// content check was first written, with contents that differed. This is the same
/// trap with contents that do not, which is the version the size-and-hash test
/// cannot see.
#[test]
fn a_name_that_matches_only_by_case_is_not_the_same_object_however_alike() {
    let rig = Rig::new("case_collision_same_bytes");
    let body = b"byte for byte the same";
    let lower = rig.file("report.txt", body);

    rig.script(
        put(path_content(MINE, "report.txt")),
        vec![reply(409, graph_error("nameAlreadyExists"))],
    );
    // What Graph answers for `root:/report.txt` on a drive holding `Report.txt`:
    // the other object, with the other name, and identical content.
    rig.script(
        get(path_meta(MINE, "report.txt")),
        vec![ok(hashed_item("01UPPER", "Report.txt", body, "c:{G},1"))],
    );

    let mut sink = rig.sink();
    let out = sink.upload(&lower, None);

    assert!(
        out.is_err(),
        "a file adopted the id of an object with a different name because their \
         contents happened to match; deleting either would now remove the other"
    );
    let calls = rig.journal.calls();
    assert!(
        !calls
            .iter()
            .any(|c| c.method == Method::Put && c.path() == item_content(MINE, "01UPPER")),
        "the other object was written over: {calls:#?}"
    );
}

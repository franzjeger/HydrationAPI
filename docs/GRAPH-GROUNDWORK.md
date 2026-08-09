# Groundwork: a Microsoft Graph provider

Design only. No Graph code exists yet, and this document is what it will be
written from — the test list below is meant to be written *first*, and to fail
against an empty implementation.

It exists because the three modules before it each shipped with blocking defects
their own tests could not see: a scale test that fed parent-first input to guard
a path documented as not-parent-first, a cycle test that asserted the symptom as
the contract, a `nodump` test that asserted over the whole line. Writing the
attacks before the code is the correction.

## What it already found, before any code was written

Two real defects in `namespace.rs`, both shipped, both fixed in the same commit
as this document:

- **A package's contents were refused**, and the refusal could never be cleared —
  `problems` is emptied only by a successful upsert or a delete of that id, and
  for a notebook's internals neither ever comes. One OneNote notebook on the
  drive would have blocked a provider's cursor permanently.
- **A refused folder left its contents waiting forever.** They were reported as
  *pending*, which says "not yet" about a parent that will never exist — so a
  caller watching the pending set to drain would have waited indefinitely.

And roughly ten proposed tests were struck before being written, for asserting
things that cannot fail: a bound serde already guarantees, determinism that a
`BTreeSet` already provides, a URL asserted to contain the constant it was built
from. Four more were fed parent-first fixtures to guard order-sensitive
behaviour — the same construction that hid the last three bugs.

The critique sections at the end are kept verbatim, including everything it says
about this document's own weaknesses. They are the most useful part.

---

# Groundwork: Microsoft Graph `Discover` — mapping layer design

**Status:** design only. No code exists. The test list in §3 is written to fail against an empty implementation.
**Proposed crate:** `crates/hydration-graph` (new workspace member).
**Dependencies:** `hydration-client` (for `delta::{Change, Cursor, Discover}`, `namespace::{Namespace, Item, Kind, Problem}`), `hydration-protocol` (for `MAX_OBJECT`, `names::is_internal`), `serde`, `serde_json`. **No** `reqwest`/`tokio`/`std::fs` outside the `http` feature.

```
src/wire.rs      serde types. The only place raw JSON exists.
src/ids.rs       DriveId, ItemId, ObjectKey, ParentKey, CloudId, Name, ContentSize, ContentTag, MetaTag
src/shape.rs     Shape, the one total match over facets
src/map.rs       map_item / map_page — pure, no I/O, no clock
src/index.rs     TreeIndex — derived from Namespace::snapshot(); shape/collision/depth memory
src/round.rs     Round driver: paging, fixpoint, escalations, blast radius, stall detection
src/state.rs     PersistedState, StateStore trait (tree and token saved separately)
src/source.rs    PageSource trait + RawPage + ScriptedPages test double
src/http.rs      #[cfg(feature = "http")] the ONLY networking code
src/discover.rs  impl Discover for GraphDiscover<P: PageSource, S: StateStore>
```

---

## 1. The type design

### 1.1 Identity

```rust
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct DriveId(String);
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ItemId(String);          // NOT Display, NOT Deref, no Into<String>, no as_str()
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ObjectKey { drive: DriveId, item: ItemId }
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CloudId(String);

pub const MAX_ID_BYTES: usize = 256;
pub const MAX_CLOUD_ID_BYTES: usize = 512;

impl ItemId  { pub fn parse(raw: &str) -> Result<Self, Unmappable>; }   // rejects "", NUL, >MAX_ID_BYTES
impl DriveId { pub fn parse(raw: &str) -> Result<Self, Unmappable>; }   // same
impl ObjectKey {
    /// The ONLY constructor of a CloudId in the crate.
    pub fn to_cloud_id(&self) -> CloudId;                               // "{drive}|{item}", verbatim, no case folding
}
impl CloudId { pub fn into_inner(self) -> String; }                     // consumed once, into Change::Upserted
```

`ItemId` has no rendering at all. There is no function anywhere that turns an `ItemId` into a `String` a `Change` will accept. A `cloud_id` composed from a download URL or a cTag is not merely discouraged — there is no expression that builds one.

### 1.2 Scope and the root permit

```rust
pub struct RootPermit(());                                   // private field; no public constructor

pub struct DriveScope { drive: DriveId, anchor: Option<Anchor> }
pub struct Anchor { placeholder: ObjectKey, remote_root: ItemId }

impl DriveScope {
    pub fn primary(drive: DriveId) -> Self;
    pub fn mounted(drive: DriveId, anchor: Anchor) -> Self;
    pub fn drive(&self) -> &DriveId;
    /// `Some` only for the primary drive.
    pub fn root_permit(&self) -> Option<RootPermit>;
}
```

`Mapped::Root { permit: RootPermit, .. }` cannot be constructed for a mounted scope: the permit is unobtainable.

### 1.3 Wire types — the outer/inner split is structural

```rust
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DriveItem {
    pub id: Option<String>,
    pub name: Option<String>,
    pub parent_reference: Option<ItemReference>,
    pub deleted: Option<Deleted>,                 // OUTER ONLY
    pub root: Option<RootFacet>,                  // OUTER ONLY
    pub remote_item: Option<Box<ItemBody>>,
    #[serde(flatten)] body: ItemBody,             // private
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemBody {
    pub folder: Option<Folder>,
    pub file: Option<FileFacet>,
    pub package: Option<Package>,
    pub size: Option<RawSize>,
    pub c_tag: Option<String>,
    pub e_tag: Option<String>,
    pub malware: Option<serde_json::Value>,
    pub pending_operations: Option<serde_json::Value>,
    pub pending_content_update: Option<serde_json::Value>,
    pub parent_reference: Option<ItemReference>,  // inner: NEVER read by ParentKey
}

#[derive(Deserialize)] pub struct Deleted {}      // `state` is deliberately absent from the type
#[derive(Deserialize)] pub struct RootFacet {}
#[derive(Deserialize)] #[serde(rename_all = "camelCase")]
pub struct ItemReference { pub drive_id: Option<String>, pub id: Option<String>,
                           pub path: Option<PathHint> }

/// `parentReference.path`. Opaque on purpose: no split, no decode, no components.
#[derive(Deserialize)] pub struct PathHint(String);
impl std::fmt::Debug for PathHint { /* truncated, log-only */ }

#[derive(Deserialize)] #[serde(untagged)]
pub enum RawSize { Bytes(u64), NotAnInteger(serde_json::Value) }

impl DriveItem {
    /// Shape, size and tags come from here and nowhere else.
    fn shape_body(&self) -> &ItemBody { self.remote_item.as_deref().unwrap_or(&self.body) }
}
```

Three things become structural rather than disciplinary:

* `deleted` and `root` are not fields of `ItemBody`, so they can never be read from inside `remoteItem`.
* `folder`/`file`/`package`/`size`/`cTag` are not fields of `DriveItem`, so they can only be reached via `shape_body()`, which already picks the inner body when `remoteItem` is present.
* `PathHint` has no accessor returning `&str` or an iterator of segments, so a name can never be derived from it.

`Option<Folder>` via serde maps JSON `null` → `None`. The `Value::get("folder").is_some()` trap is not expressible because no `serde_json::Value` reaches the mapper.

### 1.4 Envelope

```rust
pub struct NextLink(String);
pub struct DeltaLink(String);                     // stored verbatim, never re-encoded

pub enum PageEnd { More(NextLink), Done(DeltaLink) }
pub struct DeltaPage { pub value: Vec<DriveItem>, pub end: PageEnd }

pub enum EnvelopeError {
    HttpStatus { status: u16, code: Option<String> },
    GraphError { code: String, message: String },  // an `error` key, even on HTTP 200
    ValueMissing, ValueNotArray, NoLink, BothLinks, EmptyLink, Malformed(String),
}

impl DeltaPage {
    pub fn parse(status: u16, body: &[u8]) -> Result<Self, EnvelopeError>;
}
```

`value` is **not** `#[serde(default)]`. Exactly-one-of is `PageEnd`, so "no link" and "both links" are not states the rest of the code can see.

### 1.5 Shape — one total match

```rust
pub enum Shape {
    Deleted,
    Root,
    Blocked,                       // malware
    Unsettled,                     // pendingOperations / pendingContentUpdate
    Package,
    Folder,
    File { size: ContentSize, tag: Option<ContentTag> },
    Ambiguous,                     // file AND folder at the level examined
    NoShape,                       // neither, and not deleted
}

pub fn shape_of(item: &DriveItem, tags: TagSource) -> Shape {
    let b = item.shape_body();
    match (item.deleted.is_some(), item.root.is_some(),
           b.malware.is_some(),
           b.pending_operations.is_some() || b.pending_content_update.is_some(),
           b.package.is_some(),
           b.folder.is_some(), b.file.is_some())
    {
        (true,  _, _, _, _, _, _) => Shape::Deleted,
        (_, true,  _, _, _, _, _) => Shape::Root,
        (_, _, true,  _, _, _, _) => Shape::Blocked,
        (_, _, _, true,  _, _, _) => Shape::Unsettled,
        (_, _, _, _, true,  _, _) => Shape::Package,
        (_, _, _, _, _, true, true) => Shape::Ambiguous,
        (_, _, _, _, _, true, false) => Shape::Folder,
        (_, _, _, _, _, false, true) => file_shape(item, tags),   // may itself refuse
        (_, _, _, _, _, false, false) => Shape::NoShape,
    }
}

impl TryFrom<Shape> for Kind {                      // no `_ =>` arm, no default
    type Error = Unmappable;
    // Package -> Kind::Opaque, Folder -> Kind::Folder, File -> Kind::File
    // everything else -> Err
}
```

There is exactly one match over facets in the crate, its arms are exhaustive over a 7-tuple of bools, and the order is fixed inside it. `deleted` wins over everything. `package` wins over `folder`. Neither-facet is a named arm, never an `else`.

### 1.6 Size, name, tags

```rust
pub struct ContentSize(u64);
impl ContentSize {
    /// Only callable from the `Shape::File` arm.
    fn of_file(b: &ItemBody) -> Result<Self, Unmappable>;
    // requires RawSize::Bytes(n); RawSize::NotAnInteger -> BadSize; None -> NoSize
    // n > hydration_protocol::MAX_OBJECT -> TooLarge
    pub fn get(&self) -> u64;
}

pub struct Name(String);
impl Name {
    /// The only constructor. Takes the item, not a &str, so no other string can become a Name.
    pub fn of(item: &DriveItem) -> Result<Self, Unmappable>;
    pub fn into_inner(self) -> String;
}
```

`Name::of` reads `item.name` verbatim — no percent-decoding, no Unicode normalisation, no case folding, no trimming, no truncation — and rejects, with a reason: empty; contains `/`, `\`, or NUL; `.` or `..`; any C0/C1 control; U+202A–U+202E or U+2066–U+2069; `hydration_protocol::names::is_internal`. Everything else is accepted exactly as sent, including `report .pdf`, `COM1`, `~$doc`, `...`.

```rust
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TagSource { CTag, QuickXor, Sha256, Sha1 }

pub struct ContentTag(String);      // from the pinned TagSource ONLY
pub struct MetaTag(String);         // from eTag; Debug only, no into_inner()

impl ContentTag {
    fn of_file(b: &ItemBody, src: TagSource) -> Result<Self, Unmappable>;  // absent -> NoContentTag
    pub fn into_inner(self) -> String;   // prefixed: "ct:", "qx:", "s256:", "s1:"
}
```

`MetaTag` has no `into_inner`, no `Display`, no `From<MetaTag> for ContentTag`. `Kind::File { ctag }` takes `Option<String>`; the only value that reaches it is `ContentTag::into_inner()`.

**`TagSource` is pinned per drive and persisted.** It is chosen on the first enumeration by probing the first 64 file-shaped items; it never changes silently. If the pinned source is missing on an item, that item is refused (`NoContentTag`) rather than falling back — a fallback flips every tag string at once, and `is_current` byte-compares, which dehydrates the whole tree. If it is missing on >10% of a round's files, the round raises `Escalation::TagSourceUnavailable` and does not persist a token. The prefixes exist so a source migration is a visible refresh rather than a silent false-current.

### 1.7 Mapping result and refusals

```rust
pub struct Mapping {
    pub item: Option<Item>,          // at most one, and there is no accumulator
    pub mount: Option<MountPoint>,   // a foreign drive to fan out to
    pub note: Option<Note>,
}

pub struct MountPoint { pub placeholder: ObjectKey, pub remote: ObjectKey }

pub struct Refusal { pub key: Option<ObjectKey>, pub why: Unmappable, pub echo: RawEcho }

pub enum Unmappable {
    NoId, IdTooLong, NoParent, SelfParent,
    ForeignParent { parent_drive: DriveId },
    BadName(&'static str),
    NoShape, Ambiguous, Blocked, Unsettled,
    NoSize, BadSize, TooLarge { size: u64 },
    NoContentTag { source: TagSource },
    ShapeFlip { from: KindTag, to: KindTag, children: usize },
    PathCollision { holder: ItemId },
    TooDeep { depth: usize },
    RootDeleted, RootShapeChanged, SecondRoot { seen: ItemId },
    RootFromMountedScope,
}

pub struct MappedPage {
    pub items: Vec<Item>,            // feed order, NOT deduped here, NOT sorted
    pub mounts: Vec<MountPoint>,
    pub refusals: Vec<Refusal>,      // no constructor omits this field
    pub notes: Vec<Note>,
}

pub fn map_item(scope: &DriveScope, ix: &TreeIndex, tags: TagSource, item: &DriveItem)
    -> Result<Mapping, Unmappable>;

pub fn map_page(scope: &DriveScope, ix: &mut TreeIndex, tags: TagSource, page: &DeltaPage)
    -> MappedPage;
```

`Result`, never `Option`, so `filter_map` cannot discard a refusal. `MappedPage` has no `From<Vec<Item>>` and its fields are all public and required, so a caller cannot construct one without carrying the refusals.

### 1.8 Parent

```rust
pub struct ParentKey(ObjectKey);
impl ParentKey {
    /// Reads the OUTER parentReference only. Takes `self_id` so self-parent is caught here.
    fn from_outer(scope: &DriveScope, self_id: &ItemId, pr: Option<&ItemReference>)
        -> Result<Self, Unmappable>;
}
```

Rules, all of them refusals rather than defaults: `pr` absent → `NoParent`; `pr.id` absent or empty → `NoParent`; `pr.drive_id` present and ≠ `scope.drive()` → `ForeignParent`; `pr.id == self_id` → `SelfParent`. There is no `unwrap_or_default()` on a parent anywhere; a defaulted parent id is not expressible.

### 1.9 TreeIndex — derived, not separately persisted

```rust
pub struct TreeIndex { /* per ItemId: parent, name_fold, kind_tag, depth */ }
impl TreeIndex {
    pub fn from_snapshot(items: &[Item]) -> Self;     // Namespace::snapshot() is the single source
    pub fn shape_of(&self, id: &ItemId) -> Option<KindTag>;
    pub fn child_count(&self, id: &ItemId) -> usize;
    pub fn depth_of(&self, id: &ItemId) -> Option<usize>;
    pub fn occupant(&self, parent: &ParentKey, fold: &NameFold) -> Option<&ItemId>;
    pub fn observe(&mut self, item: &Item);           // maintained during a round
}
pub const MAX_MAPPED_DEPTH: usize = 128;              // well under namespace::MAX_DEPTH = 512
```

Rebuilt from the snapshot at load, so it cannot drift from the tree it describes.

### 1.10 Round, report, escalation

```rust
pub struct CompletedRound { pub changes: Vec<Change>, pub token: DeltaLink, pub report: Report }

pub enum Escalation {
    TokenExpired,                               // HTTP 410 / resyncRequired
    RootDeleted,
    SecondRoot { seen: ItemId, now: ItemId },
    ShapeFlipWithChildren { key: ObjectKey, children: usize },
    TagSourceUnavailable { chosen: TagSource, missing: usize, of: usize },
    BlastRadius { removals: usize, known: usize },
    StalledRetryable { passes: u32, failed: Vec<String> },
    Envelope(EnvelopeError),
}

pub struct Report {
    pub mapped: usize, pub refusals: Vec<Refusal>, pub deferred: Vec<(ObjectKey, Unmappable)>,
    pub unresolved_problems: BTreeMap<String, Problem>, pub pending_after_round: Vec<String>,
    pub mounts: Vec<MountPoint>, pub quarantined: usize,
}

impl Round {
    pub fn finish(self) -> Result<CompletedRound, (Escalation, Report)>;
}
```

A `DeltaLink` is reachable only through `CompletedRound`. "Here is a cursor" cannot be said without "the round reached a deltaLink and raised no escalation".

### 1.11 Claim-by-claim

| # | Claim to eliminate | Enforcement | Where |
|---|---|---|---|
| 1 | No `folder` ⇒ file | **Type** | `shape_of` 7-tuple match has a named `NoShape` arm; `TryFrom<Shape> for Kind` has no `_ =>`; facets read via `shape_body()` |
| 2 | An id's shape is stable | **Runtime** — untypeable, `Namespace` supports reshape deliberately | `map_item` consults `TreeIndex::shape_of` + `child_count`; Folder→File/Opaque with children ⇒ `ShapeFlip` refusal + `Escalation::ShapeFlipWithChildren`. Never forwarded, so `Namespace::delete`'s descendant purge is never triggered by a mis-read |
| 3 | `package` co-occurs with `folder`, folder-first is harmless | **Type** | package arm precedes folder arm in the single match |
| 4 | Tombstone is `state == "deleted"` | **Type** | `Deleted` is a fieldless struct; `state` is not in the wire type, so it cannot be read |
| 5 | Facet check order is irrelevant | **Type** | one match, no `if`-chains, no fallthrough |
| 6 | Exactly one `root` in the feed | **Type** | `RootPermit` obtainable only from `DriveScope::root_permit()`, `None` for a mounted scope |
| 7 | Root is only ever emitted as `Item::Root` | **Type** | `map_item` returns one `Mapping`; no `&mut Vec<Item>` accumulator exists |
| 8 | Missing `root` facet is survivable | **Type** | `ParentKey::from_outer` is fallible; a rootless root becomes `NoParent`, never parent `""` |
| 9 | `parentReference.id` present on every non-root | **Type** | same constructor; no `unwrap_or_default` on a parent in the crate |
| 10 | `id` present and non-empty | **Type** | `ItemId::parse` rejects empty/NUL/oversize; every variant takes `ItemId` |
| 11 | An item id identifies an object | **Type** | `ObjectKey`; `ItemId` is not `Display` and has no `to_cloud_id` |
| 12 | `parentReference.driveId` is my drive | **Runtime** (equality is a value comparison) — but *routing* is typed: only the outer reference is reachable from `ParentKey::from_outer`; inner `parent_reference` is used only by `MountPoint` | `ForeignParent` |
| 13 | One item ⇒ ≤1 `Item`, pure function of the item | **Type** | signature `fn(&DriveScope, &TreeIndex, TagSource, &DriveItem) -> Result<Mapping, _>`; anchor rewriting is a scope case, not a field read |
| 14 | `size` present and is the byte length | **Type** | `ContentSize::of_file`, `RawSize::Bytes` only; `Kind::File` unconstructible otherwise; absent ⇒ `NoSize`, never 0 |
| 15 | A reported size is an acceptable size | **Runtime**, inside `ContentSize::of_file` | `TooLarge { size }` — refused loudly instead of the framework's silent terminal `failed` |
| 16 | cTag/None/eTag are interchangeable | **Type** | `ContentTag` from the pinned `TagSource`; `MetaTag` has no conversion, no `into_inner` |
| 17 | An unmappable item can be skipped | **Type** | `Result` not `Option`; `MappedPage.refusals` is non-optional; round refuses to persist a token while refusals are unquarantined |
| 18 | A refused item is genuinely invalid | **Runtime** — arrival order is not a type | `Round::fixpoint()` re-feeds every id in `problems()` from the round buffer until the set stops shrinking |
| 19 | An item is applied or reported (`waiting` is a silent third state) | **Runtime**, plus one type win | `SelfParent` is refused in `ParentKey::from_outer`, closing the verified hole where `waiting[X]` holds X forever with `problems()` empty. `pending_ids()` is drained at round end into `Report.pending_after_round`; a set that survives a complete enumeration blocks the token |
| 20 | Feed order is an implementation detail | **Runtime + structural** | `MappedPage.items: Vec<Item>`, `RoundBuffer` exposes only `push`; no `HashMap<ItemId, Item>` type exists between parser and `Namespace`; dedup is last-wins via a `Vec` + last-index filter, the shape `namespace::finalise` uses |
| 21 | `name` is a legal path component | **Runtime** (`Name::of`), **type**-restricted source (`Name::of` takes `&DriveItem`; `PathHint` yields no segments) | |
| 22 | Two items never map to one path | **Runtime** (`TreeIndex::occupant`, case-folded per parent) — the type half is *no transforms*, so the mapper never manufactures a collision | `PathCollision { holder }`; the loser is refused, so the rename-into-occupied stall is never reached |
| 23 | Depth > `MAX_DEPTH` is unreachable | **Runtime** | `TreeIndex::depth_of` ≥ `MAX_MAPPED_DEPTH` ⇒ `TooDeep`. Necessary because `Namespace::upsert` emits nothing when `path_of` returns `None` and records no `Problem` |
| 24 | file-or-folder, so `else` may mean file | **Type** | `Ambiguous` and `NoShape` are named arms |
| 25 | `Change::Upserted.size` is real | **Type** | as #14; `Unsettled`/`Blocked` shapes never produce a `Kind::File` |
| 26 | `cloud_id` is non-empty and distinct | **Type** | `CloudId` only from `ObjectKey::to_cloud_id`; length bounded at construction |
| 27 | `safe_join` resolves inside the sync root | **DOCUMENTED ONLY — the mapper cannot enforce it** | See §1.12 |
| 28 | Folder↔package reshape is a re-classification | **Runtime**, and it is a *refusal*, not a passthrough | `namespace::upsert` treats it as `reshaped` and calls `delete`, emitting `Removed` for every descendant and purging them from its own tree. The mapper refuses the transition (`ShapeFlip`) and escalates for a from-scratch re-enumeration rather than letting it reach `Namespace`. Fixing this properly means splitting container-ness from opacity in `namespace::Kind` — a framework change, filed, not done here |
| 29 | An item is not its own ancestor | **Type-adjacent runtime** in `ParentKey::from_outer` (`SelfParent`), because `would_cycle` is never consulted for an unknown id | |

### 1.12 The one claim this design cannot enforce

**Claim 27 — `safe_join` (delta.rs:409-441) is purely lexical and follows symlinks.** With `<root>/out` a symlink, `safe_join(root, "out/pwned.txt")` returns `Some` and `place()` writes outside the sync root, reporting `created: 1`. `place()` overwrites via `rename`, so a cloud-controlled path can atomically replace `~/.bashrc` or `~/.config/systemd/user/*.service`.

This is **documented, not enforced, and the justification is that the mapping layer physically cannot fix it**: "no component of this path is a symlink" is a property of the filesystem at an instant, and this crate has no filesystem access by construction (that is what makes it testable without credentials). The fix belongs in `delta.rs`/`place.rs` — `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`, or `safe_join` returning a verified directory fd plus a basename, the way `reclaim.rs:114` already does for eviction.

What this layer *does* do about it: refuses names containing `\`, `/`, NUL, `.`, `..` and controls, so the mapper is not the source of a hostile path. That is mitigation, not enforcement. **A Graph provider must not ship on top of the current `safe_join`.** This is a blocking dependency, recorded here so it is not discovered later.

Two smaller documented-only items, stated for the same reason:

* **Unicode normalisation in the collision fold.** `NameFold` uses simple lowercasing; NFC vs NFD names will not fold together without a normalisation dependency. Residual risk: a missed collision reaches the framework's rename-into-occupied path. Mitigated by `StallDetector` (§1.13), not eliminated.
* **`$select` completeness.** `REQUIRED_SELECT` is a `pub const` in this crate and a test asserts the built URL contains every entry, but the request is constructed in the `http` module — the coupling is a test, not a type.

### 1.13 Guards that exist because the framework has no escape hatch

```rust
pub struct StallDetector { passes: u32, last_failed: Vec<String> }
```

`Applied::retryable` is a pass-wide bool with no attempt counter, no backoff and no escape anywhere in the tree; a two-object path swap pins the cursor forever (measured: 25 consecutive passes, never resolving). `GraphDiscover` observes the `Applied` it caused, and after `STALL_LIMIT` (3) consecutive retryable passes with a non-shrinking `failed` set raises `Escalation::StalledRetryable` and forces a from-scratch enumeration.

```rust
pub fn guard_blast_radius(removals: usize, known: usize) -> Result<(), Escalation>;
// refuses when removals > max(64, known / 10)
pub fn deletions_since(before: &[Item], after: &Namespace) -> Result<Vec<Change>, Escalation>;
// the expired-token diff (PROVIDER.md:200-203), with the same guard;
// a diff concluding "everything was deleted" is a bug, not an instruction
```

---

## 2. The seam

**HTTP ends at `PageSource`. Everything above it is pure and takes no credentials, no clock, no socket and no filesystem.**

```rust
pub struct RawPage {
    pub status: u16,
    pub retry_after: Option<std::time::Duration>,
    pub body: Vec<u8>,
}

pub trait PageSource: Send {
    fn first(&mut self, scope: &DriveScope) -> io::Result<RawPage>;     // tokenless full enumeration
    fn next(&mut self, link: &NextLink) -> io::Result<RawPage>;
    fn resume(&mut self, link: &DeltaLink) -> io::Result<RawPage>;
    fn latest(&mut self, scope: &DriveScope) -> io::Result<RawPage>;    // ?token=latest
}

pub trait StateStore: Send {
    fn load(&mut self) -> io::Result<Option<PersistedState>>;
    fn save_tree(&mut self, tree: &TreeBlob) -> io::Result<()>;
    fn save_token(&mut self, tokens: &TokenBlob) -> io::Result<()>;
}

pub struct GraphDiscover<P: PageSource, S: StateStore> { /* … */ }
impl<P: PageSource, S: StateStore> Discover for GraphDiscover<P, S> { /* … */ }
```

* `RawPage` is bytes plus status, so 410/429/5xx **policy** is tested without a network — only socket mechanics live below the seam.
* Two `StateStore` methods, not one, so "write the tree first, then the token" is expressible and testable: a store double whose `save_token` fails must leave a readable tree.
* Auth, the shared token cache and single-flight refresh live **below the `PageSource` seam**. As built: `auth::TokenCache` owns the credential and the refresh; `http::GraphHttp` holds one as its `TokenSource` (`Arc<TokenCache<…>>`, cloned into the delta client and the upload client so both share the one refresh); and `http::GraphTokens` is the `auth::TokenTransport` the refresh POST goes out on, over the same agent configuration as every other request. PROVIDER.md:216-224 — four provider instances, three concurrent, a single-use refresh token. The mapping layer has no concept of a credential, which is exactly why it can be tested with zero of them.
* Test double: `pub struct ScriptedPages { pages: VecDeque<io::Result<RawPage>> }` — constructed from JSON string literals in the test file.

`crates/hydration-graph` builds and its whole test suite runs with `--no-default-features`; the HTTP client is behind `feature = "http"`. (As built that client is `ureq` rather than `reqwest`: `PageSource` and `Transport` are synchronous `&mut self` traits called from dedicated threads, so an async client would mean a runtime to block on. See the note in `Cargo.toml`.) A test asserts the crate's non-`http` sources contain no `std::fs`, `std::net` or `std::time::SystemTime`.

---

## 3. The adversarial test list

Written first. Every one must fail against an empty implementation.

### A. Envelope and transport policy (`tests/envelope.rs`)

| Test | Input | Assertion |
|---|---|---|
| `an_error_body_served_with_http_200_is_not_an_empty_page` | `200`, `{"error":{"code":"InvalidAuthenticationToken","message":"expired"}}` | `DeltaPage::parse` = `Err(GraphError{code:"InvalidAuthenticationToken",..})` |
| `a_page_without_value_is_refused_not_defaulted` | `{"@odata.deltaLink":"x"}` | `Err(ValueMissing)` |
| `a_value_that_is_an_object_is_refused` | `{"value":{},"@odata.deltaLink":"x"}` | `Err(ValueNotArray)` |
| `a_page_with_neither_link_is_refused` | `{"value":[]}` | `Err(NoLink)` |
| `a_page_with_both_links_is_refused` | `{"value":[],"@odata.nextLink":"n","@odata.deltaLink":"d"}` | `Err(BothLinks)` |
| `a_null_delta_link_is_refused` | `{"value":[],"@odata.deltaLink":null}` | `Err(NoLink)` |
| `an_empty_delta_link_is_refused` | `{"value":[],"@odata.deltaLink":""}` | `Err(EmptyLink)` |
| `a_captive_portal_html_body_is_an_error_not_a_page` | `200`, `<html>…` | `Err(Malformed(_))` |
| `a_410_resync_required_becomes_token_expired` | `410`, `{"error":{"code":"resyncRequired"}}` | `Round::finish` = `Err((Escalation::TokenExpired, _))` |
| `a_429_retries_the_same_url_and_honours_retry_after` | `ScriptedPages`: `429 Retry-After: 7`, then a good page | source recorded the same URL twice; `Round` slept ≥ 7 s via injected `Sleeper`; no cursor advance between |
| `a_next_link_is_followed_and_never_persisted_as_a_token` | 3-page script, 2 nextLinks then a deltaLink | `CompletedRound.token` == the deltaLink; `save_token` called exactly once, with that value |
| `a_round_that_never_reaches_a_delta_link_yields_no_token` | script ends with an `Err(io)` after 1 nextLink | `finish()` is `Err`; `save_token` never called |
| `a_delta_link_is_stored_byte_for_byte` | deltaLink containing `%2B`, `+`, `=` | round-tripped value is byte-identical; no re-encoding |

### B. Identity (`tests/identity.rs`)

| Test | Input | Assertion |
|---|---|---|
| `an_item_with_no_id_is_refused_not_defaulted` | `{"name":"a.txt","file":{},"size":10,"parentReference":{"driveId":"b!X","id":"R"}}` | `Err(NoId)`; `MappedPage.items` empty; `refusals.len()==1` |
| `three_id_less_items_produce_three_refusals_not_one_change` | the verified 3-item page (`one/two/three.txt`, no ids) | `items.is_empty()`; `refusals.len()==3`; **not** `created:1` |
| `a_null_id_is_refused` | `"id":null` | `Err(NoId)` |
| `a_non_string_id_is_refused` | `"id":12345` | `Err(NoId)` |
| `an_oversized_id_is_refused_at_the_mapper` | `id` of 128 KiB | `Err(IdTooLong)`; verifies the refusal is not deferred to the xattr write |
| `a_cloud_id_is_drive_and_item_and_nothing_else` | `{"id":"01A",…}` on drive `b!X` | emitted `Change::Upserted.cloud_id == "b!X|01A"` |
| `a_cloud_id_does_not_change_when_the_content_does` | same item, two rounds, cTag `c:{G},1` then `c:{G},2` | both rounds emit the same `cloud_id` |
| `a_download_url_cannot_reach_a_cloud_id` | item with `@microsoft.graph.downloadUrl` 1.8 KB | emitted `cloud_id` length ≤ 64; no `http` substring |
| `two_drives_with_the_same_item_id_are_two_objects` | id `01A` on `b!mine` and on `b!theirs` | two distinct `cloud_id`s |

### C. Shape and facet ordering (`tests/shape.rs`)

| Test | Input | Assertion |
|---|---|---|
| `a_remote_item_folder_is_a_folder_not_a_4096_byte_file` | the verified `01SH`/`Team Files` placeholder | `Kind::Folder`; **not** `Kind::File{size:4096}` |
| `a_child_of_a_correctly_mapped_mount_gets_a_directory` | mount page then `Team Files/x.txt` via the mounted scope | both map; child's parent chain resolves under the placeholder |
| `an_explicit_null_folder_facet_is_absent_not_present` | `{"id":"01A","name":"x.txt","folder":null,"file":{},"size":10,…}` | `Kind::File{size:10,..}` |
| `an_explicit_null_file_facet_with_a_folder_is_a_folder` | `"file":null,"folder":{"childCount":2}` | `Kind::Folder` |
| `an_item_with_both_file_and_folder_is_refused` | `{"file":{…},"folder":{…},"size":4096}` | `Err(Ambiguous)` — never `Kind::File` |
| `an_item_with_neither_facet_and_no_deleted_is_refused` | `{"id":"01A","name":"x","size":10,"parentReference":{…}}` | `Err(NoShape)` |
| `a_package_outranks_its_folder_facet` | `{"folder":{"childCount":3},"package":{"type":"oneNote"}}` | `Kind::Opaque` |
| `a_notebooks_internals_never_become_files` | notebook + `Section.one` + `Open Notebook.onetoc2` under it, one page | zero `Change::Upserted` with a `.one`/`.onetoc2` path; internals appear in `Report.refusals` or `problems`, counted once |
| `malware_emits_no_change_and_is_deferred` | `{"file":{},"size":10,"malware":{}}` | `Mapping.item == None`; `Report.deferred` names it |
| `a_pending_operations_item_emits_no_placeholder` | the verified `master.mov`, `size:0`, `pendingOperations:{}` | `Mapping.item == None`; **no** `Change` with size 0 |
| `a_pending_content_update_item_emits_no_change` | `"pendingContentUpdate":{…}`, `size:1`, matching cTag | `Mapping.item == None` |
| `a_folder_to_file_flip_with_children_is_refused_not_forwarded` | `F` as folder with 2 children in the index, then `F` as `{"file":{},"size":4096}` | `Err(ShapeFlip{children:2})`; `Namespace` never sees it; `Escalation::ShapeFlipWithChildren` |
| `a_folder_to_package_flip_is_refused_not_forwarded` | `NB` folder with children, then `NB` with `package` | `Err(ShapeFlip{..})`; **zero** `Change::Removed` emitted |
| `a_file_to_folder_flip_on_a_childless_id_is_allowed` | `a.txt` file, then `a.txt` folder, no children | forwarded; positive control that the guard is not blanket |

### D. Deletion (`tests/deletion.rs`)

| Test | Input | Assertion |
|---|---|---|
| `a_tombstone_is_a_delete_whatever_its_state_says` | `"deleted":{"state":"softDeleted"}`, `name`, `eTag`, no `size` | `Item::Delete{id:"01ABC"}`; **not** an upsert with size 0 |
| `an_empty_deleted_object_is_still_a_delete` | `"deleted":{}` | `Item::Delete` |
| `a_tombstone_carrying_a_file_facet_is_still_a_delete` | `deleted` + `file:{mimeType:"application/pdf"}`, no `size` | `Item::Delete`; the verified truncate-to-zero does not occur |
| `a_bare_tombstone_does_not_panic` | `{"id":"01ABC","deleted":{"state":"deleted"},"parentReference":{"driveId":"b!X","id":"R"}}` — no name | `Ok(Item::Delete)`; no read of `name`, `size`, `file` |
| `a_tombstone_with_no_parent_reference_is_still_a_delete` | `{"id":"01ABC","deleted":{}}` | `Item::Delete`; **not** `NoParent` |
| `a_root_tombstone_is_an_escalation_not_a_cascade` | `{"id":"01ROOT","root":{},"deleted":{},"name":"root"}` | `Err(RootDeleted)`; `Escalation::RootDeleted`; zero `Change::Removed`; `Namespace::is_empty()` still false |
| `a_delete_naming_the_current_root_id_is_refused` | `Item::Delete{root_id}` synthesized from a non-root-faceted tombstone | refused before `Namespace::apply`; tree survives |
| `a_delete_for_an_unknown_id_is_forwarded_and_harmless` | tombstone for an id never seen | forwarded; `Report.refusals` empty |
| `a_round_that_would_delete_most_of_the_drive_is_refused` | 1000 known files, page of 900 tombstones | `Err(BlastRadius{removals:900,known:1000})`; no `Change` returned |
| `a_round_deleting_a_few_files_is_not_blocked` | 1000 known, 3 tombstones | positive control: `Ok`, 3 `Removed` |

### E. Root (`tests/root.rs`)

| Test | Input | Assertion |
|---|---|---|
| `the_real_root_maps_to_item_root` | `{"id":"01ROOT","name":"root","root":{},"folder":{"childCount":9},"parentReference":{"driveId":"b!X","driveType":"business"}}` | `Item::Root{id:"01ROOT"}` |
| `the_roots_name_is_never_a_path_segment` | root above + `a.txt` under it | emitted path == `"a.txt"`, not `"root/a.txt"` |
| `a_user_folder_named_root_is_not_the_root` | `{"id":"01USR","name":"root","folder":{},"parentReference":{"id":"01ROOT"}}` | `Item::Upsert{..}`; exactly one `Item::Root` in the page |
| `the_root_re_sent_every_page_is_idempotent` | 3 pages each containing the same root item | no `SecondRoot`; `problems()` empty |
| `a_second_root_id_is_an_escalation` | root `A` then root `B` | `Escalation::SecondRoot{seen:A,now:B}`; `Namespace` never sees `B`, so no `ForeignRoot` orphaning |
| `the_root_id_re_sent_without_its_facet_is_refused` | `{"id":"01ROOT","name":"Documents","folder":{},"parentReference":{"id":"01SITE"}}` after `Item::Root{01ROOT}` | `Err(RootShapeChanged)`; every existing path unchanged (no `Documents/` prefix appears) |
| `a_mounted_scope_cannot_emit_a_root` | root-faceted item mapped under `DriveScope::mounted(..)` | `Err(RootFromMountedScope)`; compile-level note: `RootPermit` unobtainable |

### F. Parent and placement (`tests/parent.rs`)

| Test | Input | Assertion |
|---|---|---|
| `a_missing_parent_id_is_refused_not_defaulted` | `{"id":"01X","name":"a.txt","file":{},"size":10,"parentReference":{"driveId":"b!X"}}` | `Err(NoParent)`; no item with parent `""` |
| `an_absent_parent_reference_on_a_live_item_is_refused` | no `parentReference` at all, no `root` facet | `Err(NoParent)` |
| `a_self_parent_is_refused_at_the_mapper` | `{"id":"X","folder":{},"parentReference":{"driveId":"b!X","id":"X"}}` | `Err(SelfParent)`; `Namespace::pending()` == 0 (the verified silent forever-wait does not occur) |
| `a_parent_on_another_drive_is_refused` | `parentReference.driveId == "b!theirs"`, scope `b!mine` | `Err(ForeignParent)` |
| `the_inner_remote_parent_reference_never_becomes_the_parent` | mount placeholder with inner `parentReference.driveId=="b!theirs"` | emitted parent == outer `01ROOT` on `b!mine` |
| `an_item_too_deep_is_refused_rather_than_silently_dropped` | synthetic chain of `MAX_MAPPED_DEPTH + 1` | `Err(TooDeep{..})`; `Report.refusals` names it (`Namespace` would emit nothing and record nothing) |
| `pending_items_surviving_a_complete_round_block_the_token` | file under parent `NOWHERE`, round reaches a deltaLink | `finish()` is `Err`; `Report.pending_after_round == ["…NOWHERE child…"]`; `save_token` not called |

### G. Size (`tests/size.rs`)

| Test | Input | Assertion |
|---|---|---|
| `an_absent_size_on_a_file_is_refused_not_zero` | `{"id":"01A","name":"a.txt","file":{},"cTag":"c:{G},1"}` | `Err(NoSize)`; no `Change` with `size: 0` |
| `a_float_size_is_refused` | `"size":1.0e3` | `Err(BadSize)` |
| `a_string_size_is_refused` | `"size":"1024"` | `Err(BadSize)` |
| `a_negative_size_is_refused` | `"size":-1` | `Err(BadSize)` |
| `a_null_size_is_refused` | `"size":null` | `Err(NoSize)` |
| `a_size_above_max_object_is_refused_at_the_mapper` | `"size":2199023255552` (2 TiB) | `Err(TooLarge{size})` surfaced in `Report`; not left to the framework's silent terminal `failed` |
| `exactly_max_object_is_accepted` | `"size":1099511627776` | positive control: `Ok`, boundary is `>` not `>=` |
| `a_folder_size_never_becomes_a_file_size` | `{"folder":{"childCount":9},"size":98123}` | `Kind::Folder`; no `size` in the emitted change |
| `a_remote_item_size_comes_from_inside` | outer `size:0`, `remoteItem.size:9999`, `remoteItem.file:{}` | `size == 9999` |

### H. Content version (`tests/version.rs`)

| Test | Input | Assertion |
|---|---|---|
| `the_ctag_is_the_version_and_the_etag_is_not` | `{"eTag":"\"{G},12\"","cTag":"c:{G},3","file":{},"size":10}` | emitted `etag == Some("ct:c:{G},3")`; the string `{G},12` appears nowhere |
| `an_absent_ctag_under_a_ctag_source_is_refused_not_none` | pinned `TagSource::CTag`, item with `eTag` only | `Err(NoContentTag{source:CTag})`; **not** `etag: None` |
| `a_metadata_only_change_does_not_change_the_emitted_version` | same item, `eTag` bumped, `cTag` unchanged | both rounds emit the identical `etag` string |
| `a_content_change_changes_the_emitted_version` | `cTag` bumped | positive control: emitted `etag` differs |
| `a_quickxor_source_drive_uses_the_hash` | pinned `QuickXor`, `file.hashes.quickXorHash:"AAAA…"` | `etag == Some("qx:AAAA…")` |
| `the_tag_source_does_not_flip_between_rounds` | round 1 all cTag; round 2 same items with cTag removed | source stays `CTag`; items refused; `Escalation::TagSourceUnavailable`; **zero** emitted changes (no mass re-place) |
| `a_folder_rename_does_not_change_any_descendant_version` | 3-deep tree, 50 files, folder renamed, descendants re-emitted with new eTags and identical cTags | every emitted `Upserted.etag` equals the previous round's for that id; only `path` differs |

### I. Names and paths (`tests/names.rs`)

| Test | Input | Assertion |
|---|---|---|
| `a_backslash_name_is_refused` | `{"name":"a\\b"}` | `Err(BadName(_))`; no flat filename containing `\` reaches a `Change` |
| `a_windows_style_path_in_name_is_refused` | `{"name":"..\\..\\x"}` | `Err(BadName(_))` |
| `a_slash_name_is_refused` | `{"name":"a/b"}` | `Err(BadName(_))` |
| `a_nul_name_is_refused` | `{"name":"a\u{0}b"}` | `Err(BadName(_))` |
| `a_dot_and_dotdot_name_are_refused` | `"."`, `".."` | `Err(BadName(_))` for each |
| `an_empty_name_is_refused` | `""` | `Err(BadName(_))` |
| `a_framework_internal_name_is_refused` | `".hydration-manifest"`, `".a.hydration-7"` | `Err(BadName(_))` for each |
| `a_control_character_name_is_refused` | `"a\nb"`, `"\u{7}x"` | `Err(BadName(_))` |
| `a_bidi_override_name_is_refused` | `"\u{202e}txt.exe"` | `Err(BadName(_))` |
| `a_percent_sequence_in_a_name_is_never_decoded` | `{"name":"Q1%20report.txt"}` | emitted path == `"Q1%20report.txt"` |
| `a_name_is_never_normalised` | NFD `"cafe\u{301}.txt"` | emitted path bytes identical to input bytes |
| `a_name_is_never_case_folded` | `"Report.TXT"` | emitted path == `"Report.TXT"` |
| `a_name_is_never_truncated` | 300-char name | emitted path retains all 300 chars (refusal is a valid alternative, silent truncation is not) |
| `a_trailing_space_name_is_accepted` | `"report .pdf"` | positive control: `Ok` — legal on Linux, the service sent it |
| `a_windows_reserved_name_is_accepted` | `"COM1"`, `"aux.c"`, `"~$doc"` | positive control: `Ok` for each — read direction does not sanitise |
| `the_parent_reference_path_is_never_used_to_build_a_path` | item whose `parentReference.path` is `/drive/root:/Docs` but whose parent id resolves to `Archive` | emitted path starts `"Archive/"` |
| `two_items_colliding_case_insensitively_in_one_parent_refuse_the_second` | `Report.txt` (id A) present, then `report.txt` (id B) same parent | B is `Err(PathCollision{holder:A})`; exactly one `Upserted` at that path |
| `two_items_at_one_path_never_both_reach_the_framework` | any round | assert over the whole batch: emitted `Upserted` paths are unique |

### J. Ordering and dedup (`tests/ordering.rs`)

| Test | Input | Assertion |
|---|---|---|
| `feed_order_is_preserved_across_pages` | page1 `[Upsert A→a.txt]`, page2 `[Delete A]`, page3 `[Upsert A→b.txt]` | final batch has one change for A: `Upserted{path:"b.txt"}` |
| `a_delete_then_recreate_in_one_page_survives` | `[deleted A, Upsert A size 20]` | one change for A: `Upserted{size:20}` — **not** `Removed` |
| `a_recreate_then_delete_in_one_page_deletes` | `[Upsert A, deleted A]` | one change: `Removed{A}` |
| `changes_are_never_bucketed_by_type` | the two inputs above | the two produce *different* results (proves no grouping) |
| `dedup_is_deterministic_across_runs` | page with the same id 5 times, run 50× in one process | identical output every run (no HashMap iteration order) |
| `an_item_repeated_across_pages_keeps_the_last_occurrence` | `A→a.txt` on page 1, `A→z.txt` on page 3 | one change, path `z.txt` |
| `a_cycle_caused_by_arrival_order_is_resolved_by_the_fixpoint` | folder `B` moved to root and folder `A` moved into `B`, page lists `A` first | after `finish()`, `problems()` is empty and `listing()` shows `A` under `B` |
| `a_problem_that_survives_the_fixpoint_blocks_the_token` | a genuine cycle `A→B→A` | `finish()` is `Err`; `Report.unresolved_problems` non-empty; `save_token` not called |
| `the_fixpoint_terminates_on_a_permanent_problem` | same input | completes in < 100 ms, bounded passes |

### K. Round completion, cursor, persistence (`tests/round.rs`)

| Test | Input | Assertion |
|---|---|---|
| `a_page_of_wholly_unmappable_items_does_not_return_an_empty_ok` | `$select`-trimmed page, every item lacking `parentReference` | `changes()` returns `Err`, **not** `Ok((vec![], next))` — the verified unconditional cursor advance is not reached |
| `refusals_cannot_be_filtered_away` | half-mappable page | `MappedPage.refusals.len() == 3`; `Report.refusals` non-empty; token withheld |
| `the_tree_is_written_before_the_token` | successful round, recording `StateStore` | call order is `save_tree` then `save_token` |
| `a_token_write_failure_leaves_a_readable_tree` | `save_token` returns `Err` | `save_tree` already succeeded; a fresh `load()` yields the tree with no token |
| `a_tree_write_failure_writes_no_token` | `save_tree` returns `Err` | `save_token` never called |
| `a_restored_state_reproduces_the_same_listing` | build tree, snapshot, `Namespace::restore`, rebuild `TreeIndex` | `listing()` equal; `TreeIndex` equal; `pending()==0`; `problems()` empty |
| `an_expired_token_returns_a_full_listing_and_a_fresh_cursor` | `410` then a tokenless enumeration script | `Ok((changes, Cursor(Some(new))))`; changes == `listing()` plus the deletion diff |
| `the_expired_token_diff_finds_files_deleted_while_away` | snapshot has A,B,C; fresh enumeration has A,B | exactly one `Removed{C}` |
| `an_expired_token_diff_that_says_everything_vanished_is_refused` | snapshot has 500; fresh enumeration returns 0 (root refused) | `Escalation::BlastRadius`; zero `Removed` |
| `token_latest_yields_an_empty_round_and_a_token` | `{"value":[],"@odata.deltaLink":"d"}` from `latest()` | `changes()` = `Ok((vec![], Cursor(Some("d"))))`; `save_tree` still called first |
| `a_persistent_retryable_stall_forces_a_re_enumeration` | feed three consecutive `Applied{retryable:true, failed:["a.txt","b.txt"]}` | `Escalation::StalledRetryable{passes:3,..}`; next `changes()` call uses `first()`, not `resume()` |
| `a_shrinking_failed_set_does_not_trigger_the_stall_guard` | `failed` of 5, then 3, then 1 | positive control: no escalation |
| `required_select_fields_are_all_requested` | URL built by `delta_url` (moved out of the `http` module per (b)10, so this runs with `--no-default-features`) | URL contains every entry of `REQUIRED_SELECT` (`id,name,size,eTag,cTag,file,folder,package,deleted,root,remoteItem,parentReference,fileSystemInfo,lastModifiedDateTime`) |

### L. Fan-out (`tests/fanout.rs`)

| Test | Input | Assertion |
|---|---|---|
| `a_mount_is_discovered_and_recorded` | the `01SH` placeholder | `MappedPage.mounts == [MountPoint{placeholder:(b!mine,01SH), remote:(b!theirs,01FAR)}]` |
| `a_mounted_scope_re_anchors_its_own_root_item` | scoped delta on `b!theirs/01FAR` returning `01FAR` itself | maps to `Item::Upsert{parent: placeholder key}`, not `Item::Root` |
| `mounted_items_do_not_land_in_pending` | the above, then a child of `01FAR` | `pending()==0`; `listing()` names the child under the placeholder path |
| `a_mount_gets_its_own_token` | two-drive round | `TokenBlob` has two entries keyed by `DriveId`; the primary token is never sent to the mounted scope |
| `a_root_delta_missing_a_change_inside_a_mount_is_not_treated_as_a_deletion` | root delta returns only the placeholder; mount not enumerated | zero `Removed` for anything under the mount |

### M. Positive controls, end to end (`tests/golden.rs`)

| Test | Input | Assertion |
|---|---|---|
| `a_plain_file_in_the_root_maps` | root + `{"id":"01A","name":"a.txt","file":{},"size":10,"cTag":"c:{G},1","parentReference":{"driveId":"b!X","id":"01ROOT"}}` | one `Upserted{cloud_id:"b!X|01A",path:"a.txt",size:10,etag:Some("ct:c:{G},1")}` |
| `a_plain_folder_produces_no_change` | root + folder `Work` | zero changes |
| `a_file_in_a_folder_gets_its_full_path` | root + `Work` + `a.txt` under it | path == `"Work/a.txt"` |
| `a_file_rename_reports_the_new_name_with_the_same_id` | then `a.txt` → `renamed.txt` | one `Upserted{cloud_id unchanged, path:"Work/renamed.txt"}` |
| `a_folder_move_moves_every_descendant` | 3-deep tree, 50 files, one `Upsert` for the top folder | 50 `Upserted`, all under the new prefix, each id exactly once |
| `a_folder_delete_removes_every_file_beneath_it` | one tombstone for the top folder | one `Removed` per descendant file, none for folders |
| `a_replayed_full_listing_is_identical_to_the_previous_one` | same enumeration twice | the two `Vec<Change>` are equal (the framework then makes it a no-op) |
| `an_unchanged_object_is_still_reported` | round 2 with no service-side change, tokenless | every known file appears in the output (a locally deleted placeholder can come back) |
| `a_three_page_capture_produces_exactly_the_expected_paths` | checked-in 3-page fixture, ~40 items incl. root, nested folders, one mount, one notebook, two tombstones | full `Vec<Change>` equals a checked-in expected list, byte for byte |
| `the_mapping_crate_touches_no_io` | source scan of `src/*.rs` excluding `http.rs` | no `std::fs`, `std::net`, `std::process`, `SystemTime::now` |
| `the_whole_suite_runs_with_no_default_features` | `cargo test -p hydration-graph --no-default-features` | passes; proves zero network, zero credentials |

---

## 4. What this deliberately does not do

**Not in the mapping layer, and why:**

* **HTTP, auth, refresh-token rotation.** Below `PageSource`. The mapping layer must be testable with zero credentials, and a layer that can open a socket cannot honestly claim that. The single-flight refresh across the four provider instances (PROVIDER.md:216-224) is a property of the shared `auth::TokenCache` that `http::GraphHttp` holds as its `TokenSource`, and is tested in `auth` against a transport double that stops mid-request — including the failing case, where holding a lock serialises refreshes without deduplicating them.
* **Throttling mechanics.** The *policy* — honour `Retry-After` exactly, retry the same URL, never restart the round from the deltaLink, page sequentially within a drive and concurrently across drives, decorate the User-Agent as `NONISV|…` — is tested at the round level against `RawPage` doubles. The sleeping and the socket are not.
* **`Provider::fetch` and `Sink::upload`.** Different traits, different failure modes. In particular **QuickXorHash is not implemented here**; content verification belongs on the fetch path, where the bytes are. This layer only reads a hash as an opaque version string.
* **Anything touching the filesystem.** No `safe_join` replacement, no symlink resolution, no `place()`. Claim 27 is a framework defect (§1.12) and is filed as a blocking dependency, not worked around here.
* **Write-back name sanitisation.** Reserved names, the `\ / : * ? " < > |` set, the ~400-character path limit, trailing dots — all upload-direction concerns. On the read path a name the service sent is a name that exists, and mangling it manufactures the collisions §1.11 #22 exists to prevent.
* **Conflict presentation.** `Applied::kept_local` mixes root-relative paths (upserts) with absolute local paths (removals) and the struct does not say which. Joining those namespaces for a UI is a separate piece of work.
* **Change notifications / subscriptions.** A webhook that triggers a round is a scheduling concern above `Discover`.
* **Consumer-OneDrive bundles and albums, and `sharedWithMe` discovery.** Bundles live outside the root hierarchy and are believed not to appear in root delta; `sharedWithMe` is a separate collection. Only mounts *discovered in the feed* are fanned out. Anything else claiming to enumerate "everything" would be a lie.
* **Reconstructing intermediate history.** Graph reports latest state per item. This is a state reconciler, and `Namespace` is built on that assumption.
* **Cross-drive deduplication of the same physical file.** The placeholder and the owner's copy are two `ObjectKey`s, deliberately. Collapsing them requires content identity we do not have on this path.
* **A `$select` tuned for bandwidth.** `REQUIRED_SELECT` is fixed and complete. Trimming it turns deletes into no-ops; the saving is not worth a class of silent data loss.

---

# Critique of the above


## Critique 1

## (a) Tests that cannot fail for the reason they claim

**Guaranteed-pass by construction:**

- `a_download_url_cannot_reach_a_cloud_id` — `DriveItem` has no `@microsoft.graph.downloadUrl` field, so serde discards it before the mapper exists. Any implementation that compiles passes. The asserted bound also contradicts §1.1: `MAX_ID_BYTES 256` + `MAX_CLOUD_ID_BYTES 512` permit a 513-byte `cloud_id`, not ≤64.
- `required_select_fields_are_all_requested` — asserts that a URL built by joining `REQUIRED_SELECT` contains `REQUIRED_SELECT`. The failure it exists to catch (the mapper reads a field nobody added to the const) is not reachable from this assertion.
- `the_mapping_crate_touches_no_io` and `the_whole_suite_runs_with_no_default_features` both pass against the empty crate, contradicting §3's own preamble. A grep for `std::fs` also misses `use std::fs as f`, `Instant::now`, and anything a dependency does.
- `an_explicit_null_folder_facet_is_absent_not_present` — `Option<T>` + serde guarantees it; §1.3 already says the `Value::get` trap is unrepresentable.
- `dedup_is_deterministic_across_runs` — `namespace.rs:588` `finalise` sorts by (depth, key) and `children` is a `BTreeSet`; determinism is already structural. 50 in-process reps prove nothing.
- `a_bare_tombstone_does_not_panic` — "no read of `name`, `size`, `file`" is not externally observable; only `Ok(Delete)` is actually asserted.

**Fixture is the friendly order — the exact failure mode named in the brief:** `a_folder_to_file_flip_with_children_is_refused_not_forwarded`, `an_item_too_deep_is_refused_rather_than_silently_dropped`, `two_items_colliding_case_insensitively_in_one_parent_refuse_the_second`, `a_notebooks_internals_never_become_files`. All four guards read `TreeIndex` (`child_count`, `depth_of`, `occupant`, parent kind) and all four are handed a pre-populated or parent-first index. Graph's delta feed is not parent-ordered. Feed the child first and `child_count`→0, `depth_of`→`None`, `occupant`→`None`: every guard answers "fine" and every test still passes. `a_file_to_folder_flip_on_a_childless_id_is_allowed` is the same hazard as a positive control — it asserts "forwarded" without asserting the `Change::Removed` that `namespace.rs:376` emits on reshape.

**Pair cannot distinguish the predicate:** `a_persistent_retryable_stall_forces_a_re_enumeration` (identical set ×3) and `a_shrinking_failed_set_does_not_trigger_the_stall_guard` (5→3→1) pass whether "non-shrinking" means set size, set membership, or `Vec` equality. `StallDetector.last_failed: Vec<String>` makes the choice order-sensitive and unspecified.

**Asserts on the wrong side of the seam:** `a_delta_link_is_stored_byte_for_byte` checks the stored value; re-encoding happens in `http.rs` when the link goes back into a request. `a_429_retries_the_same_url_and_honours_retry_after` — `RawPage.retry_after` is already a parsed `Duration` handed over by the double, so the round sleeps the number the test gave it; the actual `Retry-After` parse is below the seam and untested anywhere.

Minor: `exactly_max_object_is_accepted` hard-codes `1099511627776` instead of `hydration_protocol::MAX_OBJECT` (`lib.rs:452`, `1 << 40`) — it drifts silently. `a_name_is_never_truncated`'s parenthetical ("refusal is a valid alternative") makes the assertion unfalsifiable if written as one `assert!`. `a_three_page_capture_produces_exactly_the_expected_paths` compares against an expected list authored from the same mental model and regenerated whenever it fails.

## (b) Claims still documented rather than typed

**The whole "Type" column is untested as a type claim.** §3 has no compile-fail (`trybuild`) suite, so every "Type" row is asserted by a runtime test that a purely disciplinary implementation also passes. `a_mounted_scope_cannot_emit_a_root` says "compile-level note: `RootPermit` unobtainable" and then asserts a runtime `Err`. Not defensible — ~10 trybuild cases cover it.

**#1 is not structural as written.** `DriveItem.remote_item` is `pub` and every `ItemBody` field is `pub`, so `item.remote_item.as_ref()?.folder` compiles anywhere in the crate. `shape_body()` is a chokepoint by convention only. Not defensible; making `remote_item` private costs nothing.

**#5 ("exactly one match"), #7 ("no accumulator exists"), #20 ("no `HashMap<ItemId, Item>` exists")** are grep-level facts about code not yet written, labelled "Type". Cheap to actually enforce with the source scan test M already has.

**The last hop is untyped.** `CloudId::into_inner`, `Name::into_inner`, `ContentTag::into_inner` all yield `String`, and `Change::Upserted` (`delta.rs:29`) takes `cloud_id: String, path: String, etag: Option<String>`. The newtypes end one statement before the fields they protect. Defensible (`Change` is framework-owned) but should be said out loud; the golden test is the only guard.

**#27 `safe_join`** — the analysis is correct and this layer genuinely cannot fix it, so documenting is right. Not defensible as a *control*: "must not ship on top of the current `safe_join`" is prose in a markdown file. Make it structural — a build-time assertion or a `hydration-client` version floor that only a fixed `safe_join` satisfies.

**NFC/NFD fold — not defensible.** `unicode-normalization` is pure, allocates, touches no clock/socket/filesystem, and violates nothing in §2; the crate already takes `serde_json`. Normalising only the *fold key* and never `Name` keeps the "no transforms" promise intact. The stated fallback (`StallDetector` → forced full re-enumeration) is an expensive user-visible failure for a case that is routine on macOS-originated names, and it lands in exactly the path #22 exists to prevent.

**`TagSource` pinning** is persisted and prefixed specifically to make a source change visible, but nothing validates a loaded tag's prefix against the loaded pin. Untyped and untested.

## (c) Input shapes missing entirely

1. **Reverse-topological input as a category.** One test (`a_cycle_caused_by_arrival_order_is_resolved_by_the_fixpoint`) uses child-first order; every other order-sensitive guard is fed parent-first. There is no test that feeds a whole page in reverse depth order.
2. **A poison element in `value`:** `{"value":[null]}`, a non-object element, or a name containing an unpaired surrogate. `Vec<DriveItem>` deserialization fails wholesale, so one junk item kills the page and pins the cursor. The design never states whether parse failure is per-item or per-page, and no test forces the choice.
3. **Name byte length.** There is `MAX_ID_BYTES` but no `MAX_NAME_BYTES`. A 300-char name is tested for not-truncating; a name whose UTF-8 exceeds `NAME_MAX` (255) is not, and it lands in the framework's silent-terminal `failed` (see `Problem::BadName`'s own doc comment, `namespace.rs:117-124`).
4. **Paging pathologies:** a `nextLink` identical to the previous one, an unbounded `nextLink` chain, a `nextLink` to another host or scheme. `ScriptedPages` is a finite `VecDeque`, so an infinite page loop is not expressible in the double at all.
5. **Retry-After shapes:** absent on a 429, `0`, an HTTP-date, two consecutive 429s, 503/504.
6. **Blast radius specifics:** one folder tombstone expanding to N descendant `Removed` (is `removals` tombstones or emitted changes?); the boundary at exactly `max(64, known/10)`; and a *legitimate* bulk delete — no test shows a genuine 900-file deletion ever being applied, and the design gives it no path.
7. **An incurable, recurring refusal.** An item refused every round forever (a `\` in a Mac-authored name, a permanent `PathCollision`) blocks the token permanently under #17. `Report.quarantined` is the intended escape and appears in no test at all.
8. **`TagSource` probe inputs:** fewer than 64 files, a first page with zero files, a unanimous 64-sample with a divergent tail, a drive with no tag of any kind.
9. **Mount edges:** a self-mount or A→B→A mount cycle, a mounted drive that 403s or 410s mid-round (does the primary token persist? does `deletions_since` read the un-enumerated subtree as deletions?), a placeholder deleted while its token survives, a mount nested inside a mount.
10. **`remoteItem` edges:** outer facets disagreeing with inner, `remoteItem` nested in `remoteItem`, `remoteItem` on a tombstone, `remoteItem` carrying the pinned tag while the outer does not.
11. **`Applied` feedback other than `retryable`** — `kept_local` and `failed` naming paths the round never emitted. §4 punts conflict presentation, but §1.13 says `GraphDiscover` observes `Applied`, so it must survive them.

## Critique 2

Read all three files plus `hydration-protocol/src/lib.rs`, `providers.rs`, and the delta driver in `bin/hydration-sync.rs`.

## (a) Types that don't compose with what exists

1. **`TreeIndex` is keyed by `ItemId`; it must be keyed by `ObjectKey`.** §1.9's `shape_of/child_count/depth_of` take `&ItemId`, `occupant` returns `Option<&ItemId>`, and `Unmappable::{PathCollision, ShapeFlip, SecondRoot}` carry `ItemId`. Item ids are unique only per drive — the design's own test `two_drives_with_the_same_item_id_are_two_objects` and PROVIDER.md:178 ("key your own state by `(driveId, itemId)`") both say so. Once a mount is in the tree, `shape_of(&ItemId)` silently answers about the wrong drive.

2. **The "`ItemId` has no rendering at all" invariant is incompatible with the mandated persistence format.** `namespace.rs:405` sets `cloud_id: id.clone()` from `Item::Upsert.id`, so the `Namespace` node id *is* the cloud id string, and §1.9 + PROVIDER.md:190-192 make `Namespace::snapshot()` the single source for `TreeIndex`. Rebuilding therefore requires turning `Item.id: String` back into an `ObjectKey` — but the design supplies no `ObjectKey::parse`, only the one-way `to_cloud_id`/`into_inner`. Add `ObjectKey::parse`, and reject `|` in both `ItemId::parse` and `DriveId::parse` or `"a|b|c"` is ambiguous (`ItemId::parse` currently rejects only empty/NUL/oversize).

3. **`MAX_CLOUD_ID_BYTES = 512` is unreachable as a bound.** Two 256-byte ids plus a separator is 513, and `to_cloud_id` is infallible. Claim #26's "length bounded at construction" is false as written. (Test B8's `cloud_id length ≤ 64` also contradicts the declared 256-byte id bound.)

4. **The mount anchor contradicts itself and adds a path segment.** Test L2 says `01FAR` "maps to `Item::Upsert{parent: placeholder key}`"; L3 says the child appears "under the placeholder path". Both cannot hold: an `Upsert` for `01FAR` carries a non-empty `name`, so paths become `Team Files/<remote root name>/x.txt`. `name: ""` is not an escape — `namespace::bad_name` refuses it (`Problem::BadName("empty")`). `Anchor` must *alias* `remote_root` to the placeholder's `ObjectKey` and emit no `Item` for `01FAR` at all.

5. **`namespace::MAX_DEPTH` is private** (`namespace.rs:160`, no `pub`), so §1.9's comparison against it can't be written. Pick the local constant on its own merits. (Related and in the design's favour: `would_cycle` returns `true` on depth exhaustion, so a genuinely 512-deep chain would be reported as `Problem::Cycle`; `MAX_MAPPED_DEPTH = 128` pre-empts that.)

6. **`Escalation` and `Report` have no channel.** `Discover::changes -> io::Result<(Vec<Change>, Cursor)>` flattens every escalation to an `io::Error`. Symmetrically, `Cursor(pub Option<String>)` means the `DeltaLink` leaves as a bare `String` and comes back as one, so "a `DeltaLink` is reachable only through `CompletedRound`" does not survive the trait boundary — you need a `DeltaLink::parse` too, and the guarantee becomes a runtime one.

7. **`PageSource` takes `&mut self`**, which forbids §4's "page sequentially within a drive and concurrently across drives" from one source object. Either one `PageSource` per scope, or `&self` plus interior mutability.

## (b) Seam choices that break testability or correctness

8. **`StallDetector` (§1.13) is not implementable against this framework.** Nothing ever hands `Applied` back to the provider — `hydration-sync.rs:454-483` consumes it and never speaks to `cloud` again. `Escalation::StalledRetryable { failed: Vec<String> }` and "non-shrinking `failed` set" are unobservable. The only observable signal is being re-called with a cursor already served.

   That signal exposes a worse bug the design doesn't handle: on a retryable pass the driver re-calls `changes(&old_cursor)`. If `GraphDiscover` maps that to `resume()`, Graph returns an empty page — and `hydration-sync.rs:512` (`Ok((_, next)) => cursor = next`) advances the cursor **unconditionally** on an empty batch. The retryable refusal is silently consumed and the swap never resolves. `GraphDiscover` must serve `Namespace::listing()` when handed a cursor it has already served, and count those repeats for the stall guard.

9. **Cursor vs `StateStore` is two sources of truth, never reconciled.** PROVIDER.md:127-131: the framework does not persist the cursor and hands `Cursor::default()` after every restart. The design persists a token itself. Which wins is unstated — and both answers are wrong by default (obey the empty cursor → full enumeration every restart, defeating `StateStore`; ignore it → lose the signal in #8).

10. **Test K13 cannot run under `--no-default-features`.** It builds a URL from the `http` module, which is `#[cfg(feature = "http")]`. Move `REQUIRED_SELECT` and a pure `fn delta_url(&DriveScope) -> String` into a non-`http` module; then the coupling is testable and §1.12's "the coupling is a test, not a type" costs nothing. *(Done: both live at the crate root.)*

11. **`Sleeper` is not in the declared seam.** Test A2 asserts the round "slept ≥ 7 s", but §2 lists only `PageSource` and `StateStore` and claims the layer "takes no clock". As written the suite has a 7-second wall-clock floor. Declare `trait Sleeper` alongside `PageSource` and assert the *recorded* durations.

12. **K1 and K11 assert on state with no accessor.** "`changes()` returns `Err`" plus a `Report`, and "next `changes()` call uses `first()`", need `GraphDiscover` to expose the last `Report`/`Escalation`. Add one, or those tests can only be written against `Round` directly, which is not what they claim to cover.

## (c) Duplicated or omitted framework rules

13. **The package rule is the blocking defect.** `namespace.rs:351` records `Problem::ParentCannotContain` for *any* child of a `Kind::Opaque` node, and that entry is cleared only by a successful upsert or a delete of that id — neither of which can ever happen. Combined with claim #17 ("refusals block the token") and test J8 ("a problem that survives the fixpoint blocks the token"), **one OneNote notebook on the drive blocks the cursor permanently.** The design also supplies no mechanism for C8: there is no `Unmappable` variant for "an ancestor is a package" and no `TreeIndex` query for ancestor opacity. `Namespace` already enforces the rule correctly on its own — `collect_files` skips `Kind::Opaque` subtrees, so internals are tracked for pathing and never emitted. Forward them as ordinary upserts and exclude `ParentCannotContain`-under-an-`Opaque`-ancestor from the token gate.

14. **Refusing a container strands its subtree forever.** `PathCollision`, `BadName`, `TooDeep` or `ShapeFlip` on a *folder* means its children are still forwarded, land in `Namespace::waiting` keyed by a parent that will never arrive, and `Report.pending_after_round` then blocks the token permanently — the same liveness failure as #13, reached from a different direction. No rule in §1 pairs a container refusal with refusal of its descendants. (Minor, same area: `NameFold`'s case folding is stricter than either side needs — OneDrive won't produce two case-variant siblings, and ext4 holds both — so every fold-only collision is a false refusal that triggers this.)

15. **No round-level coalesce; PROVIDER.md:137-141 requires one.** `namespace::finalise` dedups within a *single* `apply` call. A round feeds items one at a time and concatenates the per-call `Vec<Change>`s, so an object touched on page 1 and page 3 appears twice in `CompletedRound.changes`. §1.11 #20 misattributes `finalise`'s guarantee to the round. Tests J1/J2/J3/J6 all depend on a coalesce step that §1.10 never specifies.

16. **No rollback path, so the blast-radius guard cannot do what its tests assert.** `Namespace` has no un-apply; by the time removals are counted, `delete` has already purged the descendants. K9 and D9 assert "no `Change` returned" *and* a surviving tree, which needs the round to hold a pre-round `snapshot()` and `Namespace::restore` it. Unstated — and note `snapshot()` walks only from `root` through `children`, so it silently drops everything in `waiting`, and `restore` clears `problems`.

17. **Omits PROVIDER.md:103-105 — "report everything you know about, not only what changed."** An incremental round emits only what the delta feed mentioned, so a placeholder the user deleted locally never comes back. The design needs a stated `Namespace::listing()` cadence; test M8 only covers the tokenless case, which is exactly the case that already works.

18. Duplication I checked and consider justified: `Name::of` re-implements `namespace::bad_name`'s set (it adds `\`, C0/C1 and bidi, which neither `bad_name` nor `safe_join` cover), and `ContentSize::of_file`'s ceiling duplicates `delta.rs:152`. Both are acknowledged in the text and both buy a named reason where the framework gives silence. `MAX_OBJECT` is `1 << 40` = 1099511627776, and `delta.rs` uses `>` — G6/G7's boundary values are correct.

//! Microsoft Graph's `driveItem` delta feed, mapped onto
//! [`hydration_client::namespace::Item`].
//!
//! **Skeleton only.** Every function body here is `unimplemented!()`. What is
//! real is the *shape*: the types, the signatures, the derives and the wire
//! model. `tests/mapping.rs` compiles against this and every one of its tests
//! fails, which is the point — a test that passes against `unimplemented!()`
//! is a test that cannot fail.
//!
//! The public surface is flat: everything is re-exported (or declared) at the
//! crate root, so the internal `src/` split stays free to change without
//! touching a single import in the tests.

// Skeleton allowances. Both must go once the bodies are written: the wire
// fields below are read by nobody yet, and no parameter of an `unimplemented!()`
// function is live.
#![allow(dead_code, unused_variables)]

use hydration_client::delta::Change;
use hydration_client::namespace::{Item, Namespace, Problem, Kind};
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Ids
//
// The newtypes exist so that a drive id and an item id cannot be swapped, and
// so that `CloudId` — the string that reaches the framework, an xattr and a C
// string boundary — has exactly one constructor.
// ---------------------------------------------------------------------------

/// The byte ceiling on a single id component, counted in **bytes**, not chars.
pub const MAX_ID_BYTES: usize = 256;

/// The one place an id is judged.
///
/// Bounded in **bytes**, not characters: the limit exists so a composed cloud id
/// fits in an extended attribute, and an attribute budget is bytes. A
/// character-counting bound passes a 256-character id that is 768 bytes of
/// UTF-8.
///
/// The separator is refused outright rather than escaped. `to_cloud_id` joins a
/// drive and an item with it, and if either side may contain one then
/// `("a|b", "c")` and `("a", "b|c")` compose to the same string — two different
/// objects sharing one identity, which is the corruption every identity rule in
/// this framework exists to prevent.
fn check_id(raw: &str) -> Result<(), Unmappable> {
    if raw.is_empty() {
        return Err(Unmappable::NoId);
    }
    if raw.len() > MAX_ID_BYTES {
        return Err(Unmappable::IdTooLong);
    }
    if raw.contains('\0') || raw.contains(CLOUD_ID_SEPARATOR) {
        return Err(Unmappable::NoId);
    }
    Ok(())
}

/// Joins a drive and an item into a cloud id. Refused inside an id, so the
/// composition is unambiguous by construction.
const CLOUD_ID_SEPARATOR: char = '|';

/// How deep below the drive root an item may be placed.
pub const MAX_MAPPED_DEPTH: usize = 128;

/// The byte ceiling on a composed [`CloudId`].
pub const MAX_CLOUD_ID_BYTES: usize = 512;

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct DriveId(String);

#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ItemId(String);

/// A drive-qualified identity. Item ids are unique per drive, not globally.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct ObjectKey {
    drive: DriveId,
    item: ItemId,
}

/// The identity as the framework sees it. Built only by [`ObjectKey::to_cloud_id`].
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct CloudId(String);

impl DriveId {
    pub fn parse(raw: &str) -> Result<Self, Unmappable> {
        check_id(raw).map(|()| Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ItemId {
    pub fn parse(raw: &str) -> Result<Self, Unmappable> {
        check_id(raw).map(|()| Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl ObjectKey {
    pub fn new(drive: DriveId, item: ItemId) -> Self {
        Self { drive, item }
    }

    pub fn drive(&self) -> &DriveId {
        &self.drive
    }

    pub fn item(&self) -> &ItemId {
        &self.item
    }

    /// The only way to make a [`CloudId`].
    pub fn to_cloud_id(&self) -> CloudId {
        CloudId(format!(
            "{}{CLOUD_ID_SEPARATOR}{}",
            self.drive.0, self.item.0
        ))
    }
}

impl CloudId {
    pub fn into_inner(self) -> String {
        self.0
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// Scope
//
// One scope per drive being enumerated. A mounted scope carries the anchor that
// rewrites the far drive's root onto the near drive's placeholder.
// ---------------------------------------------------------------------------

/// Where a mounted drive attaches to the tree the primary scope built.
#[derive(Clone, Debug)]
pub struct Anchor {
    placeholder: ObjectKey,
    remote_root: ItemId,
}

#[derive(Clone, Debug)]
pub struct DriveScope {
    drive: DriveId,
    anchor: Option<Anchor>,
}

impl Anchor {
    pub fn new(placeholder: ObjectKey, remote_root: ItemId) -> Self {
        Self {
            placeholder,
            remote_root,
        }
    }

    pub fn placeholder(&self) -> &ObjectKey {
        &self.placeholder
    }

    pub fn remote_root(&self) -> &ItemId {
        &self.remote_root
    }
}

impl DriveScope {
    pub fn primary(drive: DriveId) -> Self {
        Self {
            drive,
            anchor: None,
        }
    }

    pub fn mounted(drive: DriveId, anchor: Anchor) -> Self {
        Self {
            drive,
            anchor: Some(anchor),
        }
    }

    pub fn drive(&self) -> &DriveId {
        &self.drive
    }

    pub fn anchor(&self) -> Option<&Anchor> {
        self.anchor.as_ref()
    }
}

// ---------------------------------------------------------------------------
// The wire types
//
// All fields private: nothing outside this crate reads a raw Graph field, so
// the mapper stays the only thing that has an opinion about facet precedence.
//
// Two omissions in `ItemBody` are structural rather than accidental, and the
// tests depend on them: it carries neither `deleted` nor `root`. Those are
// outer-only signals, and modelling `driveItem` once and reusing it for
// `remoteItem` is what makes an inner tombstone delete the near placeholder.
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DriveItem {
    id: Option<String>,
    name: Option<String>,
    /// Decoded permissively and judged in the mapper, on purpose.
    ///
    /// `Option<u64>` fails the whole page on `-1`, `1.0e3` or `"1024"` — and a
    /// page that fails takes every good item on it down too, including the root,
    /// and pins the cursor because the retry fetches the same page. A malformed
    /// size is one item's problem. It must not be *coerced* either: `as u64`,
    /// `as_u64().unwrap_or_default()` and `f64` rounding turn those three into
    /// 0, 1000 and 0 — placeholder lengths nobody meant.
    size: Option<serde_json::Value>,
    e_tag: Option<String>,
    c_tag: Option<String>,
    file: Option<FileFacet>,
    folder: Option<FolderFacet>,
    package: Option<PackageFacet>,
    root: Option<RootFacet>,
    malware: Option<MalwareFacet>,
    deleted: Option<DeletedFacet>,
    pending_operations: Option<PendingOperations>,
    remote_item: Option<Box<ItemBody>>,
    shared: Option<SharedFacet>,
    parent_reference: Option<ItemReference>,
    file_system_info: Option<FileSystemInfo>,
    last_modified_date_time: Option<String>,
}

/// The half of a `driveItem` that a `remoteItem` may also carry.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct ItemBody {
    id: Option<String>,
    name: Option<String>,
    size: Option<serde_json::Value>,
    e_tag: Option<String>,
    c_tag: Option<String>,
    file: Option<FileFacet>,
    folder: Option<FolderFacet>,
    package: Option<PackageFacet>,
    malware: Option<MalwareFacet>,
    pending_operations: Option<PendingOperations>,
    parent_reference: Option<ItemReference>,
    file_system_info: Option<FileSystemInfo>,
    shared: Option<SharedFacet>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct FileFacet {
    mime_type: Option<String>,
    hashes: Option<Hashes>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct Hashes {
    quick_xor_hash: Option<String>,
    sha256_hash: Option<String>,
    sha1_hash: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct FolderFacet {
    child_count: Option<u64>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct PackageFacet {
    r#type: Option<String>,
}

/// Graph sends `"root":{}`. An empty struct, not a marker, so a future field
/// does not become a breaking change.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct RootFacet {}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct MalwareFacet {
    description: Option<String>,
}

/// `state` is optional on purpose: Graph sends bare `"deleted":{}` as well as
/// `{"state":"deleted"}` and `{"state":"softDeleted"}`, and a non-optional
/// field here fails to deserialise the first and takes the whole page with it.
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct DeletedFacet {
    state: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct PendingOperations {
    pending_content_update: Option<PendingContentUpdate>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct PendingContentUpdate {
    queued_date_time: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct SharedFacet {
    scope: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct FileSystemInfo {
    created_date_time: Option<String>,
    last_modified_date_time: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
struct ItemReference {
    drive_id: Option<String>,
    drive_type: Option<String>,
    id: Option<String>,
    path: Option<String>,
}

// ---------------------------------------------------------------------------
// The envelope
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextLink(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaLink(String);

impl NextLink {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl DeltaLink {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exactly one of the two links ends a page. Both, or neither, is `Malformed`.
#[derive(Debug)]
pub enum PageEnd {
    More(NextLink),
    Done(DeltaLink),
}

#[derive(Debug)]
pub struct DeltaPage {
    pub value: Vec<DriveItem>,
    pub end: PageEnd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The body is not a page this layer can account for every item of.
    ///
    /// `DeltaPage` has no refusal channel, so per-item tolerance is not
    /// expressible: a silently dropped element is a change nothing ever sees
    /// while the cursor advances past it.
    Malformed(String),
    /// A non-2xx status with no body worth reading.
    HttpStatus { status: u16 },
    /// 429 / 503.
    Throttled { retry_after_secs: Option<u64> },
    /// 410: the delta token is too old and the caller must start again.
    ResyncRequired,
}

impl DeltaPage {
    /// Parse a response, refusing anything that is not exactly one page.
    ///
    /// Status is judged before the body, because Graph's throttling and
    /// resync-required answers carry bodies that parse as something else
    /// entirely — and a 429 read as a page is a page of nothing, which looks
    /// like "the drive is empty".
    pub fn parse(status: u16, raw: &[u8]) -> Result<Self, EnvelopeError> {
        if status == 429 {
            return Err(EnvelopeError::Throttled {
                retry_after_secs: None,
            });
        }
        if status == 410 {
            return Err(EnvelopeError::ResyncRequired);
        }

        let root: serde_json::Value = serde_json::from_slice(raw)
            .map_err(|e| EnvelopeError::Malformed(e.to_string()))?;

        // An `error` key outranks the status. Graph answers 200 with one.
        if let Some(err) = root.get("error") {
            let code = err.get("code").and_then(|c| c.as_str()).unwrap_or("");
            if code == "resyncRequired" {
                return Err(EnvelopeError::ResyncRequired);
            }
            return Err(EnvelopeError::Malformed(format!(
                "graph error {code}: {}",
                err.get("message").and_then(|m| m.as_str()).unwrap_or("")
            )));
        }
        if status >= 400 {
            return Err(EnvelopeError::HttpStatus { status });
        }

        // Deliberately not `#[serde(default)]`. A response with no `value` is
        // not an empty page; it is not a page.
        let Some(value) = root.get("value") else {
            return Err(EnvelopeError::Malformed("no `value`".into()));
        };
        let Some(array) = value.as_array() else {
            return Err(EnvelopeError::Malformed("`value` is not an array".into()));
        };

        let next = link(&root, "@odata.nextLink")?;
        let delta = link(&root, "@odata.deltaLink")?;
        let end = match (next, delta) {
            (Some(_), Some(_)) => {
                return Err(EnvelopeError::Malformed(
                    "both a nextLink and a deltaLink".into(),
                ))
            }
            (None, None) => return Err(EnvelopeError::Malformed("no link".into())),
            (Some(n), None) => PageEnd::More(NextLink(n)),
            (None, Some(d)) => PageEnd::Done(DeltaLink(d)),
        };

        // One malformed element costs the whole page, and that is the safer
        // answer.
        //
        // There is no refusal channel here — `DeltaPage` carries items and a
        // link, nothing else — so an element dropped at this layer is a change
        // nobody ever sees while the cursor advances past it. Failing the page
        // keeps the cursor where it is, which is visible and recoverable;
        // silently syncing 999 of 1000 items is neither.
        let mut items = Vec::with_capacity(array.len());
        for (i, element) in array.iter().enumerate() {
            match serde_json::from_value::<DriveItem>(element.clone()) {
                Ok(item) => items.push(item),
                Err(e) => {
                    return Err(EnvelopeError::Malformed(format!(
                        "element {i} is not a driveItem: {e}"
                    )))
                }
            }
        }

        Ok(DeltaPage { value: items, end })
    }
}

fn link(root: &serde_json::Value, key: &str) -> Result<Option<String>, EnvelopeError> {
    match root.get(key) {
        None => Ok(None),
        Some(v) => match v.as_str() {
            Some(s) if !s.is_empty() => Ok(Some(s.to_string())),
            _ => Err(EnvelopeError::Malformed(format!("{key} is empty or not a string"))),
        },
    }
}

// ---------------------------------------------------------------------------
// Mapping
// ---------------------------------------------------------------------------

/// Which field becomes `Kind::File.ctag`.
///
/// Threaded rather than fixed because the answer differs per drive, and each
/// source carries its own prefix so that a tag from one can never compare equal
/// to a tag from another after a source change.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TagSource {
    CTag,
    QuickXor,
    Sha256,
    Sha1,
}

/// A shape without its payload, for talking about a change of shape.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KindTag {
    File,
    Folder,
    Opaque,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Unmappable {
    NoId,
    IdTooLong,
    NoParent,
    SelfParent,
    ForeignParent { parent_drive: DriveId },
    NoShape,
    Ambiguous,
    Blocked,
    Unsettled,
    NoSize,
    NoContentTag { source: TagSource },
    ShapeFlip { from: KindTag, to: KindTag, children: usize },
    TooDeep { depth: usize },
    RootDeleted,
}

/// Something worth saying about an item that mapped anyway.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Note {
    pub key: ObjectKey,
    pub what: &'static str,
}

/// A near-drive placeholder and the far-drive object it stands for.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MountPoint {
    pub placeholder: ObjectKey,
    pub remote: ObjectKey,
}

/// An item that did not map, named so that the round can decide what to do
/// about it. `key: None` only when there was no id to name.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Refusal {
    pub key: Option<ObjectKey>,
    pub why: Unmappable,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Mapping {
    pub item: Option<Item>,
    pub mount: Option<MountPoint>,
    pub note: Option<Note>,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct MappedPage {
    pub items: Vec<Item>,
    pub mounts: Vec<MountPoint>,
    pub refusals: Vec<Refusal>,
}

/// What the mapper remembers about the tree so far, so that a shape flip or an
/// over-deep chain can be recognised. Keyed by [`ObjectKey`], never by a bare
/// item id: ids collide across drives.
#[derive(Debug, Default)]
pub struct TreeIndex {
    shapes: std::collections::HashMap<ObjectKey, KindTag>,
    parents: std::collections::HashMap<ObjectKey, ObjectKey>,
    children: std::collections::HashMap<ObjectKey, std::collections::BTreeSet<ObjectKey>>,
    root: Option<ObjectKey>,
}

impl TreeIndex {
    pub fn new() -> Self {
        Self::default()
    }

    fn shape_of(&self, key: &ObjectKey) -> Option<KindTag> {
        self.shapes.get(key).copied()
    }

    fn child_count(&self, key: &ObjectKey) -> usize {
        self.children.get(key).map_or(0, |c| c.len())
    }

    /// How deep `key` sits, following what the index already knows.
    ///
    /// Counted from whatever ancestor the index can reach, which is the honest
    /// answer during a page that arrives leaf-first: the chain is as long as we
    /// have been told it is, and it only grows.
    fn depth_of(&self, key: &ObjectKey) -> usize {
        let mut depth = 0;
        let mut cur = key.clone();
        while let Some(parent) = self.parents.get(&cur) {
            depth += 1;
            if depth > MAX_MAPPED_DEPTH * 4 {
                break;
            }
            cur = parent.clone();
        }
        depth
    }

    fn attach(&mut self, key: ObjectKey, parent: Option<ObjectKey>, shape: KindTag) {
        if let Some(old) = self.parents.get(&key).cloned() {
            if let Some(set) = self.children.get_mut(&old) {
                set.remove(&key);
            }
        }
        if let Some(p) = parent {
            self.children.entry(p.clone()).or_default().insert(key.clone());
            self.parents.insert(key.clone(), p);
        }
        self.shapes.insert(key, shape);
    }

    fn forget(&mut self, key: &ObjectKey) {
        self.shapes.remove(key);
        if let Some(parent) = self.parents.remove(key) {
            if let Some(set) = self.children.get_mut(&parent) {
                set.remove(key);
            }
        }
        self.children.remove(key);
    }
}

/// What an item is, decided once.
///
/// A single total match rather than a chain of `if`s, because facet precedence
/// is the whole difficulty here and a chain lets two arms both be right. Graph
/// sends combinations that look contradictory and are not: a package always
/// carries a folder facet, a root always carries one too, and a tombstone still
/// carries whatever the item was before it died.
enum Shape {
    /// Outer only. A tombstone outranks everything, including its own facets:
    /// the item is gone, and what it used to be does not matter.
    Deleted,
    /// Outer only. Never read from inside a `remoteItem` — a shared folder's
    /// far-side root is not this drive's root.
    Root,
    /// Quarantined by the service. Not a permanent fault: a scan clears it.
    Blocked,
    /// An upload is still in flight. The size and hash on it are not final.
    Unsettled,
    /// A package outranks the folder facet it always arrives with.
    Package,
    Folder,
    File,
    /// Both a file and a folder facet. Graph does not send this; something is
    /// wrong, and guessing which one wins is how a folder becomes a file.
    Ambiguous,
    /// Neither, and not a tombstone.
    NoShape,
}

fn shape_of(item: &DriveItem) -> Shape {
    // The body facets come from inside a `remoteItem` when there is one: the
    // outer object is a link, and reading its facets makes a shared folder look
    // like a file. `deleted` and `root` are deliberately absent from `ItemBody`,
    // so they cannot be reached from in there at all.
    let b = item.body();
    match (
        item.deleted.is_some(),
        item.root.is_some(),
        b.malware,
        b.pending,
        b.package,
        b.folder,
        b.file,
    ) {
        (true, ..) => Shape::Deleted,
        (_, true, ..) => Shape::Root,
        (_, _, true, ..) => Shape::Blocked,
        (_, _, _, true, ..) => Shape::Unsettled,
        (_, _, _, _, true, ..) => Shape::Package,
        (_, _, _, _, _, true, true) => Shape::Ambiguous,
        (_, _, _, _, _, true, false) => Shape::Folder,
        (_, _, _, _, _, false, true) => Shape::File,
        (_, _, _, _, _, false, false) => Shape::NoShape,
    }
}

/// The facets that may live inside a `remoteItem`, flattened.
struct Body<'a> {
    file: bool,
    folder: bool,
    package: bool,
    malware: bool,
    pending: bool,
    size: Option<&'a serde_json::Value>,
    c_tag: Option<&'a str>,
    hashes: Option<&'a Hashes>,
}

impl DriveItem {
    /// Shape, size and tags come from here and nowhere else.
    fn body(&self) -> Body<'_> {
        match &self.remote_item {
            Some(r) => Body {
                file: r.file.is_some(),
                folder: r.folder.is_some(),
                package: r.package.is_some(),
                malware: r.malware.is_some(),
                pending: r.pending_operations.is_some(),
                size: r.size.as_ref(),
                c_tag: r.c_tag.as_deref(),
                hashes: r.file.as_ref().and_then(|f| f.hashes.as_ref()),
            },
            None => Body {
                file: self.file.is_some(),
                folder: self.folder.is_some(),
                package: self.package.is_some(),
                malware: self.malware.is_some(),
                pending: self.pending_operations.is_some(),
                size: self.size.as_ref(),
                c_tag: self.c_tag.as_deref(),
                hashes: self.file.as_ref().and_then(|f| f.hashes.as_ref()),
            },
        }
    }
}

/// The content version, from the source the caller pinned.
///
/// Prefixed, and never silently substituted. A source that quietly falls back
/// rewrites every tag on the drive at once — and `is_current` compares tags
/// byte for byte, so the next pass finds nothing current and dehydrates
/// everything. Missing is an error; wrong is a catastrophe.
fn content_tag(b: &Body<'_>, source: TagSource) -> Result<String, Unmappable> {
    let missing = || Unmappable::NoContentTag { source };
    match source {
        TagSource::CTag => b.c_tag.map(|t| format!("ct:{t}")).ok_or_else(missing),
        TagSource::QuickXor => b
            .hashes
            .and_then(|h| h.quick_xor_hash.as_deref())
            .map(|t| format!("qx:{t}"))
            .ok_or_else(missing),
        TagSource::Sha256 => b
            .hashes
            .and_then(|h| h.sha256_hash.as_deref())
            .map(|t| format!("s256:{t}"))
            .ok_or_else(missing),
        TagSource::Sha1 => b
            .hashes
            .and_then(|h| h.sha1_hash.as_deref())
            .map(|t| format!("s1:{t}"))
            .ok_or_else(missing),
    }
}

/// The key an item belongs under.
///
/// Always from the *outer* `parentReference`. The one inside a `remoteItem`
/// describes where the object sits on the far drive, which is not where the
/// link sits here — using it files a shared folder under a parent this drive has
/// never heard of.
fn parent_key(scope: &DriveScope, item: &DriveItem) -> Result<ObjectKey, Unmappable> {
    let Some(r) = item.parent_reference.as_ref() else {
        return Err(Unmappable::NoParent);
    };
    let Some(id) = r.id.as_deref() else {
        return Err(Unmappable::NoParent);
    };
    let parent_item = ItemId::parse(id).map_err(|_| Unmappable::NoParent)?;
    let drive = match r.drive_id.as_deref() {
        None => scope.drive().clone(),
        Some(d) => DriveId::parse(d).map_err(|_| Unmappable::NoParent)?,
    };
    if &drive != scope.drive() {
        return Err(Unmappable::ForeignParent {
            parent_drive: drive,
        });
    }
    // The far side's root is the near side's placeholder.
    //
    // A mounted drive has no root in this tree — the user sees a folder on
    // *their* drive, and its children must hang from that. Parenting them to
    // the remote root instead files them under an id this tree has never been
    // told about, so they wait forever for a folder that will never arrive.
    if let Some(anchor) = scope.anchor() {
        if &parent_item == anchor.remote_root() {
            return Ok(anchor.placeholder().clone());
        }
    }
    Ok(ObjectKey::new(drive, parent_item))
}

/// One item, in isolation apart from what `ix` already knows.
pub fn map_item(
    scope: &DriveScope,
    ix: &TreeIndex,
    tags: TagSource,
    item: &DriveItem,
) -> Result<Mapping, Unmappable> {
    let Some(raw_id) = item.id.as_deref() else {
        return Err(Unmappable::NoId);
    };
    let id = ItemId::parse(raw_id)?;
    let key = ObjectKey::new(scope.drive().clone(), id.clone());

    let shape = shape_of(item);

    // A tombstone is decided before anything else is read.
    //
    // It still carries a name and a parentReference, and Graph sends the
    // `deleted` facet three ways — `{}`, `{"state":"deleted"}` and
    // `{"state":"softDeleted"}`. Reading the parent first turns every deletion
    // on a drive into `NoParent`; matching on the state string turns two of the
    // three into upserts, which resurrects files the service deleted.
    if matches!(shape, Shape::Deleted) {
        if item.root.is_some() {
            return Err(Unmappable::RootDeleted);
        }
        return Ok(Mapping {
            item: Some(Item::Delete {
                id: key.to_cloud_id().into_inner(),
            }),
            mount: None,
            note: None,
        });
    }

    if matches!(shape, Shape::Root) {
        // A mounted scope has no root of its own: its anchor is a placeholder
        // on the near drive, and emitting a second `Item::Root` would blank the
        // tree that placeholder lives in.
        if scope.anchor().is_some() {
            return Ok(Mapping {
                item: None,
                mount: None,
                note: Some(Note {
                    key,
                    what: "the far side's root is not this tree's root",
                }),
            });
        }
        return Ok(Mapping {
            item: Some(Item::Root {
                id: key.to_cloud_id().into_inner(),
            }),
            mount: None,
            note: None,
        });
    }

    match shape {
        Shape::Blocked => return Err(Unmappable::Blocked),
        Shape::Unsettled => return Err(Unmappable::Unsettled),
        Shape::Ambiguous => return Err(Unmappable::Ambiguous),
        Shape::NoShape => return Err(Unmappable::NoShape),
        _ => {}
    }

    let parent = parent_key(scope, item)?;
    if parent == key {
        return Err(Unmappable::SelfParent);
    }

    // How deep this would sit. Counted before anything is emitted, because a
    // chain long enough to exhaust `Namespace`'s own limit is reported there as
    // a cycle — a different and misleading fault.
    let depth = ix.depth_of(&parent) + 1;
    if depth > MAX_MAPPED_DEPTH {
        return Err(Unmappable::TooDeep { depth });
    }

    let b = item.body();
    let kind = match shape {
        Shape::Package => KindTag::Opaque,
        Shape::Folder => KindTag::Folder,
        Shape::File => KindTag::File,
        _ => unreachable!("handled above"),
    };

    // A shape that changed over children is a subtree deletion wearing a
    // rename's clothes: `Namespace` answers a kind change by deleting the old
    // node, which emits a `Removed` for every file beneath it.
    if let Some(was) = ix.shape_of(&key) {
        if was != kind {
            let children = ix.child_count(&key);
            if children > 0 {
                return Err(Unmappable::ShapeFlip {
                    from: was,
                    to: kind,
                    children,
                });
            }
        }
    }

    let name = item.name.clone().unwrap_or_default();
    let mount = item.remote_item.as_ref().and_then(|r| {
        let far_drive = r
            .parent_reference
            .as_ref()
            .and_then(|p| p.drive_id.as_deref())
            .and_then(|d| DriveId::parse(d).ok())?;
        let far_item = r.id.as_deref().and_then(|i| ItemId::parse(i).ok())?;
        Some(MountPoint {
            placeholder: key.clone(),
            remote: ObjectKey::new(far_drive, far_item),
        })
    });

    let node_kind = match kind {
        KindTag::Opaque => Kind::Opaque,
        KindTag::Folder => Kind::Folder,
        KindTag::File => {
            // Exactly a non-negative integer, and within the framework's
            // ceiling. Anything else is refused rather than repaired: a
            // placeholder's length is what every later read is checked against,
            // and a length nobody meant makes the file unreadable forever.
            let size = match b.size.and_then(|v| v.as_u64()) {
                Some(n) if n <= hydration_protocol::MAX_OBJECT => n,
                _ => return Err(Unmappable::NoSize),
            };
            Kind::File {
                size,
                ctag: Some(content_tag(&b, tags)?),
            }
        }
    };

    Ok(Mapping {
        item: Some(Item::Upsert {
            id: key.to_cloud_id().into_inner(),
            parent: parent.to_cloud_id().into_inner(),
            name,
            kind: node_kind,
        }),
        mount,
        note: None,
    })
}

/// A whole page. Registers what it maps in `ix`, so a later page can see it.
///
/// Two passes, and the order is the point. A delta page is not parent-ordered,
/// so a folder's children can arrive before the folder does — and a shape flip
/// or a depth limit can only be judged against a tree that already knows them.
/// Registering everything first means the second pass judges against the page
/// as a whole rather than against however much of it happened to arrive early.
pub fn map_page(
    scope: &DriveScope,
    ix: &mut TreeIndex,
    tags: TagSource,
    page: &DeltaPage,
) -> MappedPage {
    // Pass one: shape and parentage only, no judgement.
    for item in &page.value {
        let Some(raw) = item.id.as_deref() else {
            continue;
        };
        let Ok(id) = ItemId::parse(raw) else { continue };
        let key = ObjectKey::new(scope.drive().clone(), id);
        if item.deleted.is_some() {
            continue;
        }
        if item.root.is_some() {
            ix.root = Some(key.clone());
            ix.attach(key, None, KindTag::Folder);
            continue;
        }
        let b = item.body();
        let kind = if b.package {
            KindTag::Opaque
        } else if b.folder && !b.file {
            KindTag::Folder
        } else if b.file && !b.folder {
            KindTag::File
        } else {
            continue;
        };
        let parent = parent_key(scope, item).ok();
        // Only the parentage is recorded here; the shape it *was* must survive
        // pass one, or a flip has nothing to be compared against.
        let previous = ix.shape_of(&key);
        ix.attach(key.clone(), parent, previous.unwrap_or(kind));
    }

    // Pass two: judge, with the whole page visible.
    let mut out = MappedPage::default();
    for item in &page.value {
        match map_item(scope, ix, tags, item) {
            Ok(m) => {
                if let Some(mount) = m.mount {
                    out.mounts.push(mount);
                }
                if let Some(it) = m.item {
                    if let Item::Upsert { id, kind, .. } = &it {
                        // Now the new shape replaces the old, having been judged
                        // against it.
                        if let Some(key) = key_of_cloud_id(id) {
                            let tag = match kind {
                                Kind::File { .. } => KindTag::File,
                                Kind::Folder => KindTag::Folder,
                                Kind::Opaque => KindTag::Opaque,
                            };
                            let parent = ix.parents.get(&key).cloned();
                            ix.attach(key, parent, tag);
                        }
                    }
                    if let Item::Delete { id } = &it {
                        if let Some(key) = key_of_cloud_id(id) {
                            ix.forget(&key);
                        }
                    }
                    out.items.push(it);
                }
            }
            Err(why) => {
                let key = item
                    .id
                    .as_deref()
                    .and_then(|raw| ItemId::parse(raw).ok())
                    .map(|id| ObjectKey::new(scope.drive().clone(), id));
                out.refusals.push(Refusal { key, why });
            }
        }
    }

    // A refused container's children are refused with it.
    //
    // They would otherwise be forwarded, land in `Namespace::waiting` under a
    // parent that will never arrive, and be reported as *pending* — which says
    // "not yet" about something that is settled, and which nothing can ever
    // clear. The round then withholds the token forever. Refusing them says the
    // same true thing about all of them, once.
    let refused: std::collections::BTreeSet<ObjectKey> =
        out.refusals.iter().filter_map(|r| r.key.clone()).collect();
    if !refused.is_empty() {
        let mut orphaned = Vec::new();
        for item in &page.value {
            let Some(raw) = item.id.as_deref() else {
                continue;
            };
            let Ok(id) = ItemId::parse(raw) else { continue };
            let key = ObjectKey::new(scope.drive().clone(), id);
            if refused.contains(&key) {
                continue;
            }
            let Ok(parent) = parent_key(scope, item) else {
                continue;
            };
            if let Some(reason) = out
                .refusals
                .iter()
                .find(|r| r.key.as_ref() == Some(&parent))
                .map(|r| r.why.clone())
            {
                orphaned.push(Refusal {
                    key: Some(key.clone()),
                    why: reason,
                });
                out.items.retain(|it| match it {
                    Item::Upsert { id, .. } | Item::Delete { id } | Item::Root { id } => {
                        key_of_cloud_id(id).as_ref() != Some(&key)
                    }
                });
            }
        }
        out.refusals.extend(orphaned);
    }
    out
}

/// One change per object across the whole round, last occurrence winning.
///
/// `Namespace` already does this within a single `apply`, but a round spans
/// pages: an object touched on page one and again on page three produces two
/// changes at two different paths, and the later one is the truth. Leaving that
/// to the reconciler would make this layer depend on exactly what `PROVIDER.md`
/// tells providers not to depend on.
fn coalesce(changes: Vec<Change>) -> Vec<Change> {
    let mut last: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (i, c) in changes.iter().enumerate() {
        let id = match c {
            Change::Upserted { cloud_id, .. } | Change::Removed { cloud_id } => cloud_id.clone(),
        };
        last.insert(id, i);
    }
    changes
        .iter()
        .enumerate()
        .filter(|(i, c)| {
            let id = match c {
                Change::Upserted { cloud_id, .. } | Change::Removed { cloud_id } => cloud_id,
            };
            last.get(id) == Some(i)
        })
        .map(|(_, c)| c.clone())
        .collect()
}

/// The inverse of [`ObjectKey::to_cloud_id`].
///
/// Sound because the separator is refused inside an id, so there is exactly one
/// way to split.
fn key_of_cloud_id(id: &str) -> Option<ObjectKey> {
    let (drive, item) = id.split_once(CLOUD_ID_SEPARATOR)?;
    Some(ObjectKey::new(
        DriveId::parse(drive).ok()?,
        ItemId::parse(item).ok()?,
    ))
}

// ---------------------------------------------------------------------------
// The round
//
// One round may span several pages and several scopes — a fan-out into a
// mounted drive is still one round — and it is the only layer that may decide
// a state is one to stop for rather than a change to apply.
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Report {
    /// Permanent: a human has to do something. Withholds the token.
    pub refusals: Vec<Refusal>,
    /// Transient: a scanner will clear the flag, an upload will finish. Does
    /// *not* withhold the token, because a refusal that recurs every round is
    /// cleared by nothing and pins the cursor forever.
    pub deferred: Vec<(ObjectKey, Unmappable)>,
    /// What `Namespace` itself could not settle.
    pub unresolved_problems: Vec<(String, Problem)>,
    /// Items still waiting on a parent when the round ended.
    pub pending_after_round: Vec<String>,
}

#[derive(Debug)]
pub struct CompletedRound {
    pub changes: Vec<Change>,
    pub token: DeltaLink,
    pub report: Report,
}

/// A condition the round refuses to advance past.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Escalation {
    /// The drive root was tombstoned. Applying it purges the whole tree.
    RootDeleted,
    /// A folder with children became a file. Applying it deletes them.
    ShapeFlipWithChildren { key: ObjectKey, children: usize },
    /// A second root arrived with a different id.
    ForeignRoot { key: ObjectKey },
    /// The round did not account for everything it was given.
    ///
    /// Not a fault in the data — a refused item, or one still waiting on a
    /// parent the page did not contain. It withholds the token because a delta
    /// feed does not replay: advancing past an item that was never placed is
    /// how a file silently never syncs, and the next round would have no reason
    /// to mention it again.
    Incomplete { refusals: usize, pending: usize },
}

pub struct Round {
    tags: TagSource,
    namespace: Namespace,
    index: TreeIndex,
    changes: Vec<Change>,
    report: Report,
    token: Option<DeltaLink>,
    escalation: Option<Escalation>,
}

impl Round {
    pub fn new(tags: TagSource, ns: Namespace) -> Self {
        Self {
            tags,
            namespace: ns,
            index: TreeIndex::new(),
            changes: Vec::new(),
            report: Report::default(),
            token: None,
            escalation: None,
        }
    }

    /// The scope travels with the page, not with the round, so one round can
    /// span a primary drive and every drive it fans out into.
    pub fn feed(&mut self, scope: &DriveScope, page: &DeltaPage) {
        let mapped = map_page(scope, &mut self.index, self.tags, page);

        for r in mapped.refusals {
            match r.why {
                // The three the round will not advance past. Applying any of
                // them deletes files that still exist.
                Unmappable::RootDeleted => {
                    self.escalation.get_or_insert(Escalation::RootDeleted);
                }
                Unmappable::ShapeFlip { children, .. } if children > 0 => {
                    if let Some(key) = r.key.clone() {
                        self.escalation
                            .get_or_insert(Escalation::ShapeFlipWithChildren { key, children });
                    }
                }
                // Transient: a scanner clears the flag, an upload finishes.
                // Filing these as refusals would withhold the token every round
                // forever, since nothing about them changes on our side.
                Unmappable::Blocked | Unmappable::Unsettled => {
                    if let Some(key) = r.key.clone() {
                        self.report.deferred.push((key, r.why.clone()));
                    }
                }
                _ => self.report.refusals.push(r),
            }
        }

        for item in mapped.items {
            self.changes.extend(self.namespace.apply(item));
        }

        if let PageEnd::Done(link) = &page.end {
            self.token = Some(link.clone());
        }
    }

    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    pub fn finish(mut self) -> Result<CompletedRound, (Escalation, Report)> {
        self.report.unresolved_problems = self
            .namespace
            .problems()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        self.report.pending_after_round = self.namespace.pending_ids();

        if let Some(e) = self.escalation {
            return Err((e, self.report));
        }
        // A refusal that survives the round, or an item still waiting on a
        // parent nobody described, means the next round would not see it again
        // — a delta feed does not replay. Advancing the token past either is
        // how a file silently never syncs.
        if !self.report.refusals.is_empty() || !self.report.pending_after_round.is_empty() {
            return Err((
                Escalation::Incomplete {
                    refusals: self.report.refusals.len(),
                    pending: self.report.pending_after_round.len(),
                },
                self.report,
            ));
        }
        // No deltaLink means the round has not reached the end of the feed, so
        // there is nothing to save even if everything mapped.
        let Some(token) = self.token else {
            return Err((
                Escalation::Incomplete {
                    refusals: 0,
                    pending: 0,
                },
                self.report,
            ));
        };
        Ok(CompletedRound {
            changes: coalesce(self.changes),
            token,
            report: self.report,
        })
    }
}

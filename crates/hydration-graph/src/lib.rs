//! Microsoft Graph's `driveItem` delta feed, mapped onto
//! [`hydration_client::namespace::Item`].
//!
//! Three layers, bottom to top: the wire model and its envelope, the mapper that
//! turns one page into [`Item`]s, and the driver that runs a whole round —
//! paging, fanning out into mounted drives, persisting the tree and the token,
//! and deciding what the framework's cursor is telling it.
//!
//! The public surface is flat: everything is re-exported (or declared) at the
//! crate root, so the internal `src/` split stays free to change without
//! touching a single import in the tests.

// The wire model is decoded in full and read selectively — `eTag`, `mimeType`,
// `childCount`, `driveType` and the timestamps are all deserialised so that a
// future reader has them, and none of them is consulted today. Dropping the
// fields instead would make adding one a wire-format change rather than a
// one-line read.
#![allow(dead_code)]

use hydration_client::delta::{Change, Cursor};
use hydration_client::namespace::{Item, Namespace, Problem, Kind};
use serde::{Deserialize, Serialize};
use std::io;

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
/// Serialised into the tree, because the pin has to survive a restart: a source
/// that flips between two rounds rewrites every tag on the drive at once, and
/// `delta::is_current` compares them byte for byte.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
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
    /// The same cursor has come back too many times: the framework cannot apply
    /// what it is being given, and repeating it forever is not progress.
    StalledRetryable { passes: u32, failed: Vec<String> },
    /// A round would remove more than a mistake should be able to.
    BlastRadius { removals: usize, known: usize },
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
    /// Every placeholder-to-far-drive pair the round has seen.
    ///
    /// Kept here rather than dropped in `feed`, because the fan-out is decided
    /// *during* the round: a share only becomes a scope to enumerate once the
    /// primary drive's page has described it, and the driver has no other way to
    /// learn about it. Persisted with the tree too, so a later round resumes the
    /// mounted library instead of re-enumerating it against a throttling
    /// endpoint every pass.
    mounts: Vec<MountPoint>,
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
            mounts: Vec::new(),
        }
    }

    /// The mounts described so far, in arrival order.
    pub fn mounts(&self) -> &[MountPoint] {
        &self.mounts
    }

    /// The scope travels with the page, not with the round, so one round can
    /// span a primary drive and every drive it fans out into.
    pub fn feed(&mut self, scope: &DriveScope, page: &DeltaPage) {
        let mapped = map_page(scope, &mut self.index, self.tags, page);

        for m in mapped.mounts {
            // Same placeholder twice is one mount: a delta page may report the
            // share again on any later page, and enumerating the far drive twice
            // in one round doubles the request count against the endpoint most
            // likely to be throttling.
            if !self.mounts.iter().any(|k| k.placeholder == m.placeholder) {
                self.mounts.push(m);
            }
        }

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

// ---------------------------------------------------------------------------
// The transport seam, persisted state, and the driver
//
// The seam exists so that everything above HTTP is testable with no socket, no
// credentials and no clock: a suite with a real seven-second floor is a suite
// nobody runs.
// ---------------------------------------------------------------------------

/// One HTTP reply, before anything reads it as a page.
///
/// `retry_after` is the header already parsed, because parsing it belongs below
/// this line and nothing above should have an opinion about HTTP-dates.
#[derive(Clone, Debug)]
pub struct RawPage {
    pub status: u16,
    pub retry_after: Option<std::time::Duration>,
    pub body: Vec<u8>,
}

/// Where pages come from. The only thing the `http` feature implements.
pub trait PageSource: Send {
    /// Start an enumeration from the beginning.
    fn first(&mut self, scope: &DriveScope) -> io::Result<RawPage>;
    fn next(&mut self, link: &NextLink) -> io::Result<RawPage>;
    /// Resume from a saved token.
    fn resume(&mut self, link: &DeltaLink) -> io::Result<RawPage>;
    /// The token for "everything from now on", without enumerating what is
    /// already there. Graph's `delta?token=latest`.
    fn latest(&mut self, scope: &DriveScope) -> io::Result<RawPage>;
}

/// Waiting, injected so a test can assert on the duration rather than live it.
pub trait Sleeper: Send {
    fn sleep(&mut self, how_long: std::time::Duration);
}

/// The fields a delta enumeration must ask for.
///
/// A mapper that reads a facet nobody added here sees `None` on every item and
/// silently maps the whole drive wrong, so the list and the reader have to be
/// checked against each other.
pub const REQUIRED_SELECT: &[&str] = &[
    "id",
    "name",
    "size",
    "eTag",
    "cTag",
    "file",
    "folder",
    "package",
    "root",
    "deleted",
    "malware",
    "pendingOperations",
    "remoteItem",
    "parentReference",
];

/// Graph's page size. Named rather than inlined so the page budget below can be
/// read as a number of *items*: 1024 pages at 200 is about 204k.
const PAGE_SIZE: usize = 200;

/// The one host this layer will send a credential to.
const GRAPH_HOST: &str = "graph.microsoft.com";

/// The URL an enumeration starts at.
///
/// Not behind the `http` feature: which origin a link may point at is transport
/// *policy*, and policy has to be testable without a socket.
pub fn delta_url(scope: &DriveScope) -> String {
    format!(
        "https://{GRAPH_HOST}/v1.0/drives/{}/root/delta?$select={}&$top={PAGE_SIZE}",
        scope.drive().as_str(),
        REQUIRED_SELECT.join(",")
    )
}

/// Whether a link the service handed us may be fetched with our credentials.
///
/// Scheme, host and port, compared after splitting the URL — never by substring.
/// `contains("graph.microsoft.com")` follows
/// `https://graph.microsoft.com.evil.example/…`; `starts_with("https://graph
/// .microsoft.com")` follows `https://graph.microsoft.com@evil.example/…`,
/// because everything before an `@` in an authority is *userinfo* and the real
/// host is what follows it; and a scheme-relative `//evil.example/…` inherits
/// our scheme and looks like a path to anything doing prefix arithmetic.
///
/// This is the check that matters most in the crate. `PageSource` is the seam
/// the bearer token lives below, so a link that gets past here is a live
/// OneDrive access token delivered to whatever host a response body named.
fn on_the_graph_endpoint(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("https") {
        return false;
    }
    // The authority ends at the first delimiter; a `/`, `?` or `#` inside what
    // looks like a host is the start of the path, query or fragment.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // The *last* `@` separates userinfo from the host: a userinfo section may
    // itself contain one.
    let host_port = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority,
    };
    let (host, port) = match host_port.rsplit_once(':') {
        Some((h, p)) => (h, p),
        None => (host_port, ""),
    };
    host.eq_ignore_ascii_case(GRAPH_HOST) && (port.is_empty() || port == "443")
}

// --- the stored shapes -----------------------------------------------------
//
// `Item` and `Kind` live in `hydration-client` and carry no serde derives, so
// the tree is written through mirrors declared here. That is not a workaround:
// it makes the on-disk format this crate's own, and a rename in the framework's
// public enum cannot silently change what a five-year-old state directory means.

/// A generation stamps a tree and the token written after it.
///
/// Equality is the wrong relation. `PROVIDER.md:198` says a tree newer than its
/// token is *harmless* — the replayed items are no-ops — while a token newer
/// than its tree is unrecoverable. So the pair is usable when the tree's
/// generation is at least the token's, and the token is discarded when it is
/// ahead. That asymmetry is what makes a tree write that reported success and
/// did not land recoverable rather than silent.
const FIRST_GENERATION: u64 = 1;

#[derive(Serialize, Deserialize)]
struct StoredTree {
    generation: u64,
    /// The tree names its own drive, so state left behind by another account is
    /// discarded whole rather than diffed against the new one — which would
    /// report every file of the old account as removed.
    drive: String,
    tags: TagSource,
    items: Vec<StoredItem>,
    #[serde(default)]
    mounts: Vec<StoredMount>,
}

#[derive(Serialize, Deserialize)]
enum StoredItem {
    Root {
        id: String,
    },
    Upsert {
        id: String,
        parent: String,
        name: String,
        kind: StoredKind,
    },
    Delete {
        id: String,
    },
}

#[derive(Serialize, Deserialize)]
enum StoredKind {
    File {
        size: u64,
        ctag: Option<String>,
    },
    Folder,
    /// Deliberately not collapsed into `Folder`. `Namespace` paths the two
    /// identically, which makes one `Dir` variant look like tidying — and a
    /// OneNote notebook restored as an ordinary folder is walked into on the
    /// next round and written out as separate files, which corrupts it.
    Opaque,
}

#[derive(Serialize, Deserialize)]
struct StoredMount {
    placeholder_drive: String,
    placeholder_item: String,
    remote_drive: String,
    remote_item: String,
}

impl From<&Item> for StoredItem {
    fn from(item: &Item) -> Self {
        match item {
            Item::Root { id } => StoredItem::Root { id: id.clone() },
            Item::Delete { id } => StoredItem::Delete { id: id.clone() },
            Item::Upsert {
                id,
                parent,
                name,
                kind,
            } => StoredItem::Upsert {
                id: id.clone(),
                parent: parent.clone(),
                name: name.clone(),
                kind: match kind {
                    // The tag travels with the file. `delta::is_current` reads
                    // `(Some(remote), None)` as *not* current, so a format that
                    // dropped it would make every file on the drive compare as
                    // changed after the first restart and re-place all of them.
                    Kind::File { size, ctag } => StoredKind::File {
                        size: *size,
                        ctag: ctag.clone(),
                    },
                    Kind::Folder => StoredKind::Folder,
                    Kind::Opaque => StoredKind::Opaque,
                },
            },
        }
    }
}

impl From<StoredItem> for Item {
    fn from(item: StoredItem) -> Self {
        match item {
            StoredItem::Root { id } => Item::Root { id },
            StoredItem::Delete { id } => Item::Delete { id },
            StoredItem::Upsert {
                id,
                parent,
                name,
                kind,
            } => Item::Upsert {
                id,
                parent,
                name,
                kind: match kind {
                    StoredKind::File { size, ctag } => Kind::File { size, ctag },
                    StoredKind::Folder => Kind::Folder,
                    StoredKind::Opaque => Kind::Opaque,
                },
            },
        }
    }
}

impl From<&MountPoint> for StoredMount {
    fn from(m: &MountPoint) -> Self {
        StoredMount {
            placeholder_drive: m.placeholder.drive().as_str().to_string(),
            placeholder_item: m.placeholder.item().as_str().to_string(),
            remote_drive: m.remote.drive().as_str().to_string(),
            remote_item: m.remote.item().as_str().to_string(),
        }
    }
}

impl StoredMount {
    /// Fallible on the way back: the bytes may be anything, and an id that no
    /// longer parses is a mount that must be forgotten rather than guessed at.
    fn parse(&self) -> Option<MountPoint> {
        Some(MountPoint {
            placeholder: ObjectKey::new(
                DriveId::parse(&self.placeholder_drive).ok()?,
                ItemId::parse(&self.placeholder_item).ok()?,
            ),
            remote: ObjectKey::new(
                DriveId::parse(&self.remote_drive).ok()?,
                ItemId::parse(&self.remote_item).ok()?,
            ),
        })
    }
}

fn encode_tree(
    drive: &DriveId,
    tags: TagSource,
    items: &[Item],
    mounts: &[MountPoint],
    generation: u64,
) -> TreeBlob {
    let stored = StoredTree {
        generation,
        drive: drive.as_str().to_string(),
        tags,
        items: items.iter().map(StoredItem::from).collect(),
        mounts: mounts.iter().map(StoredMount::from).collect(),
    };
    // Infallible in practice — these are our own types with no map keys that
    // are not strings. An empty blob rather than a panic if it ever were not:
    // an unreadable tree is recoverable (it is discarded and re-enumerated), and
    // a panic on the delta thread is not, because that thread is spawned bare
    // and never restarted.
    TreeBlob {
        bytes: serde_json::to_vec(&stored).unwrap_or_default(),
    }
}

/// The tree, encoded for storage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeBlob {
    bytes: Vec<u8>,
}

impl TreeBlob {
    pub fn encode(drive: &DriveId, tags: TagSource, items: &[Item]) -> TreeBlob {
        encode_tree(drive, tags, items, &[], FIRST_GENERATION)
    }
    pub fn from_bytes(bytes: Vec<u8>) -> TreeBlob {
        TreeBlob { bytes }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Every accessor goes through here, and every one of them is fallible.
    ///
    /// The bytes come off a disk this process does not own exclusively and may
    /// be truncated by a power cut mid-write. `unwrap_or_default()` here would
    /// look like a fresh install while the token beside it was still resumed —
    /// the drive would never be enumerated — and `expect()` would kill the delta
    /// thread outright.
    fn decode(&self) -> io::Result<StoredTree> {
        serde_json::from_slice(&self.bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn drive(&self) -> io::Result<DriveId> {
        let stored = self.decode()?;
        DriveId::parse(&stored.drive)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))
    }
    pub fn tag_source(&self) -> io::Result<TagSource> {
        Ok(self.decode()?.tags)
    }
    pub fn items(&self) -> io::Result<Vec<Item>> {
        Ok(self.decode()?.items.into_iter().map(Item::from).collect())
    }
    pub fn mounts(&self) -> io::Result<Vec<MountPoint>> {
        Ok(self
            .decode()?
            .mounts
            .iter()
            .filter_map(StoredMount::parse)
            .collect())
    }
    pub fn with_mounts(self, mounts: &[MountPoint]) -> TreeBlob {
        let Ok(mut stored) = self.decode() else {
            // Junk in, the same junk out. Repairing an unparseable blob by
            // writing a well-formed one over it would destroy the evidence that
            // it was ever damaged.
            return self;
        };
        stored.mounts = mounts.iter().map(StoredMount::from).collect();
        match serde_json::to_vec(&stored) {
            Ok(bytes) => TreeBlob { bytes },
            Err(_) => self,
        }
    }
}

/// One delta token per drive: a fan-out has several, and one string cannot
/// stand for all of them.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TokenBlob {
    per_drive: std::collections::BTreeMap<String, String>,
    /// The generation of the tree this token was written *after*.
    ///
    /// Not part of the map, and not exposed: it is not a position, it is the
    /// evidence that this token and that tree describe the same moment. Without
    /// it, a tree write that returns success and does not land leaves a
    /// mismatched pair that is indistinguishable from a good one — and costs the
    /// same lost move as writing the two in the wrong order.
    #[serde(default)]
    generation: u64,
}

impl TokenBlob {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn one(drive: &DriveId, link: &str) -> Self {
        let mut t = Self::new();
        t.set(drive, link);
        t
    }
    pub fn set(&mut self, drive: &DriveId, link: &str) {
        self.per_drive
            .insert(drive.as_str().to_string(), link.to_string());
    }
    pub fn get(&self, drive: &DriveId) -> Option<&str> {
        self.per_drive.get(drive.as_str()).map(|s| s.as_str())
    }
    pub fn drives(&self) -> Vec<DriveId> {
        self.per_drive
            .keys()
            .filter_map(|d| DriveId::parse(d).ok())
            .collect()
    }
    pub fn is_empty(&self) -> bool {
        self.per_drive.is_empty()
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        // Deterministic: the map is a `BTreeMap`, so two blobs that agree
        // produce the same bytes and "the state did not move" is a byte
        // comparison rather than a structural one.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// A tree and a token, and whether they agree.
pub struct PersistedState {
    tree: Option<TreeBlob>,
    token: Option<TokenBlob>,
}

impl PersistedState {
    /// A pair a completed round would have written.
    pub fn consistent(
        drive: &DriveId,
        tags: TagSource,
        items: &[Item],
        token: &TokenBlob,
    ) -> Self {
        let mut token = token.clone();
        // Same generation on both halves is exactly what the two writes leave
        // behind when neither is interrupted.
        token.generation = FIRST_GENERATION;
        Self {
            tree: Some(TreeBlob::encode(drive, tags, items)),
            token: Some(token),
        }
    }
    pub fn tree_only(drive: &DriveId, tags: TagSource, items: &[Item]) -> Self {
        Self {
            tree: Some(TreeBlob::encode(drive, tags, items)),
            token: None,
        }
    }
    /// Deliberately unbound, for the tests that make a mismatched pair.
    pub fn raw(tree: Option<TreeBlob>, token: Option<TokenBlob>) -> Self {
        Self { tree, token }
    }
    pub fn tree(&self) -> Option<&TreeBlob> {
        self.tree.as_ref()
    }
    pub fn token(&self) -> Option<&TokenBlob> {
        self.token.as_ref()
    }
}

/// Where the tree and the token live.
///
/// Two writes, never one, because the order between them is the whole rule: a
/// tree newer than its token is harmless, and a token newer than its tree is
/// unrecoverable.
pub trait StateStore: Send {
    fn load(&mut self) -> io::Result<Option<PersistedState>>;
    fn save_tree(&mut self, tree: &TreeBlob) -> io::Result<()>;
    fn save_token(&mut self, token: &TokenBlob) -> io::Result<()>;
}

/// A ceiling on one round, so an endless `nextLink` chain is a bounded failure
/// rather than a daemon that never returns.
pub const MAX_PAGES_PER_ROUND: usize = 1024;

/// How many times the same cursor may be handed back before the round stops
/// believing progress is possible.
pub const STALL_LIMIT: u32 = 3;

/// How long to wait on a 429 that carried no `Retry-After`.
///
/// Never zero. `retry_after.unwrap_or_default()` re-issues the request
/// immediately, which is a hot loop against the one endpoint that has already
/// said it is overloaded — and the ban that earns is on the app registration, so
/// it lands on every user of the client rather than the one that caused it.
const BLIND_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);

/// How many times one request may be throttled before the round gives up.
///
/// A permanent 429 must cost a round, not the thread: `hydration-sync.rs:446`
/// spawns the delta thread bare and puts no timeout around `cloud.changes`, so
/// an unbounded retry loop stops the download direction forever with nothing in
/// any log.
const MAX_THROTTLE_RETRIES: u32 = 4;

/// What the round is asking the seam for.
enum Fetch {
    First,
    Next(String),
    Resume(String),
}

/// Why an attempt stopped.
enum Fault {
    Io(io::Error),
    /// A condition with a name, kept whole so `last_escalation` can report the
    /// variant rather than a flattened string.
    Escalated(Escalation),
    /// 410. Not a failure — `PROVIDER.md` calls a full listing plus a fresh
    /// cursor a supported outcome — so it is answered by re-running the round as
    /// an enumeration rather than returned to the caller.
    Resync,
}

/// The store's answer, once it has been judged.
///
/// Everything here has already survived the two questions that decide whether
/// persisted state may be believed at all: does the tree parse, and does it
/// describe *this* drive.
struct StoredView {
    items: Vec<Item>,
    tags: Option<TagSource>,
    mounts: Vec<MountPoint>,
    tokens: TokenBlob,
    generation: u64,
}

impl StoredView {
    fn nothing() -> Self {
        Self {
            items: Vec::new(),
            tags: None,
            mounts: Vec::new(),
            tokens: TokenBlob::new(),
            generation: 0,
        }
    }

    fn read(scope: &DriveScope, state: Option<PersistedState>) -> Self {
        let Some(state) = state else {
            return Self::nothing();
        };
        // The tree is judged first and a failure discards both halves. A token
        // whose tree we do not have is the one unrecoverable state: resuming it
        // builds the namespace out of only what changed since, so every
        // unchanged file is absent from `listing()` forever and the next
        // expired-token diff reads all of them as deletions.
        let Some(blob) = state.tree() else {
            return Self::nothing();
        };
        let Ok(tree) = blob.decode() else {
            return Self::nothing();
        };
        if tree.drive != scope.drive().as_str() {
            // The user signed into a different account, or the site id changed.
            // Kept whole would report every file of the old account as removed;
            // merged, the new root is refused as `ForeignRoot` and every new
            // item waits forever on a root that will never arrive.
            return Self::nothing();
        }
        let tokens = match state.token() {
            // A tree at least as new as its token is resumable; the replayed
            // items are no-ops. A token ahead of its tree is discarded, and the
            // tree is kept — that is the whole of the ordering rule, read back.
            Some(t) if t.generation <= tree.generation => t.clone(),
            _ => TokenBlob::new(),
        };
        Self {
            items: tree.items.into_iter().map(Item::from).collect(),
            tags: Some(tree.tags),
            mounts: tree.mounts.iter().filter_map(StoredMount::parse).collect(),
            tokens,
            generation: tree.generation,
        }
    }
}

/// One completed pass over the feed, before anything is written.
struct Attempt {
    listing: Vec<Change>,
    removals: Vec<Change>,
    items: Vec<Item>,
    mounts: Vec<MountPoint>,
    tokens: TokenBlob,
    tags: TagSource,
}

pub struct GraphDiscover<P: PageSource, S: StateStore, K: Sleeper> {
    scope: DriveScope,
    pages: P,
    store: S,
    sleeper: K,
    /// The input cursor of the last call that returned `Ok`, and what that call
    /// answered with.
    ///
    /// Being handed the same input again is the *only* evidence a provider ever
    /// gets that the framework could not apply a batch: `hydration-sync.rs`
    /// leaves `cursor` untouched on a retryable pass and never speaks to the
    /// provider about it again. A failed call is deliberately not remembered —
    /// a laptop that lost its network must retry the request, not be diagnosed
    /// as a wedged framework.
    last_input: Option<Cursor>,
    served: Option<(Vec<Change>, Cursor)>,
    repeats: u32,
    /// Makes every cursor this provider mints unique.
    ///
    /// Graph hands back the same deltaLink for two consecutive rounds when the
    /// feed has not moved, so a cursor that *is* the token makes a repeat and an
    /// acknowledgement indistinguishable — and the provider then either
    /// re-serves batch one forever or drops deferred work as though it had been
    /// applied.
    rounds: u64,
    escalation: Option<Escalation>,
}

impl<P: PageSource, S: StateStore, K: Sleeper> GraphDiscover<P, S, K> {
    pub fn new(scope: DriveScope, pages: P, store: S, sleeper: K) -> Self {
        Self {
            scope,
            pages,
            store,
            sleeper,
            last_input: None,
            served: None,
            repeats: 0,
            rounds: 0,
            escalation: None,
        }
    }

    /// `Escalation` has no channel through `Discover`'s `io::Result`, so the
    /// last one is readable here rather than flattened into an error string.
    pub fn last_escalation(&self) -> Option<Escalation> {
        self.escalation.clone()
    }

    /// The same instance, handed the same input cursor it was last handed after
    /// a call that succeeded.
    ///
    /// Answered from memory: no request, no sleep, the same cursor back. Running
    /// the next round instead consumes a page whose tombstones `listing()` can
    /// never re-express — a two-object path swap was measured at 25 consecutive
    /// retryable passes, which would be 25 delta requests into a throttling
    /// endpoint while the framework made no progress at all.
    fn repeat(&mut self, cursor: &Cursor) -> Option<(Vec<Change>, Cursor)> {
        if self.last_input.as_ref() != Some(cursor) {
            return None;
        }
        let served = self.served.clone()?;
        self.repeats += 1;
        if self.repeats >= STALL_LIMIT {
            // Reported, and the same batch keeps being served. Re-enumerating
            // instead is the tempting answer and it is lossy: the tombstone that
            // is stuck was consumed from the feed on the first pass, so the tree
            // already agrees the file is gone and a fresh enumeration diffs
            // against it and finds nothing to remove. The removal the framework
            // could not apply would be dropped by the very mechanism meant to
            // recover it.
            self.escalation = Some(Escalation::StalledRetryable {
                passes: self.repeats,
                // The removals are the half of the batch that cannot be
                // re-derived from anything, so they are what a human needs named.
                failed: served
                    .0
                    .iter()
                    .filter_map(|c| match c {
                        Change::Removed { cloud_id } => Some(cloud_id.clone()),
                        _ => None,
                    })
                    .collect(),
            });
        }
        Some(served)
    }

    fn fail(&mut self, fault: Fault) -> io::Error {
        match fault {
            Fault::Io(e) => e,
            Fault::Escalated(e) => {
                let rendered = format!("{e:?}");
                self.escalation = Some(e);
                io::Error::new(io::ErrorKind::Other, rendered)
            }
            Fault::Resync => io::Error::new(
                io::ErrorKind::Other,
                "the service asked for a resync twice in one round",
            ),
        }
    }

    /// One page, with throttling handled and the envelope read.
    fn fetch(&mut self, scope: &DriveScope, what: &Fetch) -> Result<DeltaPage, Fault> {
        let mut throttled = 0u32;
        loop {
            let raw = match what {
                Fetch::First => self.pages.first(scope),
                Fetch::Next(link) => self.pages.next(&NextLink(link.clone())),
                Fetch::Resume(link) => self.pages.resume(&DeltaLink(link.clone())),
            }
            .map_err(Fault::Io)?;

            // Read from the reply, not from `EnvelopeError::Throttled` — which
            // `DeltaPage::parse` hardcodes to `None`, because parsing an HTTP
            // date belongs below this seam. And the same link is retried rather
            // than the round restarted: restarting on every 429 means a
            // throttled tenant re-fetches page one forever and generates exactly
            // the request volume that caused the throttle.
            if raw.status == 429 {
                if throttled >= MAX_THROTTLE_RETRIES {
                    return Err(Fault::Io(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "throttled without end; the round is lost, not the thread",
                    )));
                }
                throttled += 1;
                self.sleeper.sleep(raw.retry_after.unwrap_or(BLIND_BACKOFF));
                continue;
            }

            return match DeltaPage::parse(raw.status, &raw.body) {
                Ok(page) => Ok(page),
                // Only a resume can be too old. A 410 on a fresh enumeration is
                // nonsense from the service, and answering it by enumerating
                // again is a loop.
                Err(EnvelopeError::ResyncRequired) if matches!(what, Fetch::Resume(_)) => {
                    Err(Fault::Resync)
                }
                Err(e) => Err(Fault::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{e:?}"),
                ))),
            };
        }
    }

    /// One pass over every scope this round covers.
    ///
    /// `enumerate` forces a full listing: no stored token, or a 410 on the way
    /// in. The two paths differ in more than the first request — an enumeration
    /// is judged against an *empty* namespace, because a restored one answers
    /// "still there" for every item the enumeration never mentions, which is
    /// precisely the deletion it exists to find.
    fn attempt(&mut self, stored: &StoredView, force_enumerate: bool) -> Result<Attempt, Fault> {
        let enumerate = force_enumerate || stored.tokens.get(self.scope.drive()).is_none();

        let mut queue: Vec<DriveScope> = vec![self.scope.clone()];
        let mut mounts: Vec<MountPoint> = Vec::new();
        if !enumerate {
            // A mounted library keeps its own token, so a primary round resumes
            // it rather than re-enumerating a shared site every five seconds.
            for m in &stored.mounts {
                queue_mount(&mut queue, &mut mounts, m);
            }
        }

        let ns = if enumerate {
            Namespace::new()
        } else {
            Namespace::restore(stored.items.clone())
        };
        let mut ns = Some(ns);
        let mut round: Option<Round> = None;
        let mut tags = stored.tags;

        let mut tokens = TokenBlob::new();
        // Per round, not per scope: a link is a position in one enumeration and
        // two scopes never legitimately share one.
        let mut visited: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut fetched = 0usize;

        let mut at = 0;
        while at < queue.len() {
            let scope = queue[at].clone();
            at += 1;

            let mut what = match (enumerate, stored.tokens.get(scope.drive())) {
                (false, Some(link)) => {
                    visited.insert(link.to_string());
                    Fetch::Resume(link.to_string())
                }
                _ => Fetch::First,
            };

            loop {
                fetched += 1;
                if fetched > MAX_PAGES_PER_ROUND {
                    // A chain of fresh links that never ends is an OOM of the
                    // process that owns the upload queue, and killing that loses
                    // queued uploads with no other copy. The budget belongs to
                    // the round: held on the provider instead, a third round
                    // would trip a limit the first two consumed.
                    return Err(Fault::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("the round exceeded {MAX_PAGES_PER_ROUND} pages"),
                    )));
                }

                let page = self.fetch(&scope, &what)?;

                // Both links are read out before the page is handed over, since
                // `feed` borrows it and the decision about what to do next is
                // made from them.
                let end = match &page.end {
                    PageEnd::More(n) => Err(n.as_str().to_string()),
                    PageEnd::Done(d) => Ok(d.as_str().to_string()),
                };

                match &mut round {
                    Some(r) => r.feed(&scope, &page),
                    None => {
                        // The source is pinned once, from the first page, and
                        // then persisted — never re-probed. A drive that starts
                        // reporting cTags alongside its hashes would otherwise
                        // flip every tag on it at once, and `is_current`
                        // compares byte for byte, so the next pass would find
                        // nothing current and dehydrate the whole drive.
                        let pinned = tags.or_else(|| probe_tag_source(&page)).unwrap_or(
                            // A first page with no file on it pins nothing
                            // meaningful; the conventional source is the honest
                            // default, and nothing reads a tag until a file
                            // arrives. (A hash-only drive whose first page holds
                            // no file would refuse its files for one round and
                            // withhold the token, which is visible rather than
                            // silent.)
                            TagSource::CTag,
                        );
                        tags = Some(pinned);
                        let mut r = Round::new(pinned, ns.take().unwrap_or_default());
                        r.feed(&scope, &page);
                        round = Some(r);
                    }
                }

                match end {
                    Ok(delta) => {
                        if !on_the_graph_endpoint(&delta) {
                            return Err(Fault::Io(foreign_link(&delta)));
                        }
                        tokens.set(scope.drive(), &delta);
                        break;
                    }
                    Err(next) => {
                        // Checked before it is fetched, not after: the fetch is
                        // where the credential goes.
                        if !on_the_graph_endpoint(&next) {
                            return Err(Fault::Io(foreign_link(&next)));
                        }
                        // A visited *set*, not a memory of the last link. `if
                        // next == previous` is one-deep and a two-link cycle
                        // walks straight through it.
                        if !visited.insert(next.clone()) {
                            return Err(Fault::Io(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("the feed looped back to {next}"),
                            )));
                        }
                        what = Fetch::Next(next);
                    }
                }
            }

            // Only now: a share becomes a scope once the page describing it has
            // been mapped, so the queue grows as the round runs.
            if let Some(r) = &round {
                for m in r.mounts().to_vec() {
                    queue_mount(&mut queue, &mut mounts, &m);
                }
            }
        }

        let round = match round {
            Some(r) => r,
            // Unreachable: the queue always holds the primary scope and its loop
            // fetches at least one page or returns. Kept total rather than
            // unwrapped, because a panic here kills the delta thread.
            None => Round::new(TagSource::CTag, ns.take().unwrap_or_default()),
        };
        // Nothing is emitted for a scope that was never reached, so a mount the
        // store knew about and this round could not queue must not survive into
        // the tree as though it had.
        mounts.retain(|m| queue.iter().any(|s| s.drive() == m.remote.drive()));

        let listing = round.namespace().listing();
        let items = round.namespace().snapshot();
        // Taken before `finish` consumes the round, and *before* the round's own
        // verdict is applied — but only unwrapped after it, so a round that was
        // going to escalate anyway is reported as what it is rather than as a
        // blast radius.
        let diff = if enumerate {
            Some(deletions_since(&stored.items, round.namespace()))
        } else {
            None
        };
        let completed = round.finish().map_err(|(e, _)| Fault::Escalated(e))?;
        let diff = match diff {
            Some(Ok(gone)) => gone,
            Some(Err(e)) => return Err(Fault::Escalated(e)),
            None => Vec::new(),
        };

        // A tombstone this round consumed, and a deletion only the diff could
        // find. Both are removals and neither can be re-derived from `listing()`.
        let mut removals: Vec<Change> = completed
            .changes
            .into_iter()
            .filter(|c| matches!(c, Change::Removed { .. }))
            .collect();
        for gone in diff {
            if !removals.contains(&gone) {
                removals.push(gone);
            }
        }

        Ok(Attempt {
            listing,
            removals,
            items,
            mounts,
            tokens,
            tags: tags.unwrap_or(TagSource::CTag),
        })
    }

    fn run_round(&mut self) -> io::Result<(Vec<Change>, Cursor)> {
        // Once per round, and re-read every round. An instance that loaded at
        // construction holds a snapshot from before any of its siblings ran —
        // `hydration-sync.rs` builds one provider per role at startup — and
        // writes its stale tree back over their state with the newer token still
        // in place, which is the unrecoverable pair produced without any crash.
        let stored = StoredView::read(&self.scope, self.store.load()?);

        let attempted = match self.attempt(&stored, false) {
            Err(Fault::Resync) => self.attempt(&stored, true),
            other => other,
        };
        let done = match attempted {
            Ok(d) => d,
            Err(f) => return Err(self.fail(f)),
        };

        // Write the tree, then the token, and only once the round is known to
        // have completed. "Always write the tree, then decide about the token"
        // satisfies every ordering assertion and destroys the state a refusal
        // was protecting: the next round starts from a tree that agrees with the
        // page it refused to trust.
        let generation = stored.generation + 1;
        let tree = encode_tree(
            self.scope.drive(),
            done.tags,
            &done.items,
            &done.mounts,
            generation,
        );
        self.store.save_tree(&tree)?;

        let mut token = done.tokens;
        token.generation = generation;
        self.store.save_token(&token)?;

        let Some(link) = token.get(self.scope.drive()).map(str::to_string) else {
            // The primary scope always ends at a deltaLink or the attempt fails,
            // so this cannot happen — and `Cursor(None)` on a batch would make
            // the driver reset to an empty cursor and re-enumerate the whole
            // drive every pass, so it is refused rather than returned.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the round persisted no token for the drive it was syncing",
            ));
        };

        self.rounds += 1;
        let cursor = Cursor(Some(format!("r{}:{link}", self.rounds)));

        // The batch is the tree plus this round's removals, never the round's
        // own change list. After a restart the framework's `Store` knows only
        // what is on disk, so filtering to what the service said changed means a
        // placeholder the user deleted locally never comes back — and the
        // restart is exactly when the framework has lost every other way to find
        // out. Removals first: they free the paths the upserts may claim.
        let mut batch = done.removals;
        batch.extend(done.listing);
        Ok((batch, cursor))
    }
}

impl<P: PageSource, S: StateStore, K: Sleeper> hydration_client::delta::Discover
    for GraphDiscover<P, S, K>
{
    fn changes(&mut self, cursor: &Cursor) -> io::Result<(Vec<Change>, Cursor)> {
        if let Some(served) = self.repeat(cursor) {
            return Ok(served);
        }
        let out = self.run_round();
        if let Ok((changes, next)) = &out {
            self.last_input = Some(cursor.clone());
            self.served = Some((changes.clone(), next.clone()));
            self.repeats = 0;
            // A round that completed clears a stall. Latching it would turn the
            // second retryable pass in the process's life into an instant
            // escalation.
            self.escalation = None;
        }
        out
    }
}

fn foreign_link(link: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("refusing to send a credential to {link}"),
    )
}

/// Add a mount to the round, and the scope it implies.
fn queue_mount(queue: &mut Vec<DriveScope>, mounts: &mut Vec<MountPoint>, m: &MountPoint) {
    if mounts.iter().any(|k| k.placeholder == m.placeholder) {
        return;
    }
    mounts.push(m.clone());
    // A far feed that carries a placeholder back to a drive already in this
    // round is a cycle, and nothing bounds *scopes* per round the way
    // `MAX_PAGES_PER_ROUND` bounds pages — so it would recurse until the process
    // died, silently.
    if queue.iter().any(|s| s.drive() == m.remote.drive()) {
        return;
    }
    queue.push(DriveScope::mounted(
        m.remote.drive().clone(),
        Anchor::new(m.placeholder.clone(), m.remote.item().clone()),
    ));
}

/// Which field this drive's content versions come from, read off a page.
///
/// The first file-shaped item decides, preferring the cheapest thing the service
/// actually sends. Never *falls back* later: a source that quietly substitutes
/// rewrites every tag on the drive at once, and missing is an error while wrong
/// is a catastrophe.
fn probe_tag_source(page: &DeltaPage) -> Option<TagSource> {
    for item in &page.value {
        if item.deleted.is_some() {
            continue;
        }
        let b = item.body();
        if !b.file || b.folder || b.package {
            continue;
        }
        if b.c_tag.is_some() {
            return Some(TagSource::CTag);
        }
        if let Some(h) = b.hashes {
            if h.quick_xor_hash.is_some() {
                return Some(TagSource::QuickXor);
            }
            if h.sha256_hash.is_some() {
                return Some(TagSource::Sha256);
            }
            if h.sha1_hash.is_some() {
                return Some(TagSource::Sha1);
            }
        }
    }
    None
}

/// Refuse a round that would remove more than a mistake should be able to.
///
/// The floor matters as much as the ratio. A proportional limit alone lets a
/// small drive be emptied — ten removals out of a hundred known is "10%" and is
/// also the user's whole Documents folder — and a fixed limit alone refuses the
/// ordinary cleanup of a large one.
pub fn guard_blast_radius(removals: usize, known: usize) -> Result<(), Escalation> {
    let limit = std::cmp::max(64, known / 10);
    if removals > limit {
        return Err(Escalation::BlastRadius { removals, known });
    }
    Ok(())
}

/// What a full enumeration cannot say on its own.
///
/// A listing names what exists, never what stopped existing — so after a token
/// expiry the only way to find a remote deletion is to diff a fresh enumeration
/// against the tree from before it.
pub fn deletions_since(before: &[Item], after: &Namespace) -> Result<Vec<Change>, Escalation> {
    let snapshot = after.snapshot();
    let present: std::collections::BTreeSet<&str> = snapshot.iter().map(item_id).collect();
    // Files only. A folder that vanished takes its contents with it, and every
    // one of those files is in `before` in its own right — emitting the
    // container as well would name something the framework has no path for.
    let gone: Vec<Change> = before
        .iter()
        .filter_map(|i| match i {
            Item::Upsert {
                id,
                kind: Kind::File { .. },
                ..
            } if !present.contains(id.as_str()) => Some(Change::Removed {
                cloud_id: id.clone(),
            }),
            _ => None,
        })
        .collect();
    guard_blast_radius(gone.len(), before.len())?;
    Ok(gone)
}

fn item_id(item: &Item) -> &str {
    match item {
        Item::Root { id } | Item::Upsert { id, .. } | Item::Delete { id } => id,
    }
}

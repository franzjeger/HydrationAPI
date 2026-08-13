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

/// OAuth: the device code flow and the shared token cache.
///
/// The one part of this crate that is *not* flattened into the root. Its names
/// are credential names — `Secret`, `AccessToken`, `RefreshToken` — and they are
/// worth the `auth::` in front of them at every use site; and two of its seams,
/// [`auth::TokenTransport`] and [`auth::Clock`], deliberately mirror
/// [`Transport`] and [`Sleeper`] closely enough that flattening both sets into
/// one namespace would make the wrong one easy to implement by accident.
///
/// Nothing above the [`PageSource`] and [`Transport`] seams may reach it. That
/// is what lets every test in `tests/` run with no credential at all. Below
/// them it is joined up: with the `http` feature, `auth::TokenCache` *is* a
/// `TokenSource`, and [`auth::TokenTransport`] — the refresh POST's socket — is
/// implemented by `GraphTokens` over the same client configuration as
/// everything else.
pub mod auth;

#[cfg(feature = "http")]
mod access;
#[cfg(feature = "http")]
pub use access::{
    FileCredentialStore, FileStateStore, GraphAccess, GraphProvider, MonotonicClock,
    SharedCredentialStore, SharedTokenCache, SystemSleeper,
};

use hydration_client::delta::{Change, Cursor};
use hydration_client::namespace::{Item, Kind, Namespace, Problem};
use serde::{Deserialize, Serialize};
use std::io;

// The only code in the crate that opens a socket — for pages, for uploads and
// for the refresh POST alike. It is a child of the root so that it can reach
// `on_the_graph_endpoint` — the origin check is private on purpose, and the one
// place a credential is attached has to be the one place that consults it.
// Re-exported flat, per the note above.
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "http")]
pub use http::{GraphHttp, GraphTokens, StaticToken, TokenSource};

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
    /// Parse the drive-qualified id previously produced by [`ObjectKey::to_cloud_id`].
    pub fn parse(raw: &str) -> Result<ObjectKey, Unmappable> {
        let (drive, item) = raw.split_once(CLOUD_ID_SEPARATOR).ok_or(Unmappable::NoId)?;
        if item.contains(CLOUD_ID_SEPARATOR) {
            return Err(Unmappable::NoId);
        }
        Ok(ObjectKey::new(DriveId::parse(drive)?, ItemId::parse(item)?))
    }

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

        let root: serde_json::Value =
            serde_json::from_slice(raw).map_err(|e| EnvelopeError::Malformed(e.to_string()))?;

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
            _ => Err(EnvelopeError::Malformed(format!(
                "{key} is empty or not a string"
            ))),
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
    ForeignParent {
        parent_drive: DriveId,
    },
    NoShape,
    Ambiguous,
    Blocked,
    Unsettled,
    NoSize,
    NoContentTag {
        source: TagSource,
    },
    ShapeFlip {
        from: KindTag,
        to: KindTag,
        children: usize,
    },
    TooDeep {
        depth: usize,
    },
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
            self.children
                .entry(p.clone())
                .or_default()
                .insert(key.clone());
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
    /// Neither a file facet nor a folder one, and not a tombstone.
    Neither,
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
        (_, _, _, _, _, false, false) => Shape::Neither,
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

// The QuickXorHash lives here rather than beside the transport that verifies
// downloads with it. It is an algorithm, not a socket, and the collision
// reconciliation in `put_at_path` needs it in a build with no HTTP feature at
// all — which is how it came to be referenced through a module that did not
// exist there.
/// Streaming implementation of Microsoft's published 160-bit QuickXorHash.
/// The bytes are never buffered beyond the HTTP client's own read buffer.
pub(crate) struct QuickXorWriter<W> {
    inner: W,
    digest: [u8; 20],
    length: u64,
}

impl<W> QuickXorWriter<W> {
    pub(crate) fn new(inner: W) -> Self {
        Self {
            inner,
            digest: [0; 20],
            length: 0,
        }
    }

    pub(crate) fn verify(mut self, expected: &str) -> io::Result<()> {
        for (slot, byte) in self.digest[12..].iter_mut().zip(self.length.to_le_bytes()) {
            *slot ^= byte;
        }
        if base64_20(&self.digest) == expected {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Graph content did not match its QuickXorHash",
            ))
        }
    }
}

impl<W: std::io::Write> std::io::Write for QuickXorWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        for &byte in &buf[..written] {
            let shift = (self.length % 160) as usize * 11 % 160;
            let value = (byte as u16) << (shift % 8);
            let cell = shift / 8;
            self.digest[cell] ^= value as u8;
            self.digest[(cell + 1) % 20] ^= (value >> 8) as u8;
            self.length += 1;
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// QuickXorHash of a whole buffer, in the form Graph reports it.
///
/// Used to answer one question and only one: is the object already in the cloud
/// at this name byte for byte the same document as the local file? A hash is
/// exactly the right instrument for that and exactly the wrong one for a
/// precondition, which is why `TagSource::QuickXor` is not used as an
/// `if-match` and this is not used as a version.
pub fn quickxor_of(bytes: &[u8]) -> String {
    use std::io::Write as _;
    let mut sink = std::io::sink();
    let mut w = QuickXorWriter::new(&mut sink);
    // Writing to a sink cannot fail, and a hash that silently gave up would
    // answer "not the same" and turn a safe reconciliation into a conflict.
    if w.write_all(bytes).is_err() {
        return String::new();
    }
    for (slot, byte) in w.digest[12..].iter_mut().zip(w.length.to_le_bytes()) {
        *slot ^= byte;
    }
    base64_20(&w.digest)
}

pub(crate) fn base64_20(bytes: &[u8; 20]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(28);
    for chunk in bytes.chunks(3) {
        let value = (chunk[0] as u32) << 16
            | (chunk.get(1).copied().unwrap_or(0) as u32) << 8
            | chunk.get(2).copied().unwrap_or(0) as u32;
        out.push(ALPHABET[((value >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((value >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((value >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(value & 63) as usize] as char
        } else {
            '='
        });
    }
    out
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
        Shape::Neither => return Err(Unmappable::NoShape),
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
        KindTag::Folder => Kind::Folder {
            etag: item
                .e_tag
                .as_deref()
                .filter(|tag| !tag.is_empty())
                .map(|tag| format!("et:{tag}")),
        },
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
                                Kind::Folder { .. } => KindTag::Folder,
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

fn change_cloud_id(change: &Change) -> &str {
    match change {
        Change::Upserted { cloud_id, .. }
        | Change::FolderUpserted { cloud_id, .. }
        | Change::Removed { cloud_id }
        | Change::FolderRemoved { cloud_id, .. } => cloud_id,
    }
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
    /// How many items the feed handed this round, mapped and applied.
    ///
    /// Not the same as `changes.len()`, and the difference is the whole reason
    /// this exists. A new empty folder produces a folder change and changes the
    /// tree, and a round that skipped the tree
    /// write on an empty change list would advance the token past the folder's
    /// creation with no record of it. A delta feed never re-reports an unchanged
    /// folder, so every file that ever arrives inside it waits for a parent that
    /// will never come. `a_round_that_produced_no_changes_still_persists_its_
    /// tree` is that failure, written down.
    ///
    /// An empty *feed*, though, is an empty round: nothing was applied, so the
    /// tree on disk is still the tree.
    applied: usize,
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
            applied: 0,
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
            self.applied += 1;
            let changes = self.namespace.apply(item);

            // Graph may report one object more than once across the pages of a
            // round. The later feed occurrence is authoritative, so discard
            // changes produced by earlier occurrences before retaining the
            // complete result of this one. Keeping the result as a group is
            // important: one occurrence can legitimately emit both a removal
            // and an upsert when an object's shape changes.
            let changed_ids: std::collections::BTreeSet<&str> =
                changes.iter().map(change_cloud_id).collect();
            if !changed_ids.is_empty() {
                self.changes
                    .retain(|change| !changed_ids.contains(change_cloud_id(change)));
            }
            self.changes.extend(changes);
        }

        if let PageEnd::Done(link) = &page.end {
            self.token = Some(link.clone());
        }
    }

    pub fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    /// How many items the feed handed this round. Zero means the tree on disk is
    /// still the tree.
    pub fn applied(&self) -> usize {
        self.applied
    }

    // The error side is large because a refused round carries its whole report,
    // and that is the point of it — a caller that cannot see what was refused
    // cannot act on it. Boxing would move the cost to every caller for a value
    // constructed at most once per round.
    #[allow(clippy::result_large_err)]
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
            changes: self.changes,
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

/// Where pages come from. One of the three seams the `http` feature implements —
/// with [`Transport`] for the write half and [`auth::TokenTransport`] for the
/// credential.
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

/// The URL that asks for a token describing "everything from now on".
///
/// Graph answers `delta?token=latest` with an empty `value` and a `deltaLink`,
/// so a new sync root can be adopted without enumerating what is already in it.
///
/// Composed here rather than in the transport, for the same reason as
/// [`delta_url`]: the URL a request goes to is policy, and a test that cannot
/// see it without a socket is a test of nothing. `$select` is kept even though
/// the answer carries no items — a service that ever *did* return one would
/// return it with the fields the mapper needs, rather than a page this crate
/// has to refuse.
pub fn latest_url(scope: &DriveScope) -> String {
    format!("{}&token=latest", delta_url(scope))
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
    VersionedFolder {
        etag: String,
    },
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
                    Kind::Folder { etag: Some(etag) } => {
                        StoredKind::VersionedFolder { etag: etag.clone() }
                    }
                    Kind::Folder { etag: None } => StoredKind::Folder,
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
                    StoredKind::Folder => Kind::Folder { etag: None },
                    StoredKind::VersionedFolder { etag } => Kind::Folder { etag: Some(etag) },
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
    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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
    pub fn consistent(drive: &DriveId, tags: TagSource, items: &[Item], token: &TokenBlob) -> Self {
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
    /// The token was too old and the service said so.
    ///
    /// Not a failure. `PROVIDER.md` calls a full listing plus a fresh cursor a
    /// supported outcome, so it is answered by re-running the round as an
    /// enumeration rather than by returning it to the caller.
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

/// A completed round's two writes, derived and held back until the framework
/// proves it applied the batch they describe.
///
/// A provider is never told a batch was applied. Committing at the end of the
/// round that derived them therefore advances the durable position past changes
/// the framework may never have seen — and a removal is the one change that
/// cannot be recovered afterwards. Graph does not replay a consumed tombstone,
/// `Namespace::listing()` cannot express a deletion, and the tree written
/// alongside the token already agrees the object is gone, so no later diff can
/// rediscover it either.
///
/// Deferring only the token is not enough, and that is not a guess: with the
/// tree still written in-round, a restart resumes the older token and replays
/// the tombstone, but `Namespace::apply(Item::Delete { id })` for an id the
/// restored tree no longer holds emits no `Change` at all. The position
/// recovers; the removal does not. So the pair moves together or not at all.
struct Uncommitted {
    /// `None` when the round changed nothing and the tree on disk is still the
    /// one this token was derived after.
    tree: Option<TreeBlob>,
    token: TokenBlob,
}

/// One completed pass over the feed, before anything is written.
struct Attempt {
    listing: Vec<Change>,
    removals: Vec<Change>,
    /// Whether this round listed the drive from nothing rather than resuming a
    /// token, which is one of the two states in which the tree must be written
    /// whatever the feed said.
    enumerated: bool,
    /// How many items the feed handed this round. Zero means nothing was applied
    /// and the tree on disk is still the tree.
    applied: usize,
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
    /// The previous round's tree and token, derived and not yet on disk.
    ///
    /// Held here rather than written where they were derived, because the
    /// round that derived them has no way of knowing whether the batch it
    /// returned was ever applied. See [`Uncommitted`].
    pending: Option<Uncommitted>,
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
            pending: None,
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
                        Change::Removed { cloud_id } | Change::FolderRemoved { cloud_id, .. } => {
                            Some(cloud_id.clone())
                        }
                        _ => None,
                    })
                    .collect(),
            });
        }
        Some(served)
    }

    /// Land the previous round's writes, tree first, then token.
    ///
    /// Reached only from the path that has just been handed a cursor other than
    /// the one it was last handed — the sole evidence this trait offers that
    /// `hydration-sync` accepted the batch and advanced past it. The ordering
    /// between the two writes is unchanged and still absolute: a tree newer
    /// than its token is harmless, a token newer than its tree is
    /// unrecoverable.
    ///
    /// A failure discards the pair instead of holding it for another attempt.
    /// Everything it describes is derivable again from the token still on disk,
    /// and re-deriving it is exactly what a crash here would cost — one round
    /// trip. Retaining a pair whose tree may have half landed, and writing it
    /// later against a store that has moved underneath it, costs more.
    fn commit(&mut self) -> io::Result<()> {
        let Some(pending) = self.pending.take() else {
            return Ok(());
        };
        if let Some(tree) = &pending.tree {
            self.store.save_tree(tree)?;
        }
        self.store.save_token(&pending.token)
    }

    fn fail(&mut self, fault: Fault) -> io::Error {
        match fault {
            Fault::Io(e) => e,
            Fault::Escalated(e) => {
                let rendered = format!("{e:?}");
                self.escalation = Some(e);
                io::Error::other(rendered)
            }
            Fault::Resync => io::Error::other("the service asked for a resync twice in one round"),
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
        let applied = round.applied();
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
            .filter(|c| matches!(c, Change::Removed { .. } | Change::FolderRemoved { .. }))
            .collect();
        for gone in diff {
            if !removals.contains(&gone) {
                removals.push(gone);
            }
        }

        Ok(Attempt {
            listing,
            removals,
            enumerated: enumerate,
            applied,
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

        // Derive the tree and the token, and write neither. A round that
        // completed is not a round that was applied, and only [`commit`] — on
        // the next call that proves the framework moved on — puts either on
        // disk. "Always write the tree, then decide about the token" satisfies
        // every ordering assertion and destroys the state a refusal was
        // protecting: the next round starts from a tree that agrees with the
        // page it refused to trust.
        // A round that changed nothing does not rewrite the tree.
        //
        // `encode_tree` serialises every object on the drive and `commit` writes
        // the result. Measured on a live account on 2026-08-13: 167,890 objects,
        // 67.6 MB, written every eight seconds to record that the cloud had not
        // moved. That is where the daemon's 45% of a core went, and it grows
        // with the user's file count, which is what made a large folder feel
        // like the client's limit rather than the client's bug.
        //
        // The generation is what makes skipping it safe. A token may never be
        // newer than the tree it was written after — that pair is unrecoverable
        // and costs a full re-enumeration — so the token keeps the generation
        // the tree on disk already carries. Equal is allowed; ahead is not.
        // "Nothing was applied", not "no changes were emitted".
        //
        // A new empty folder emits no `Change` and still changes the tree, and
        // `a_round_that_produced_no_changes_still_persists_its_tree` is the
        // failure that follows from confusing the two: the token advances past
        // the folder's creation, the feed never re-reports an unchanged folder,
        // and every file that later arrives inside it waits forever for a parent
        // that will never come. Sync stops permanently, on a folder.
        //
        // An empty feed is a different thing entirely. Nothing was applied, so
        // the tree on disk is still the tree, and the only thing that moved is
        // the delta link.
        let unchanged = !done.enumerated
            && done.applied == 0
            && done.removals.is_empty()
            && done.mounts == stored.mounts
            && stored.tags == Some(done.tags);
        let generation = if unchanged {
            stored.generation
        } else {
            stored.generation + 1
        };
        let tree = if unchanged {
            None
        } else {
            Some(encode_tree(
                self.scope.drive(),
                done.tags,
                &done.items,
                &done.mounts,
                generation,
            ))
        };

        let mut token = done.tokens;
        token.generation = generation;

        let Some(link) = token.get(self.scope.drive()).map(str::to_string) else {
            // The primary scope always ends at a deltaLink or the attempt fails,
            // so this cannot happen — and `Cursor(None)` on a batch would make
            // the driver reset to an empty cursor and re-enumerate the whole
            // drive every pass, so it is refused rather than returned.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the round derived no token for the drive it was syncing",
            ));
        };

        // Held, not written. A crash from here until the next accepted pass
        // costs one round trip and nothing else: the older token is still on
        // disk, so the round — tombstones included — is simply run again.
        self.pending = Some(Uncommitted { tree, token });

        self.rounds += 1;
        let cursor = Cursor(Some(format!("r{}:{link}", self.rounds)));

        // The batch is the tree plus this round's removals, never the round's
        // own change list. After a restart the framework's `Store` knows only
        // what is on disk, so filtering to what the service said changed means a
        // placeholder the user deleted locally never comes back — and the
        // restart is exactly when the framework has lost every other way to find
        // out. Removals first: they free the paths the upserts may claim.
        // The batch is the tree plus this round's removals, never the round's
        // own change list. After a restart the framework's `Store` knows only
        // what is on disk, so filtering to what the service said changed means a
        // placeholder the user deleted locally never comes back — and the
        // restart is exactly when the framework has lost every other way to find
        // out. Removals first: they free the paths the upserts may claim.
        //
        // Narrowing this to the round's own changes was tried, on the grounds
        // that the five hundredth quiet round has nothing new to re-assert, and
        // `a_quiet_steady_state_round_reports_the_tree_rather_than_an_empty_batch`
        // refused it. It is right to: a quiet round would then be
        // `(vec![], new_cursor)`, which is the shape PROVIDER.md:103 forbids and
        // which one framework version ago consumed a refusal that had been
        // deliberately held back.
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
            // A repeat is the framework saying it could not apply the batch, so
            // the previous round's writes stay held: advancing the position now
            // is precisely what makes an unapplied tombstone unrecoverable.
            return Ok(served);
        }
        // Anything else is a cursor other than the one this instance was last
        // handed, which `hydration-sync` only produces after a pass it accepted
        // (`bin/hydration-sync.rs`, the delta thread: `cursor = next` on a
        // clean pass and on a quiet one, and the cursor left untouched on a
        // retryable one). That is the acknowledgement, and it is what makes the
        // previous round's pair safe to land — before this round reads the
        // store, so the round that follows builds on it.
        self.commit()?;
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
    // Rebuild the prior namespace to recover each vanished folder's path. A
    // raw snapshot intentionally stores parent ids rather than denormalised
    // paths, and a folder removal now has to name the local directory whose
    // identity is being withdrawn.
    let prior = Namespace::restore(before.to_vec());
    let gone: Vec<Change> = prior
        .listing()
        .into_iter()
        .filter_map(|change| match change {
            Change::Upserted { cloud_id, .. } if !present.contains(cloud_id.as_str()) => {
                Some(Change::Removed { cloud_id })
            }
            Change::FolderUpserted { cloud_id, path, .. }
                if !path.is_empty() && !present.contains(cloud_id.as_str()) =>
            {
                Some(Change::FolderRemoved { cloud_id, path })
            }
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

// ---------------------------------------------------------------------------
// The write seam
//
// The read half sends typed requests through `PageSource` because everything it
// has to prove is about *which page* was asked for. The write half has to prove
// things about the request itself — which URL an update was addressed at,
// whether a create declared a conflict behaviour, which `if-match` a
// conditional write carried, what a fragment's `content-range` said, and
// whether the account credential was attached — so its seam is one request and
// one reply, and the sink builds both.
//
// Same three properties as the read seam: injected, so no socket; recording, so
// the *interleaving* of a request and a sleep is observable; and scriptable, so
// the wrong branch can be made to succeed and only the log tells right from
// wrong.
// ---------------------------------------------------------------------------

use hydration_client::upload::Uploaded;

/// The verbs the write half uses.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Method {
    Get,
    Put,
    Post,
    Patch,
    Delete,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Put => "PUT",
            Method::Post => "POST",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
        }
    }
}

/// One request, as the sink hands it to the transport.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Request {
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Whether the transport may attach the account's bearer token.
    ///
    /// The decision belongs to the sink, not to the transport, because the sink
    /// is the only layer that knows where a URL came from. An upload session's
    /// `uploadUrl` is named by a *response body* and carries its own
    /// pre-authorisation — attaching the Graph token to it would hand a live
    /// write credential for the user's whole drive to whatever host that body
    /// named. A transport that decides for itself has no way to tell that URL
    /// apart from one this crate composed.
    pub authorize: bool,
}

impl Request {
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            headers: Vec::new(),
            body: Vec::new(),
            authorize: true,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Send this one without the account credential. See [`Request::authorize`].
    pub fn unauthorized(mut self) -> Self {
        self.authorize = false;
        self
    }

    /// Header lookup, case-insensitive: HTTP field names are.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One reply, before anything reads it as a `driveItem` or a session.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reply {
    pub status: u16,
    pub retry_after: Option<std::time::Duration>,
    pub body: Vec<u8>,
}

/// Where writes go. The write half of what the `http` feature implements — see
/// [`PageSource`] for the read half and [`auth::TokenTransport`] for the
/// credential.
pub trait Transport: Send {
    fn send(&mut self, request: &Request) -> io::Result<Reply>;
}

/// Graph's fragment quantum. Every fragment but the last must be a whole
/// multiple of it, or the *commit* fails — after the entire file has crossed
/// the wire.
pub const FRAGMENT_QUANTUM: usize = 320 * 1024;

/// The service's ceiling on one fragment.
pub const MAX_FRAGMENT_BYTES: usize = 60 * 1024 * 1024;

/// The largest body sent as a single PUT rather than through a session.
pub const MAX_SIMPLE_UPLOAD: u64 = 4 * 1024 * 1024;

/// The deepest a name may sit, counted over the whole decoded path from the
/// drive root.
pub const MAX_PATH_CHARS: usize = 400;

/// The byte ceiling on one path segment.
pub const MAX_NAME_BYTES: usize = 255;

/// How a large upload is chopped up, and where the session threshold sits.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct UploadPolicy {
    /// Must be a multiple of [`FRAGMENT_QUANTUM`] and below
    /// [`MAX_FRAGMENT_BYTES`].
    pub fragment_bytes: usize,
    /// Files at or below this go as one PUT.
    pub simple_upload_max: u64,
}

impl Default for UploadPolicy {
    fn default() -> Self {
        Self {
            // 10 MiB: inside the recommended 5–10 MiB band *and* exactly 32
            // quanta. 4 MiB is the tempting round number and 4194304 / 327680
            // is 12.8, which fails at the commit and nowhere earlier.
            fragment_bytes: 32 * FRAGMENT_QUANTUM,
            simple_upload_max: MAX_SIMPLE_UPLOAD,
        }
    }
}

/// The conflict behaviour a create declares.
///
/// Never defaulted, because the two v1.0 pages disagree about what the default
/// is: the `driveItem` resource says `replace` for PUT, `createUploadSession`
/// says `fail`. An omitted parameter is a bet on which page is right, per
/// endpoint, with the user's data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConflictBehavior {
    Fail,
    Rename,
    Replace,
}

impl ConflictBehavior {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConflictBehavior::Fail => "fail",
            ConflictBehavior::Rename => "rename",
            ConflictBehavior::Replace => "replace",
        }
    }
}

/// The write half: content up, objects removed.
///
/// Holds the two things the framework's `Sink` signature does not carry and the
/// write cannot be made safe without: the sync root, so a path can be resolved
/// to a drive-relative name at the moment the bytes are sent rather than from a
/// name captured earlier; and the content tags the last completed round
/// recorded, so a conditional write has a precondition that means something.
/// The tag comes from the persisted tree — not from a `GET` issued just before
/// the write, which is a precondition that can never fail.
pub struct GraphSink<T: Transport, K: Sleeper> {
    scope: DriveScope,
    root: std::path::PathBuf,
    tags: TagSource,
    known: std::collections::BTreeMap<String, String>,
    policy: UploadPolicy,
    transport: T,
    sleeper: K,
}

impl<T: Transport, K: Sleeper> GraphSink<T, K> {
    pub fn new(
        scope: DriveScope,
        root: impl Into<std::path::PathBuf>,
        tags: TagSource,
        transport: T,
        sleeper: K,
    ) -> Self {
        Self {
            scope,
            root: root.into(),
            tags,
            known: std::collections::BTreeMap::new(),
            policy: UploadPolicy::default(),
            transport,
            sleeper,
        }
    }

    pub fn with_policy(mut self, policy: UploadPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// What the last completed round recorded as this object's content tag.
    ///
    /// The tag an upload is *based on*, which is the only value an `if-match`
    /// may carry. A drive whose source is not [`TagSource::CTag`] has no value
    /// here that Graph will accept as a precondition, and that is a fact about
    /// the drive rather than a gap to be filled in with something else.
    pub fn record_tag(&mut self, cloud_id: &str, tag: &str) {
        self.known.insert(cloud_id.to_string(), tag.to_string());
    }

    pub fn scope(&self) -> &DriveScope {
        &self.scope
    }

    pub fn policy(&self) -> UploadPolicy {
        self.policy
    }
}

// --- addressing ------------------------------------------------------------
//
// Every URL below is composed here rather than at the call site, so the
// difference between the two addressing forms — by id and by name — is one
// function apart and cannot be reached by accident. The whole of Class A is
// that difference: a name resolves to whichever object currently holds it, and
// the delta pass renames local files itself, so the path an inode sits at
// routinely stops naming the object that inode claims.

/// The API version every URL in this half is built on.
const GRAPH_VERSION: &str = "v1.0";

/// `https://{host}/{version}/drives/{drive}` — the prefix every form shares.
fn drive_base(drive: &DriveId) -> String {
    format!(
        "https://{GRAPH_HOST}/{GRAPH_VERSION}/drives/{}",
        drive.as_str()
    )
}

/// Content, addressed by the identity the local file claims. The update form.
fn item_content_url(key: &ObjectKey) -> String {
    format!(
        "{}/items/{}/content",
        drive_base(key.drive()),
        key.item().as_str()
    )
}

/// The object itself: metadata with `GET`, the object with `DELETE`.
fn item_url(key: &ObjectKey) -> String {
    format!("{}/items/{}", drive_base(key.drive()), key.item().as_str())
}

fn item_children_url(key: &ObjectKey) -> String {
    format!(
        "{}/items/{}/children",
        drive_base(key.drive()),
        key.item().as_str()
    )
}

/// An upload session against an object that already exists.
fn item_session_url(key: &ObjectKey) -> String {
    format!(
        "{}/items/{}/createUploadSession",
        drive_base(key.drive()),
        key.item().as_str()
    )
}

/// Content, addressed by a drive-root-relative name. The create form, and the
/// only place in this half where a name reaches a URL at all.
fn path_content_url(drive: &DriveId, rel: &str, behaviour: ConflictBehavior) -> String {
    format!(
        "{}/root:/{}:/content?@microsoft.graph.conflictBehavior={}",
        drive_base(drive),
        encode_path(rel),
        behaviour.as_str()
    )
}

fn path_session_url(drive: &DriveId, rel: &str) -> String {
    format!(
        "{}/root:/{}:/createUploadSession",
        drive_base(drive),
        encode_path(rel)
    )
}

/// The properties a write's follow-up metadata read has to come back with.
///
/// The same discipline as [`REQUIRED_SELECT`]: a field nobody asks for reads as
/// `None` on every item, and a `None` here becomes an upload that reports no
/// content tag — which leaves version 1's tag on a file that now holds version
/// 2 and puts a placeholder over content the user just uploaded.
const WRITE_SELECT: &[&str] = &[
    "id",
    "name",
    "size",
    "eTag",
    "cTag",
    "file",
    "parentReference",
];

/// The metadata of whatever object currently holds a name.
///
/// Path-addressed on purpose, and it is the only read in this crate that is. It
/// answers one question — what is already sitting at the name a create just
/// collided with — and an id cannot ask it, because not knowing the id is the
/// whole situation.
fn path_metadata_url(drive: &DriveId, rel: &str) -> String {
    format!(
        "{}/root:/{}?$select={}",
        drive_base(drive),
        encode_path(rel),
        WRITE_SELECT.join(",")
    )
}

fn item_metadata_url(key: &ObjectKey) -> String {
    format!("{}?$select={}", item_url(key), WRITE_SELECT.join(","))
}

/// The path form Graph addresses a *name* with, percent-encoded.
///
/// `/` survives, because the segments below the sync root are part of the path
/// between `root:` and `:/content`. Nothing else outside the unreserved set
/// does: a `#` in a file name would otherwise cut the URL short and address the
/// *parent*, and a `%` or a `?` would turn the rest of the name into an escape
/// or a query — each of which lands a create on an object the user never named.
fn encode_path(rel: &str) -> String {
    let mut out = String::with_capacity(rel.len());
    for b in rel.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// --- names -----------------------------------------------------------------

/// Names the service refuses outright, compared case-insensitively and whole.
///
/// `.lock` and `desktop.ini` are on the same list as the DOS device names in
/// OneDrive's own documentation, so they are judged the same way.
const RESERVED_NAMES: &[&str] = &[
    ".lock",
    "desktop.ini",
    "con",
    "prn",
    "aux",
    "nul",
    "com0",
    "com1",
    "com2",
    "com3",
    "com4",
    "com5",
    "com6",
    "com7",
    "com8",
    "com9",
    "lpt0",
    "lpt1",
    "lpt2",
    "lpt3",
    "lpt4",
    "lpt5",
    "lpt6",
    "lpt7",
    "lpt8",
    "lpt9",
];

/// Characters the service will not hold in a name.
const RESERVED_CHARS: &[char] = &['"', '*', ':', '<', '>', '?', '\\', '|', '/'];

/// Whether this drive-relative name can exist in the cloud, judged before a
/// byte moves.
///
/// Two separate losses if this is left to the service. Sending it spends a whole
/// transfer that can only fail, and on a resumable upload the rejection arrives
/// at the *last* fragment — so a 2 GB file transfers 2 GB and then 400s, on
/// every retry, forever. Sanitising is worse: the object is created under a name
/// no local file has, and the next delta round places it as a second file beside
/// the one the user is editing.
///
/// The trailing period is refused for a third reason. Leading and trailing
/// spaces are documented as invalid, but a trailing period is not addressed at
/// all — so the service may reject it or may silently trim it, and if it trims,
/// the object is named `report`, the local file is `report.`, and the id gets
/// stamped onto a file whose name the cloud does not have. Refusing is the only
/// branch that cannot produce that pair.
fn check_relative_name(rel: &str) -> io::Result<()> {
    if rel.is_empty() {
        return Err(refused("a file with no name below the sync root"));
    }
    // Counted in characters, because the ceiling is on the decoded path Graph
    // shows the user, not on its percent-encoded form.
    if rel.chars().count() > MAX_PATH_CHARS {
        return Err(refused(format!(
            "the path is {} characters, and the service holds {MAX_PATH_CHARS}",
            rel.chars().count()
        )));
    }
    for segment in rel.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(refused("a path segment that names no object"));
        }
        if segment.len() > MAX_NAME_BYTES {
            return Err(refused(format!(
                "the segment {segment:?} is {} bytes, and the service holds {MAX_NAME_BYTES}",
                segment.len()
            )));
        }
        if segment.starts_with(' ') || segment.ends_with(' ') || segment.ends_with('.') {
            return Err(refused(format!(
                "{segment:?} would be trimmed or refused, and a trimmed name is one \
                 the local file does not have"
            )));
        }
        if segment.starts_with("~$") {
            return Err(refused(format!(
                "{segment:?} is a name the service reserves"
            )));
        }
        let unholdable =
            |c: char| RESERVED_CHARS.contains(&c) || (c as u32) < 0x20 || c == '\u{7f}';
        if segment.chars().any(unholdable) {
            return Err(refused(format!(
                "{segment:?} holds a character the service will not"
            )));
        }
        let folded = segment.to_ascii_lowercase();
        if folded.contains("_vti_") {
            return Err(refused(format!(
                "{segment:?} holds the reserved infix _vti_"
            )));
        }
        if RESERVED_NAMES.contains(&folded.as_str()) {
            return Err(refused(format!(
                "{segment:?} is a name the service reserves"
            )));
        }
    }
    Ok(())
}

// --- the local file --------------------------------------------------------

/// How much of the file's head is kept as evidence of *which* content the
/// transfer is describing.
const HEAD_BYTES: usize = 4096;

/// The inode a transfer describes, at the moment it started describing it.
///
/// `mtime` alone is not enough and the shortfall is not theoretical: the kernel
/// stamps an inode from a coarse clock, so a save that lands in the same tick as
/// the one before it moves nothing a comparison of stamps can see — and a save
/// that lands *during* the transfer is the whole case this guard exists for.
/// Size does not close it either, because an editor rewriting a file in place
/// usually produces the same length. The head is the cheapest byte-level
/// evidence there is that the inode still holds the document the earlier
/// fragments came from.
struct Snapshot {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: Option<std::time::SystemTime>,
    head: Vec<u8>,
}

/// Whether the file carries reclaim's eviction mark.
///
/// The mark, never the bytes. `reclaim::evict` builds a fresh inode sparse to
/// the object's full size, stamps it and renames it over the path, so a
/// placeholder is a file of NULs at the right size under the right name with its
/// own fresh stamp — nothing in the content distinguishes it from a freshly
/// `truncate`d database or a disk image, and refusing a body of zeros would
/// silently stop syncing both of those forever.
///
/// An xattr that cannot be *read* is treated as a placeholder rather than as an
/// ordinary file: the question is whether these bytes are the user's document,
/// and "I could not find out" is not an answer that may commit over one.
fn is_placeholder(path: &std::path::Path) -> io::Result<bool> {
    match hydration_client::store::get_xattr(path, hydration_protocol::xattr::DEHYDRATED) {
        Ok(mark) => Ok(mark.is_some()),
        Err(e) => Err(refused(format!(
            "cannot tell a placeholder from content at this path: {e}"
        ))),
    }
}

fn snapshot_of(file: &std::fs::File) -> io::Result<Snapshot> {
    use std::os::unix::fs::{FileExt, MetadataExt};
    let md = file.metadata()?;
    let len = md.len();
    let mut head = vec![0u8; std::cmp::min(len as usize, HEAD_BYTES)];
    if !head.is_empty() {
        // A short read is not padded here either: what was readable is what the
        // comparison is made against.
        let got = file.read_at(&mut head, 0)?;
        head.truncate(got);
    }
    Ok(Snapshot {
        dev: md.dev(),
        ino: md.ino(),
        len,
        mtime: md.modified().ok(),
        head,
    })
}

/// A whole small file, read through the handle it was judged through.
///
/// The size is a hint for the allocation and never a promise about what comes
/// back: a file that grew between the two is sent whole, and one that shrank is
/// sent short. The buffer is filled by reading rather than sized and handed to
/// the wire, because an untouched tail goes out as the user's data and the
/// service commits it.
fn read_whole(file: &std::fs::File, snap: &Snapshot) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut body = Vec::with_capacity(snap.len as usize);
    (&mut &*file).read_to_end(&mut body)?;
    Ok(body)
}

/// Whether the file at `path` is still the one `snap` describes.
///
/// Consulted before every fragment, because a session is minutes long and each
/// of the three ways it can stop being true commits something that has never
/// existed on any machine: an in-place save splices two documents together, a
/// truncation leaves the tail of the buffer to be sent as the user's data, and
/// an eviction replaces the file with a hole of exactly the right size.
fn unchanged(path: &std::path::Path, snap: &Snapshot) -> io::Result<()> {
    use std::os::unix::fs::{FileExt, MetadataExt};
    if is_placeholder(path)? {
        return Err(refused(
            "the file became a dehydrated placeholder while the transfer ran",
        ));
    }
    let file = std::fs::File::open(path)?;
    let md = file.metadata()?;
    if md.dev() != snap.dev || md.ino() != snap.ino {
        return Err(refused(
            "another inode took the path while the transfer ran",
        ));
    }
    if md.len() != snap.len {
        return Err(refused(format!(
            "the file is {} bytes and the transfer declared {}",
            md.len(),
            snap.len
        )));
    }
    if md.modified().ok() != snap.mtime {
        return Err(refused("the file was written while the transfer ran"));
    }
    let mut head = vec![0u8; snap.head.len()];
    if !head.is_empty() {
        let got = file.read_at(&mut head, 0)?;
        head.truncate(got);
    }
    if head != snap.head {
        return Err(refused(
            "the file's content changed while the transfer ran, without moving its \
             size or its timestamp",
        ));
    }
    Ok(())
}

// --- session wire shapes ---------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionBody {
    upload_url: Option<String>,
    next_expected_ranges: Option<Vec<String>>,
}

/// The offset the service is still waiting for, read from its own answer.
///
/// A starting point, never a size. The documentation carries an explicit warning
/// against using a range's length as the next fragment's length, because a
/// fragment that is not a whole number of quanta fails at the *commit* — after
/// the entire file has crossed the wire.
fn outstanding_offset(body: &[u8]) -> Option<u64> {
    let parsed: SessionBody = serde_json::from_slice(body).ok()?;
    let ranges = parsed.next_expected_ranges?;
    let first = ranges.first()?;
    first
        .split('-')
        .next()
        .and_then(|start| start.trim().parse::<u64>().ok())
}

// --- errors ----------------------------------------------------------------
//
// `run_upload` turns every `Err` into `Outcome::Failed(e.to_string())`, which
// the daemon logs and shows in status output. So an error string is a log line,
// and nothing that reaches one may name a credential.

fn refused(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, what.into())
}

/// A Graph refusal, named by the service's own error code.
fn service_refused(what: &str, status: u16, body: &[u8]) -> io::Error {
    let code = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error")
                .and_then(|e| e.get("code"))
                .and_then(|c| c.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    io::Error::other(format!("{what}: the service answered {status} {code}"))
}

/// The one answer an update with nothing to guard it may have.
///
/// Both forms refuse for the same reason and it is worth saying once: an update
/// is a write over a version somebody else may have moved on from, and the only
/// thing that catches that is a value this drive can offer as a precondition.
/// The cost is named rather than hidden — on a drive whose tags are hashes this
/// refuses every update to an object that already exists, and the framework then
/// keeps the file visibly unsent instead of overwriting a stranger's edit with
/// it.
/// What was about to be written, kept only long enough to compare it.
struct Sent {
    len: u64,
    hash: String,
}

/// Whether a refused write was refused because the *name* is taken.
///
/// By the service's own error code, never by the status alone: 409 also carries
/// quota and locking refusals, and treating those as a name collision would send
/// this into a content comparison that answers a question nobody asked.
fn collided_on_name(status: u16, body: &[u8]) -> bool {
    status == 409
        && serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("code"))
                    .and_then(|c| c.as_str())
                    .map(str::to_string)
            })
            .is_some_and(|c| c == "nameAlreadyExists")
}

fn no_precondition() -> io::Error {
    refused(
        "this drive offers no value the service accepts as a precondition, so the \
         update is refused rather than written blind",
    )
}

/// Everything an upload session can go wrong with, said without saying where.
///
/// The `uploadUrl` is a bearer credential — the documentation says to strip
/// `Authorization` when using it precisely because it carries its own — so the
/// URL, its host and its query are never allowed into a message, a `Debug`
/// rendering or a source chain. That is why the underlying error is discarded
/// here rather than wrapped: `source()` is walked when an error is rendered.
fn session_failed(what: &str) -> io::Error {
    io::Error::other(format!("the upload session {what}"))
}

/// How many times one Graph request may be re-issued before the call gives up.
///
/// Bounded, not "until it works". A failed upload is re-queued by the framework
/// and stays visibly unsent, so a bounded failure here costs a delay; an
/// unbounded retry costs the upload thread, and every edit behind it in the
/// queue exists nowhere but this machine.
const MAX_WRITE_ATTEMPTS: u32 = 4;

/// How many transport faults one session tolerates before it is abandoned.
const MAX_FRAGMENT_FAULTS: u32 = 3;

/// How many answers that do not move the outstanding offset forward a session
/// tolerates before it is given up as stuck.
///
/// A `202` is progress, and a `202` that names the same offset forever is not.
/// Without this the natural loop re-sends the completing fragment against a
/// service that never finishes assembling, for as long as the process lives.
const MAX_FRAGMENT_STALLS: u32 = 3;

/// A ceiling on fragments per session, for the case the stall counter cannot
/// see: a service that alternates between two outstanding offsets makes forward
/// progress by the counter's measure on every other answer and still never
/// converges.
const FRAGMENT_HEADROOM: u64 = 8;

impl<T: Transport, K: Sleeper> GraphSink<T, K> {
    // --- the transport, and the two retry policies -------------------------

    /// One Graph request, with throttling and transient service failures
    /// answered by waiting rather than by taking a different route.
    ///
    /// The *same* request object is re-sent, which is the whole point: the
    /// natural retry loop rebuilds the request from whatever is still in scope
    /// and drops the `if-match` on the way, and `429 activityLimitReached` is
    /// the single most common thing a busy drive answers — so that is not a rare
    /// path, it is most writes, and each one destroys the remote edit the
    /// precondition existed to catch.
    fn call(&mut self, request: &Request) -> io::Result<Reply> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let reply = self.transport.send(request)?;
            let transient = reply.status == 429 || (500..600).contains(&reply.status);
            if transient && attempt < MAX_WRITE_ATTEMPTS {
                // Never zero: `retry_after.unwrap_or_default()` re-issues
                // immediately against the endpoint that has just said it is
                // overloaded, and the ban that earns lands on the app
                // registration rather than on the user who caused it.
                self.sleeper
                    .sleep(reply.retry_after.unwrap_or(BLIND_BACKOFF));
                continue;
            }
            return Ok(reply);
        }
    }

    /// One request to a URL a *response body* named.
    ///
    /// Identical to [`GraphSink::call`] but for the error: nothing the transport
    /// says about this request may be propagated, because everything it can say
    /// contains the pre-authenticated URL.
    fn call_session(&mut self, request: &Request) -> io::Result<Reply> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let reply = match self.transport.send(request) {
                Ok(r) => r,
                Err(_) => return Err(session_failed("could not be reached")),
            };
            let transient = reply.status == 429 || (500..600).contains(&reply.status);
            if transient && attempt < MAX_WRITE_ATTEMPTS {
                self.sleeper
                    .sleep(reply.retry_after.unwrap_or(BLIND_BACKOFF));
                continue;
            }
            return Ok(reply);
        }
    }

    /// The `if-match` an update to `cloud_id` may carry, if there is one.
    ///
    /// Not "some header": `if-match: *` matches any version and a quickXor hash
    /// matches none, so the first is the blind overwrite this precondition
    /// exists to forbid and the second rejects every attempt forever. A drive
    /// whose tags are hashes has no value Graph accepts as a precondition, and
    /// that is a fact about the drive rather than a gap to fill in.
    ///
    /// The tag is the one the *last completed round* recorded — the version this
    /// upload is based on — never one read back immediately before the write,
    /// which is a precondition that can never fail and silently overwrites the
    /// newer version it has just seen.
    fn precondition(&self, cloud_id: &str) -> Option<String> {
        let tag = self.known.get(cloud_id)?;
        if let Some(raw) = tag.strip_prefix("et:").filter(|raw| !raw.is_empty()) {
            return Some(raw.to_string());
        }
        if self.tags == TagSource::CTag {
            if let Some(raw) = tag.strip_prefix("ct:").filter(|raw| !raw.is_empty()) {
                return Some(raw.to_string());
            }
        }
        None
    }

    /// The content tag of the version an object holds right now.
    fn read_tag(&mut self, key: &ObjectKey) -> io::Result<Option<String>> {
        let reply = self.call(&Request::new(Method::Get, item_metadata_url(key)))?;
        if !(200..300).contains(&reply.status) {
            return Err(service_refused(
                "the object's metadata could not be read",
                reply.status,
                &reply.body,
            ));
        }
        let item: DriveItem = serde_json::from_slice(&reply.body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        Ok(content_tag(&item.body(), self.tags).ok())
    }

    /// What a successful write means, once the service has answered.
    ///
    /// The id comes from the response and is drive-qualified here, never taken
    /// from `existing`: some services renumber an item on write, and a cloud id
    /// naming an object the service has replaced can never be fetched again.
    /// The drive is the one the request was addressed at — the only drive this
    /// call can know the object is on.
    fn settle(&mut self, drive: &DriveId, body: &[u8]) -> io::Result<Uploaded> {
        let item: DriveItem = serde_json::from_slice(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        let Some(raw) = item.id.as_deref() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the service accepted the write and named no object",
            ));
        };
        let key = ObjectKey::new(
            drive.clone(),
            ItemId::parse(raw).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the service named {e:?}"),
                )
            })?,
        );
        // Graph's documented default property set carries no cTag and no
        // hashes, and hashes routinely lag a write. `store::adopt_cloud_id`
        // writes the etag only when it is `Some` and never clears a stale one,
        // so punting here leaves the *previous* version's tag on a file that
        // now holds this one — and the next delta pass puts a placeholder over
        // content the user has just successfully uploaded. Reading it back
        // costs one request; inventing one is not available, and failing would
        // re-queue an upload that already happened, forever.
        let tag = match content_tag(&item.body(), self.tags) {
            Ok(t) => Some(t),
            Err(_) => self.read_tag(&key)?,
        };
        let cloud_id = key.to_cloud_id().into_inner();
        if let Some(t) = &tag {
            // Remembered so a `remove` seconds later can be conditional on the
            // version this sink wrote, rather than on whatever another device
            // has committed since.
            self.known.insert(cloud_id.clone(), t.clone());
        }
        Ok(Uploaded {
            cloud_id,
            etag: tag,
        })
    }

    fn settle_folder(&mut self, drive: &DriveId, body: &[u8]) -> io::Result<Uploaded> {
        let item: DriveItem = serde_json::from_slice(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        if !matches!(shape_of(&item), Shape::Folder) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the service answered a folder write with an object that is not an ordinary folder",
            ));
        }
        let raw_id = item.id.as_deref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the service accepted the folder write and named no object",
            )
        })?;
        let key = ObjectKey::new(
            drive.clone(),
            ItemId::parse(raw_id).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("the service named {e:?}"),
                )
            })?,
        );
        let raw_tag = item
            .e_tag
            .as_deref()
            .filter(|tag| !tag.is_empty())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the service accepted the folder write but returned no eTag",
                )
            })?;
        let cloud_id = key.to_cloud_id().into_inner();
        let tag = format!("et:{raw_tag}");
        self.known.insert(cloud_id.clone(), tag.clone());
        Ok(Uploaded {
            cloud_id,
            etag: Some(tag),
        })
    }

    /// Reconcile a create whose name is already occupied by an ordinary folder.
    ///
    /// Folder identity has no content hash to prove, and it does not need one:
    /// two same-name ordinary folders beneath the same stable parent represent
    /// the same namespace container and their children are merged by identity.
    /// Files and packages are never adopted through this path.
    fn reconcile_folder(&mut self, drive: &DriveId, rel: &str) -> io::Result<Option<Uploaded>> {
        let reply = self.call(&Request::new(Method::Get, path_metadata_url(drive, rel)))?;
        if !(200..300).contains(&reply.status) {
            return Err(service_refused(
                "the object already at this folder name could not be read",
                reply.status,
                &reply.body,
            ));
        }
        let item: DriveItem = serde_json::from_slice(&reply.body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        let ours = rel.rsplit('/').next().unwrap_or(rel);
        if item.name.as_deref() != Some(ours) || !matches!(shape_of(&item), Shape::Folder) {
            return Ok(None);
        }
        self.settle_folder(drive, &reply.body).map(Some)
    }

    // --- the simple form ---------------------------------------------------

    /// A whole file as one `PUT`, at the object the local file claims.
    fn put_at_item(
        &mut self,
        key: &ObjectKey,
        cloud_id: &str,
        body: Vec<u8>,
    ) -> io::Result<Written> {
        let Some(tag) = self.precondition(cloud_id) else {
            return Err(no_precondition());
        };
        let request = Request::new(Method::Put, item_content_url(key))
            .with_header("if-match", &tag)
            .with_header("content-type", "application/octet-stream")
            .with_body(body);
        let reply = self.call(&request)?;
        match reply.status {
            200..=299 => Ok(Written::Done(self.settle(key.drive(), &reply.body)?)),
            // The one place a failed update may become a create, and it is one
            // token wide: `if !reply.ok()` where `if status == 404` was meant
            // answers a throttle with a second object holding the same document
            // under the same name, and the two then chase each other.
            404 => Ok(Written::Gone),
            _ => Err(service_refused(
                "the update was refused",
                reply.status,
                &reply.body,
            )),
        }
    }

    /// A whole file as one `PUT`, at a name the drive may or may not hold.
    /// Whether the object already at `rel` is byte for byte what we just tried
    /// to send.
    ///
    /// `Ok(Some(u))` means it is, and `u` names it — the caller adopts that
    /// identity and no write is made. `Ok(None)` means it is a different
    /// document. `Err` means the question could not be answered, which is a
    /// third thing and must not be collapsed into the second: reporting "they
    /// differ" for a request that failed would strand a file for a reason that
    /// was never established.
    ///
    /// Size first, because it is free and settles almost every case. The hash is
    /// what makes the answer a proof rather than a guess — two files of the same
    /// length are routine, and a length check alone would adopt a stranger's
    /// object whenever it happened to match, which is the exact failure the
    /// collision branch exists to prevent.
    fn reconcile_by_content(
        &mut self,
        drive: &DriveId,
        rel: &str,
        sent: &Sent,
    ) -> io::Result<Option<Uploaded>> {
        let reply = self.call(&Request::new(Method::Get, path_metadata_url(drive, rel)))?;
        if !(200..300).contains(&reply.status) {
            return Err(service_refused(
                "the object already at this name could not be read",
                reply.status,
                &reply.body,
            ));
        }
        let item: DriveItem = serde_json::from_slice(&reply.body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        let body = item.body();
        // The name has to match exactly, and this is not pedantry.
        //
        // Graph resolves a path case-insensitively, so `report.txt` finds an
        // object named `Report.txt` and answers `409 nameAlreadyExists` for a
        // create at either. If the two happen to hold the same bytes — an
        // ordinary thing for a copy — adopting on content alone would give two
        // distinct local files one object id. Both would read Clean, and
        // deleting either would remove the object the other depends on. The
        // existing `two_local_names_differing_only_in_case_stay_two_objects`
        // caught precisely that, which is what a suite is for.
        let ours = rel.rsplit('/').next().unwrap_or(rel);
        if item.name.as_deref() != Some(ours) {
            return Ok(None);
        }
        // `as_u64` the same way the mapper does: the service sends this as a
        // number or as a string depending on the endpoint, and a size that will
        // not convert is a size we do not know.
        if body.size.and_then(|v| v.as_u64()) != Some(sent.len) {
            return Ok(None);
        }
        // A drive that reports no hash cannot prove anything, and an unproven
        // adoption is the thing this must not do.
        let Some(theirs) = body.hashes.and_then(|h| h.quick_xor_hash.as_deref()) else {
            return Ok(None);
        };
        if theirs != sent.hash || sent.hash.is_empty() {
            return Ok(None);
        }
        self.settle(drive, &reply.body).map(Some)
    }

    fn put_at_path(&mut self, rel: &str, body: Vec<u8>) -> io::Result<Uploaded> {
        check_relative_name(rel)?;
        let drive = self.scope.drive().clone();
        // Hashed before the body is handed to the request, which consumes it.
        // Only paid for when the write collides — the hash is cheap next to the
        // transfer that just happened, and it is the only thing that can tell a
        // stranger's file from this one.
        let sent = Sent {
            len: body.len() as u64,
            hash: quickxor_of(&body),
        };
        let request = Request::new(
            Method::Put,
            // Never `replace`, and never `rename`. A create has never seen the
            // object it would be replacing, and `rename` invents `notes 1.txt` —
            // an object no local file claims, stamped onto the inode that asked
            // for `notes.txt`. The parameter is never omitted either: the two
            // v1.0 pages disagree about the default, so an omitted parameter is
            // a bet on which page is right, with the user's data.
            path_content_url(&drive, rel, ConflictBehavior::Fail),
        )
        .with_header("content-type", "application/octet-stream")
        .with_body(body);
        let reply = self.call(&request)?;
        match reply.status {
            200..=299 => self.settle(&drive, &reply.body),
            // A collision is answered by stopping. Adopting the other object's
            // id writes a stranger's item id onto the local inode: reclaim may
            // then evict the local file, the next read fetches their document,
            // and when the user deletes their own file the framework calls
            // `remove` on the stranger's object.
            //
            // Every one of those consequences rests on the object being a
            // *stranger's*. If the bytes already at that name are the bytes we
            // were about to send, it is not a stranger's document — it is this
            // one, and adopting its id is not a write at all. Evicting and
            // refetching gives back the same content; removing it removes the
            // object the file actually is.
            //
            // So the collision is reconciled when, and only when, the content
            // can be proved identical. This is what strands a file whose
            // extended attributes were destroyed by an atomic save before
            // anything recorded them: it has no id, the create collides, and
            // until now the answer was to fail forever. Measured on a live
            // account on 2026-08-13 — five files, retried in a loop for hours,
            // three of them git pack files whose names are content-addressed
            // and which therefore could never have differed.
            _ if collided_on_name(reply.status, &reply.body) => {
                match self.reconcile_by_content(&drive, rel, &sent) {
                    Ok(Some(u)) => Ok(u),
                    Ok(None) => Err(refused(
                        "a different file already exists in the cloud under this name, and this \
                         copy has no record of which version it was based on, so it \
                         cannot be sent without overwriting that one blind",
                    )),
                    // Could not find out. Not the same as "they differ", and it
                    // must not be reported as though it were.
                    Err(e) => Err(io::Error::other(format!(
                        "a file already exists in the cloud under this name, and whether it \
                         holds the same content could not be established: {e}"
                    ))),
                }
            }
            _ => Err(service_refused(
                "the create was refused",
                reply.status,
                &reply.body,
            )),
        }
    }

    // --- the resumable form ------------------------------------------------

    /// Open a session, transfer the file through it, and commit.
    fn upload_session(
        &mut self,
        path: &std::path::Path,
        rel: &str,
        target: Option<(ObjectKey, String)>,
        file: &std::fs::File,
        snap: &Snapshot,
    ) -> io::Result<Written> {
        let drive = match &target {
            Some((key, _)) => key.drive().clone(),
            None => self.scope.drive().clone(),
        };
        let (url, behaviour) = match &target {
            // An update's session is created *at the item*. A path-addressed
            // one lands on whichever object now holds the name — and the
            // framework's rename repair calls back with the id it was just
            // given and relies entirely on that second call updating that
            // object, so a path-addressed session orphans the first one under
            // its temp name forever.
            //
            // `replace` rather than `fail`, and only because the URL names the
            // object: the behaviour governs a *name* collision, and the name in
            // question is the object's own. `fail` would make every large update
            // collide with itself, which is the other way to lose an edit. A
            // path-addressed session gets `fail` for exactly the opposite
            // reason — it has never seen what it would be replacing.
            Some((key, cloud_id)) => {
                // Asked here, before the transfer rather than at the commit.
                // The pre-commit re-read compares against this tag, so without
                // one the session can only ever be abandoned — after the whole
                // file has crossed the wire, on every retry, forever.
                if self.precondition(cloud_id).is_none() {
                    return Err(no_precondition());
                }
                (item_session_url(key), ConflictBehavior::Replace)
            }
            None => {
                check_relative_name(rel)?;
                (path_session_url(&drive, rel), ConflictBehavior::Fail)
            }
        };
        // The body carries the conflict behaviour and nothing else. A `name`
        // here would rename the object the session is addressed at, which is
        // the one thing an update must never do.
        let body = serde_json::json!({
            "item": {"@microsoft.graph.conflictBehavior": behaviour.as_str()},
        })
        .to_string();
        let reply = self.call(
            &Request::new(Method::Post, url)
                .with_header("content-type", "application/json")
                .with_body(body.into_bytes()),
        )?;
        if reply.status == 404 && target.is_some() {
            return Ok(Written::Gone);
        }
        if !(200..300).contains(&reply.status) {
            return Err(service_refused(
                "the upload session was refused",
                reply.status,
                &reply.body,
            ));
        }
        let session: SessionBody = serde_json::from_slice(&reply.body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e}")))?;
        let Some(upload_url) = session.upload_url.filter(|u| u.starts_with("https://")) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the service opened an upload session at no usable URL",
            ));
        };

        let outcome = self.transfer(path, &upload_url, &target, file, snap);
        match outcome {
            Ok(Transferred::Committed(body)) => Ok(Written::Done(self.settle(&drive, &body)?)),
            // The session is already gone; there is nothing at the far end to
            // cancel, and a `DELETE` would only ask a second time.
            Ok(Transferred::Vanished) => Err(session_failed(
                "vanished before the transfer committed, and a session that has \
                 completed vanishes the same way — so nothing here is evidence the \
                 content landed",
            )),
            Ok(Transferred::Abandoned(e)) | Err(e) => {
                // The destination item is untouched until the commit, so a failed
                // session has nothing of its own to clean up but the staged
                // bytes. On OneDrive Personal those count against quota until
                // expiry, so leaving them turns repeated failures into a drive
                // full of invisible partial copies and unrelated uploads start
                // failing 507. "Delete the item I was writing to" would recycle
                // the user's complete previous version instead.
                let _ = self
                    .call_session(&Request::new(Method::Delete, upload_url.clone()).unauthorized());
                Err(e)
            }
        }
    }

    /// The fragment protocol: what to send next is the service's answer, not a
    /// local byte counter.
    fn transfer(
        &mut self,
        path: &std::path::Path,
        upload_url: &str,
        target: &Option<(ObjectKey, String)>,
        file: &std::fs::File,
        snap: &Snapshot,
    ) -> io::Result<Transferred> {
        use std::os::unix::fs::FileExt;

        // Fixed here and never recomputed. "Your app must ensure the total file
        // size specified in the Content-Range header is the same for all
        // requests" — and a `metadata()` call inside the loop turns any save
        // during a long upload into a wasted whole-file transfer.
        let total = snap.len;
        let fragment = self.fragment_bytes();
        let ceiling = total / fragment as u64 + FRAGMENT_HEADROOM + 1;

        let mut offset = 0u64;
        let mut stalls = 0u32;
        let mut faults = 0u32;
        let mut sent = 0u64;
        // Once per session, immediately before the first attempt at the
        // fragment that completes the file. Re-reading before *every* attempt
        // doubles the request count against an endpoint that is already
        // answering slowly, and the question it asks is the same one.
        let mut rechecked = false;

        while offset < total {
            if sent > ceiling {
                return Ok(Transferred::Abandoned(session_failed(
                    "never converged on an outstanding range",
                )));
            }
            sent += 1;

            // Before the bytes are read, every time: a session is minutes long,
            // and the reclaim guard that would otherwise cover this is read
            // outside the transfer.
            unchanged(path, snap)?;

            let len = std::cmp::min(fragment as u64, total - offset) as usize;
            let mut buf = vec![0u8; len];
            // `read_exact_at`, never `read`: `read` may return short and its
            // return value is easy to discard, and then the untouched tail of
            // the buffer goes on the wire as the user's data and the service
            // commits it.
            file.read_exact_at(&mut buf, offset)?;
            let end = offset + len as u64 - 1;

            if end + 1 == total && !rechecked {
                rechecked = true;
                if let Some((key, cloud_id)) = target {
                    // `if-match` on an upload session is evaluated when the
                    // session is created and never re-evaluated when the bytes
                    // commit. A 12 MiB file is seconds; a 2 GB file is an hour,
                    // and every remote edit made during that hour is destroyed
                    // by the commit.
                    let based_on = self.known.get(cloud_id).cloned();
                    let now = self.read_tag(key)?;
                    if now.is_none() || now != based_on {
                        return Ok(Transferred::Abandoned(refused(
                            "the object moved on under the session, so the commit \
                             would overwrite a version this machine has never seen",
                        )));
                    }
                }
            }

            let request = Request::new(Method::Put, upload_url.to_string())
                .with_header("content-range", &format!("bytes {offset}-{end}/{total}"))
                .with_body(buf)
                // The `uploadUrl` carries its own pre-authorisation. Attaching
                // the Graph token would hand a live write credential for the
                // user's whole drive to whatever host a response body named.
                .unauthorized();
            let reply = match self.call_session(&request) {
                Ok(r) => r,
                Err(e) => {
                    faults += 1;
                    if faults >= MAX_FRAGMENT_FAULTS {
                        return Ok(Transferred::Abandoned(e));
                    }
                    // The server's view is the authoritative one, so a lost
                    // fragment is resolved by asking where it is rather than by
                    // restarting the session or by assuming the local counter
                    // was right. If the probe cannot be reached either, the
                    // same fragment goes again from the same offset.
                    if let Some(at) = self.probe(upload_url) {
                        offset = at;
                    }
                    continue;
                }
            };

            match reply.status {
                // The commit. Only a `200` or a `201` is one: `202` is a
                // success status to every HTTP client library and means the
                // service has the bytes and has not assembled them, so an early
                // return here stamps the file Clean over content that was never
                // committed.
                200 | 201 => return Ok(Transferred::Committed(reply.body)),
                202 => {
                    let next = outstanding_offset(&reply.body).unwrap_or(end + 1);
                    if next >= total {
                        return Ok(Transferred::Abandoned(session_failed(
                            "accepted every byte without committing any of them",
                        )));
                    }
                    // `offset.max(next)` is a one-word defensive clamp that
                    // silently discards the only signal a chunk was lost, and
                    // the session can then never commit. The server's
                    // outstanding range is honoured even when it goes backwards.
                    if next <= offset {
                        stalls += 1;
                        if stalls >= MAX_FRAGMENT_STALLS {
                            return Ok(Transferred::Abandoned(session_failed(
                                "kept asking for a range it had already been sent",
                            )));
                        }
                    } else {
                        stalls = 0;
                    }
                    offset = next;
                }
                416 => {
                    // The range is not one the service is willing to take. Read
                    // as fatal this makes every lost fragment a permanently
                    // failing upload; read as "restart" it re-transfers
                    // gigabytes on a blip; read as "it already has it" it
                    // returns Ok with no commit at all.
                    match self.probe(upload_url) {
                        Some(at) => offset = at,
                        None => {
                            return Ok(Transferred::Abandoned(session_failed(
                                "refused the range and would not say which it wanted",
                            )))
                        }
                    }
                }
                // A session vanishes on expiry, on `DELETE` *and* on successful
                // completion, so this is genuinely ambiguous. Resolving it
                // optimistically returns Ok for content that never committed;
                // resolving it by deleting the item destroys the good version
                // too. Reporting it re-queues one upload.
                404 | 410 => return Ok(Transferred::Vanished),
                _ => {
                    return Ok(Transferred::Abandoned(service_refused(
                        "a fragment was refused",
                        reply.status,
                        &reply.body,
                    )))
                }
            }
        }

        // Every declared byte has been offered and nothing was answered as a
        // commit.
        Ok(Transferred::Abandoned(session_failed(
            "took the whole file and never committed it",
        )))
    }

    /// Where the service says the transfer is.
    ///
    /// Best effort: a probe that cannot be reached leaves the caller to resend
    /// from where it was, which is correct and merely wasteful.
    fn probe(&mut self, upload_url: &str) -> Option<u64> {
        let reply = self
            .call_session(&Request::new(Method::Get, upload_url.to_string()).unauthorized())
            .ok()?;
        if !(200..300).contains(&reply.status) {
            return None;
        }
        outstanding_offset(&reply.body)
    }

    /// The fragment size, held to the two limits that only fail at the commit.
    ///
    /// A size that is not a whole number of quanta fails *after* the entire file
    /// has crossed the wire, so a policy that names one is corrected here rather
    /// than believed.
    fn fragment_bytes(&self) -> usize {
        let quanta = (self.policy.fragment_bytes / FRAGMENT_QUANTUM).max(1);
        let ceiling = (MAX_FRAGMENT_BYTES - 1) / FRAGMENT_QUANTUM;
        std::cmp::min(quanta, ceiling) * FRAGMENT_QUANTUM
    }
}

/// What one write attempt settled on.
enum Written {
    Done(Uploaded),
    /// The service does not have the object the local file claims. The local
    /// file is now the only copy, so this becomes a create — the one and only
    /// place in this half where a failed update may.
    Gone,
}

/// What one session's transfer settled on.
enum Transferred {
    Committed(Vec<u8>),
    /// The session is no longer there, and a completed session is gone the same
    /// way — so this is not evidence either way.
    Vanished,
    Abandoned(io::Error),
}

impl<T: Transport, K: Sleeper> hydration_client::upload::Sink for GraphSink<T, K> {
    fn upload(
        &mut self,
        path: &std::path::Path,
        existing: Option<hydration_client::upload::Known<'_>>,
    ) -> io::Result<Uploaded> {
        // §5.5 states the absence rule about the moment an upload *finishes*.
        // The moment it starts is the same fact: `run_upload` folds `ENOENT`
        // into `None` and calls this anyway, so the path is routinely one that
        // no longer exists. `fs::read(path).unwrap_or_default()` would replace
        // the user's document with an empty object, and answering from a
        // remembered copy of the last call restores the file they just deleted.
        // An empty file that *exists* is content and still uploads: refusing it
        // leaves the pre-truncation version in the cloud permanently.
        let file = std::fs::File::open(path)?;
        if is_placeholder(path)? {
            return Err(refused(
                "the file is a dehydrated placeholder, and its holes are not the \
                 user's document",
            ));
        }
        let snap = snapshot_of(&file)?;

        // Resolved now, from the path the framework resolved now — never from a
        // name captured when the job was queued (§5.4).
        //
        // Judged only where it is *sent*, which is the create forms and the
        // fallback below. An update is addressed by id and carries no name at
        // all, so refusing one for a name the service dislikes would strand an
        // edit to an object whose remote name is already whatever the service
        // agreed to — a local file called `report .docx` that the cloud holds as
        // `report.docx` is an ordinary state, and its edits still have to leave
        // the laptop.
        let rel = path
            .strip_prefix(&self.root)
            .map_err(|_| refused("the file is not under this sink's sync root"))?
            .to_str()
            .ok_or_else(|| refused("the path below the sync root is not UTF-8"))?
            .to_string();

        let target = match existing {
            None => None,
            Some(known) => {
                let cloud_id = known.cloud_id;
                let Some(key) = key_of_cloud_id(cloud_id) else {
                    // A junk id is a damaged record of *which* object this file
                    // is. Creating a second one instead would put the same
                    // document in the cloud twice under one name, and the two
                    // would then overwrite each other every round; the error is
                    // visible and the file stays queued.
                    return Err(refused(
                        "the recorded cloud id names no drive and no item, so there is \
                         no object this write could be addressed at",
                    ));
                };
                // Seed this process's memory from the framework's durable
                // record, so a conditional write has something to be conditional
                // on.
                //
                // Without this, `known` is populated by `record_tag` — and
                // `record_tag` was called from forty-three tests and from
                // nothing else in either repository. On a live account the map
                // was therefore always empty, `precondition` always answered
                // `None`, and every update to an object that already existed was
                // refused for want of a precondition. Measured 2026-08-13: six
                // files sat unsent for hours, retried in a loop, while the tag
                // each one was based on lay in its own `user.hydration.etag`.
                //
                // `or_insert`, never overwrite: what this process learned from a
                // completed round is at least as fresh as what is on the file,
                // and the tag an update may carry is the one it is *based on* —
                // taking the newer of the two is how a precondition stops being
                // able to fail.
                //
                // A stale tag is the safe direction to be wrong in. It fails the
                // `if-match` and the edit stays queued and visible, which is the
                // outcome this whole path exists to choose over a blind write.
                if let Some(tag) = known.tag {
                    self.known
                        .entry(cloud_id.to_string())
                        .or_insert_with(|| tag.to_string());
                }
                Some((key, cloud_id.to_string()))
            }
        };

        // The size observed once, before the first byte is read. Both the
        // threshold and every `content-range` come from it.
        if snap.len > self.policy.simple_upload_max {
            return match self.upload_session(path, &rel, target, &file, &snap)? {
                Written::Done(u) => Ok(u),
                Written::Gone => self.create(path, &rel),
            };
        }

        // Read through the handle the checks above were made against, so the
        // whole body is one inode's worth of bytes even if the path is renamed
        // out from under it while the read runs.
        let body = read_whole(&file, &snap)?;
        match &target {
            Some((key, cloud_id)) => {
                let key = key.clone();
                let cloud_id = cloud_id.clone();
                match self.put_at_item(&key, &cloud_id, body)? {
                    Written::Done(u) => Ok(u),
                    Written::Gone => self.create(path, &rel),
                }
            }
            None => self.put_at_path(&rel, body),
        }
    }

    fn move_item(
        &mut self,
        from: &std::path::Path,
        to: &std::path::Path,
        existing: hydration_client::upload::Known<'_>,
    ) -> io::Result<Uploaded> {
        let from_rel = from
            .strip_prefix(&self.root)
            .map_err(|_| refused("the old path is not under this sink's sync root"))?;
        let to_rel = to
            .strip_prefix(&self.root)
            .map_err(|_| refused("the new path is not under this sink's sync root"))?;
        let from_parent = from_rel
            .parent()
            .unwrap_or_else(|| std::path::Path::new(""));
        let to_parent = to_rel.parent().unwrap_or_else(|| std::path::Path::new(""));
        let to_rel = to_rel
            .to_str()
            .ok_or_else(|| refused("the new path below the sync root is not UTF-8"))?;
        check_relative_name(to_rel)?;
        let name = to
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| refused("the new file name is not UTF-8"))?;

        let Some(key) = key_of_cloud_id(existing.cloud_id) else {
            return Err(refused(
                "the recorded cloud id names no drive and no item, so there is no object to move",
            ));
        };
        if let Some(tag) = existing.tag {
            self.known
                .entry(existing.cloud_id.to_string())
                .or_insert_with(|| tag.to_string());
        }
        let Some(precondition) = self.precondition(existing.cloud_id) else {
            return Err(no_precondition());
        };
        let mut patch = serde_json::json!({"name": name});
        if from_parent != to_parent {
            let parent = to.parent().ok_or_else(|| {
                refused("the new path has no destination folder below the sync root")
            })?;
            let parent_id = hydration_client::store::get_xattr(
                parent,
                hydration_client::store::XATTR_ID,
            )?
            .and_then(|raw| String::from_utf8(raw).ok())
            .ok_or_else(|| {
                refused(
                    "the destination folder has no recorded cloud identity; the object was not moved by path",
                )
            })?;
            let parent_key = key_of_cloud_id(&parent_id)
                .ok_or_else(|| refused("the destination folder's cloud identity is malformed"))?;
            if parent_key.drive() != key.drive() {
                return Err(refused(
                    "moving an object between drives is not a same-drive folder move",
                ));
            }
            patch["parentReference"] = serde_json::json!({"id": parent_key.item().as_str()});
        }
        let body = patch.to_string().into_bytes();
        let reply = self.call(
            &Request::new(Method::Patch, item_url(&key))
                .with_header("if-match", &precondition)
                .with_header("content-type", "application/json")
                .with_body(body),
        )?;
        match reply.status {
            200..=299 if to.is_dir() => self.settle_folder(key.drive(), &reply.body),
            200..=299 => self.settle(key.drive(), &reply.body),
            _ => Err(service_refused(
                "the object was not renamed",
                reply.status,
                &reply.body,
            )),
        }
    }

    fn create_folder(&mut self, path: &std::path::Path) -> io::Result<Uploaded> {
        let rel = path
            .strip_prefix(&self.root)
            .map_err(|_| refused("the folder is not under this sink's sync root"))?
            .to_str()
            .ok_or_else(|| refused("the folder path below the sync root is not UTF-8"))?;
        check_relative_name(rel)?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| refused("the folder name is not UTF-8"))?;
        let parent = path
            .parent()
            .ok_or_else(|| refused("the folder has no parent below the sync root"))?;
        let parent_id =
            hydration_client::store::get_xattr(parent, hydration_client::store::XATTR_ID)?
                .and_then(|raw| String::from_utf8(raw).ok())
                .ok_or_else(|| refused("the parent folder has no recorded cloud identity"))?;
        let parent_key = key_of_cloud_id(&parent_id)
            .ok_or_else(|| refused("the parent folder's cloud identity is malformed"))?;
        if parent_key.drive() != self.scope.drive() {
            return Err(refused(
                "the parent folder belongs to another drive; this create cannot be addressed there",
            ));
        }
        let body = serde_json::json!({
            "name": name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "fail",
        })
        .to_string()
        .into_bytes();
        let reply = self.call(
            &Request::new(Method::Post, item_children_url(&parent_key))
                .with_header("content-type", "application/json")
                .with_body(body),
        )?;
        match reply.status {
            200..=299 => self.settle_folder(parent_key.drive(), &reply.body),
            _ if collided_on_name(reply.status, &reply.body) => {
                match self.reconcile_folder(parent_key.drive(), rel) {
                    Ok(Some(folder)) => Ok(folder),
                    Ok(None) => Err(refused(
                        "a different object already exists in the cloud under this folder name; \
                         it was not adopted or replaced",
                    )),
                    Err(e) => Err(e),
                }
            }
            _ => Err(service_refused(
                "the folder was not created",
                reply.status,
                &reply.body,
            )),
        }
    }

    fn remove(&mut self, cloud_id: &str) -> io::Result<()> {
        // Before a request, not after a response. `rsplit('|').next()
        // .unwrap_or(cloud_id)` turns junk in an extended attribute — one
        // written by an older build, or by another provider — into a live
        // `DELETE` against a real endpoint, and item ids are unique per drive,
        // so a shared-drive id sent to the user's own drive either 404s or
        // removes something unrelated.
        let Some(key) = key_of_cloud_id(cloud_id) else {
            return Err(refused(
                "the cloud id names no drive and no item, so there is no object to \
                 remove",
            ));
        };
        let mut request = Request::new(Method::Delete, item_url(&key));
        // Conditional when it can be. §5.5 makes the local delete win, and it
        // is right about the *file* — it says nothing about the *version* the
        // object holds. `run_upload`'s delete-during-upload path removes an id
        // this sink wrote seconds earlier and whose tag it therefore knows; if
        // another device committed in between, an unconditional `DELETE`
        // recycle-bins work that was never on this machine at all. A
        // precondition the sink cannot supply is not a reason to strand the
        // user's delete, so an object with no recorded tag is removed anyway.
        if let Some(tag) = self.precondition(cloud_id) {
            request = request.with_header("if-match", &tag);
        }
        // Never `permanentDelete`, which needs no permission beyond an ordinary
        // delete and has no undo — the recycle bin is the only recovery a
        // business drive has. Never `prefer: bypass-shared-lock` either: a
        // coauthoring lock means somebody has the document open, and it is not
        // ours to bypass.
        let reply = self.call(&request)?;
        match reply.status {
            // Already gone is the state that was wanted. An error here makes
            // the framework retry forever, so the object is never removed and
            // comes back down the delta feed to resurrect the file the user
            // deleted.
            200..=299 | 404 => Ok(()),
            // A `412` is another device's newer version saying so, and
            // re-issuing without the precondition is the same instinct as
            // retrying a `412` on a write — except that a `DELETE` has no
            // version history behind it to recover from.
            _ => Err(service_refused(
                "the object was not removed",
                reply.status,
                &reply.body,
            )),
        }
    }

    fn remove_known(&mut self, existing: hydration_client::upload::Known<'_>) -> io::Result<()> {
        if let Some(tag) = existing.tag {
            self.known
                .entry(existing.cloud_id.to_string())
                .or_insert_with(|| tag.to_string());
        }
        self.remove(existing.cloud_id)
    }
}

impl<T: Transport, K: Sleeper> GraphSink<T, K> {
    /// The create an update falls back to when the service no longer has the
    /// object the local file claims.
    ///
    /// Opened and judged again rather than reusing anything the update was built
    /// from: the two are separated by a round trip, and in that window the file
    /// can be saved over, truncated, or evicted into a placeholder. The content
    /// that goes up is the content at send time, and every guard that decided
    /// the first attempt has to decide this one too.
    fn create(&mut self, path: &std::path::Path, rel: &str) -> io::Result<Uploaded> {
        let file = std::fs::File::open(path)?;
        if is_placeholder(path)? {
            return Err(refused(
                "the file is a dehydrated placeholder, and its holes are not the \
                 user's document",
            ));
        }
        let snap = snapshot_of(&file)?;
        if snap.len > self.policy.simple_upload_max {
            return match self.upload_session(path, rel, None, &file, &snap)? {
                Written::Done(u) => Ok(u),
                // A create has no object to be told is gone; kept total rather
                // than unwrapped, because a panic here kills the upload thread.
                Written::Gone => Err(refused("the create named no object")),
            };
        }
        let body = read_whole(&file, &snap)?;
        self.put_at_path(rel, body)
    }
}

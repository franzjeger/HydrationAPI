//! Attack tests for the `hydration-graph` mapping layer.
//!
//! Every test here is written to fail against an empty implementation, and —
//! more importantly — to fail against the *plausible wrong* implementation named
//! in its comment. A test that only a `todo!()` can fail is not carrying weight.
//!
//! Two construction rules, both learned the hard way in the three modules before
//! this one:
//!
//!   * **No fixture is fed parent-first unless the test is about parent-first
//!     order.** Graph's delta feed is not topologically sorted, and a guard that
//!     reads `TreeIndex` answers "fine" to everything when the index is empty.
//!   * **Every negative has a positive control nearby.** A suite of refusals is
//!     satisfied by `fn map_item(..) -> Result<_, _> { Err(NoShape) }`.
//!
//! Sections are damage classes, not modules: what breaks on the user's disk when
//! the property fails, which is the only ordering that makes the omissions
//! visible.

use hydration_client::delta::Change;
use hydration_client::namespace::{Item, Kind, Namespace};
use hydration_graph::{
    map_item, map_page, Anchor, DeltaPage, DriveId, DriveItem, DriveScope, EnvelopeError,
    Escalation, ItemId, MappedPage, Mapping, MountPoint, ObjectKey, Round, TagSource, TreeIndex,
    Unmappable, MAX_ID_BYTES, MAX_MAPPED_DEPTH,
};

// ---------------------------------------------------------------------------
// Fixture plumbing
//
// A test should read as its input. Everything below exists so that the body of
// a test is a JSON constant, one call, and the assertion.
// ---------------------------------------------------------------------------

const MINE: &str = "b!mine";
const THEIRS: &str = "b!theirs";
const D1: &str = "b!Kx9Yz3QpUEeF2mVn7TbLdQ1";
const D2: &str = "b!Pq2Wr8LmNEeT4kXc9ZaHfA2";
const D3: &str = "b!8vXQ2hRkT0i7pOa9m3LcNw";

/// Any syntactically valid deltaLink. No test asserts on its value; it exists so
/// `DeltaPage::parse` sees a well-formed envelope.
const DELTA: &str = "https://graph.microsoft.com/v1.0/drives/x/root/delta?token=aTZpPTE7bT0x";

fn drive_id(s: &str) -> DriveId {
    DriveId::parse(s).unwrap_or_else(|e| panic!("fixture drive id {s:?} must parse: {e:?}"))
}

fn item_id(s: &str) -> ItemId {
    ItemId::parse(s).unwrap_or_else(|e| panic!("fixture item id {s:?} must parse: {e:?}"))
}

fn okey(drive: &str, item: &str) -> ObjectKey {
    ObjectKey::new(drive_id(drive), item_id(item))
}

/// The expected `Change::Upserted.cloud_id` for an object, built the only way
/// the crate permits one to be built.
fn cloud(drive: &str, item: &str) -> String {
    okey(drive, item).to_cloud_id().into_inner()
}

fn primary(drive: &str) -> DriveScope {
    DriveScope::primary(drive_id(drive))
}

fn one(json: &str) -> DriveItem {
    serde_json::from_str(json).unwrap_or_else(|e| panic!("fixture is not a DriveItem: {e}\n{json}"))
}

fn body(items: &[&str]) -> String {
    format!(
        r#"{{"value":[{}],"@odata.deltaLink":"{}"}}"#,
        items.join(","),
        DELTA
    )
}

fn page(items: &[&str]) -> DeltaPage {
    DeltaPage::parse(200, body(items).as_bytes())
        .unwrap_or_else(|e| panic!("fixture page must parse: {e:?}"))
}

/// `map_item` against an index that has seen nothing. The default, deliberately:
/// a guard that needs a pre-populated index to fire does not fire on Graph's
/// real feed order either.
fn map_alone(scope: &DriveScope, json: &str) -> Result<Mapping, Unmappable> {
    map_item(scope, &TreeIndex::new(), TagSource::CTag, &one(json))
}

fn map_whole_page(scope: &DriveScope, items: &[&str]) -> MappedPage {
    let mut index = TreeIndex::new();
    map_page(scope, &mut index, TagSource::CTag, &page(items))
}

fn as_upsert(m: &Mapping) -> (&str, &str, &str, &Kind) {
    match &m.item {
        Some(Item::Upsert {
            id,
            parent,
            name,
            kind,
        }) => (id, parent, name, kind),
        other => panic!("expected Item::Upsert, got {other:?}"),
    }
}

fn kind_of(m: &Mapping) -> &Kind {
    as_upsert(m).3
}

fn file(size: u64, ctag: &str) -> Kind {
    Kind::File {
        size,
        ctag: Some(ctag.to_string()),
    }
}

fn ns_rooted(drive: &str, root: &str) -> Namespace {
    Namespace::restore(vec![Item::Root {
        id: cloud(drive, root),
    }])
}

fn apply_all(ns: &mut Namespace, items: &[Item]) -> Vec<Change> {
    let mut out = Vec::new();
    for i in items {
        out.extend(ns.apply(i.clone()));
    }
    out
}

fn upserted_for<'a>(cs: &'a [Change], cloud_id: &str) -> Vec<&'a Change> {
    cs.iter()
        .filter(|c| matches!(c, Change::Upserted { cloud_id: id, .. } if id == cloud_id))
        .collect()
}

fn removals(cs: &[Change]) -> Vec<&str> {
    cs.iter()
        .filter_map(|c| match c {
            Change::Removed { cloud_id } => Some(cloud_id.as_str()),
            _ => None,
        })
        .collect()
}

fn paths(cs: &[Change]) -> Vec<&str> {
    cs.iter()
        .filter_map(|c| match c {
            Change::Upserted { path, .. } => Some(path.as_str()),
            _ => None,
        })
        .collect()
}

fn file_changes(cs: &[Change]) -> Vec<Change> {
    cs.iter()
        .filter(|c| matches!(c, Change::Upserted { .. } | Change::Removed { .. }))
        .cloned()
        .collect()
}

fn folder_paths(cs: &[Change]) -> Vec<&str> {
    cs.iter()
        .filter_map(|c| match c {
            Change::FolderUpserted { path, .. } => Some(path.as_str()),
            _ => None,
        })
        .collect()
}

// ===========================================================================
// DAMAGE CLASS 1 — A mis-read facet is a subtree deletion
//
// `namespace::upsert` treats a File→Folder or Folder→Opaque transition as a
// `reshaped` node: it calls `delete()`, which emits `Change::Removed` for every
// descendant and purges them from its own tree. So a facet read in the wrong
// order does not merely mis-classify one item — the correction on the following
// round removes everything the user had underneath it.
// ===========================================================================

const PLAIN_FILE: &str = r#"{"id":"01A","name":"a.txt","size":10,
  "eTag":"\"{E80C4A17-5D29-4B63-98F1-2A7D0E6C3B54},1\"",
  "cTag":"\"c:{E80C4A17-5D29-4B63-98F1-2A7D0E6C3B54},1\"",
  "file":{"mimeType":"text/plain","hashes":{"quickXorHash":"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg="}},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"createdDateTime":"2026-01-04T10:00:00Z",
                    "lastModifiedDateTime":"2026-08-02T09:15:31Z"}}"#;

/// POSITIVE CONTROL, and the one this whole file rests on.
///
/// Without it the entire facet suite is satisfied by
/// `fn map_item(..) -> Result<Mapping, Unmappable> { Err(Unmappable::NoShape) }`
/// — a real risk when a class is written attack-first. A mapper that refuses
/// ordinary files syncs nothing at all, and because every unquarantined refusal
/// withholds the token, the provider never advances past its first page: an
/// outage indistinguishable from a service failure.
///
/// Concretely it catches an over-eager Ambiguous/NoShape rule — treating
/// `file.hashes` or `fileSystemInfo` as a competing facet — and a
/// remoteItem-aware body selector that looks for size and cTag only *inside*
/// `remoteItem` and so finds neither on a plain item. It also pins the exact
/// prefixed tag string, so a mapper that strips the quotes Graph puts inside the
/// cTag value, or emits the raw tag without the `ct:` prefix, fails here rather
/// than silently making every later tag comparison mismatch.
#[test]
fn a_plain_file_maps_with_its_size_and_its_pinned_content_tag() {
    let scope = primary(MINE);
    let m = map_alone(&scope, PLAIN_FILE).expect("an ordinary file must map");
    assert_eq!(
        m.item,
        Some(Item::Upsert {
            id: cloud(MINE, "01A"),
            parent: cloud(MINE, "01ROOT"),
            name: "a.txt".into(),
            kind: file(10, "ct:\"c:{E80C4A17-5D29-4B63-98F1-2A7D0E6C3B54},1\""),
        })
    );
    assert_eq!(m.mount, None);
    assert_eq!(m.note, None);

    let mp = map_whole_page(&scope, &[PLAIN_FILE]);
    assert!(mp.refusals.is_empty(), "{:?}", mp.refusals);
    assert_eq!(mp.items.len(), 1);
}

const AMBIGUOUS: &str = r#"{"id":"01AMBIG","name":"Quarterly","size":4096,
  "eTag":"\"{2E4C7A11-5B3D-4C8E-9A21-7D0F6B4E1C93},1\"",
  "cTag":"\"c:{2E4C7A11-5B3D-4C8E-9A21-7D0F6B4E1C93},1\"",
  "file":{"mimeType":"application/octet-stream"},
  "folder":{"childCount":2},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-07-14T09:12:03Z"}}"#;

/// An `if`-chain answers `Folder`; the reverse order answers `File{4096}`. Both
/// compile. Only a match over the `(folder, file)` pair with a named both-set
/// arm answers `Ambiguous`.
///
/// The fixture carries a valid `size` and `cTag` on purpose, so the File branch
/// *completes* rather than failing with `NoSize`/`NoContentTag` and letting a
/// broken implementation pass for an unrelated reason.
#[test]
fn a_file_and_folder_facet_on_one_item_is_ambiguous_not_whichever_is_checked_first() {
    let scope = primary(MINE);
    assert_eq!(
        map_alone(&scope, AMBIGUOUS).unwrap_err(),
        Unmappable::Ambiguous,
        "both facets set must be Ambiguous — not Folder (folder checked first), \
         not File{{size:4096}} (file checked first), not NoShape"
    );

    let mp = map_whole_page(&scope, &[AMBIGUOUS]);
    assert!(mp.items.is_empty(), "got items {:?}", mp.items);
    assert_eq!(mp.refusals.len(), 1, "refusals: {:?}", mp.refusals);
    assert_eq!(mp.refusals[0].why, Unmappable::Ambiguous);
    assert_eq!(mp.refusals[0].key, Some(okey(MINE, "01AMBIG")));
}

const NO_SHAPE: &str = r#"{"id":"01NOSHAPE","name":"budget.xlsx","size":10240,
  "eTag":"\"{8B1F3D42-90AC-41E7-8E55-2C6A9B0D7F31},4\"",
  "cTag":"\"c:{8B1F3D42-90AC-41E7-8E55-2C6A9B0D7F31},2\"",
  "lastModifiedDateTime":"2026-08-01T16:41:09Z",
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T16:41:09Z"}}"#;

/// `match (folder, file) { (Some(_), _) => Folder, _ => File }` — a two-arm match
/// with a catch-all — compiles and returns `File{10240}` here, because every
/// input the File arm needs is present. A named neither-facet arm is the only
/// thing that fails this. Graph really does emit facet-less items when `$select`
/// is trimmed or the caller's permissions hide the facet.
#[test]
fn an_item_with_no_shape_facet_is_refused_rather_than_assumed_to_be_a_file() {
    let scope = primary(MINE);
    assert_eq!(
        map_alone(&scope, NO_SHAPE).unwrap_err(),
        Unmappable::NoShape,
        "neither facet must be NoShape specifically — NoSize and NoContentTag are \
         both satisfiable from this input, so either of those means the File arm ran"
    );
}

const ROOT: &str = r#"{"id":"01ROOT","name":"root","size":10485760,
  "eTag":"\"{0A9D6E27-4C11-4F03-A7B2-3E8C5D1A9B44},19\"",
  "root":{},"folder":{"childCount":9},
  "parentReference":{"driveId":"b!mine","driveType":"business"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-05-11T07:22:40Z"}}"#;

/// POSITIVE CONTROL.
///
/// Graph always sends `folder` alongside `root`, and folder is the common case,
/// so a folder-first chain is the natural ordering. It compiles and classifies
/// the drive root as an ordinary folder; `ParentKey::from_outer` then finds a
/// `parentReference` with a driveId but no `id` and returns `NoParent`. The
/// fixture keeps that id-less parentReference rather than omitting the reference
/// entirely, so the failure is a *wrong refusal*, not an obviously missing field.
#[test]
fn the_root_facet_outranks_the_folder_facet_it_always_arrives_with() {
    let m = map_alone(&primary(MINE), ROOT).expect("the drive root must map");
    assert_eq!(
        m.item,
        Some(Item::Root {
            id: cloud(MINE, "01ROOT")
        }),
        "root must be Item::Root — not NoParent (folder arm reached first), \
         not Upsert{{name:\"root\"}} (which puts a phantom \"root/\" on every path)"
    );
}

const PACKAGE: &str = r#"{"id":"01NB","name":"Team Notebook","size":88123,
  "eTag":"\"{5D3B9F80-6A72-4E19-BC44-9F2E71A0C8D5},2\"",
  "cTag":"\"c:{5D3B9F80-6A72-4E19-BC44-9F2E71A0C8D5},2\"",
  "folder":{"childCount":3},"package":{"type":"oneNote"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-07-19T12:00:00Z"}}"#;

/// Graph never sends `package` without `folder`, so a folder-before-package chain
/// returns `Folder` and no plain-folder test distinguishes it. The fixture also
/// carries a plausible size and cTag so the "a notebook is one document, so treat
/// it as a file" reading *completes* rather than erroring — `File{88123}` is a
/// live alternative this assertion has to exclude by name.
#[test]
fn a_package_outranks_the_folder_facet_it_always_arrives_with() {
    let m = map_alone(&primary(MINE), PACKAGE).expect("a package must map");
    assert_eq!(
        kind_of(&m),
        &Kind::Opaque,
        "a package is Opaque — as Folder its sections sync as separate files and \
         corrupt the notebook; as File{{88123}} the size is not the sum of its \
         parts and §5.7 refuses every read"
    );
}

const MALWARE: &str = r#"{"id":"01MAL","name":"invoice.doc","size":31744,
  "eTag":"\"{A2C4E608-7B31-4D5F-91A0-6E8B2F4C7D19},1\"",
  "cTag":"\"c:{A2C4E608-7B31-4D5F-91A0-6E8B2F4C7D19},1\"",
  "file":{"mimeType":"application/msword",
          "hashes":{"quickXorHash":"pQ3nA9kZ2s0Lm4YtB7xR1eC5dG8="}},
  "malware":{"description":"Trojan:Win32/Emotet.A!ml"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-05T22:13:47Z"}}"#;

/// The file facet here is complete and valid, so any implementation that
/// dispatches on file/folder and treats `malware` as decorative metadata — or
/// omits the field from the wire type, which is easy when the struct is written
/// from a capture with no infected files — emits an ordinary upsert. Graph still
/// serves a download URL for these, so nothing downstream stops it.
#[test]
fn malware_outranks_the_complete_file_facet_it_arrives_with() {
    let scope = primary(MINE);
    assert_eq!(
        map_alone(&scope, MALWARE).unwrap_err(),
        Unmappable::Blocked,
        "a flagged file must be Blocked, not mapped and not NoShape"
    );

    let mp = map_whole_page(&scope, &[MALWARE]);
    assert!(mp.items.is_empty(), "got items {:?}", mp.items);
    assert_eq!(
        mp.refusals.len(),
        1,
        "the item must be named in the refusal channel, not dropped: {:?}",
        mp.refusals
    );
    assert_eq!(mp.refusals[0].why, Unmappable::Blocked);
    assert_eq!(mp.refusals[0].key, Some(okey(MINE, "01MAL")));
}

const UNSETTLED: &str = r#"{"id":"01MOV","name":"master.mov","size":0,
  "eTag":"\"{3F7B1C55-08E2-4A93-B6D7-4C1E9A02F8B3},1\"",
  "cTag":"\"c:{3F7B1C55-08E2-4A93-B6D7-4C1E9A02F8B3},1\"",
  "file":{"mimeType":"video/quicktime"},
  "pendingOperations":{"pendingContentUpdate":{"queuedDateTime":"2026-08-07T11:04:22Z"}},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-07T11:04:22Z"}}"#;

/// Two implementations fail this. (a) File-arm-first: `0` is a perfectly legal
/// `u64`, so `ContentSize::of_file` accepts it and `File{size:0}` is produced
/// with no error anywhere — the verified truncate-to-zero, against a local copy
/// that is the only copy of the bytes. (b) A wire type modelling only a
/// top-level `pendingContentUpdate` — the name Graph uses for the *inner* key,
/// so the name an implementer copies from the docs — never sees this signal,
/// because the real shape nests it under `pendingOperations`.
#[test]
fn a_pending_operations_item_is_refused_rather_than_reported_as_zero_bytes() {
    let scope = primary(MINE);
    assert_eq!(
        map_alone(&scope, UNSETTLED).unwrap_err(),
        Unmappable::Unsettled,
        "an item mid-upload must be Unsettled — File{{size:0}} replaces a hydrated \
         local master.mov with a zero-byte placeholder"
    );

    // The page half is about the *channel*, not about the change: an item that is
    // dropped with no refusal recorded also emits no change, and that is the worse
    // failure — the round still reaches its deltaLink and the cursor advances past
    // a change Graph will never repeat.
    let mp = map_whole_page(&scope, &[UNSETTLED]);
    assert!(mp.items.is_empty(), "got items {:?}", mp.items);
    assert_eq!(
        mp.refusals.len(),
        1,
        "refused, not silently dropped: {:?}",
        mp.refusals
    );
    assert_eq!(mp.refusals[0].why, Unmappable::Unsettled);
    assert_eq!(mp.refusals[0].key, Some(okey(MINE, "01MOV")));
}

const EMPTY_FOLDER: &str = r#"{"id":"01F","name":"Work","size":98123,
  "eTag":"\"{2B7E9C05-4A61-4F28-B0D3-8C1E5A72D69F},3\"",
  "folder":{"childCount":0},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT","path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-06T07:48:19Z"}}"#;

/// POSITIVE CONTROL.
///
/// Two concrete implementations fail it. (a) Folder-ness derived from the count
/// — `folder.is_some_and(|f| f.child_count > 0)` — tempting because
/// `TreeIndex::child_count` exists; it returns `NoShape` for every empty folder,
/// and a refused *container* strands every child that arrives later. (b)
/// `size.is_some() ⇒ file`, which Graph invites because folders always carry an
/// aggregate size; it returns `File{98123}`. `childCount:0` and a large size are
/// both present so that each of those reaches a wrong answer instead of erroring.
#[test]
fn an_empty_folder_facet_with_an_aggregate_size_is_a_folder() {
    let scope = primary(MINE);
    let m = map_alone(&scope, EMPTY_FOLDER).expect("an empty folder must map");
    assert_eq!(kind_of(&m), &Kind::Folder);

    // The page half's only residual power is catching a map_item/map_page
    // divergence, so it says that and nothing more: a first-sight folder produces
    // no change at all, so a substring test for the aggregate size would run
    // against "[]" whatever the mapper did.
    let mp = map_whole_page(&scope, &[EMPTY_FOLDER]);
    assert!(mp.refusals.is_empty(), "{:?}", mp.refusals);
    assert_eq!(mp.items.len(), 1, "{:?}", mp.items);
    assert_eq!(
        kind_of_item(&mp.items[0]),
        &Kind::Folder,
        "map_page must not diverge from map_item"
    );

    let mut ns = ns_rooted(MINE, "01ROOT");
    let changes = apply_all(&mut ns, &mp.items);
    assert!(file_changes(&changes).is_empty(), "{changes:?}");
    assert_eq!(folder_paths(&changes), vec!["Work"]);
}

// ===========================================================================
// DAMAGE CLASS 2 — A tombstone read wrong is either a resurrection or a purge
//
// A delta feed never re-reports an item it has already tombstoned, so a missed
// delete is permanent. In the other direction `Namespace::delete` expands to the
// whole subtree, so a delete synthesised from the wrong id removes files that
// are still live and nothing brings them back.
// ===========================================================================

const TOMB_WITH_FILE: &str = r#"{"id":"01ABC","name":"contract.pdf","size":41234,
  "eTag":"\"{C71A05E9-2F4B-4D6A-B8C3-15E9A7D2F604},7\"",
  "cTag":"\"c:{C71A05E9-2F4B-4D6A-B8C3-15E9A7D2F604},4\"",
  "file":{"mimeType":"application/pdf",
          "hashes":{"quickXorHash":"tCCr8ZKk1s9E0pQ2xB7Yk3mA1nQ="}},
  "deleted":{"state":"softDeleted"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-07-30T10:02:11Z"}}"#;

/// Two wrong implementations. (a) Dispatch that checks `file` before `deleted` —
/// the interesting facet first — emits `Upsert{File{41234}}`; the design's own
/// D3 fixture omits `size`, so against *that* fixture the bug fails with
/// `NoSize` and the test passes for the wrong reason. This fixture makes the
/// File arm fully satisfiable. (b) A tombstone detector written as
/// `deleted.state == "deleted"`; Graph documents the `state` field, so modelling
/// and comparing it is the obvious move, and `"softDeleted"` defeats it.
#[test]
fn a_tombstone_carrying_a_complete_file_facet_and_a_real_size_is_still_a_delete() {
    let m = map_alone(&primary(MINE), TOMB_WITH_FILE).expect("a tombstone must map");
    assert_eq!(
        m.item,
        Some(Item::Delete {
            id: cloud(MINE, "01ABC")
        }),
        "a tombstone is a delete whatever else it carries, and the id is the \
         ObjectKey-derived cloud id, not the bare \"01ABC\""
    );
}

const ROOT_TOMB: &str = r#"{"id":"01ROOT","name":"root","size":10485760,
  "eTag":"\"{0A9D6E27-4C11-4F03-A7B2-3E8C5D1A9B44},19\"",
  "root":{},"folder":{"childCount":9},"deleted":{"state":"softDeleted"},
  "parentReference":{"driveId":"b!mine","driveType":"business"}}"#;

/// An implementation that answers "is this the root?" by consulting remembered
/// state — `ix.root() == Some(&id)`, or `depth_of` — answers "unknown" against an
/// empty index and falls straight through to the ordinary Delete arm. That
/// compiles and passes any test whose index was pre-populated with the root,
/// which is exactly the friendly fixture this one refuses to use: the item
/// carries `root:{}` itself, so a correct implementation needs no memory.
///
/// It also catches root-before-deleted precedence, which returns `Item::Root` and
/// swallows the tombstone in silence.
#[test]
fn a_root_tombstone_is_refused_from_the_items_own_facets_with_an_empty_index() {
    let scope = primary(MINE);
    assert_eq!(
        map_alone(&scope, ROOT_TOMB).unwrap_err(),
        Unmappable::RootDeleted,
        "Item::Delete here reaches Namespace::delete, which purges every \
         descendant and sets root = None — the next listing() is empty and the \
         additive reconciler deletes the user's whole local tree"
    );

    let root = cloud(MINE, "01ROOT");
    let ns = Namespace::restore(vec![
        Item::Root { id: root.clone() },
        Item::Upsert {
            id: cloud(MINE, "01A"),
            parent: root,
            name: "a.txt".into(),
            kind: file(10, "ct:c1"),
        },
    ]);
    let before = ns.listing();
    assert!(!before.is_empty(), "fixture precondition");

    let mut round = Round::new(TagSource::CTag, ns);
    round.feed(&scope, &page(&[ROOT_TOMB]));
    assert_eq!(
        round.namespace().listing(),
        before,
        "zero removals: the tree must be untouched, and `before` is non-empty, so \
         this also says the tree was not emptied"
    );
    match round.finish() {
        Err((Escalation::RootDeleted, _)) => {}
        other => panic!("expected Escalation::RootDeleted, got {other:?}"),
    }
}

const LINK_TOMB: &str = r#"{"id":"01SH","name":"Team Files",
  "eTag":"\"{9E5A1D73-2C68-4B0F-A3E1-7D94C2B6F085},3\"",
  "deleted":{"state":"softDeleted"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "remoteItem":{"id":"01FAR","name":"Team Files","size":83920184,
    "folder":{"childCount":12},
    "cTag":"\"c:{9E5A1D73-2C68-4B0F-A3E1-7D94C2B6F085},7\"",
    "parentReference":{"driveId":"b!theirs","driveType":"documentLibrary","id":"01FARROOT"}}}"#;

/// "remoteItem is the real item, so look there first" is a coherent-sounding
/// rule and it compiles: `let b = shape_body(); if b.folder.is_some() { Folder }`
/// evaluated before the deleted check returns `Folder` here, because `deleted` is
/// the one facet that is *not* in the body being consulted. Separately, an
/// implementation that has just learned to take shape and size from the inner
/// body naturally takes the id from there too.
///
/// Three distinct failures: a Folder upsert strands an unshared library forever;
/// a delete keyed on `01FAR` either does nothing or, once `b!theirs` is mounted,
/// removes the *owner's* copy — a deletion crossing a drive boundary; and a
/// MountPoint for a dead link makes the round enumerate a drive the user no
/// longer has access to.
#[test]
fn an_outer_tombstone_on_a_link_deletes_the_near_id_and_fans_out_to_nothing() {
    let m = map_alone(&primary(MINE), LINK_TOMB).expect("a link tombstone must map");
    assert_eq!(
        m.item,
        Some(Item::Delete {
            id: cloud(MINE, "01SH")
        }),
        "the delete names the NEAR id, not b!theirs|01FAR, and is not an Upsert"
    );
    assert_eq!(m.mount, None, "a dead link must not be fanned out to");
}

const TOMB_NO_ID: &str = r#"{"name":"gone.txt","deleted":{"state":"softDeleted"},
  "eTag":"\"{9E4A},9\"",
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"}}"#;

/// A well-formed tombstone for a *different* id, in the same page: the only thing
/// that makes the deletion channel observable at all here. Without it every
/// deletion assertion below runs over an empty vector.
const TOMB_WITH_ID: &str = r#"{"id":"01BYE5RZ7BQXZWBTUFOFD3GSPGOHDJD36K","name":"b.txt",
  "eTag":"\"{9E4B},3\"","deleted":{"state":"softDeleted"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"}}"#;

/// The tombstone arm is the one that legitimately skips name, size, shape and
/// parent, so it is the arm most likely to be written as an early return
/// *before* the id is parsed:
/// `if item.deleted.is_some() { return Ok(Delete { id: item.id.clone().unwrap_or_default() }) }`.
/// That compiles, passes every deletion test that carries an id, and is
/// invisible because its symptom is an absence: a `Delete` for `""` finds no
/// node, `Namespace::delete` silently does nothing, and the deletion the service
/// reported is lost with nothing recorded to say so.
#[test]
fn a_tombstone_without_an_id_is_a_refusal_not_a_delete_of_the_empty_string() {
    let scope = primary(D1);
    let root = cloud(D1, "01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K");
    let live = cloud(D1, "01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR");
    let doomed = cloud(D1, "01BYE5RZ7BQXZWBTUFOFD3GSPGOHDJD36K");
    let mut ns = Namespace::restore(vec![
        Item::Root { id: root.clone() },
        Item::Upsert {
            id: live.clone(),
            parent: root.clone(),
            name: "a.txt".into(),
            kind: file(10, "ct:c1"),
        },
        Item::Upsert {
            id: doomed.clone(),
            parent: root,
            name: "b.txt".into(),
            kind: file(20, "ct:c2"),
        },
    ]);

    assert_eq!(
        map_alone(&scope, TOMB_NO_ID).unwrap_err(),
        Unmappable::NoId,
        "an id-less tombstone is refused, not turned into a delete of \"\""
    );

    // The two tombstones travel in one page so that the deletion channel is
    // non-empty: "no removals" over an empty `items` is true of every
    // implementation, including one that deletes `""`.
    let mp = map_whole_page(&scope, &[TOMB_NO_ID, TOMB_WITH_ID]);
    assert_eq!(
        mp.items,
        vec![Item::Delete { id: doomed.clone() }],
        "exactly the well-formed tombstone, and nothing keyed on \"\": {:?}",
        mp.items
    );
    assert_eq!(mp.refusals.len(), 1, "refusals: {:?}", mp.refusals);
    assert_eq!(mp.refusals[0].why, Unmappable::NoId);
    assert_eq!(mp.refusals[0].key, None, "there is no key to name");

    let changes = apply_all(&mut ns, &mp.items);
    assert_eq!(
        removals(&changes),
        vec![doomed.as_str()],
        "one removal, naming the id the service actually sent: {changes:?}"
    );
    assert_eq!(
        paths(&ns.listing()),
        vec!["a.txt"],
        "the live file must survive and b.txt must be gone"
    );
}

// ===========================================================================
// DAMAGE CLASS 3 — The remoteItem outer/inner split
//
// A shared library arrives as a near-drive placeholder wrapping a far-drive
// body. Shape, size and tags come from inside; identity, parent and `deleted`
// come from outside. Every test in this class is a different way of getting one
// of those two directions wrong, and each one has been chosen so that the wrong
// answer *succeeds* rather than erroring.
// ===========================================================================

const REMOTE_FOLDER: &str = r#"{"id":"01SH","name":"Team Files","size":4096,
  "eTag":"\"{9E5A1D73-2C68-4B0F-A3E1-7D94C2B6F085},1\"",
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "remoteItem":{"id":"01FAR","name":"Team Files","size":83920184,
    "folder":{"childCount":12},
    "cTag":"\"c:{9E5A1D73-2C68-4B0F-A3E1-7D94C2B6F085},7\"",
    "parentReference":{"driveId":"b!theirs","driveType":"documentLibrary","id":"01FARROOT"},
    "fileSystemInfo":{"lastModifiedDateTime":"2026-06-02T08:00:00Z"},
    "shared":{"scope":"users"}},
  "shared":{"scope":"users"}}"#;

/// POSITIVE CONTROL for `remoteItem`.
///
/// The outer body carries no facet at all, so (a) an implementation reading
/// facets from the top level returns `NoShape` and refuses every shared folder —
/// and refusing a *container* leaves each of its children waiting on a parent
/// that will never arrive, which blocks the delta token — and (b) the same
/// implementation with the `else ⇒ file` rule returns `File{size:4096}` from the
/// outer size, the verified defect this whole class exists for. Separately, an
/// implementation that takes the id from the inner body keys the placeholder as
/// `b!theirs|01FAR`, collapsing it onto the far-drive original.
#[test]
fn a_remote_item_folder_is_a_folder_and_the_identity_stays_on_the_near_drive() {
    let m = map_alone(&primary(MINE), REMOTE_FOLDER).expect("a shared folder must map");
    let (id, parent, name, kind) = as_upsert(&m);
    assert_eq!(kind, &Kind::Folder, "not File{{4096}} from the outer size");
    assert_eq!(id, cloud(MINE, "01SH"), "never b!theirs|01FAR");
    assert_eq!(parent, cloud(MINE, "01ROOT"));
    assert_eq!(name, "Team Files");
    assert_eq!(
        m.mount,
        Some(MountPoint {
            placeholder: okey(MINE, "01SH"),
            remote: okey(THEIRS, "01FAR"),
        })
    );
}

const REMOTE_FILE: &str = r#"{"id":"01SHF","name":"budget.xlsx","size":0,
  "eTag":"\"{4F2A88C1-6D30-4E7B-9C52-1A0B3E6D8F47},12\"",
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "remoteItem":{"id":"01FARF","name":"budget.xlsx","size":9999,
    "file":{"mimeType":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    "cTag":"\"c:{4F2A88C1-6D30-4E7B-9C52-1A0B3E6D8F47},3\"",
    "parentReference":{"driveId":"b!theirs","driveType":"documentLibrary","id":"01FARROOT"},
    "fileSystemInfo":{"lastModifiedDateTime":"2026-07-28T14:55:02Z"}},
  "shared":{"scope":"users"}}"#;

/// `ContentSize::of_file(&self.body)` — reading the size off the item rather
/// than off `shape_body()` — finds `0`, which is a present, valid `u64`, so it
/// succeeds and yields `File{size:0}`. The outer zero is the whole point: if the
/// outer size were *absent*, the same bug would surface as `NoSize` and the test
/// would pass while the defect remained.
#[test]
fn a_remote_item_files_size_comes_from_inside_not_from_the_outer_zero() {
    let scope = primary(MINE);
    let m = map_alone(&scope, REMOTE_FILE).expect("a shared file must map");
    match kind_of(&m) {
        Kind::File { size, .. } => assert_eq!(
            *size, 9999,
            "size comes from shape_body(); the outer 0 truncates the local copy"
        ),
        other => panic!("expected Kind::File, got {other:?}"),
    }

    // The exact change, not a filtered loop: `upserted_for(.., 01SHF)` is empty
    // both when the mapper emits nothing and when it keys the change on
    // `b!theirs|01FARF` — the sibling test's named failure mode — so a loop over
    // it passes on the wrong key.
    let mut ns = ns_rooted(MINE, "01ROOT");
    let changes = apply_all(&mut ns, &map_whole_page(&scope, &[REMOTE_FILE]).items);
    assert_eq!(
        changes,
        vec![Change::Upserted {
            cloud_id: cloud(MINE, "01SHF"),
            path: "budget.xlsx".into(),
            size: 9999,
            etag: Some("ct:\"c:{4F2A88C1-6D30-4E7B-9C52-1A0B3E6D8F47},3\"".into()),
        }]
    );
}

const REMOTE_FILE_TAGGED: &str = r#"{"id":"01SHF","name":"budget.xlsx","size":0,
  "eTag":"\"{4F2A88C1-6D30-4E7B-9C52-1A0B3E6D8F47},12\"",
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "remoteItem":{"id":"01FARF","name":"budget.xlsx","size":9999,
    "file":{"mimeType":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    "eTag":"\"{4F2A88C1-6D30-4E7B-9C52-1A0B3E6D8F47},12\"",
    "cTag":"\"c:{4F2A88C1-6D30-4E7B-9C52-1A0B3E6D8F47},3\"",
    "parentReference":{"driveId":"b!theirs","driveType":"documentLibrary","id":"01FARROOT"}},
  "shared":{"scope":"users"}}"#;

/// Reading `cTag` from the outer body finds `None`, and there are exactly two
/// ways to continue: refuse (`NoContentTag` on every shared file, forever, which
/// pins the cursor) or fall back to the eTag that *is* present at the outer
/// level. The fallback is the sympathetic choice — it produces a working sync
/// that looks correct until the first rename, at which point every hydrated file
/// under the renamed folder is dehydrated. Putting the eTag at both levels and
/// the cTag only at the inner one makes the fallback silently succeed.
#[test]
fn a_remote_item_files_content_tag_comes_from_inside_and_the_outer_etag_is_not_a_fallback() {
    let scope = primary(MINE);
    let m = map_alone(&scope, REMOTE_FILE_TAGGED).expect("a shared file must map");
    assert_eq!(
        kind_of(&m),
        &file(9999, "ct:\"c:{4F2A88C1-6D30-4E7B-9C52-1A0B3E6D8F47},3\""),
        "the inner cTag verbatim behind the ct: prefix — not NoContentTag, not None"
    );

    let mut ns = ns_rooted(MINE, "01ROOT");
    let changes = apply_all(
        &mut ns,
        &map_whole_page(&scope, &[REMOTE_FILE_TAGGED]).items,
    );
    assert_eq!(
        changes,
        vec![Change::Upserted {
            cloud_id: cloud(MINE, "01SHF"),
            path: "budget.xlsx".into(),
            size: 9999,
            etag: Some("ct:\"c:{4F2A88C1-6D30-4E7B-9C52-1A0B3E6D8F47},3\"".into()),
        }],
        "the whole change, so that the eTag's `,12` is excluded by what the field \
         *is* rather than by a substring test that also passes on an empty vector"
    );
}

const REMOTE_DISAGREES: &str = r#"{"id":"01SHX","name":"Design Assets","size":4096,
  "eTag":"\"{7C0E4B9A-1F82-4D36-A5B7-0E3C9D18F2A6},1\"",
  "file":{"mimeType":"application/octet-stream"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "remoteItem":{"id":"01FARX","name":"Design Assets","size":511229384,
    "folder":{"childCount":240},
    "parentReference":{"driveId":"b!theirs","driveType":"documentLibrary","id":"01FARROOT"},
    "fileSystemInfo":{"lastModifiedDateTime":"2026-04-17T09:31:55Z"}},
  "shared":{"scope":"anonymous"}}"#;

/// Deliberately hostile: outer and inner facets contradict each other, and the
/// contract says the inner body is the whole answer, not a supplement.
///
/// Three implementations diverge here and all three compile. Outer-only returns
/// `File{4096}`. A union/merge — `folder: outer.folder.or(inner.folder)`, written
/// as a defensive "look in both places" — sees folder AND file set and returns
/// `Ambiguous`, which looks like the *cautious* answer and so will never be
/// questioned without this test; a refused container strands its 240 children on
/// a parent that never arrives. Only inner-wins returns `Folder`.
#[test]
fn an_outer_file_facet_disagreeing_with_an_inner_folder_facet_follows_the_inner_one() {
    let m = map_alone(&primary(MINE), REMOTE_DISAGREES)
        .expect("inner-wins: not Ambiguous, which strands 240 children");
    assert_eq!(
        kind_of(&m),
        &Kind::Folder,
        "shape_body() is the whole answer — not File{{4096}}, not Ambiguous"
    );
}

const REMOTE_PACKAGE: &str = r#"{"id":"01SHNB","name":"Shared Notebook","size":4096,
  "eTag":"\"{B6D2F401-3A57-4C88-9E10-5F7B0A2C4D93},1\"",
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "remoteItem":{"id":"01FARNB","name":"Shared Notebook","size":1048576,
    "folder":{"childCount":4},"package":{"type":"oneNote"},
    "cTag":"\"c:{B6D2F401-3A57-4C88-9E10-5F7B0A2C4D93},5\"",
    "parentReference":{"driveId":"b!theirs","driveType":"documentLibrary","id":"01FARROOT"},
    "fileSystemInfo":{"lastModifiedDateTime":"2026-07-03T18:20:11Z"}}}"#;

/// The natural way `remoteItem` gets handled once someone notices it is a
/// separate branch: `if let Some(ri) = &item.remote_item { if ri.folder.is_some()
/// { Folder } else if ri.file.is_some() { File } } else { /* the careful match */ }`.
/// It compiles, it passes every plain-facet precedence test in this file
/// including the non-shared package one, and it silently drops
/// package/malware/pending precedence *for shared items only*. Precedence proven
/// at the outer level proves nothing about the inner one.
#[test]
fn a_package_inside_a_remote_item_still_outranks_the_folder_beside_it() {
    let m = map_alone(&primary(MINE), REMOTE_PACKAGE).expect("a shared notebook must map");
    assert_eq!(
        kind_of(&m),
        &Kind::Opaque,
        "not Folder (walked into, sections synced piecemeal), not File{{1048576}}"
    );
}

const REMOTE_MALWARE: &str = r#"{"id":"01SHM","name":"deck.pptx","size":0,
  "eTag":"\"{1D8C3E62-9B04-4F71-8A26-C50E7B93D1F8},1\"",
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "remoteItem":{"id":"01FARM","name":"deck.pptx","size":2359296,
    "file":{"mimeType":"application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    "cTag":"\"c:{1D8C3E62-9B04-4F71-8A26-C50E7B93D1F8},2\"",
    "malware":{"description":"Virus:Win32/Nabucur.D"},
    "parentReference":{"driveId":"b!theirs","driveType":"documentLibrary","id":"01FARROOT"}},
  "shared":{"scope":"users"}}"#;

/// Distinct from the package-inside-remoteItem case: an implementation can route
/// the *shape* through `shape_body()` correctly and still read the safety flags
/// off the near item — `if item.body.malware.is_some()` — on the reasoning that
/// the flags describe the object being synced. That compiles, keeps every shape
/// test green, and here finds no malware facet at the outer level, so a flagged
/// 2.3 MB file arriving from a drive the user does not control maps as an
/// ordinary upsert. The outer body is left facet-less so this cannot be caught
/// by accident.
#[test]
fn malware_declared_only_inside_a_remote_item_still_blocks_the_item() {
    let scope = primary(MINE);
    assert_eq!(
        map_alone(&scope, REMOTE_MALWARE).unwrap_err(),
        Unmappable::Blocked,
        "not Ok(File{{2359296}}) — the flags are read from shape_body() too"
    );

    let mp = map_whole_page(&scope, &[REMOTE_MALWARE]);
    assert!(mp.items.is_empty(), "got items {:?}", mp.items);
    assert_eq!(
        mp.refusals.len(),
        1,
        "a flagged executable from a drive the user does not control must be \
         named in the refusal channel, not silently dropped: {:?}",
        mp.refusals
    );
    assert_eq!(mp.refusals[0].why, Unmappable::Blocked);
    assert_eq!(mp.refusals[0].key, Some(okey(MINE, "01SHM")));
}

const REMOTE_DELETED_INSIDE: &str = r#"{"id":"01SH","name":"Team Files","size":4096,
  "eTag":"\"{9E5A1D73-2C68-4B0F-A3E1-7D94C2B6F085},2\"",
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "remoteItem":{"id":"01FAR","name":"Team Files","size":83920184,
    "folder":{"childCount":12},"deleted":{"state":"softDeleted"},
    "parentReference":{"driveId":"b!theirs","driveType":"documentLibrary","id":"01FARROOT"}},
  "shared":{"scope":"users"}}"#;

/// `deleted` is outer-only; inside `remoteItem` it is not a signal the mapper is
/// allowed to read. The design makes this structural by leaving `deleted` out of
/// `ItemBody` — but including it there is the *default* choice: it is a
/// driveItem field, and modelling driveItem once and reusing it for remoteItem
/// is what anyone does first. Combined with a `shape_of` that reads the chosen
/// body, this input returns `Deleted`, `Namespace::delete` purges the whole
/// mount subtree, and because a delta feed never re-reports unchanged items, no
/// later page restores it.
///
/// This test is what makes the outer/inner split a checked property rather than
/// a paragraph in a design document.
#[test]
fn a_deleted_facet_inside_a_remote_item_does_not_delete_the_placeholder() {
    let m = map_alone(&primary(MINE), REMOTE_DELETED_INSIDE).expect("still a live placeholder");
    assert_eq!(
        m.item,
        Some(Item::Upsert {
            id: cloud(MINE, "01SH"),
            parent: cloud(MINE, "01ROOT"),
            name: "Team Files".into(),
            kind: Kind::Folder,
        }),
        "not Item::Delete for b!mine|01SH and not for b!theirs|01FAR"
    );
    assert_eq!(
        m.mount,
        Some(MountPoint {
            placeholder: okey(MINE, "01SH"),
            remote: okey(THEIRS, "01FAR"),
        }),
        "the positive direction too: suppressing the MountPoint whenever the inner \
         body carries `deleted` keeps the placeholder and still never enumerates \
         b!theirs, and a delta feed never re-reports it"
    );
}

const REMOTE_ROOT_INSIDE: &str = r#"{"id":"01SHD","name":"Contoso Docs","size":4096,
  "eTag":"\"{6B0F27D4-8E13-45A9-B2C7-90D6E4A15F38},1\"",
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"},
  "remoteItem":{"id":"01FARROOT","name":"Documents","size":9182736,
    "root":{},"folder":{"childCount":31},
    "parentReference":{"driveId":"b!theirs","driveType":"documentLibrary"},
    "fileSystemInfo":{"lastModifiedDateTime":"2026-03-09T13:44:02Z"}},
  "shared":{"scope":"users"}}"#;

/// Sharing a whole document library really does produce a `remoteItem` that is
/// that library's root, carrying `root:{}` and a parentReference with no id. An
/// `ItemBody` that includes `root` — again the default when driveItem is
/// modelled once — plus shape read from `shape_body()` returns `Root` here.
/// `Namespace` then records `Problem::ForeignRoot` (blocking the token) or, if
/// the shared item is mapped before the real root, makes a foreign library the
/// tree's root: `listing()` walks the wrong tree, and `listing()` is precisely
/// the answer the provider gives when its delta token expires.
///
/// The same input catches parent-from-the-inner-reference: the inner
/// parentReference has no `id`, so an implementation reading it returns
/// `NoParent` instead of anchoring under `b!mine|01ROOT`.
#[test]
fn a_root_facet_inside_a_remote_item_does_not_become_a_second_root() {
    let scope = primary(MINE);
    let m = map_alone(&scope, REMOTE_ROOT_INSIDE).expect("a shared library is an ordinary upsert");
    assert_eq!(
        m.item,
        Some(Item::Upsert {
            id: cloud(MINE, "01SHD"),
            parent: cloud(MINE, "01ROOT"),
            name: "Contoso Docs".into(),
            kind: Kind::Folder,
        }),
        "not Item::Root"
    );
    assert_eq!(
        m.mount,
        Some(MountPoint {
            placeholder: okey(MINE, "01SHD"),
            remote: okey(THEIRS, "01FARROOT"),
        })
    );

    // Alongside the drive's real root, exactly one Item::Root in the page.
    let mp = map_whole_page(&scope, &[REMOTE_ROOT_INSIDE, ROOT]);
    let roots: Vec<&Item> = mp
        .items
        .iter()
        .filter(|i| matches!(i, Item::Root { .. }))
        .collect();
    assert_eq!(roots.len(), 1, "exactly one root per drive: {roots:?}");
    assert_eq!(
        roots[0],
        &Item::Root {
            id: cloud(MINE, "01ROOT")
        }
    );
}

const REMOTE_PARENT_INSIDE: &str = r#"{"id":"01BYE5RZ2LKSHAREXYZ7NQ4M5TVB3WCDEF",
  "name":"Team Files","size":4096,"eTag":"\"{1A2B},1\"",
  "remoteItem":{"id":"01FARDRIVE7QN3ZWBTUFOFD3GSPGOHDJ36","name":"Team Files","size":4096,
    "folder":{"childCount":3},
    "parentReference":{"driveId":"b!Pq2Wr8LmNEeT4kXc9ZaHfA2","driveType":"documentLibrary",
                       "id":"01FARROOT9ZWBTUFOFD3GSPGOHDJD36KQ2",
                       "path":"/drives/b!Pq2Wr8LmNEeT4kXc9ZaHfA2/root:"},
    "fileSystemInfo":{"createdDateTime":"2026-02-11T08:00:00Z",
                      "lastModifiedDateTime":"2026-07-20T12:00:00Z"},
    "shared":{"scope":"users"}},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"},
  "lastModifiedDateTime":"2026-07-20T12:00:00Z"}"#;

const D1_ROOT: &str = r#"{"id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","name":"root",
  "root":{},"folder":{"childCount":1},"size":4096,
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business"}}"#;

/// POSITIVE CONTROL plus an attack.
///
/// Shape, size and tags route through `shape_body()`, which prefers `remoteItem`.
/// Reusing that same helper for the parent — `self.shape_body().parent_reference`
/// — is a two-word change that reads as consistency, and `ItemBody` carries a
/// `parent_reference` field so the expression compiles. The comment "inner: NEVER
/// read by ParentKey" is a comment; nothing in the types stops it, and no fixture
/// without a `remoteItem` can catch it.
///
/// Either way every shared-library placeholder is lost: refused as
/// `ForeignParent` (unclearable, blocks the token) or attached under an id on a
/// drive the primary scope never enumerates (pending forever).
#[test]
fn the_inner_remote_parent_reference_is_never_the_parent() {
    let scope = primary(D1);
    let mp = map_whole_page(&scope, &[REMOTE_PARENT_INSIDE, D1_ROOT]);
    assert!(
        mp.refusals.is_empty(),
        "no ForeignParent{{b!Pq2...}}: {:?}",
        mp.refusals
    );

    let m = map_alone(&scope, REMOTE_PARENT_INSIDE).expect("the placeholder must map");
    let (_, parent, _, kind) = as_upsert(&m);
    assert_eq!(
        parent,
        cloud(D1, "01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K"),
        "the OUTER reference, never b!Pq2...|01FARROOT9ZWBTUFOFD3GSPGOHDJD36KQ2"
    );
    assert_eq!(
        kind,
        &Kind::Folder,
        "shape from shape_body(): `remoteItem` + `folder` and no `package` is a \
         Folder. Accepting Opaque here would license \"a foreign library is not \
         ours to walk into\", and collect_files then skips the entire mounted \
         subtree, so no shared file ever syncs"
    );
    assert_eq!(
        mp.mounts,
        vec![MountPoint {
            placeholder: okey(D1, "01BYE5RZ2LKSHAREXYZ7NQ4M5TVB3WCDEF"),
            remote: okey(D2, "01FARDRIVE7QN3ZWBTUFOFD3GSPGOHDJ36"),
        }]
    );

    let mut ns = Namespace::new();
    apply_all(&mut ns, &mp.items);
    assert_eq!(ns.pending(), 0, "nothing may be left waiting");
}

// ===========================================================================
// DAMAGE CLASS 4 — Two objects on one key, or one object on no key
//
// `namespace::finalise` dedups last-wins on `cloud_id`. Every way of composing
// the wrong key therefore erases a file from the batch with no refusal to
// explain it, and a later `Removed` for that key deletes whichever file last
// claimed it.
// ===========================================================================

const EMPTY_ID: &str = r#"{"id":"","name":"a.txt","size":10,
  "cTag":"\"c:{9E4A2B1C-0000-4000-8000-000000000001},1\"",
  "eTag":"\"{9E4A2B1C-0000-4000-8000-000000000001},2\"",
  "file":{"mimeType":"text/plain","hashes":{"quickXorHash":"nO0Yq1ZpAAA"}},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"},
  "fileSystemInfo":{"createdDateTime":"2026-08-01T09:00:00Z",
                    "lastModifiedDateTime":"2026-08-01T10:00:00Z"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

/// serde maps `""` to `Some("")`, which is a different state from `None`. A
/// mapper written `item.id.as_deref().ok_or(NoId)?` handles the absent case and
/// passes the empty one straight through; likewise an `ItemId::parse` written as
/// `if raw.len() > MAX_ID_BYTES { Err } else { Ok }`. Both compile and pass every
/// friendly fixture. The result is an object keyed by the drive prefix and
/// nothing else, which every id-less item on the drive then folds onto.
#[test]
fn an_empty_string_item_id_is_refused_not_composed_into_a_cloud_id() {
    let scope = primary(D1);
    assert_eq!(map_alone(&scope, EMPTY_ID).unwrap_err(), Unmappable::NoId);

    // The root and a well-formed file share the page so that `changes` is not
    // empty: the `<drive>|` bucket is the actual damage, and an assertion about it
    // that only runs over a vector the test itself proved empty is not an
    // assertion about anything.
    let mp = map_whole_page(&scope, &[EMPTY_ID, GOOD_FILE, D1_ROOT]);
    assert_eq!(mp.refusals.len(), 1, "refusals: {:?}", mp.refusals);
    assert_eq!(mp.refusals[0].why, Unmappable::NoId);
    assert_eq!(mp.refusals[0].key, None, "there is no key to name");
    assert_eq!(
        mp.items.len(),
        2,
        "the good file and the root map; the id-less item does not: {:?}",
        mp.items
    );

    let mut ns = Namespace::new();
    let changes = apply_all(&mut ns, &mp.items);
    let forbidden = format!("{D1}|");
    for c in &changes {
        if let Change::Upserted { cloud_id, .. } = c {
            assert_ne!(cloud_id, &forbidden, "the drive prefix alone is not a key");
        }
    }
    assert_eq!(
        paths(&changes),
        vec!["good.txt"],
        "the empty id produced no change of its own: {changes:?}"
    );
}

// The `\u0000` here is a JSON escape sitting inside a Rust *raw* string, so
// serde decodes it to a real interior NUL. Written as a literal NUL byte the
// fixture would not be valid JSON at all, and the test would fail for the wrong
// reason.
const NUL_ID: &str = r#"{"id":"01BYE5RZ\u00006QN3ZWBTUFOFD3GSPGOHDJD36K","name":"a.txt","size":10,
  "cTag":"\"c:{9E4A2B1C-0000-4000-8000-000000000001},1\"",
  "file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

/// A Rust `String` holds NUL happily and JSON decodes it without complaint, so
/// the only thing that rejects it is an explicit `raw.contains('\0')`. The
/// natural implementation writes `is_empty()` and the length bound — both
/// visibly needed — and omits the NUL check, which no other test exercises.
///
/// The damage is downstream: a cloud_id with an interior NUL is written to an
/// xattr and crosses C string boundaries, where it truncates. The effective key
/// becomes a prefix a genuinely different item can also produce, so one file's
/// placeholder and hydration state get applied to another file.
#[test]
fn an_item_id_containing_nul_is_refused() {
    let scope = primary(D1);
    assert_eq!(
        map_alone(&scope, NUL_ID).unwrap_err(),
        Unmappable::NoId,
        "the only id-shaped variant the design provides"
    );

    // Two rules for the page half. The good file and the root are present so the
    // change vector is non-empty; and the NUL check is against the raw field, not
    // against `format!("{changes:?}")` — `Debug` for `str` escapes NUL to the two
    // characters `\` `0`, so a Debug rendering never contains a 0x00 byte for any
    // input whatsoever.
    let mp = map_whole_page(&scope, &[NUL_ID, GOOD_FILE, D1_ROOT]);
    assert_eq!(mp.refusals.len(), 1, "refusals: {:?}", mp.refusals);
    assert_eq!(mp.refusals[0].why, Unmappable::NoId);
    assert_eq!(
        mp.items.len(),
        2,
        "the good file and the root map; the NUL-bearing id does not: {:?}",
        mp.items
    );

    let mut ns = Namespace::new();
    let changes = apply_all(&mut ns, &mp.items);
    for c in &changes {
        if let Change::Upserted { cloud_id, .. } = c {
            assert!(
                !cloud_id.contains('\0'),
                "a NUL reached a cloud_id: {cloud_id:?}"
            );
        }
    }
    assert_eq!(
        paths(&changes),
        vec!["good.txt"],
        "the NUL-bearing id produced no change of its own: {changes:?}"
    );
}

fn file_with_id(id: &str, name: &str, ctag: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","size":10,"cTag":"{ctag}",
           "file":{{"mimeType":"text/plain"}},
           "parentReference":{{"driveId":"{D1}","driveType":"business",
                              "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"}},
           "lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#
    )
}

/// Both halves in one test, because a one-sided version passes an implementation
/// that refuses everything over 100 bytes.
///
/// `raw.len() >= MAX_ID_BYTES` compiles and fails the control half — and a
/// refusal that recurs every round (Graph re-reports the item forever) blocks the
/// delta token permanently, so the whole drive stops syncing. No bound at all, or
/// a bound applied only to the composed `CloudId`, fails the attack half; note
/// that the design's own arithmetic invites the second error, since
/// `MAX_CLOUD_ID_BYTES` is 512 while two 256-byte ids plus a separator is 513.
///
/// The limit is read from the constant, never a literal.
#[test]
fn an_item_id_at_the_byte_limit_is_accepted_and_one_byte_over_is_refused() {
    let scope = primary(D1);
    let at_limit = "A".repeat(MAX_ID_BYTES);
    let over = "B".repeat(MAX_ID_BYTES + 1);
    let ok = file_with_id(&at_limit, "at-the-limit.txt", r#"\"c:{9E4A},1\""#);
    let bad = file_with_id(&over, "one-over.txt", r#"\"c:{9E4B},1\""#);

    // POSITIVE CONTROL half.
    let m = map_alone(&scope, &ok).expect("an id of exactly MAX_ID_BYTES is legal");
    assert_eq!(as_upsert(&m).0, cloud(D1, &at_limit));

    // Attack half.
    assert_eq!(
        map_item(&scope, &TreeIndex::new(), TagSource::CTag, &one(&bad)).unwrap_err(),
        Unmappable::IdTooLong
    );

    let mut index = TreeIndex::new();
    let mp = map_page(
        &scope,
        &mut index,
        TagSource::CTag,
        &page(&[ok.as_str(), bad.as_str(), D1_ROOT]),
    );
    assert_eq!(mp.refusals.len(), 1, "exactly one: {:?}", mp.refusals);
    assert_eq!(mp.refusals[0].why, Unmappable::IdTooLong);
    assert_eq!(
        mp.items.len(),
        2,
        "the legal id and the root map; not zero, not three"
    );

    let mut ns = Namespace::new();
    let changes = apply_all(&mut ns, &mp.items);
    assert_eq!(paths(&changes), vec!["at-the-limit.txt"]);
}

/// `raw.chars().count() > MAX_ID_BYTES` compiles, reads as correct, and is
/// indistinguishable from the right check under every ASCII fixture in this file
/// — including the boundary test above. The constant is named `MAX_ID_BYTES`
/// precisely because someone will reach for `chars()`.
#[test]
fn an_item_id_is_bounded_in_bytes_not_characters() {
    let scope = primary(D1);
    let wide = "\u{1F600}".repeat(100); // 100 chars, 400 UTF-8 bytes
    assert!(
        wide.chars().count() <= MAX_ID_BYTES && wide.len() > MAX_ID_BYTES,
        "fixture precondition: inside the limit counted in chars, outside it \
         counted in bytes — if MAX_ID_BYTES moves, this test stops meaning anything"
    );

    let json = file_with_id(&wide, "wide.txt", r#"\"c:{9E4C},1\""#);
    assert_eq!(
        map_alone(&scope, &json).unwrap_err(),
        Unmappable::IdTooLong,
        "400 bytes exceeds MAX_ID_BYTES even though the id is only 100 characters"
    );

    let mp = map_whole_page(&scope, &[json.as_str()]);
    assert!(mp.items.is_empty());
    assert_eq!(mp.refusals.len(), 1);
}

const NUMERIC_ID: &str = r#"{"id":12345,"name":"numeric-id.txt","size":20,
  "cTag":"\"c:{9E4D},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

const GOOD_FILE: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"good.txt","size":10,
  "cTag":"\"c:{9E4A},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

/// `DeltaPage::parse` cannot be a plain derive — it has to spot an `error` key on
/// HTTP 200 and enforce exactly-one-of nextLink/deltaLink — so the implementation
/// holds a `serde_json::Value` first. Once it does,
/// `arr.iter().filter_map(|v| from_value::<DriveItem>(v.clone()).ok()).collect()`
/// is the obvious next line, compiles, and passes every other envelope test.
///
/// A silently dropped element is a change the mapper never sees: nothing refuses
/// it, the round still reaches its deltaLink, and the cursor advances past a
/// change Graph will never repeat. `DeltaPage` carries no refusal channel, so
/// per-item tolerance is not expressible in the declared types — `Malformed` is
/// the only outcome that keeps the item accounted for.
#[test]
fn a_non_string_item_id_fails_the_page_rather_than_dropping_the_item() {
    let raw = body(&[GOOD_FILE, NUMERIC_ID]);
    match DeltaPage::parse(200, raw.as_bytes()) {
        Err(EnvelopeError::Malformed(_)) => {}
        Err(other) => panic!("expected Malformed, got {other:?}"),
        Ok(p) => panic!(
            "the Ok arm must never be taken; the element was silently dropped \
             (value.len() == {})",
            p.value.len()
        ),
    }
}

/// The design hands `parse` a `&[u8]`. `from_str(&String::from_utf8_lossy(body))`
/// is the shortest route from those bytes to a `&str`, compiles, and passes every
/// other envelope test — it just silently rewrites the identity field. Only
/// `from_slice` (or an explicit `str::from_utf8`) fails the body.
///
/// A U+FFFD-repaired id is not the id the service sent, so the object is created
/// under a key Graph will never mention again; and distinct corrupt sequences
/// collapse to identical replacement-char strings, putting two objects on one
/// cloud_id.
#[test]
fn an_id_with_invalid_utf8_bytes_is_not_lossily_repaired() {
    let mut raw: Vec<u8> = Vec::new();
    raw.extend_from_slice(br#"{"value":[{"id":"01BYE5RZ"#);
    raw.extend_from_slice(&[0xED, 0xA0, 0x80]); // a raw unpaired surrogate, not a \u escape
    raw.extend_from_slice(br#"4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt","size":10,"#);
    raw.extend_from_slice(br#""cTag":"c1","file":{"mimeType":"text/plain"},"#);
    raw.extend_from_slice(
        br#""parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","id":"R"}}],"#,
    );
    // The well-formed DELTA constant, not a one-character stand-in: if `parse`
    // validates the link's shape at all, a `from_utf8_lossy` implementation would
    // still return `Malformed` and this test would pass with the lossy repair
    // intact. Invalid UTF-8 must be the only thing wrong with this body.
    raw.extend_from_slice(format!(r#""@odata.deltaLink":"{DELTA}"}}"#).as_bytes());

    match DeltaPage::parse(200, &raw) {
        Err(EnvelopeError::Malformed(_)) => {}
        Err(other) => panic!("expected Malformed, got {other:?}"),
        Ok(_) => panic!("lossy repair: an id containing U+FFFD is not the id the service sent"),
    }
}

/// Against the design exactly as written this fails on first run: `parse` rejects
/// only empty, NUL and oversize, and `to_cloud_id` is an infallible
/// `format!("{drive}|{item}")`. Nothing in the declared types excludes the
/// separator from either component, so
/// `("b!X", "01A|01B")` and `("b!X|01A", "01B")` compose to the same string.
///
/// Rejecting the separator in `ItemId::parse` and/or `DriveId::parse` satisfies
/// this; silently composing both does not. (The drive-side value is adversarial
/// rather than something Graph emits today; the enforcement point is `parse`, and
/// the job here is to make the missing exclusion visible before an
/// `ObjectKey::parse` is written on top of it.)
#[test]
fn the_id_separator_cannot_compose_two_object_keys_into_one_cloud_id() {
    // One disjunction, so that both correct answers pass and only the collision
    // fails. Refusing the component at `parse` and length-prefixing (or escaping)
    // in `to_cloud_id` are both correct, and the design names the second as an
    // alternative; asserting which one is chosen would be asserting an
    // implementation choice this test has no business making.
    let collide = match (
        DriveId::parse(D1),
        ItemId::parse("01BYE5RZ|6QN3ZWBTUFOFD3GSPGOHDJD36K"),
        DriveId::parse(&format!("{D1}|01BYE5RZ")),
        ItemId::parse("6QN3ZWBTUFOFD3GSPGOHDJD36K"),
    ) {
        (Ok(ad), Ok(ai), Ok(bd), Ok(bi)) => {
            ObjectKey::new(ad, ai).to_cloud_id().into_inner()
                == ObjectKey::new(bd, bi).to_cloud_id().into_inner()
        }
        // At least one component was refused at `parse` — the other correct
        // answer, and the exclusion is then enforced before a key exists.
        _ => false,
    };

    assert!(
        !collide,
        "two distinct objects composed to one cloud_id: \
         \"{D1}|01BYE5RZ|6QN3ZWBTUFOFD3GSPGOHDJD36K\" — finalise dedups \
         last-wins on cloud_id, so one is erased from every batch and a \
         Removed for either deletes the other's local file"
    );
}

const D1_SHARE: &str = r#"{"id":"01BYE5RZ2LKSHAREXYZ7NQ4M5TVB3WCDEF","name":"Team Files",
  "size":4096,"eTag":"\"{1A2B},1\"",
  "remoteItem":{"id":"01FARDRIVE7QN3ZWBTUFOFD3GSPGOHDJ36","name":"Team Files","size":4096,
    "folder":{"childCount":1},
    "parentReference":{"driveId":"b!Pq2Wr8LmNEeT4kXc9ZaHfA2","driveType":"documentLibrary",
                       "id":"01FARROOT9ZWBTUFOFD3GSPGOHDJD36KQ2"},
    "fileSystemInfo":{"lastModifiedDateTime":"2026-07-20T12:00:00Z"}},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"}}"#;

const D2_SAME_ID_FILE: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt",
  "size":77,"cTag":"\"c:{7C3D},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Pq2Wr8LmNEeT4kXc9ZaHfA2","driveType":"documentLibrary",
                     "id":"01FARDRIVE7QN3ZWBTUFOFD3GSPGOHDJ36",
                     "path":"/drives/b!Pq2Wr8LmNEeT4kXc9ZaHfA2/root:/Team Files"},
  "lastModifiedDateTime":"2026-07-20T12:00:00Z"}"#;

fn mounted_d2() -> DriveScope {
    DriveScope::mounted(
        drive_id(D2),
        Anchor::new(
            okey(D1, "01BYE5RZ2LKSHAREXYZ7NQ4M5TVB3WCDEF"),
            item_id("01FARDRIVE7QN3ZWBTUFOFD3GSPGOHDJ36"),
        ),
    )
}

/// Item ids are unique per drive, not globally. `namespace.rs` already sets
/// `cloud_id: id.clone()` from `Item::Upsert.id`, so `Item::Upsert { id:
/// item_id_string, .. }` is the shortest thing that compiles and it passes every
/// single-drive fixture. `finalise`'s last-wins dedup then keeps exactly one of
/// the two, so the failure is a *missing change* rather than a crash, and it is
/// invisible until the first shared library appears on the drive.
///
/// The two sizes make the survivor of a collapse identifiable in the message.
#[test]
fn two_drives_with_the_same_item_id_stay_two_objects() {
    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(&primary(D1), &page(&[D1_ROOT, D1_SHARE, GOOD_FILE]));
    round.feed(&mounted_d2(), &page(&[D2_SAME_ID_FILE]));
    let done = round.finish().expect("both scopes must complete");

    let near = cloud(D1, "01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR");
    let far = cloud(D2, "01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR");
    assert_ne!(near, far, "the drive must be part of the key");

    let ups: Vec<&Change> = done
        .changes
        .iter()
        .filter(|c| matches!(c, Change::Upserted { .. }))
        .collect();
    assert_eq!(
        ups.len(),
        2,
        "one change means the two files collapsed onto one node: {ups:?}"
    );
    assert!(
        ups.contains(&&Change::Upserted {
            cloud_id: near,
            path: "good.txt".into(),
            size: 10,
            etag: Some("ct:\"c:{9E4A},1\"".into()),
        }),
        "changes: {ups:?}"
    );
    assert!(
        ups.contains(&&Change::Upserted {
            cloud_id: far,
            path: "Team Files/a.txt".into(),
            size: 77,
            etag: Some("ct:\"c:{7C3D},1\"".into()),
        }),
        "changes: {ups:?}"
    );
}

const D2_FOLDER_SAME_ID: &str = r#"{"id":"01SHAREDIDQN3ZWBTUFOFD3GSPGOHDJD3K","name":"Reports",
  "folder":{"childCount":2},"size":8192,
  "parentReference":{"driveId":"b!Pq2Wr8LmNEeT4kXc9ZaHfA2","driveType":"documentLibrary",
                     "id":"01FARDRIVE7QN3ZWBTUFOFD3GSPGOHDJ36",
                     "path":"/drives/b!Pq2Wr8LmNEeT4kXc9ZaHfA2/root:/Team Files"}}"#;

const D2_CHILD_1: &str = r#"{"id":"01FARCHILD1N3ZWBTUFOFD3GSPGOHDJD3K","name":"q1.txt","size":11,
  "cTag":"\"c:{7C31},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Pq2Wr8LmNEeT4kXc9ZaHfA2","driveType":"documentLibrary",
                     "id":"01SHAREDIDQN3ZWBTUFOFD3GSPGOHDJD3K"}}"#;

const D2_CHILD_2: &str = r#"{"id":"01FARCHILD2N3ZWBTUFOFD3GSPGOHDJD3K","name":"q2.txt","size":12,
  "cTag":"\"c:{7C32},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Pq2Wr8LmNEeT4kXc9ZaHfA2","driveType":"documentLibrary",
                     "id":"01SHAREDIDQN3ZWBTUFOFD3GSPGOHDJD3K"}}"#;

const D1_FILE_SAME_ID: &str = r#"{"id":"01SHAREDIDQN3ZWBTUFOFD3GSPGOHDJD3K","name":"notes.txt",
  "size":10,"cTag":"\"c:{9E4F},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"},
  "lastModifiedDateTime":"2026-08-02T10:00:00Z"}"#;

/// POSITIVE CONTROL for the shape-flip guard.
///
/// The design declares `TreeIndex::shape_of(&ItemId)`, `child_count(&ItemId)`,
/// `depth_of(&ItemId)` — keyed by item id with no drive component — and
/// `Unmappable::{ShapeFlip, PathCollision, SecondRoot}` carry a bare `ItemId`
/// too. Implemented literally, the guard looks up the id, finds a *foreign*
/// drive's two-child folder, and refuses a perfectly ordinary new file. The
/// refusal is unclearable — Graph re-reports the item every round — so it blocks
/// the token and the entire primary drive stops syncing.
///
/// Every single-drive test passes; only a fixture with two drives in one index
/// can fail it. The index is built by mapping, not hand-populated.
#[test]
fn the_tree_index_never_answers_about_a_different_drive() {
    let mut index = TreeIndex::new();
    let mounted = mounted_d2();
    let first = map_page(
        &mounted,
        &mut index,
        TagSource::CTag,
        &page(&[D2_FOLDER_SAME_ID, D2_CHILD_1, D2_CHILD_2]),
    );
    assert!(first.refusals.is_empty(), "round 1: {:?}", first.refusals);

    let scope = primary(D1);
    let second = map_page(
        &scope,
        &mut index,
        TagSource::CTag,
        &page(&[D1_FILE_SAME_ID, D1_ROOT]),
    );
    assert!(
        second.refusals.is_empty(),
        "a new file on the primary drive must not collide with a foreign \
         drive's folder of the same item id — specifically no \
         ShapeFlip{{from: Folder, to: File, children: 2}}: {:?}",
        second.refusals
    );

    let m = map_item(&scope, &index, TagSource::CTag, &one(D1_FILE_SAME_ID))
        .expect("an ordinary new file");
    let (id, _, _, kind) = as_upsert(&m);
    assert_eq!(id, cloud(D1, "01SHAREDIDQN3ZWBTUFOFD3GSPGOHDJD3K"));
    assert!(matches!(kind, Kind::File { size: 10, .. }), "got {kind:?}");

    // Round half. Weakened deliberately: this fixture does not describe a
    // complete primary tree, so `finish()` may legitimately withhold a token for
    // other reasons. The falsifiable claim is the escalation's identity.
    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(
        &mounted,
        &page(&[D2_FOLDER_SAME_ID, D2_CHILD_1, D2_CHILD_2]),
    );
    round.feed(&scope, &page(&[D1_FILE_SAME_ID, D1_ROOT]));
    if let Err((esc, _)) = round.finish() {
        assert!(
            !matches!(esc, Escalation::ShapeFlipWithChildren { .. }),
            "a cross-drive id coincidence must never escalate: {esc:?}"
        );
    }
}

const CASE_VARIANT_PARENT: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt",
  "size":10,"cTag":"\"c:{9E4A},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!kX9yZ3qPueEf2MvN7tBlDq1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

/// Drive ids are base64url and case-significant, so `b!Kx9...` and `b!kX9...`
/// denote different drives. `eq_ignore_ascii_case` is the reflex comparison for
/// opaque service identifiers; it compiles and passes every fixture whose driveId
/// matches exactly. A folding comparison accepts an item from another drive as
/// local and attaches it to a local parent id that *does* exist, materialising a
/// foreign tenant's file inside the sync root at a path this drive never
/// described.
///
/// The root still maps: a positive control that the drive comparison is not
/// simply always-false.
#[test]
fn a_case_variant_drive_id_is_a_different_drive() {
    let scope = primary(D1);
    assert_eq!(
        map_alone(&scope, CASE_VARIANT_PARENT).unwrap_err(),
        Unmappable::ForeignParent {
            parent_drive: drive_id("b!kX9yZ3qPueEf2MvN7tBlDq1"),
        },
        "the value as sent, not case-folded"
    );

    let mp = map_whole_page(&scope, &[D1_ROOT, CASE_VARIANT_PARENT]);
    assert_eq!(mp.refusals.len(), 1);
    assert_eq!(
        mp.items.len(),
        1,
        "POSITIVE CONTROL: the root still maps: {:?}",
        mp.items
    );

    let mut ns = Namespace::new();
    let changes = apply_all(&mut ns, &mp.items);
    assert!(file_changes(&changes).is_empty(), "{changes:?}");
    assert_eq!(folder_paths(&changes), vec![""]);
    assert!(paths(&ns.listing()).is_empty());
    assert_eq!(ns.pending(), 0);
}

// ===========================================================================
// DAMAGE CLASS 5 — Placement: a file at a path the service never described,
//                  or a file held forever on a parent that never arrives
//
// `Namespace::waiting` is a silent third state: an item held there is neither
// applied nor reported as a problem. `Report.pending_after_round` blocks the
// token, so a permanent wait is a permanent outage with no error anywhere.
// ===========================================================================

const CHILD_FIRST_FILE: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt",
  "size":10,"cTag":"\"c:{9E4A},1\"","eTag":"\"{9E4A},2\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ5MMOTFRSCTMFF2HZTQZP4B4VNY","path":"/drive/root:/Work"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

const CHILD_FIRST_FOLDER: &str = r#"{"id":"01BYE5RZ5MMOTFRSCTMFF2HZTQZP4B4VNY","name":"Work",
  "folder":{"childCount":1},"size":10,
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"}}"#;

/// The item's own id goes through `ObjectKey::to_cloud_id` because `CloudId` is
/// the only thing `Change::Upserted` accepts — but the parent arrives as
/// `ItemReference.id`, a bare `String`, and `Item::Upsert.parent` is also a
/// `String`, so `parent: pr.id.clone()` compiles, type-checks and reads
/// correctly. The root then enters the tree as `"b!Kx9...|01BYE5RZ6QN..."` while
/// `Work` waits on `"01BYE5RZ6QN..."`.
///
/// `waiting[]` never drains, `problems()` stays empty so nothing is refused and
/// nothing is reported, `listing()` is empty, and the token is blocked every
/// round while the provider reports no error. Child-first is what Graph actually
/// sends and makes the pending set the visible symptom.
#[test]
fn the_emitted_parent_is_the_parents_cloud_id_not_its_bare_item_id() {
    let scope = primary(D1);
    let mp = map_whole_page(&scope, &[CHILD_FIRST_FILE, CHILD_FIRST_FOLDER, D1_ROOT]);
    assert!(mp.refusals.is_empty(), "{:?}", mp.refusals);

    let mut ns = Namespace::new();
    apply_all(&mut ns, &mp.items);
    assert_eq!(ns.pending(), 0, "pending: {:?}", ns.pending_ids());
    assert!(ns.problems().is_empty(), "{:?}", ns.problems());
    let listing = ns.listing();
    assert_eq!(folder_paths(&listing), vec!["", "Work"]);
    assert_eq!(
        file_changes(&listing),
        vec![Change::Upserted {
            cloud_id: cloud(D1, "01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR"),
            path: "Work/a.txt".into(),
            size: 10,
            etag: Some("ct:\"c:{9E4A},1\"".into()),
        }]
    );
}

const NO_PARENT_REF: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt",
  "size":10,"cTag":"\"c:{9E4A},1\"","eTag":"\"{9E4A},2\"",
  "file":{"mimeType":"text/plain"},"lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

/// `item.parent_reference.and_then(|p| p.id).unwrap_or_default()` compiles, and
/// so does the "helpful" `.unwrap_or_else(|| self.root_id.clone())`. Both pass
/// every fixture that includes a parentReference, which is all the friendly ones.
/// An empty parent key is a node `Namespace` will never have, so the item is
/// reported as pending forever — "not yet" about a parent that does not exist.
/// Reparenting to root is worse: the file appears at the top of the sync root at
/// a path the service never described.
///
/// The `Some(key)` on the refusal is what lets the round quarantine it; a weaker
/// version of this test that only asserts `Err` would pass an implementation that
/// refuses with `key: None` and so can never be quarantined.
#[test]
fn an_absent_parent_reference_on_a_live_file_is_refused_not_held() {
    let scope = primary(D1);
    assert_eq!(
        map_alone(&scope, NO_PARENT_REF).unwrap_err(),
        Unmappable::NoParent
    );

    let mp = map_whole_page(&scope, &[NO_PARENT_REF]);
    assert!(mp.items.is_empty());
    assert_eq!(mp.refusals.len(), 1);
    assert_eq!(
        mp.refusals[0].key,
        Some(okey(D1, "01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR")),
        "keyed, so the round can quarantine it instead of blocking forever"
    );
}

const PARENT_REF_NO_ID: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt",
  "size":10,"cTag":"\"c:{9E4A},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "path":"/drive/root:/Work"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

/// This shape defeats a guard written as `if item.parent_reference.is_some()` —
/// the reference is present, only its id is missing — and it is the shape most
/// likely to reach an `.unwrap()` or `.expect("parent has an id")` written under
/// the assumption that a present parentReference is a usable one. A panic takes
/// the whole daemon down on a shape the service is entitled to send when a
/// projection drops the id.
#[test]
fn a_parent_reference_with_a_drive_but_no_id_is_refused() {
    let scope = primary(D1);
    assert_eq!(
        map_alone(&scope, PARENT_REF_NO_ID).unwrap_err(),
        Unmappable::NoParent,
        "not a panic, not NoId, not ForeignParent"
    );

    let mp = map_whole_page(&scope, &[PARENT_REF_NO_ID]);
    assert!(mp.items.is_empty());
    assert_eq!(mp.refusals.len(), 1);
    assert_eq!(
        mp.refusals[0].key,
        Some(okey(D1, "01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR"))
    );
}

const EMPTY_PARENT_A: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt",
  "size":10,"cTag":"\"c:{9E4A},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"","path":"/drive/root:"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

const EMPTY_PARENT_B: &str = r#"{"id":"01BYE5RZ7BQXZWBTUFOFD3GSPGOHDJD36K","name":"b.txt",
  "size":20,"cTag":"\"c:{9E4B},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"","path":"/drive/root:"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

/// `pr.id.as_ref().ok_or(NoParent)?` handles the absent case and lets `Some("")`
/// through untouched. The rule is "absent **or empty**" because only the first
/// half is a `None` check; the second is an extra line that no friendly fixture
/// forces. A composed parent key of `"<drive>|"` is a single bucket that every
/// empty-parent item on the drive falls into.
///
/// Two items rather than one, to catch an implementation that refuses correctly
/// but records one refusal per distinct *parent key* instead of one per item.
#[test]
fn an_empty_parent_id_is_refused_not_used_as_a_key() {
    let scope = primary(D1);
    for json in [EMPTY_PARENT_A, EMPTY_PARENT_B] {
        assert_eq!(map_alone(&scope, json).unwrap_err(), Unmappable::NoParent);
    }

    let mp = map_whole_page(&scope, &[EMPTY_PARENT_A, EMPTY_PARENT_B]);
    assert!(mp.items.is_empty());
    assert_eq!(
        mp.refusals.len(),
        2,
        "one refusal per item, not one per shared bogus parent key: {:?}",
        mp.refusals
    );
    for r in &mp.refusals {
        assert_eq!(r.why, Unmappable::NoParent);
    }
    assert_ne!(
        mp.refusals[0].key, mp.refusals[1].key,
        "the two refusals name the two items, not the one bogus parent twice: {:?}",
        mp.refusals
    );
}

const FOREIGN_PARENT: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt",
  "size":10,"cTag":"\"c:{9E4A},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Pq2Wr8LmNEeT4kXc9ZaHfA2","driveType":"documentLibrary",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K",
                     "path":"/drives/b!Pq2Wr8LmNEeT4kXc9ZaHfA2/root:"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

/// The natural implementation reads `pr.id` and stops; `driveId` is right there
/// but comparing it is a line no single-drive fixture exercises. The foreign
/// `parentReference.id` is deliberately the *same string* as this drive's root
/// id, so an implementation that ignores `driveId` does not merely mis-key — it
/// silently succeeds and drops another tenant's file into the sync root.
///
/// The typed payload matters too: a payload-less refusal is indistinguishable
/// from a missing parent, so the round cannot route a mountable object to fan-out
/// and instead treats it as garbage.
#[test]
fn a_parent_on_another_drive_is_refused_and_names_the_drive() {
    let scope = primary(D1);
    assert_eq!(
        map_alone(&scope, FOREIGN_PARENT).unwrap_err(),
        Unmappable::ForeignParent {
            parent_drive: drive_id(D2),
        },
        "the variant and its payload, not a bare NoParent"
    );

    // The refusal channel first: the `upserted_for` checks below are true of an
    // implementation that drops the item without recording anything, which is the
    // failure that costs the file rather than merely mis-filing it.
    let mp = map_whole_page(&scope, &[D1_ROOT, FOREIGN_PARENT]);
    assert_eq!(mp.refusals.len(), 1, "refusals: {:?}", mp.refusals);
    assert_eq!(
        mp.refusals[0].why,
        Unmappable::ForeignParent {
            parent_drive: drive_id(D2),
        }
    );
    assert_eq!(
        mp.refusals[0].key,
        Some(okey(D1, "01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR")),
        "keyed on the NEAR drive: the item is this drive's to refuse"
    );
    assert_eq!(
        mp.items,
        vec![Item::Root {
            id: cloud(D1, "01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K")
        }],
        "POSITIVE CONTROL: the root still maps: {:?}",
        mp.items
    );

    let mut ns = Namespace::new();
    let changes = apply_all(&mut ns, &mp.items);
    assert!(
        upserted_for(&changes, &cloud(D1, "01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR")).is_empty()
            && upserted_for(&changes, &cloud(D2, "01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR")).is_empty(),
        "{changes:?}"
    );
    let listing = ns.listing();
    assert!(paths(&listing).is_empty(), "only the root landed");
    assert_eq!(folder_paths(&listing), vec![""]);
    assert_eq!(ns.pending(), 0);
}

const MOUNTED_CHILD: &str = r#"{"id":"01FARCHILD1N3ZWBTUFOFD3GSPGOHDJD3K","name":"q1.txt",
  "size":11,"cTag":"\"c:{7C31},1\"","eTag":"\"{7C31},2\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Pq2Wr8LmNEeT4kXc9ZaHfA2","driveType":"documentLibrary",
                     "id":"01FARDRIVE7QN3ZWBTUFOFD3GSPGOHDJ36",
                     "path":"/drives/b!Pq2Wr8LmNEeT4kXc9ZaHfA2/root:/Team Files"},
  "lastModifiedDateTime":"2026-07-20T12:00:00Z"}"#;

/// POSITIVE CONTROL. Two things at once.
///
/// (a) The drive comparison is against `scope.drive()`. The shortest
/// implementation captures the *primary* DriveId once and passes every
/// primary-drive fixture; against a mount it makes every item `ForeignParent`, so
/// a shared library refuses 100% of its contents and those unclearable refusals
/// stop the entire provider.
///
/// (b) The anchor rewrites the remote root to the placeholder's `ObjectKey`
/// rather than emitting an item for it. This is the design's own stated
/// ambiguity — one paragraph says Upsert-under-placeholder, another says the
/// child lands *at* the placeholder path, and both cannot hold — so it will be
/// got wrong by default, leaving the mounted subtree waiting forever on a parent
/// for which no Item is ever emitted.
#[test]
fn a_mounted_scope_accepts_a_parent_on_its_own_drive() {
    let scope = mounted_d2();
    let m = map_alone(&scope, MOUNTED_CHILD).expect("a mounted child must map");
    assert_eq!(
        m.item,
        Some(Item::Upsert {
            id: cloud(D2, "01FARCHILD1N3ZWBTUFOFD3GSPGOHDJD3K"),
            parent: cloud(D1, "01BYE5RZ2LKSHAREXYZ7NQ4M5TVB3WCDEF"),
            name: "q1.txt".into(),
            kind: file(11, "ct:\"c:{7C31},1\""),
        }),
        "parent is the placeholder's key, not the remote root's"
    );

    // The page half says what the `map_alone` above cannot: that `map_page` routes
    // this item to `items` and not to some other channel. "No ForeignParent" alone
    // is implied by the successful `map_alone` — same `map_item`, same empty index
    // — and so is worth nothing on its own.
    let mp = map_whole_page(&scope, &[MOUNTED_CHILD]);
    assert!(
        mp.refusals.is_empty(),
        "no refusal of any kind inside a mount, ForeignParent least of all: {:?}",
        mp.refusals
    );
    assert_eq!(
        mp.items,
        vec![Item::Upsert {
            id: cloud(D2, "01FARCHILD1N3ZWBTUFOFD3GSPGOHDJD3K"),
            parent: cloud(D1, "01BYE5RZ2LKSHAREXYZ7NQ4M5TVB3WCDEF"),
            name: "q1.txt".into(),
            kind: file(11, "ct:\"c:{7C31},1\""),
        }]
    );
}

const SELF_PARENT: &str = r#"{"id":"01BYE5RZ8SELFTUFOFD3GSPGOHDJD36K","name":"Loop",
  "folder":{"childCount":0},"size":0,
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ8SELFTUFOFD3GSPGOHDJD36K","path":"/drive/root:/Loop"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

/// The verified forever-wait. `Namespace` does have a cycle check, but it is
/// unreachable here: `upsert` tests `self.nodes.get(&parent)` first, and for an id
/// the tree has never seen that is `None`, so the item goes into
/// `waiting["01BYE5RZ8SELF..."]` and returns before `would_cycle` ever runs. It
/// is neither applied nor reported: `problems()` stays empty, and
/// `pending_after_round` blocks the token every round while Graph keeps sending
/// the same item.
///
/// A mapper that omits the `self_id` parameter from `ParentKey::from_outer` and
/// lets `Namespace` adjudicate therefore compiles, passes the known-folder case,
/// and fails only on this one — which is why nothing here is pre-populated.
#[test]
fn a_self_parent_is_refused_before_the_namespace_can_hold_it() {
    let scope = primary(D1);
    assert_eq!(
        map_alone(&scope, SELF_PARENT).unwrap_err(),
        Unmappable::SelfParent,
        "not NoParent, not a forwarded Upsert"
    );

    let mp = map_whole_page(&scope, &[SELF_PARENT, D1_ROOT]);
    assert!(
        mp.refusals.iter().any(|r| r.why == Unmappable::SelfParent
            && r.key == Some(okey(D1, "01BYE5RZ8SELFTUFOFD3GSPGOHDJD36K"))),
        "keyed refusal required: {:?}",
        mp.refusals
    );

    let mut ns = Namespace::new();
    apply_all(&mut ns, &mp.items);
    assert_eq!(ns.pending(), 0, "pending: {:?}", ns.pending_ids());
}

const DEEP_A_TXT: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt","size":10,
  "cTag":"\"c:{9E4A},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ5MMOTFRSCTMFF2HZTQZP4B4VNY","path":"/drive/root:/Team/Work"}}"#;

const DEEP_WORK: &str = r#"{"id":"01BYE5RZ5MMOTFRSCTMFF2HZTQZP4B4VNY","name":"Work",
  "folder":{"childCount":1},"size":10,
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZZQXNZ7XKX5PBFZ2CHZ4HJHFVAR","path":"/drive/root:/Team"}}"#;

const DEEP_TEAM: &str = r#"{"id":"01BYE5RZZQXNZ7XKX5PBFZ2CHZ4HJHFVAR","name":"Team",
  "folder":{"childCount":1},"size":10,
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"}}"#;

const WORK_SELF_PARENT: &str = r#"{"id":"01BYE5RZ5MMOTFRSCTMFF2HZTQZP4B4VNY","name":"Work",
  "folder":{"childCount":1},"size":10,
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ5MMOTFRSCTMFF2HZTQZP4B4VNY","path":"/drive/root:/Team/Work"}}"#;

/// The complement of the previous test: this is the case `would_cycle` *does*
/// catch, so a mapper with no `self_id` parameter produces a plausible-looking
/// refusal and fails only the `problems()`-is-empty assertion. Delegating to
/// `Namespace` records `Problem::Cycle`, and that entry is cleared only by a
/// successful upsert or a delete of that id — neither of which comes while the
/// service keeps sending the same self-parent — so the token is blocked
/// permanently.
///
/// The three-deep fixture is what makes the other failure observable: an
/// implementation that "repairs" a self-parent by reparenting to the root moves
/// `Work` out from under `Team`, and `namespace::upsert` re-emits every
/// descendant at a new path. With `Work` directly under the root the repaired
/// path would be identical to the correct one and the test could not fail.
#[test]
fn a_self_parent_on_a_folder_already_in_the_tree_does_not_poison_it() {
    let scope = primary(D1);
    let mut index = TreeIndex::new();
    let first = map_page(
        &scope,
        &mut index,
        TagSource::CTag,
        &page(&[DEEP_A_TXT, DEEP_WORK, DEEP_TEAM, D1_ROOT]),
    );
    assert!(first.refusals.is_empty(), "round 1: {:?}", first.refusals);

    let mut ns = Namespace::new();
    apply_all(&mut ns, &first.items);
    let before = ns.listing();
    assert_eq!(
        paths(&before),
        vec!["Team/Work/a.txt"],
        "round 1 precondition"
    );

    assert_eq!(
        map_item(&scope, &index, TagSource::CTag, &one(WORK_SELF_PARENT)).unwrap_err(),
        Unmappable::SelfParent,
        "refused at the mapper, so Namespace never records Problem::Cycle"
    );

    let second = map_page(
        &scope,
        &mut index,
        TagSource::CTag,
        &page(&[WORK_SELF_PARENT]),
    );
    let changes = apply_all(&mut ns, &second.items);
    assert!(changes.is_empty(), "round 2 emits nothing: {changes:?}");
    assert!(
        ns.problems().is_empty(),
        "nothing may reach Namespace: {:?}",
        ns.problems()
    );
    assert_eq!(
        ns.listing(),
        before,
        "no reparent-to-root: a 50-file folder must not move on the strength of \
         a malformed parentReference"
    );
}

const REAL_ROOT_D1: &str = r#"{"id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","name":"root",
  "root":{},"folder":{"childCount":9},"size":1048576,
  "eTag":"\"{3F1C},1\"","cTag":"\"c:{3F1C},0\"",
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business"},
  "fileSystemInfo":{"createdDateTime":"2026-01-04T09:00:00Z",
                    "lastModifiedDateTime":"2026-08-01T10:00:00Z"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

const ROOT_CHILD: &str = r#"{"id":"01BYE5RZ4A7GBFN2SFHZE2S4WGXVDQAWLR","name":"a.txt","size":10,
  "cTag":"\"c:{9E4A},1\"","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!Kx9Yz3QpUEeF2mVn7TbLdQ1","driveType":"business",
                     "id":"01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K","path":"/drive/root:"},
  "lastModifiedDateTime":"2026-08-01T10:00:00Z"}"#;

/// POSITIVE CONTROL for check ordering, and the complement of the rootless-root
/// rule: only asserting both directions pins it.
///
/// Most arms of `map_item` need a `ParentKey`, so computing it once up front
/// before matching the shape is the natural structure — and the parent rules then
/// fire on the genuine Graph root, whose parentReference really does omit `id`.
/// If the root is refused the drive has no anchor: every item waits on a parent
/// that never arrives, `listing()` is empty, and the provider reports zero files
/// while the tree sits intact on disk.
#[test]
fn a_root_whose_parent_reference_has_no_id_is_the_root_not_a_refusal() {
    let scope = primary(D1);
    let m = map_alone(&scope, REAL_ROOT_D1).expect("the real Graph root must map");
    assert_eq!(
        m.item,
        Some(Item::Root {
            id: cloud(D1, "01BYE5RZ6QN3ZWBTUFOFD3GSPGOHDJD36K")
        }),
        "explicitly not NoParent and not an Upsert"
    );
    assert_eq!(m.mount, None);

    let mp = map_whole_page(&scope, &[REAL_ROOT_D1, ROOT_CHILD]);
    assert!(mp.refusals.is_empty(), "{:?}", mp.refusals);

    let mut ns = Namespace::new();
    apply_all(&mut ns, &mp.items);
    assert_eq!(ns.pending(), 0);
    assert_eq!(
        paths(&ns.listing()),
        vec!["a.txt"],
        "the root's name is never a path segment"
    );
}

// ===========================================================================
// DAMAGE CLASS 6 — A refusal that can never be cleared
//
// `namespace::problems` is emptied only by a successful upsert or a delete of
// that id. For an item that keeps arriving unchanged, neither ever comes, and an
// unresolved refusal withholds the token — so one wrongly refused item anywhere
// on the drive pins the provider's cursor permanently. This is the defect the
// design says it already found once.
// ===========================================================================

const PACKAGE_CHILD: &str = r#"{"id":"01SEC","name":"Section.one","size":40960,
  "eTag":"\"{5D3B9F80-6A72-4E19-BC44-9F2E71A0C8D5},9\"",
  "cTag":"\"c:{5D3B9F80-6A72-4E19-BC44-9F2E71A0C8D5},9\"",
  "file":{"mimeType":"application/msonenote"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01NB",
                     "path":"/drive/root:/Team Notebook"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-07-19T12:00:00Z"}}"#;

/// The design's own table says a notebook's internals should "appear in
/// `Report.refusals` or `problems`", and implementing that sentence literally is
/// the bug. Concretely: a refusal for any item whose parent is `Opaque`, or an
/// extension filter on `.one`/`.onetoc2` — both compile, both look like they are
/// protecting the notebook, and both pin the cursor forever.
///
/// Suppressing the *change* is `Namespace`'s job: `collect_files` skips `Opaque`
/// subtrees, so the internals are tracked for pathing and never listed. The index
/// holds the package and nothing else on purpose — parent-known is the order in
/// which this guard actually fires, so an empty-index fixture would let a
/// refusing implementation pass.
#[test]
fn a_packages_child_is_forwarded_as_an_ordinary_upsert_not_refused() {
    let scope = primary(MINE);
    let mut index = TreeIndex::new();
    let notebook = map_page(&scope, &mut index, TagSource::CTag, &page(&[PACKAGE]));
    assert_eq!(kind_of_item(&notebook.items[0]), &Kind::Opaque);

    let mp = map_page(&scope, &mut index, TagSource::CTag, &page(&[PACKAGE_CHILD]));
    assert!(
        mp.refusals.is_empty(),
        "a package's internals are forwarded, never refused: {:?}",
        mp.refusals
    );
    assert_eq!(
        mp.items,
        vec![Item::Upsert {
            id: cloud(MINE, "01SEC"),
            parent: cloud(MINE, "01NB"),
            name: "Section.one".into(),
            kind: file(40960, "ct:\"c:{5D3B9F80-6A72-4E19-BC44-9F2E71A0C8D5},9\""),
        }]
    );

    // The damage this class is named for, asserted where it lives: a refusal that
    // pins the cursor. Applying the items to a `Namespace` and re-checking
    // `problems()`/`listing()` only re-states `namespace.rs`'s own rules —
    // `upsert` refuses only `Kind::File` parents and `collect_files` skips
    // `Kind::Opaque` — both of which are settled by the two assertions above.
    let mut round = Round::new(TagSource::CTag, ns_rooted(MINE, "01ROOT"));
    round.feed(&scope, &page(&[PACKAGE, PACKAGE_CHILD]));
    let done = round
        .finish()
        .unwrap_or_else(|(e, r)| panic!("a notebook must not withhold the token: {e:?} / {r:?}"));
    assert!(
        done.report.refusals.is_empty(),
        "one notebook on the drive must not stop the provider: {:?}",
        done.report.refusals
    );
    assert!(
        done.report.unresolved_problems.is_empty(),
        "ParentCannotContain against a notebook's internals is cleared by nothing: {:?}",
        done.report.unresolved_problems
    );
    assert!(
        done.report.pending_after_round.is_empty(),
        "{:?}",
        done.report.pending_after_round
    );
}

fn kind_of_item(i: &Item) -> &Kind {
    match i {
        Item::Upsert { kind, .. } => kind,
        other => panic!("expected Item::Upsert, got {other:?}"),
    }
}

// ===========================================================================
// DAMAGE CLASS 7 — Order dependence
//
// `namespace.rs`'s own doc comment says a service is entitled to send a page in
// any order, and Graph does. Every guard that reads `TreeIndex` answers "fine"
// when the index has not seen the ancestor yet, so a guard proven parent-first is
// not proven at all. Both tests here feed strictly deepest-first.
// ===========================================================================

const REV_DEEP: &str = r#"{"id":"01BYE5DEEP","name":"deep.txt","size":10,
  "eTag":"{1C0D4A55-0000-0000-0000-000000000004},4",
  "cTag":"c:{1C0D4A55-0000-0000-0000-000000000004},2",
  "file":{"mimeType":"text/plain","hashes":{"quickXorHash":"HKvPRTGxLRUu9VBOr1nnMDpqWSY="}},
  "fileSystemInfo":{"createdDateTime":"2026-03-02T10:00:00Z",
                    "lastModifiedDateTime":"2026-08-02T07:45:31Z"},
  "parentReference":{"driveId":"b!8vXQ2hRkT0i7pOa9m3LcNw","driveType":"business",
                     "id":"01BYE5NOTE",
                     "path":"/drives/b!8vXQ2hRkT0i7pOa9m3LcNw/root:/Work/Notes"}}"#;

const REV_NOTES: &str = r#"{"id":"01BYE5NOTE","name":"Notes","folder":{"childCount":1},"size":10,
  "eTag":"{1C0D4A55-0000-0000-0000-000000000003},2",
  "parentReference":{"driveId":"b!8vXQ2hRkT0i7pOa9m3LcNw","driveType":"business",
                     "id":"01BYE5WORK","path":"/drives/b!8vXQ2hRkT0i7pOa9m3LcNw/root:/Work"}}"#;

const REV_WORK: &str = r#"{"id":"01BYE5WORK","name":"Work","folder":{"childCount":1},"size":10,
  "eTag":"{1C0D4A55-0000-0000-0000-000000000002},3",
  "parentReference":{"driveId":"b!8vXQ2hRkT0i7pOa9m3LcNw","driveType":"business",
                     "id":"01BYE5ROOT","path":"/drives/b!8vXQ2hRkT0i7pOa9m3LcNw/root:"}}"#;

const REV_ROOT: &str = r#"{"id":"01BYE5ROOT","name":"root","root":{},
  "folder":{"childCount":1},"size":10,
  "eTag":"{1C0D4A55-0000-0000-0000-000000000001},1",
  "parentReference":{"driveId":"b!8vXQ2hRkT0i7pOa9m3LcNw","driveType":"business"}}"#;

/// POSITIVE CONTROL for the whole hostile-order class — without it the rest of
/// this section could pass against a mapper that refuses everything.
///
/// A mapper that resolves each item's path itself from `TreeIndex` at map time
/// and treats an unknown parent id as a refusal returns `NoParent` (or defers)
/// for all three of `01BYE5DEEP`, `01BYE5NOTE` and `01BYE5WORK`, because in this
/// order none of their parents is in the index yet; the round then finishes with
/// three refusals and no changes. A weaker variant emits `path:"deep.txt"` with
/// the unresolvable ancestors silently dropped. Both compile, and both pass a
/// parent-first fixture.
#[test]
fn a_whole_page_in_reverse_depth_order_maps_to_full_paths() {
    let scope = primary(D3);
    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(&scope, &page(&[REV_DEEP, REV_NOTES, REV_WORK, REV_ROOT]));
    let done = round
        .finish()
        .unwrap_or_else(|(e, r)| panic!("deepest-first must still complete: {e:?} / {r:?}"));

    assert!(
        done.report.refusals.is_empty(),
        "{:?}",
        done.report.refusals
    );
    assert!(
        done.report.pending_after_round.is_empty(),
        "{:?}",
        done.report.pending_after_round
    );
    assert_eq!(folder_paths(&done.changes), vec!["", "Work", "Work/Notes"]);
    assert_eq!(
        file_changes(&done.changes),
        vec![Change::Upserted {
            cloud_id: cloud(D3, "01BYE5DEEP"),
            path: "Work/Notes/deep.txt".into(),
            size: 10,
            etag: Some("ct:c:{1C0D4A55-0000-0000-0000-000000000004},2".into()),
        }],
        "the full path, deepest-first order notwithstanding — and the root's name \
         is not a segment of it"
    );
}

/// Reconstructed from a truncated fixture: the original supplied a generator
/// rather than literal JSON (a chain this long does not fit in a constant), so it
/// is built here the same way.
///
/// `value` is emitted strictly leaf-first: the file, then L(LEVELS-1) … L0, then
/// the root. L(n)'s parent is L(n-1); L0's parent is the root. Depth is therefore
/// unknowable at the moment each item is mapped, which is the whole point: a guard
/// written as a single `TreeIndex::depth_of` lookup inside `map_item` answers
/// `None` for every one of these and refuses nothing. `Namespace::upsert` emits
/// nothing when `path_of` exhausts its bound and records no `Problem`, so an
/// unrefused over-deep item is not a wrong path — it is silently invisible.
///
/// **The chain is sized from `MAX_MAPPED_DEPTH`, never from a literal.** An
/// earlier version hard-coded 129 levels and asserted that the item at depth 128
/// was legal, which pinned two things nobody agreed to: the value of the constant,
/// and whether the drive root counts as depth 0 or depth 1. A correct
/// implementation with a bound of 100 or 256, or with the other root convention,
/// failed it. What is asserted here instead is the *relation* to the constant, and
/// only about levels that fall on the same side of it however the root is counted
/// and whether the bound is `>` or `>=`: the three deepest are outside it either
/// way, the four sampled shallow ones are inside it either way. The one straddling
/// level is left unasserted, because nothing in the design states which side it is
/// on — and an assertion about it would be a coin flip, not coverage.
#[test]
fn a_depth_limit_is_enforced_when_the_chain_arrives_leaf_first() {
    // L0 .. L(LEVELS-1). The two deepest folders and the leaf beneath them sit
    // past MAX_MAPPED_DEPTH whichever depth the drive root is counted as.
    const LEVELS: usize = MAX_MAPPED_DEPTH + 3;
    let lvl = |n: usize| format!("01LVL{n:03}");

    let mut items: Vec<String> = Vec::new();
    items.push(format!(
        r#"{{"id":"01BYE5LEAF","name":"leaf.txt","size":12,
           "eTag":"{{2A1B0000-0000-0000-0000-0000000000FF}},1",
           "cTag":"c:{{2A1B0000-0000-0000-0000-0000000000FF}},1",
           "file":{{"mimeType":"text/plain"}},
           "parentReference":{{"driveId":"{D3}","driveType":"business","id":"{}"}}}}"#,
        lvl(LEVELS - 1)
    ));
    for n in (0..LEVELS).rev() {
        let parent = if n == 0 {
            "01BYE5ROOT".to_string()
        } else {
            lvl(n - 1)
        };
        items.push(format!(
            r#"{{"id":"{}","name":"L{n:03}","folder":{{"childCount":1}},"size":12,
               "eTag":"{{2A1B0000-0000-0000-0000-{n:012}}},1",
               "parentReference":{{"driveId":"{D3}","driveType":"business","id":"{parent}"}}}}"#,
            lvl(n)
        ));
    }
    items.push(REV_ROOT.to_string());

    let refs: Vec<&str> = items.iter().map(String::as_str).collect();
    let scope = primary(D3);
    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(&scope, &page(&refs));
    // Either outcome is legitimate for a chain this deep; the refusals are the
    // claim, not the escalation.
    let report = match round.finish() {
        Ok(done) => done.report,
        Err((_, report)) => report,
    };

    let too_deep_depth = |key: &ObjectKey| {
        report.refusals.iter().find_map(|r| match (&r.key, &r.why) {
            (Some(k), Unmappable::TooDeep { depth }) if k == key => Some(*depth),
            _ => None,
        })
    };

    // Attack half: past the bound under either root convention.
    for id in ["01BYE5LEAF".to_string(), lvl(LEVELS - 1), lvl(LEVELS - 2)] {
        let key = okey(D3, &id);
        let depth = too_deep_depth(&key).unwrap_or_else(|| {
            panic!(
                "{id} sits past MAX_MAPPED_DEPTH ({MAX_MAPPED_DEPTH}) and must be \
                 refused TooDeep, leaf-first order notwithstanding: {:?}",
                report.refusals
            )
        });
        assert!(
            depth > MAX_MAPPED_DEPTH,
            "TooDeep must name the offending depth, got {depth} against \
             MAX_MAPPED_DEPTH {MAX_MAPPED_DEPTH} for {id}"
        );
    }

    // POSITIVE CONTROL half: inside the bound under either root convention. A
    // guard with a smaller bound than the constant, or one that refuses the whole
    // chain once any ancestor is refused, fails here.
    for n in [0, 1, MAX_MAPPED_DEPTH / 2, MAX_MAPPED_DEPTH - 3] {
        let key = okey(D3, &lvl(n));
        assert!(
            !report.refusals.iter().any(|r| r.key.as_ref() == Some(&key)),
            "L{n:03} is inside MAX_MAPPED_DEPTH ({MAX_MAPPED_DEPTH}) under either \
             root-depth convention and must map: {:?}",
            report.refusals
        );
    }
}

// ###########################################################################
// ###########################################################################
//
//  APPENDED — the eight uncovered areas from "Falsification 2 — what is
//  missing". One section per gap, numbered as in that report.
//
//  The two construction rules of the module doc still hold and are enforced
//  here: no fixture is fed parent-first unless the test is *about* order, and
//  every negative has a positive control beside it. Three of these gaps are
//  damage classes the sections above are *named* after and never exercise.
//
//  These `use` lines are down here rather than in the header because this block
//  is appended: nothing above it may be edited.
//
// ###########################################################################
// ###########################################################################

use hydration_client::delta::MAX_OBJECT;
use hydration_graph::KindTag;

/// Any syntactically valid nextLink. Needed because a round that spans pages is
/// only honest if the non-final pages say so — `page()` above always ends a
/// round, and three consecutive deltaLinks is not a paging fixture.
const NEXT: &str = "https://graph.microsoft.com/v1.0/drives/x/root/delta?token=bTZpPTI7bT0y";

fn more_page(items: &[&str]) -> DeltaPage {
    let raw = format!(
        r#"{{"value":[{}],"@odata.nextLink":"{}"}}"#,
        items.join(","),
        NEXT
    );
    DeltaPage::parse(200, raw.as_bytes())
        .unwrap_or_else(|e| panic!("fixture page must parse: {e:?}"))
}

fn map_whole_page_with(scope: &DriveScope, tags: TagSource, items: &[&str]) -> MappedPage {
    let mut index = TreeIndex::new();
    map_page(scope, &mut index, tags, &page(items))
}

/// Whether any `Item` in a batch names this cloud id, whatever its variant.
/// "The mapper emitted nothing for X" is the claim several of these tests make,
/// and `items.is_empty()` only says it on a one-item page.
fn names_item(items: &[Item], cloud_id: &str) -> bool {
    items.iter().any(|i| match i {
        Item::Root { id } | Item::Upsert { id, .. } | Item::Delete { id } => id == cloud_id,
    })
}

fn refusal_for(mp: &MappedPage, key: &ObjectKey) -> Option<Unmappable> {
    mp.refusals
        .iter()
        .find(|r| r.key.as_ref() == Some(key))
        .map(|r| r.why.clone())
}

/// An ordinary file on `b!mine` under `01ROOT`. The per-item control for every
/// page below that mixes one bad item with good ones: a mapper that fails the
/// whole page instead of the one item is caught by this file *not* arriving.
const MINE_GOOD: &str = r#"{"id":"01GOOD","name":"good.txt","size":10,
  "cTag":"c:{9E9C},1","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

// ===========================================================================
// GAP 1 — ShapeFlip, and the escalation named after it
//
// §1's heading is "A mis-read facet is a subtree deletion", and the branch it
// names — `namespace::upsert`'s `reshaped` arm, which calls `delete` — is
// reached by nothing above. `Unmappable::ShapeFlip` occurs once in this file,
// inside a *negative* assertion; `Escalation::ShapeFlipWithChildren` likewise.
// An implementation that constructs neither passes all 43 tests above.
//
// The damage is not a mis-classified folder. It is `delete`: a `Change::Removed`
// for every descendant *and* their purge from `nodes`, so no later page and no
// `listing()` can bring them back. One flipped facet on a 2,000-file folder is
// 2,000 local deletions.
//
// These are also the only tests in the file that require `map_page` to register
// *children* in the `&mut TreeIndex` it is handed; nothing else does, so a
// `map_page` that ignores its index parameter entirely passes everything above.
// ===========================================================================

const FLIP_CHILD_TWO: &str = r#"{"id":"01FC2","name":"two.txt","size":22,
  "eTag":"\"{0C1D2E3F-1111-4222-8333-444455556666},1\"",
  "cTag":"c:{0C1D2E3F-1111-4222-8333-444455556666},1",
  "file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01FLIP",
                     "path":"/drive/root:/Reports"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

const FLIP_CHILD_ONE: &str = r#"{"id":"01FC1","name":"one.txt","size":11,
  "eTag":"\"{0C1D2E3F-1111-4222-8333-444455557777},1\"",
  "cTag":"c:{0C1D2E3F-1111-4222-8333-444455557777},1",
  "file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01FLIP",
                     "path":"/drive/root:/Reports"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

const FLIP_AS_FOLDER: &str = r#"{"id":"01FLIP","name":"Reports","size":33,
  "eTag":"\"{0C1D2E3F-1111-4222-8333-444455558888},1\"",
  "folder":{"childCount":2},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

/// The same id, one round later, with a complete and satisfiable file facet.
const FLIP_AS_FILE: &str = r#"{"id":"01FLIP","name":"Reports","size":4096,
  "eTag":"\"{0C1D2E3F-1111-4222-8333-444455558888},2\"",
  "cTag":"c:{0C1D2E3F-1111-4222-8333-444455558888},2",
  "file":{"mimeType":"application/octet-stream"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-08T10:00:00Z"}}"#;

/// Catches, by name: a `map_item` with no shape-flip guard at all — the whole
/// of §1 above is single-item facet *precedence*, and every one of those tests
/// passes an implementation that never compares the new shape against the
/// remembered one. `FLIP_AS_FILE` carries a valid size and cTag so the File arm
/// completes and the item is forwarded as an ordinary `Upsert`; `Namespace`
/// then takes `reshaped`, calls `delete`, and emits `Removed` for `one.txt` and
/// `two.txt` — files that still exist in the cloud, deleted off the user's disk
/// on the strength of one facet.
///
/// It also catches a guard that fires but reports `children: 0` — the count is
/// what `Round` needs to decide between forwarding and escalating, and a guard
/// that asks `TreeIndex` for the shape but not the child count compiles.
///
/// Page 1 is fed child-before-parent, deepest first: a guard that reads the
/// index only for items whose parent it already knows never sees `01FLIP` gain
/// children at all.
#[test]
fn a_folder_that_becomes_a_file_is_refused_and_its_children_survive() {
    let scope = primary(MINE);
    let mut index = TreeIndex::new();
    let first = map_page(
        &scope,
        &mut index,
        TagSource::CTag,
        &page(&[FLIP_CHILD_TWO, FLIP_CHILD_ONE, FLIP_AS_FOLDER, ROOT]),
    );
    assert!(first.refusals.is_empty(), "round 1: {:?}", first.refusals);

    let mut ns = Namespace::new();
    apply_all(&mut ns, &first.items);
    let before = ns.listing();
    assert_eq!(
        paths(&before),
        vec!["Reports/one.txt", "Reports/two.txt"],
        "round 1 precondition"
    );

    assert_eq!(
        map_item(&scope, &index, TagSource::CTag, &one(FLIP_AS_FILE)).unwrap_err(),
        Unmappable::ShapeFlip {
            from: KindTag::Folder,
            to: KindTag::File,
            children: 2,
        },
        "a folder with children may not become a file: not Ok(Upsert{{File}}), \
         which reaches namespace::upsert's reshaped arm and deletes both \
         children off disk; and not children: 0, which lets Round forward it"
    );

    let second = map_page(&scope, &mut index, TagSource::CTag, &page(&[FLIP_AS_FILE]));
    assert_eq!(second.refusals.len(), 1, "{:?}", second.refusals);
    assert_eq!(second.refusals[0].key, Some(okey(MINE, "01FLIP")));

    // The load-bearing half, and the reason it is stated against a real
    // `Namespace` rather than against `second.items`: the deletion happens
    // inside `upsert`, and an implementation that refuses *and* forwards the
    // flip — recording the refusal for the report while still emitting the item
    // — passes every assertion above this line.
    let changes = apply_all(&mut ns, &second.items);
    assert!(
        removals(&changes).is_empty(),
        "a facet flip must remove nothing: {changes:?}"
    );
    assert_eq!(
        ns.listing(),
        before,
        "both children must still be named at their paths — delete() purges \
         them from `nodes`, so a later page cannot restore them"
    );
}

/// The round-level half. `Round` is the only layer that can decide a flip over
/// children is not a change to apply but a state to stop for, and
/// `Escalation::ShapeFlipWithChildren` is the declared way to say so.
///
/// Catches a `Round` that collects the refusal into `Report.refusals` and
/// returns `Ok` — which advances the cursor past a change Graph will never
/// repeat, leaving the tree permanently disagreeing with the service — and a
/// `Round` that escalates without naming the key, which gives an operator
/// nothing to act on.
#[test]
fn a_shape_flip_over_children_escalates_and_withholds_the_token() {
    let scope = primary(MINE);
    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(
        &scope,
        &more_page(&[FLIP_CHILD_TWO, FLIP_CHILD_ONE, FLIP_AS_FOLDER, ROOT]),
    );
    round.feed(&scope, &page(&[FLIP_AS_FILE]));
    match round.finish() {
        Err((Escalation::ShapeFlipWithChildren { key, children }, _)) => {
            assert_eq!(key, okey(MINE, "01FLIP"));
            assert_eq!(children, 2, "the count an operator has to see");
        }
        Ok(done) => panic!(
            "the token must be withheld, not advanced past a subtree deletion: \
             {:?} / {:?}",
            done.changes, done.report
        ),
        Err((other, _)) => panic!("expected ShapeFlipWithChildren, got {other:?}"),
    }
}

const SWAP_AS_FILE: &str = r#"{"id":"01SWAP","name":"notes","size":120,
  "eTag":"\"{1A2B3C4D-5555-4666-8777-888899990000},1\"",
  "cTag":"c:{1A2B3C4D-5555-4666-8777-888899990000},1",
  "file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

const SWAP_AS_FOLDER: &str = r#"{"id":"01SWAP","name":"notes","size":0,
  "eTag":"\"{1A2B3C4D-5555-4666-8777-888899990000},2\"",
  "folder":{"childCount":0},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-08T10:00:00Z"}}"#;

/// POSITIVE CONTROL for the shape-flip guard, and the reason the guard has to
/// count children rather than compare shapes.
///
/// Without it the two tests above are satisfied by `if shape changed { Err(
/// ShapeFlip) }` — a rule that refuses a legitimate, common operation (delete
/// `notes`, create a folder called `notes`; the id is reused often enough that
/// Graph reports exactly this) forever, because the service keeps re-sending
/// the same item and `problems` is cleared only by a successful upsert.
///
/// The `Change::Removed` is asserted, not glossed: `namespace::upsert` emits it
/// from the `reshaped` arm, the old placeholder must go, and a mapper that
/// forwards the flip while something suppresses that removal leaves a file and
/// a directory claiming one path.
#[test]
fn a_childless_file_that_becomes_a_folder_is_forwarded_and_the_stale_file_removed() {
    let scope = primary(MINE);
    let mut index = TreeIndex::new();
    let first = map_page(
        &scope,
        &mut index,
        TagSource::CTag,
        &page(&[SWAP_AS_FILE, ROOT]),
    );
    assert!(first.refusals.is_empty(), "round 1: {:?}", first.refusals);
    let mut ns = Namespace::new();
    apply_all(&mut ns, &first.items);
    assert_eq!(paths(&ns.listing()), vec!["notes"], "round 1 precondition");

    let m = map_item(&scope, &index, TagSource::CTag, &one(SWAP_AS_FOLDER))
        .expect("a childless flip is an ordinary upsert, not a refusal");
    assert_eq!(kind_of(&m), &Kind::Folder);

    let second = map_page(
        &scope,
        &mut index,
        TagSource::CTag,
        &page(&[SWAP_AS_FOLDER]),
    );
    assert!(second.refusals.is_empty(), "{:?}", second.refusals);

    let gone = cloud(MINE, "01SWAP");
    let changes = apply_all(&mut ns, &second.items);
    assert_eq!(
        removals(&changes),
        vec![gone.as_str()],
        "the old file must be removed exactly once: {changes:?}"
    );
    let listing = ns.listing();
    assert!(paths(&listing).is_empty(), "{listing:?}");
    assert_eq!(folder_paths(&listing), vec!["", "notes"]);
}

// ===========================================================================
// GAP 2 — `deleted.state` is one string in all five tombstones above
//
// Every tombstone in §2 and §3 is `{"state":"softDeleted"}`, so
// `match state { "softDeleted" => delete, _ => not a delete }` passes all 43
// tests. Graph also sends `"deleted":{}` — the documented shape — and
// `{"state":"deleted"}`. Under that comparison both become non-deletes: the
// item stays in the tree, `listing()` re-upserts a file the service removed,
// and a delta feed never re-reports it, so the local copy is permanent.
// ===========================================================================

fn tombstone_with(deleted: &str) -> String {
    format!(
        r#"{{"id":"01TOMB","name":"contract.pdf","size":41234,
           "eTag":"\"{{C71A05E9-2F4B-4D6A-B8C3-15E9A7D2F604}},7\"",
           "cTag":"c:{{C71A05E9-2F4B-4D6A-B8C3-15E9A7D2F604}},4",
           "file":{{"mimeType":"application/pdf"}},
           "deleted":{deleted},
           "parentReference":{{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                              "path":"/drive/root:"}},
           "fileSystemInfo":{{"lastModifiedDateTime":"2026-07-30T10:02:11Z"}}}}"#
    )
}

/// One fixture three ways, and the identical answer required of all three.
///
/// Catches `state == "deleted"` (the field Graph documents, so the field an
/// implementer models and compares), `state == "softDeleted"` (the string every
/// fixture above happens to carry), and a wire type declaring
/// `deleted: Option<Deleted>` with `Deleted { state: String }` — non-optional —
/// which fails to deserialise `{}` and takes the *whole page* down with it.
///
/// The file facet is complete and the size real, so each wrong reading produces
/// a live `Upsert{File{41234}}` rather than erroring for an unrelated reason.
#[test]
fn every_deleted_state_graph_sends_is_a_delete() {
    let scope = primary(MINE);
    let doomed = cloud(MINE, "01TOMB");

    for deleted in [
        r#"{}"#,
        r#"{"state":"deleted"}"#,
        r#"{"state":"softDeleted"}"#,
    ] {
        let json = tombstone_with(deleted);
        let m = map_alone(&scope, &json)
            .unwrap_or_else(|e| panic!("\"deleted\":{deleted} must map, got {e:?}"));
        assert_eq!(
            m.item,
            Some(Item::Delete { id: doomed.clone() }),
            "\"deleted\":{deleted} must be the same delete as every other state — \
             an Upsert here restores a file the service deleted"
        );

        let mp = map_whole_page(&scope, &[json.as_str()]);
        assert!(
            mp.refusals.is_empty(),
            "\"deleted\":{deleted}: {:?}",
            mp.refusals
        );

        let mut ns = Namespace::restore(vec![
            Item::Root {
                id: cloud(MINE, "01ROOT"),
            },
            Item::Upsert {
                id: doomed.clone(),
                parent: cloud(MINE, "01ROOT"),
                name: "contract.pdf".into(),
                kind: file(41234, "ct:c:{C71A05E9-2F4B-4D6A-B8C3-15E9A7D2F604},4"),
            },
        ]);
        let changes = apply_all(&mut ns, &mp.items);
        assert_eq!(
            removals(&changes),
            vec![doomed.as_str()],
            "\"deleted\":{deleted} removed nothing: {changes:?}"
        );
        let listing = ns.listing();
        assert!(
            paths(&listing).is_empty(),
            "\"deleted\":{deleted} left the file in the tree: {:?}",
            listing
        );
        assert_eq!(folder_paths(&listing), vec![""]);
    }
}

// ===========================================================================
// GAP 3 — a tombstone with no `parentReference` at all
//
// All four §2 tombstones carry one. Graph routinely sends `{"id":…,
// "deleted":{}}` and nothing else — there is no parent to report for an item
// that no longer exists. If `ParentKey::from_outer` runs before the deleted arm
// (and it must run first for every *other* arm, so computing it up front is the
// natural structure — see `a_root_whose_parent_reference_has_no_id_…`), then
// **every deletion on the drive becomes `NoParent`**: no `Removed` ever reaches
// the framework, remotely deleted files stay on disk, and the refusals pin the
// token as well.
// ===========================================================================

const TOMB_NO_PARENT: &str = r#"{"id":"01GONE","deleted":{}}"#;

/// The minimal tombstone, exactly as the service sends it: an id and a
/// `deleted` facet. No name, no size, no shape, no parent.
///
/// Catches parent-before-deleted ordering (`NoParent`), a name-before-deleted
/// ordering (there is no name to read), and a shape dispatch that reaches
/// `NoShape` because the tombstone carries no facet either. All three compile,
/// and all three turn every deletion the service reports into a refusal.
#[test]
fn a_tombstone_with_no_parent_reference_at_all_is_still_a_delete() {
    let scope = primary(MINE);
    let m = map_alone(&scope, TOMB_NO_PARENT)
        .expect("a bare tombstone must map — not NoParent, not NoShape, not NoContentTag");
    assert_eq!(
        m.item,
        Some(Item::Delete {
            id: cloud(MINE, "01GONE")
        })
    );

    let mp = map_whole_page(&scope, &[TOMB_NO_PARENT, MINE_GOOD, ROOT]);
    assert!(
        mp.refusals.is_empty(),
        "a deletion is never a refusal: {:?}",
        mp.refusals
    );
    assert!(
        names_item(&mp.items, &cloud(MINE, "01GONE")),
        "the delete must reach the batch: {:?}",
        mp.items
    );
}

const TOMB_UNKNOWN: &str = r#"{"id":"01NEVERSEEN","name":"whoknows.txt",
  "deleted":{"state":"softDeleted"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"}}"#;

/// The pair to the test above, so its fix cannot be "swallow deletes that look
/// awkward".
///
/// A mapper that consults `TreeIndex` and drops a tombstone for an id it has
/// not seen looks defensive and compiles. It is wrong because the index is
/// built from *this round's* pages: after a restart the tree is restored from a
/// snapshot, the item is not in the freshly built index, and the one delete the
/// service will ever send for it is discarded. `Namespace::delete` already
/// handles an unknown id (`deleting_an_unknown_item_is_not_an_error`), so
/// forwarding costs nothing.
#[test]
fn a_tombstone_for_an_id_the_tree_has_never_seen_is_forwarded_not_swallowed() {
    let scope = primary(MINE);
    let mp = map_whole_page(&scope, &[TOMB_UNKNOWN, ROOT]);
    assert!(mp.refusals.is_empty(), "{:?}", mp.refusals);
    assert!(
        names_item(&mp.items, &cloud(MINE, "01NEVERSEEN")),
        "an unknown id is still a delete the framework must be told about: {:?}",
        mp.items
    );

    let live = cloud(MINE, "01GOOD");
    let mut ns = Namespace::restore(vec![
        Item::Root {
            id: cloud(MINE, "01ROOT"),
        },
        Item::Upsert {
            id: live.clone(),
            parent: cloud(MINE, "01ROOT"),
            name: "good.txt".into(),
            kind: file(10, "ct:c:{9E9C},1"),
        },
    ]);
    let before = ns.listing();
    let changes = apply_all(&mut ns, &mp.items);
    assert!(
        removals(&changes).is_empty(),
        "a delete for an absent id removes nothing else: {changes:?}"
    );
    assert_eq!(ns.listing(), before, "the live file must be untouched");
    assert!(ns.problems().is_empty(), "{:?}", ns.problems());
    assert_eq!(ns.pending(), 0);
}

// ===========================================================================
// GAP 4 — `Report.deferred`
//
// §1 asserts `Blocked` and `Unsettled` as `map_item` errors and never says
// where they land in a `Report`. Both are *transient*: the scanner clears a
// malware flag, an upload completes. If they land in `Report.refusals` they
// block the token every round until a human intervenes — §6's damage arriving
// from a third direction, and this time triggered by the service's own routine
// behaviour rather than by a bug.
//
// The other direction is equally wrong: dropping them silently lets the cursor
// advance past a change Graph will never repeat.
// ===========================================================================

/// Catches a `Round` that funnels every `MappedPage.refusal` into
/// `Report.refusals` and withholds the token on any non-empty set — which is
/// the shortest thing that compiles and is what the two tests in §1 above
/// invite, since they assert `refusals.len() == 1` at the *page* level and stop
/// there. Also catches a round that classifies by page rather than by reason,
/// so one deferred item defers everything else on the page.
///
/// The good file and the root are in the page as the positive control: an
/// implementation that answers `Err` unconditionally, or that discards a whole
/// page containing a blocked item, fails on `good.txt`.
#[test]
fn malware_and_a_pending_upload_are_deferred_and_do_not_withhold_the_token() {
    let scope = primary(MINE);
    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(&scope, &page(&[ROOT, MINE_GOOD, MALWARE, UNSETTLED]));
    let done = round.finish().unwrap_or_else(|(e, r)| {
        panic!(
            "a flagged file and a mid-upload file are transient; the token must \
             still be issued: {e:?} / {r:?}"
        )
    });

    assert!(
        done.report.refusals.is_empty(),
        "a transient condition in `refusals` is unclearable by construction — \
         Graph re-reports the item every round and the cursor never advances: \
         {:?}",
        done.report.refusals
    );
    assert!(
        done.report
            .deferred
            .contains(&(okey(MINE, "01MAL"), Unmappable::Blocked)),
        "deferred: {:?}",
        done.report.deferred
    );
    assert!(
        done.report
            .deferred
            .contains(&(okey(MINE, "01MOV"), Unmappable::Unsettled)),
        "deferred: {:?}",
        done.report.deferred
    );
    assert!(
        done.report.pending_after_round.is_empty(),
        "{:?}",
        done.report.pending_after_round
    );

    assert_eq!(folder_paths(&done.changes), vec![""]);
    assert_eq!(
        file_changes(&done.changes),
        vec![Change::Upserted {
            cloud_id: cloud(MINE, "01GOOD"),
            path: "good.txt".into(),
            size: 10,
            etag: Some("ct:c:{9E9C},1".into()),
        }],
        "exactly the one file that is fit to sync: no change for the flagged \
         file, none for the zero-byte mid-upload, and the ordinary file is not \
         collateral"
    );
}

// ===========================================================================
// GAP 5 — a container refused at the mapper strands its subtree
//
// `Namespace::refuse` propagates a refusal to everything waiting on the refused
// id — but only for containers that *reach* `Namespace`. A folder refused
// inside `map_item` never does: it is simply absent from `MappedPage.items`,
// its children are forwarded, `upsert` files them under `waiting[missing
// parent]`, and `Report.pending_after_round` blocks the token forever with
// `problems()` empty and nothing anywhere reporting an error.
//
// Every refusal in the 43 tests above is of a leaf or of a childless container.
// ===========================================================================

const BAD_CONTAINER: &str = r#"{"id":"01BADF","name":"Broken","size":8192,
  "eTag":"\"{2B3C4D5E-6666-4777-8888-999900001111},1\"",
  "cTag":"c:{2B3C4D5E-6666-4777-8888-999900001111},1",
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

const BAD_CHILD_X: &str = r#"{"id":"01BADX","name":"x.txt","size":10,
  "cTag":"c:{2B3C4D5E-6666-4777-8888-999900002222},1",
  "file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01BADF",
                     "path":"/drive/root:/Broken"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

const BAD_CHILD_Y: &str = r#"{"id":"01BADY","name":"y.txt","size":20,
  "cTag":"c:{2B3C4D5E-6666-4777-8888-999900003333},1",
  "file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01BADF",
                     "path":"/drive/root:/Broken"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

/// The container is refused for a reason §1 already establishes — neither facet
/// — so this test is not about *whether* it is refused but about what happens
/// to the two files underneath it, which are individually perfect.
///
/// Catches the implementation every refusal test above rewards: refuse the
/// container, forward the children, return. It compiles, every assertion in §1
/// and §4 still passes, and the round then reports two files as "pending",
/// which is a lie — the parent they wait for was refused this very round and
/// will be refused identically on every future round. `namespace.rs` states
/// that principle for the case it can see (`refusing_a_folder_refuses_what_was_
/// waiting_for_it`); the mapper's refusals are the case it cannot see.
///
/// Fed deepest-first, which is what Graph sends and what makes the children
/// arrive before there is any way to know their parent will be refused.
#[test]
fn a_container_refused_at_the_mapper_does_not_strand_its_children() {
    let scope = primary(MINE);
    let mp = map_whole_page(&scope, &[BAD_CHILD_X, BAD_CHILD_Y, BAD_CONTAINER, ROOT]);
    assert_eq!(
        refusal_for(&mp, &okey(MINE, "01BADF")),
        Some(Unmappable::NoShape),
        "precondition: the container is refused: {:?}",
        mp.refusals
    );

    let x = cloud(MINE, "01BADX");
    let y = cloud(MINE, "01BADY");
    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(
        &scope,
        &page(&[BAD_CHILD_X, BAD_CHILD_Y, BAD_CONTAINER, ROOT]),
    );
    let (report, completed) = match round.finish() {
        Ok(done) => {
            for c in &done.changes {
                if let Change::Upserted { cloud_id, path, .. } = c {
                    assert!(
                        cloud_id != &x && cloud_id != &y,
                        "a child of a refused container reached a path the \
                         service never described: {path}"
                    );
                }
            }
            (done.report, true)
        }
        Err((_, report)) => (report, false),
    };

    for id in [&x, &y] {
        assert!(
            !report.pending_after_round.contains(id),
            "\"not yet\" is the one answer that is untrue and unfalsifiable — \
             the parent was refused this round and will be every round: {:?}",
            report.pending_after_round
        );
    }
    if completed {
        for (id, key) in [(&x, okey(MINE, "01BADX")), (&y, okey(MINE, "01BADY"))] {
            assert!(
                report.refusals.iter().any(|r| r.key.as_ref() == Some(&key))
                    || report.deferred.iter().any(|(k, _)| k == &key),
                "if the round completes, every child of the refused container \
                 must be accounted for rather than dropped in silence ({id}): \
                 {report:?}"
            );
        }
    }
}

const LOST_FILE: &str = r#"{"id":"01LOST","name":"orphan.txt","size":10,
  "cTag":"c:{3C4D5E6F},1","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01NOWHERE",
                     "path":"/drive/root:/Nowhere"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

/// `pending_after_round` is asserted once above, and only that it is empty. Its
/// blocking behaviour — the entire reason the field exists — is untested.
///
/// This is the other half of the class: a parent id that is *well formed* and
/// simply never described. The mapper must not refuse it (a page may
/// legitimately split a subtree, and refusing on an unknown parent fails the
/// reverse-depth test in §7), so the only layer that can notice is the round,
/// at the point where it would otherwise hand back a deltaLink.
///
/// Catches a `Round::finish` that computes `pending_after_round` and returns
/// `Ok` anyway — the cursor then advances past `orphan.txt`, whose one and only
/// mention has just been consumed, and the file never syncs and is never
/// reported. `malware_and_a_pending_upload_…` above is the control that this is
/// not simply an always-`Err` implementation.
#[test]
fn a_file_under_a_parent_the_service_never_describes_withholds_the_token() {
    let scope = primary(MINE);
    let mp = map_whole_page(&scope, &[LOST_FILE, ROOT]);
    assert!(
        mp.refusals.is_empty(),
        "an unknown parent is not a mapper refusal — a page may split a \
         subtree: {:?}",
        mp.refusals
    );

    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(&scope, &page(&[LOST_FILE, ROOT]));
    match round.finish() {
        Err((_, report)) => assert!(
            report.pending_after_round.contains(&cloud(MINE, "01LOST")),
            "the withheld round must name what it is waiting for: {:?}",
            report.pending_after_round
        ),
        Ok(done) => panic!(
            "the token must not advance past an item that was never placed: \
             {:?} / {:?}",
            done.changes, done.report
        ),
    }
}

// ===========================================================================
// GAP 6 — a `Round` spanning several pages on one scope
//
// `namespace::finalise` dedups within a *single* `apply` call. Every `Round`
// above is fed one page per scope, so nothing exercises the round-level
// coalesce: an object touched on page 1 and page 3 appears twice in
// `CompletedRound.changes`, at two different paths, which is exactly what
// PROVIDER.md forbids and what `finalise`'s own doc comment says this layer
// must not delegate to the reconciler.
//
// The non-final pages carry a nextLink, so the round is a real one.
// ===========================================================================

fn coal(name: &str, size: u64, ctag: &str) -> String {
    format!(
        r#"{{"id":"01COAL","name":"{name}","size":{size},"cTag":"{ctag}",
           "file":{{"mimeType":"text/plain"}},
           "parentReference":{{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                              "path":"/drive/root:"}},
           "fileSystemInfo":{{"lastModifiedDateTime":"2026-08-04T10:00:00Z"}}}}"#
    )
}

const COAL_TOMB: &str = r#"{"id":"01COAL","name":"a.txt",
  "deleted":{"state":"softDeleted"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT"}}"#;

/// Created, deleted and re-created inside one round — three pages, three
/// `Namespace::apply` calls, three separate batches each internally coalesced
/// and none of them aware of the others.
///
/// Catches `changes.extend(ns.apply(item))` with no coalesce at `finish` — the
/// shortest thing that compiles, and invisible on every single-page fixture
/// above. The framework's reconciler would then be handed `Upserted{a.txt}`,
/// `Removed`, `Upserted{b.txt}` for one object in one batch; `delta::apply`
/// keeps the last, but PROVIDER.md tells providers not to rely on that, and the
/// intermediate `a.txt` is a path this round is not entitled to name at all.
#[test]
fn an_object_touched_on_three_pages_of_one_round_yields_exactly_one_change() {
    let scope = primary(MINE);
    let first = coal("a.txt", 10, "c:{7A0B},1");
    let last = coal("b.txt", 30, "c:{7A0B},3");

    let mut round = Round::new(TagSource::CTag, Namespace::new());
    round.feed(&scope, &more_page(&[ROOT, first.as_str()]));
    round.feed(&scope, &more_page(&[COAL_TOMB]));
    round.feed(&scope, &page(&[last.as_str()]));
    let done = round
        .finish()
        .unwrap_or_else(|(e, r)| panic!("three ordinary pages must complete: {e:?} / {r:?}"));

    assert_eq!(folder_paths(&done.changes), vec![""]);
    assert_eq!(
        file_changes(&done.changes),
        vec![Change::Upserted {
            cloud_id: cloud(MINE, "01COAL"),
            path: "b.txt".into(),
            size: 30,
            etag: Some("ct:c:{7A0B},3".into()),
        }],
        "one change per object per round, at its final path — not a Removed \
         followed by an Upserted, and never a change naming a.txt"
    );
}

/// The two orders, feeding the same two items, must give the two different
/// answers — and the answers are asserted exactly rather than merely being
/// asserted unequal, because an inequality between two values both already
/// pinned is an assertion that cannot fail.
///
/// Catches a coalesce bucketed by *change type* rather than by feed order —
/// "removals last", or a `HashMap<cloud_id, Change>` filled with `Removed`
/// taking precedence, both of which read as cautious. Under that rule the
/// resurrect case (delete then re-create, which is how Graph reports a
/// same-round replace) loses the file: `Removed` is delivered, the local copy
/// is deleted, and nothing re-creates it because the delta feed has moved on.
#[test]
fn a_tombstone_and_an_upsert_for_one_id_coalesce_in_feed_order_not_by_type() {
    let scope = primary(MINE);
    let id = cloud(MINE, "01COAL");
    let created = coal("a.txt", 10, "c:{7A0B},1");
    let replaced = coal("a.txt", 20, "c:{7A0B},2");

    let mut resurrect = Round::new(TagSource::CTag, Namespace::new());
    resurrect.feed(&scope, &page(&[ROOT, COAL_TOMB, replaced.as_str()]));
    let done = resurrect
        .finish()
        .unwrap_or_else(|(e, r)| panic!("delete-then-create must complete: {e:?} / {r:?}"));
    assert_eq!(folder_paths(&done.changes), vec![""]);
    assert_eq!(
        file_changes(&done.changes),
        vec![Change::Upserted {
            cloud_id: id.clone(),
            path: "a.txt".into(),
            size: 20,
            etag: Some("ct:c:{7A0B},2".into()),
        }],
        "the last word wins: a Removed here deletes a file that exists"
    );

    let mut retire = Round::new(TagSource::CTag, Namespace::new());
    retire.feed(&scope, &page(&[ROOT, created.as_str(), COAL_TOMB]));
    let done = retire
        .finish()
        .unwrap_or_else(|(e, r)| panic!("create-then-delete must complete: {e:?} / {r:?}"));
    assert_eq!(folder_paths(&done.changes), vec![""]);
    assert_eq!(
        file_changes(&done.changes),
        vec![Change::Removed {
            cloud_id: id.clone()
        }],
        "the last word wins the other way: an Upserted here creates a \
         placeholder for an object the service has already destroyed"
    );
}

// ===========================================================================
// GAP 7 — `TagSource` is threaded through every entry point and never varied
//
// Every call site above passes `TagSource::CTag`, and five fixtures carry a
// `file.hashes.quickXorHash` that nothing reads. `fn tag_of(b) { b.c_tag }` —
// ignoring the argument entirely — passes all 43 tests.
//
// `Kind::File.ctag` is compared byte-for-byte by `delta::is_current`, so a
// source that silently changes, or silently falls back, rewrites every tag on
// the drive at once: every hydrated file looks stale, and the framework
// replaces each one with a placeholder. `NoContentTag` is asserted by no test
// above at all.
// ===========================================================================

const TAGGED_BOTH: &str = r#"{"id":"01TAG","name":"report.pdf","size":4096,
  "eTag":"\"{5A6B7C8D-1234-4567-89AB-CDEF01234567},9\"",
  "cTag":"c:{5A6B7C8D-1234-4567-89AB-CDEF01234567},3",
  "file":{"mimeType":"application/pdf",
          "hashes":{"quickXorHash":"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg="}},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

/// POSITIVE CONTROL for the whole `TagSource` parameter, and the only test in
/// the file that proves the argument is read.
///
/// One fixture carrying both a cTag and a quickXorHash, mapped twice. Catches
/// `tag_of` ignoring its source argument (both answers come out `ct:`), a
/// source that reads the hash but drops the prefix (the prefixes are what keep
/// a cTag and a hash from ever comparing equal after a source change), and a
/// hash lookup that takes `hashes` rather than `hashes.quickXorHash`.
#[test]
fn the_tag_source_selects_the_field_and_its_prefix() {
    let scope = primary(MINE);

    let by_ctag = map_alone(&scope, TAGGED_BOTH).expect("under CTag");
    assert_eq!(
        kind_of(&by_ctag),
        &file(4096, "ct:c:{5A6B7C8D-1234-4567-89AB-CDEF01234567},3")
    );

    let by_hash = map_item(
        &scope,
        &TreeIndex::new(),
        TagSource::QuickXor,
        &one(TAGGED_BOTH),
    )
    .expect("under QuickXor");
    assert_eq!(
        kind_of(&by_hash),
        &file(4096, "qx:Zm9vYmFyYmF6cXV4MTIzNDU2Nzg="),
        "the quickXorHash behind its own prefix — not the cTag, which is what a \
         `tag_of` ignoring its argument returns, and not a bare hash, which \
         could compare equal to a cTag across a source change"
    );

    // And the tag the framework will byte-compare really does differ.
    let mut ns = ns_rooted(MINE, "01ROOT");
    let changes = apply_all(
        &mut ns,
        &map_whole_page_with(&scope, TagSource::QuickXor, &[TAGGED_BOTH]).items,
    );
    assert!(folder_paths(&changes).is_empty());
    assert_eq!(
        file_changes(&changes),
        vec![Change::Upserted {
            cloud_id: cloud(MINE, "01TAG"),
            path: "report.pdf".into(),
            size: 4096,
            etag: Some("qx:Zm9vYmFyYmF6cXV4MTIzNDU2Nzg=".into()),
        }]
    );
}

const TAG_CTAG_ONLY: &str = r#"{"id":"01TAGC","name":"legacy.pdf","size":2048,
  "eTag":"\"{5A6B7C8D-1234-4567-89AB-CDEF0123AAAA},2\"",
  "cTag":"c:{5A6B7C8D-1234-4567-89AB-CDEF0123AAAA},1",
  "file":{"mimeType":"application/pdf"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

const TAG_FOLDER: &str = r#"{"id":"01TAGF","name":"Archive","size":6144,
  "eTag":"\"{5A6B7C8D-1234-4567-89AB-CDEF0123BBBB},1\"",
  "folder":{"childCount":0},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

/// The mass-dehydration guard.
///
/// Graph omits `hashes` for some items — very large files, items still being
/// processed, some document libraries — so under `QuickXor` this shape arrives
/// routinely. The tempting implementation is `hash.or(c_tag)`: it produces a
/// working sync, and it is silently catastrophic, because the tag written to
/// the xattr for those files is drawn from a different namespace than for every
/// other file. The moment the item gains a hash, `is_current` compares `qx:…`
/// against a stored `ct:…`, they differ, and the file is dehydrated.
///
/// Refusing is the *loud* answer, which §6 says has its own cost — hence the
/// keyed refusal, so the round can defer rather than pin the cursor.
///
/// The folder in the same page is the control: shape carries no content tag,
/// and a rule written as "no hash, no map" would refuse every directory on the
/// drive and strand everything beneath them.
#[test]
fn a_file_with_no_hash_under_a_hash_tag_source_is_refused_not_silently_ctagged() {
    let scope = primary(MINE);
    assert_eq!(
        map_item(
            &scope,
            &TreeIndex::new(),
            TagSource::QuickXor,
            &one(TAG_CTAG_ONLY)
        )
        .unwrap_err(),
        Unmappable::NoContentTag {
            source: TagSource::QuickXor
        },
        "no silent fall back to the cTag, and the refusal names the source it \
         was looking for"
    );

    let mp = map_whole_page_with(
        &scope,
        TagSource::QuickXor,
        &[TAG_CTAG_ONLY, TAG_FOLDER, TAGGED_BOTH, ROOT],
    );
    assert_eq!(
        refusal_for(&mp, &okey(MINE, "01TAGC")),
        Some(Unmappable::NoContentTag {
            source: TagSource::QuickXor
        }),
        "keyed, so the round can defer it instead of blocking forever: {:?}",
        mp.refusals
    );
    assert_eq!(
        mp.refusals.len(),
        1,
        "exactly one — a hashless file is not the page's problem: {:?}",
        mp.refusals
    );
    assert!(
        names_item(&mp.items, &cloud(MINE, "01TAGF")),
        "POSITIVE CONTROL: a folder has no content tag and is not refused for \
         want of one — refusing it would strand everything beneath it: {:?}",
        mp.items
    );

    let mut ns = Namespace::new();
    let changes = apply_all(&mut ns, &mp.items);
    assert_eq!(
        paths(&changes),
        vec!["report.pdf"],
        "only the file that has a hash: {changes:?}"
    );
    for c in &changes {
        if let Change::Upserted { etag, .. } = c {
            assert!(
                matches!(etag.as_deref(), Some(t) if t.starts_with("qx:")),
                "a cTag reached a Change under a hash source, and `is_current` \
                 byte-compares: {c:?}"
            );
        }
    }
}

const TAG_ETAG_ONLY: &str = r#"{"id":"01TAGE","name":"meta.pdf","size":1024,
  "eTag":"\"{5A6B7C8D-1234-4567-89AB-CDEF0123CCCC},7\"",
  "file":{"mimeType":"application/pdf"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

/// `Kind::File { ctag: None }` is a legal, constructible value, and
/// `is_current` reads `(None, _) => true` — "the cloud has no version, so
/// nothing can be stale". A file mapped with no tag is therefore *never*
/// updated again: the service can change its contents forever and the local
/// copy stays at the first version ever seen, with no error at any layer.
///
/// So `ctag: None` is the failure this excludes, and the eTag fallback is the
/// other: `a_remote_item_files_content_tag_…` above excludes it for shared
/// items only, where the outer/inner split gives an independent reason to look
/// again. Here there is no remoteItem at all — just a file whose cTag the
/// projection dropped — and the eTag is right there, one field away.
#[test]
fn a_file_with_only_an_etag_is_refused_not_mapped_with_no_content_tag() {
    let scope = primary(MINE);
    assert_eq!(
        map_alone(&scope, TAG_ETAG_ONLY).unwrap_err(),
        Unmappable::NoContentTag {
            source: TagSource::CTag
        },
        "not Ok(File{{ctag: None}}), which is never stale and so never updates, \
         and not the eTag, which changes on every rename and dehydrates the file"
    );

    let mp = map_whole_page(&scope, &[TAG_ETAG_ONLY, MINE_GOOD, ROOT]);
    assert_eq!(
        refusal_for(&mp, &okey(MINE, "01TAGE")),
        Some(Unmappable::NoContentTag {
            source: TagSource::CTag
        }),
        "{:?}",
        mp.refusals
    );
    assert!(
        !names_item(&mp.items, &cloud(MINE, "01TAGE")),
        "{:?}",
        mp.items
    );

    let mut ns = Namespace::new();
    let changes = apply_all(&mut ns, &mp.items);
    assert_eq!(folder_paths(&changes), vec![""]);
    assert_eq!(
        file_changes(&changes),
        vec![Change::Upserted {
            cloud_id: cloud(MINE, "01GOOD"),
            path: "good.txt".into(),
            size: 10,
            etag: Some("ct:c:{9E9C},1".into()),
        }],
        "one item's missing tag is not the page's problem, and no change may \
         carry the eTag `{{…CDEF0123CCCC}},7`: {changes:?}"
    );
}

// ===========================================================================
// GAP 8 — sizes: absent, negative, fractional, string, above MAX_OBJECT
//
// Fixture sizes above run 0…511229384, all well-formed. Nothing is absent,
// negative, fractional, a string, or past the framework's ceiling.
//
// A size becomes a placeholder's length. `delta::apply` allocates it on first
// read, which is why it refuses anything past `MAX_OBJECT` — and refuses it by
// dropping the change into `Applied::failed`, which does *not* mark the pass
// retryable, so the cursor advances and the service never mentions the item
// again. A size this layer gets wrong is a file that silently never syncs.
// ===========================================================================

fn mine_file_with_size(id: &str, name: &str, size: &str) -> String {
    format!(
        r#"{{"id":"{id}","name":"{name}","size":{size},
           "cTag":"c:{{9E9A}},1","file":{{"mimeType":"text/plain"}},
           "parentReference":{{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                              "path":"/drive/root:"}},
           "fileSystemInfo":{{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}}}"#
    )
}

/// A refusal that proves the mapper reached the size at all.
///
/// The design's `Unmappable` supplies no `BadSize`/`TooLarge`, so naming a
/// variant would be asserting an implementation choice — but the *wrong-reason*
/// passes are all nameable: each of these means the mapper stopped before the
/// size, and a test satisfied by one of them is measuring nothing.
fn reached_the_size(why: &Unmappable) -> bool {
    !matches!(
        why,
        Unmappable::NoShape
            | Unmappable::Ambiguous
            | Unmappable::NoId
            | Unmappable::IdTooLong
            | Unmappable::NoParent
            | Unmappable::SelfParent
            | Unmappable::ForeignParent { .. }
            | Unmappable::NoContentTag { .. }
    )
}

const NO_SIZE_FILE: &str = r#"{"id":"01SIZE0","name":"sizeless.txt",
  "cTag":"c:{9E9B},1","file":{"mimeType":"text/plain"},
  "parentReference":{"driveId":"b!mine","driveType":"business","id":"01ROOT",
                     "path":"/drive/root:"},
  "fileSystemInfo":{"lastModifiedDateTime":"2026-08-01T10:00:00Z"}}"#;

/// Graph omits `size` when `$select` is trimmed and on some item projections,
/// so this is not a hypothetical shape.
///
/// The named wrong implementation is `#[serde(default)] size: u64`, or
/// `size.unwrap_or(0)` — both of which read as harmless defaulting and produce
/// `File{size: 0}`. That is the verified truncate-to-zero this file already
/// fears in `a_pending_operations_item_…`, reached by a second route that the
/// pending-operations guard does not cover: the framework places a zero-length
/// placeholder over a hydrated local file, and the bytes are gone.
///
/// The cTag and the file facet are both present so the File arm is otherwise
/// fully satisfiable and `NoSize` is the only honest answer.
#[test]
fn a_file_with_no_size_is_refused_rather_than_reported_as_zero_bytes() {
    let scope = primary(MINE);
    assert_eq!(
        map_alone(&scope, NO_SIZE_FILE).unwrap_err(),
        Unmappable::NoSize,
        "an absent size is NoSize — not File{{size: 0}}, and not NoShape or \
         NoContentTag, both of which are satisfiable from this input"
    );

    let mp = map_whole_page(&scope, &[NO_SIZE_FILE, MINE_GOOD, ROOT]);
    assert_eq!(
        refusal_for(&mp, &okey(MINE, "01SIZE0")),
        Some(Unmappable::NoSize),
        "{:?}",
        mp.refusals
    );

    let mut ns = Namespace::new();
    let changes = apply_all(&mut ns, &mp.items);
    assert_eq!(folder_paths(&changes), vec![""]);
    assert_eq!(
        file_changes(&changes),
        vec![Change::Upserted {
            cloud_id: cloud(MINE, "01GOOD"),
            path: "good.txt".into(),
            size: 10,
            etag: Some("ct:c:{9E9C},1".into()),
        }],
        "one item's missing size is not the page's problem, and no zero-byte \
         placeholder is invented for 01SIZE0: {changes:?}"
    );
}

/// Negative, fractional and string sizes, each refused **per item**.
///
/// Two implementations fail this, in opposite directions. (a) `size:
/// Option<u64>` on the wire type: serde rejects `-1`, `1.0e3` and `"1024"`
/// outright, so `DeltaPage::parse` fails and one malformed item costs the whole
/// page — the same per-item-versus-per-page question
/// `an_item_id_at_the_byte_limit_…` answers for ids, and it must be answered
/// the same way here, which is why `good.txt` and the root are in every page
/// below. (b) A lenient numeric decode — `as u64`, or `serde_json::Value` plus
/// `as_u64().unwrap_or_default()`, or `f64` rounding — which turns `-1` into
/// either `0` or `18446744073709551615`, `1.0e3` into `1000`, and `"1024"` into
/// `0`. Every one of those is a placeholder length nobody meant; the u64::MAX
/// case is refused later by `delta::apply` into `Applied::failed`, which does
/// not retry, so the file never syncs and nothing says why.
#[test]
fn a_malformed_size_is_refused_per_item_and_never_coerced() {
    let scope = primary(MINE);
    for (n, raw) in ["-1", "1.0e3", "\"1024\""].into_iter().enumerate() {
        let id = format!("01SIZEB{n}");
        let bad = mine_file_with_size(&id, "bad-size.txt", raw);
        let key = okey(MINE, &id);

        let text = body(&[bad.as_str(), MINE_GOOD, ROOT]);
        let parsed = DeltaPage::parse(200, text.as_bytes()).unwrap_or_else(|e| {
            panic!(
                "size {raw} must be one item's problem, not the page's — a page \
                 that fails to parse takes good.txt and the root down with it: \
                 {e:?}"
            )
        });

        let mut index = TreeIndex::new();
        let mp = map_page(&scope, &mut index, TagSource::CTag, &parsed);
        let why = refusal_for(&mp, &key)
            .unwrap_or_else(|| panic!("size {raw} was accepted or dropped: {:?}", mp.refusals));
        assert!(
            reached_the_size(&why),
            "size {raw} was refused before the size was ever read: {why:?}"
        );
        assert!(
            !names_item(&mp.items, &cloud(MINE, &id)),
            "size {raw}: {:?}",
            mp.items
        );

        let mut ns = Namespace::new();
        let changes = apply_all(&mut ns, &mp.items);
        assert_eq!(
            paths(&changes),
            vec!["good.txt"],
            "size {raw}: the well-formed items on the page must still arrive: \
             {changes:?}"
        );
    }
}

/// The ceiling, read from the constant the framework itself enforces.
///
/// `delta::apply` refuses `size > MAX_OBJECT` — strictly greater — so exactly
/// `MAX_OBJECT` is a legal object and a mapper that guards with `>=` refuses a
/// file the framework would have taken. That refusal is unclearable: the
/// service re-reports the item every round.
///
/// The other half is the one that costs bytes. Above the ceiling the change is
/// dropped into `Applied::failed`, which does not set `retryable`, so the
/// cursor advances past it and the object is never mentioned again — a file
/// that silently never syncs, from a service bug or a signed/unsigned slip
/// upstream. Refusing here keeps it named.
///
/// The literal is never written: `MAX_OBJECT` is `1 << 40` today and a changed
/// bound must not silently pass.
#[test]
fn a_size_above_max_object_is_refused_and_exactly_max_object_is_accepted() {
    let scope = primary(MINE);
    let at = mine_file_with_size("01SIZEMAX", "at-the-ceiling.bin", &MAX_OBJECT.to_string());
    let over = mine_file_with_size("01SIZEOVR", "one-over.bin", &(MAX_OBJECT + 1).to_string());

    // POSITIVE CONTROL half.
    let m = map_alone(&scope, &at).expect("exactly MAX_OBJECT is a legal object");
    assert_eq!(kind_of(&m), &file(MAX_OBJECT, "ct:c:{9E9A},1"));

    // Attack half.
    let why = map_alone(&scope, &over).unwrap_err();
    assert!(
        reached_the_size(&why),
        "one byte over the ceiling must be refused *for its size*: {why:?}"
    );

    let mut index = TreeIndex::new();
    let mp = map_page(
        &scope,
        &mut index,
        TagSource::CTag,
        &page(&[over.as_str(), at.as_str(), MINE_GOOD, ROOT]),
    );
    assert_eq!(mp.refusals.len(), 1, "exactly one: {:?}", mp.refusals);
    assert_eq!(mp.refusals[0].key, Some(okey(MINE, "01SIZEOVR")));

    let mut ns = Namespace::new();
    let changes = apply_all(&mut ns, &mp.items);
    assert_eq!(folder_paths(&changes), vec![""]);
    assert_eq!(
        file_changes(&changes),
        vec![
            Change::Upserted {
                cloud_id: cloud(MINE, "01SIZEMAX"),
                path: "at-the-ceiling.bin".into(),
                size: MAX_OBJECT,
                etag: Some("ct:c:{9E9A},1".into()),
            },
            Change::Upserted {
                cloud_id: cloud(MINE, "01GOOD"),
                path: "good.txt".into(),
                size: 10,
                etag: Some("ct:c:{9E9C},1".into()),
            },
        ],
        "POSITIVE CONTROL: the boundary object is emitted at its full size — \
         not clamped, not dropped — and nothing is emitted for the item one \
         byte over: {changes:?}"
    );
}

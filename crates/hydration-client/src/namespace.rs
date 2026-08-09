//! The remote tree, and the changes it implies.
//!
//! A delta feed describes *items*, and the framework consumes *file paths*. The
//! gap between those two is the largest piece of hidden work in writing a
//! provider, and it is invisible until it bites:
//!
//! > A service reports one change when a folder moves. It does not re-enumerate
//! > the thousand files inside it.
//!
//! A provider that forwards changes one-for-one therefore moves the folder and
//! leaves its contents behind. The local tree splits — old files stay under the
//! old directory, anything new appears under the new one — and no single change
//! looks wrong. Microsoft Graph works this way; so does every other service with
//! an id-addressed namespace.
//!
//! So the provider has to keep the remote tree itself and derive paths from it.
//! That is what this is. Feed it items as they arrive, get back the [`Change`]s
//! they actually mean:
//!
//! ```text
//!   folder "Work" (id F) renamed to "Archive"
//!     in:  one Upsert for F
//!     out: an Upserted for every file beneath F, at its new path
//!
//!   folder F deleted
//!     in:  one Delete for F
//!     out: a Removed for every file beneath F
//! ```
//!
//! It holds the shape of the remote namespace and nothing else. Local content
//! and its state live in the sync directory, because §5.2 says the local copy is
//! the truth.
//!
//! # Nothing is ever dropped in silence
//!
//! Every item this cannot place is recorded and can be listed: an unknown parent
//! in [`Namespace::pending_ids`], anything malformed in [`Namespace::problems`].
//! An earlier version returned nothing for a cyclic parent chain and counted it
//! nowhere, so a whole subtree became stale placeholders that no later pass
//! could repair — the reconciler is additive, and a full listing that omits them
//! cannot remove them either. A tracker that quietly forgets files is worse than
//! one that refuses them loudly.
//!
//! # Persisting it
//!
//! A delta token is worthless without the tree it described, and the two must be
//! written in one order only:
//!
//! > **Write the tree first, then the token. On any doubt, discard the token and
//! > keep the tree.**
//!
//! A tree newer than its token is harmless — the replayed items are no-ops. A
//! token newer than its tree is unrecoverable: every move in between is lost,
//! and a delta feed never re-reports an unchanged item, so nothing self-corrects.
//! [`Namespace::snapshot`] and [`Namespace::restore`] round-trip through the
//! public [`Item`] type, so a provider can store them however it already stores
//! anything else.

use crate::delta::Change;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// What a service says about one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// The tree's anchor. Its name is not part of any path.
    ///
    /// A separate variant rather than a `Kind`, because it is the only item
    /// without a parent — and an earlier version expressed that as
    /// `parent: Option<String>` with a comment saying "`None` only for the
    /// root". A comment is not a constraint: a provider that failed to detect
    /// Graph's `root` facet produced a parentless folder, and the replay loop
    /// span on it forever at full CPU, with no allocation growth to attract the
    /// OOM killer and no log line. Making the state unrepresentable is cheaper
    /// than surviving it.
    Root { id: String },
    /// The item exists, with this parent, name and shape. Covers creation,
    /// rename, move and content change alike — which is what a delta feed
    /// actually gives you, and the reason the reconciler works out the
    /// difference from the disk rather than being told.
    Upsert {
        id: String,
        parent: String,
        name: String,
        kind: Kind,
    },
    /// The item is gone. For a folder this implies its whole subtree, and
    /// expanding that is the point of this module.
    Delete { id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    File {
        size: u64,
        /// A *content* version, not a metadata one.
        ///
        /// On Graph that is `cTag`, not `eTag`: `eTag` changes when an item is
        /// renamed or its metadata is touched, so mapping it makes every move
        /// look like a new version — and for a hydrated file the framework then
        /// replaces the local copy with a placeholder. A folder move in the web
        /// UI would dehydrate the whole tree.
        ctag: Option<String>,
    },
    Folder,
    /// A folder-shaped thing that must not be walked into.
    ///
    /// Graph's `package` facet — a OneNote notebook is a folder whose internals
    /// are one document. Synced as a folder it is corrupted piecemeal; synced as
    /// a file its reported size is not the sum of its parts and §5.7 refuses
    /// every read. So it is tracked for pathing, and no file is ever emitted for
    /// it or beneath it.
    Opaque,
}

/// Why an item could not be placed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// A name that cannot be part of a path.
    ///
    /// The provider is the only layer that can reject one with a reason: the
    /// framework refuses these too, but silently and terminally — the change
    /// lands in `Applied::failed`, which does not mark the pass retryable, so
    /// the cursor advances and the service never mentions the item again.
    BadName(String),
    /// The named parent is a file, or something else that cannot contain items.
    ParentCannotContain,
    /// Attaching this item here would make it its own ancestor.
    Cycle,
    /// A second root arrived with a different id. One tracker holds one drive.
    ForeignRoot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Node {
    parent: Option<String>,
    name: String,
    kind: Kind,
}

/// The remote tree as last reported.
#[derive(Debug, Default)]
pub struct Namespace {
    nodes: HashMap<String, Node>,
    children: HashMap<String, BTreeSet<String>>,
    root: Option<String>,
    /// Items waiting for a parent that has not arrived, indexed *by that
    /// parent*.
    ///
    /// By parent rather than by item, because the replay has to answer "what was
    /// waiting for this?" and the earlier version answered it by rescanning
    /// every held item on every call. That is quadratic, and measurably so: a
    /// stuck set of twenty thousand made two thousand ordinary in-order upserts
    /// take 568 ms instead of 0.9 ms — a tax on traffic that had nothing to do
    /// with them.
    waiting: HashMap<String, Vec<Item>>,
    problems: BTreeMap<String, Problem>,
}

/// Guards against a malformed tree rather than a deep one.
const MAX_DEPTH: usize = 512;

impl Namespace {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one item and return the file changes it implies.
    ///
    /// Order within the returned batch is parent-before-child, so a caller
    /// feeding these into [`crate::delta::apply`] sees directories created
    /// before the files in them. At most one change per object: a batch that
    /// renames a folder *and* something inside it would otherwise name a file
    /// twice, and relying on the reconciler to coalesce that would be relying on
    /// the very thing `PROVIDER.md` tells providers not to rely on.
    pub fn apply(&mut self, item: Item) -> Vec<Change> {
        let mut out = Vec::new();
        let mut work = vec![item];
        // Bounded by items *removed* from `waiting`, which only shrinks here —
        // nothing this loop applies is put back.
        while let Some(next) = work.pop() {
            let id = self.apply_one(next, &mut out);
            if let Some(id) = id {
                if let Some(unblocked) = self.waiting.remove(&id) {
                    work.extend(unblocked);
                }
            }
        }
        finalise(out)
    }

    /// Everything currently known, as a full listing.
    ///
    /// What a provider returns when its delta token has expired. The reconciler
    /// treats a replayed listing as a no-op, so this is cheap to send and is the
    /// honest answer to "I lost my place".
    ///
    /// It cannot express deletions — a listing says what exists, not what
    /// stopped existing — so a provider recovering from an expired token must
    /// diff this against its previous [`Namespace::snapshot`] to find what went
    /// away while it was not looking.
    pub fn listing(&self) -> Vec<Change> {
        let mut out = Vec::new();
        if let Some(root) = &self.root {
            self.collect_files(root, &mut out);
        }
        finalise(out)
    }

    /// Items held because their parent has not arrived.
    ///
    /// Not an error on its own — a delta page can legitimately split a subtree —
    /// but a set that survives a full pass means the service referenced a parent
    /// it never described, and those files will never sync. Ids rather than a
    /// count, because a caller that cannot name them cannot report them.
    pub fn pending_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .waiting
            .values()
            .flatten()
            .map(|i| match i {
                Item::Root { id } | Item::Upsert { id, .. } | Item::Delete { id } => id.clone(),
            })
            .collect();
        v.sort();
        v
    }

    pub fn pending(&self) -> usize {
        self.waiting.values().map(Vec::len).sum()
    }

    /// Items refused, and why. Never empty in silence.
    pub fn problems(&self) -> &BTreeMap<String, Problem> {
        &self.problems
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The whole tree as items, for persisting alongside a delta token.
    ///
    /// Parents before children, so [`Namespace::restore`] never has to hold
    /// anything — a snapshot restores without a single item going through the
    /// waiting path.
    pub fn snapshot(&self) -> Vec<Item> {
        let mut out = Vec::new();
        let Some(root) = &self.root else {
            return out;
        };
        out.push(Item::Root { id: root.clone() });
        let mut queue = std::collections::VecDeque::from([root.clone()]);
        let mut seen = BTreeSet::new();
        while let Some(cur) = queue.pop_front() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            let Some(kids) = self.children.get(&cur) else {
                continue;
            };
            for kid in kids {
                if let Some(node) = self.nodes.get(kid) {
                    out.push(Item::Upsert {
                        id: kid.clone(),
                        parent: cur.clone(),
                        name: node.name.clone(),
                        kind: node.kind.clone(),
                    });
                    queue.push_back(kid.clone());
                }
            }
        }
        out
    }

    /// Rebuild from a snapshot. Emits nothing: this is a restore, not news.
    pub fn restore(items: Vec<Item>) -> Self {
        let mut ns = Self::new();
        for item in items {
            ns.apply(item);
        }
        ns.problems.clear();
        ns
    }

    /// `Some(id)` when something attached to the tree, so its waiters can run.
    fn apply_one(&mut self, item: Item, out: &mut Vec<Change>) -> Option<String> {
        match item {
            Item::Root { id } => {
                if let Some(existing) = &self.root {
                    if existing != &id {
                        // One tracker, one drive. A second root would blank
                        // `listing()` while the old tree stayed live, so the
                        // answer to an expired token would become "there are no
                        // files" — with the files still on disk.
                        self.problems.insert(id, Problem::ForeignRoot);
                        return None;
                    }
                }
                self.root = Some(id.clone());
                self.nodes.insert(
                    id.clone(),
                    Node {
                        parent: None,
                        name: String::new(),
                        kind: Kind::Folder,
                    },
                );
                Some(id)
            }
            Item::Upsert {
                id,
                parent,
                name,
                kind,
            } => self.upsert(id, parent, name, kind, out),
            Item::Delete { id } => {
                self.delete(&id, out);
                None
            }
        }
    }

    fn upsert(
        &mut self,
        id: String,
        parent: String,
        name: String,
        kind: Kind,
        out: &mut Vec<Change>,
    ) -> Option<String> {
        if let Some(why) = bad_name(&name) {
            self.refuse(id, Problem::BadName(why));
            return None;
        }
        match self.nodes.get(&parent) {
            None => {
                // Held, not guessed at. A path invented for an item whose parent
                // the service has not described is a file placed somewhere it
                // never said.
                self.waiting.entry(parent.clone()).or_default().push(
                    Item::Upsert {
                        id,
                        parent,
                        name,
                        kind,
                    },
                );
                return None;
            }
            // A package is a container, just one nothing is emitted from.
            // Refusing its contents would be a refusal nothing can clear —
            // `problems` is cleared only by a successful upsert or a delete of
            // that id, and for a package's internals neither ever comes. One
            // notebook would block a provider's cursor forever. They belong in
            // the tree: pathing needs them, and a package that later turns out
            // to be an ordinary folder must already have its children.
            Some(p) if matches!(p.kind, Kind::File { .. }) => {
                self.refuse(id, Problem::ParentCannotContain);
                return None;
            }
            Some(_) => {}
        }
        if self.would_cycle(&id, &parent) {
            // Refused *and recorded*. Following it hangs a path computation;
            // dropping it silently strands every file beneath as a placeholder
            // no later pass can repair.
            self.refuse(id, Problem::Cycle);
            return None;
        }

        let previous = self.nodes.get(&id).cloned();
        let moved = match &previous {
            Some(prev) => prev.parent.as_deref() != Some(parent.as_str()) || prev.name != name,
            None => false,
        };
        // A file that became a folder, or the reverse. The old shape has to go,
        // or the tree holds one path as both — `listing()` would name it twice
        // and the directory that must exist there could never be created.
        let reshaped = previous
            .as_ref()
            .is_some_and(|prev| std::mem::discriminant(&prev.kind) != std::mem::discriminant(&kind));
        if reshaped {
            self.delete(&id, out);
        }

        if let Some(prev) = &previous {
            if let Some(old_parent) = &prev.parent {
                if let Some(set) = self.children.get_mut(old_parent) {
                    set.remove(&id);
                }
            }
        }
        self.children
            .entry(parent.clone())
            .or_default()
            .insert(id.clone());
        self.nodes.insert(
            id.clone(),
            Node {
                parent: Some(parent),
                name,
                kind: kind.clone(),
            },
        );
        self.problems.remove(&id);

        match kind {
            Kind::File { size, ctag } => {
                if let Some(path) = self.path_of(&id) {
                    out.push(Change::Upserted {
                        cloud_id: id.clone(),
                        path,
                        size,
                        etag: ctag,
                    });
                }
            }
            // A folder is not a change by itself — directories are implied by
            // the paths of the files in them. But a folder that *moved* changes
            // the path of everything beneath it, and the service will not say so
            // again. This is the whole reason this module exists.
            Kind::Folder if moved || reshaped => self.collect_files(&id, out),
            Kind::Folder | Kind::Opaque => {}
        }
        Some(id)
    }

    fn delete(&mut self, id: &str, out: &mut Vec<Change>) {
        // Anything that was waiting on this, or on anything beneath it, is
        // waiting for something that will never come.
        let Some(node) = self.nodes.get(id).cloned() else {
            self.forget_waiters(id);
            self.problems.remove(id);
            return;
        };

        // Files first, gathered before anything is unlinked — afterwards there
        // is no way to walk it.
        let mut doomed = Vec::new();
        self.collect_ids(id, &mut doomed);
        for gone in &doomed {
            if let Some(n) = self.nodes.get(gone) {
                if matches!(n.kind, Kind::File { .. }) {
                    out.push(Change::Removed {
                        cloud_id: gone.clone(),
                    });
                }
            }
        }
        if matches!(node.kind, Kind::File { .. }) {
            out.push(Change::Removed {
                cloud_id: id.to_string(),
            });
        }

        for gone in doomed {
            self.nodes.remove(&gone);
            self.children.remove(&gone);
            self.forget_waiters(&gone);
            self.problems.remove(&gone);
        }
        self.nodes.remove(id);
        self.children.remove(id);
        self.forget_waiters(id);
        self.problems.remove(id);
        if let Some(parent) = node.parent {
            if let Some(set) = self.children.get_mut(&parent) {
                set.remove(id);
            }
        }
        if self.root.as_deref() == Some(id) {
            self.root = None;
        }
    }

    /// Refuse an item, and everything that was waiting for it.
    ///
    /// A refused folder is a parent that will never exist, so anything held for
    /// it is held for good. Leaving those in `pending_ids` says "not yet", which
    /// is untrue and unfalsifiable — a caller watching for a pending set to
    /// drain would wait forever. They carry the reason the container was
    /// refused, because that is why they cannot be placed.
    fn refuse(&mut self, id: String, why: Problem) {
        let mut stack = vec![(id, why)];
        while let Some((id, why)) = stack.pop() {
            if let Some(held) = self.waiting.remove(&id) {
                for item in held {
                    if let Item::Upsert { id: child, .. } = item {
                        stack.push((child, why.clone()));
                    }
                }
            }
            self.problems.insert(id, why);
        }
        self.waiting.retain(|_, v| !v.is_empty());
    }

    /// Forget anything to do with an id that has just ceased to exist.
    ///
    /// Two directions, and only one of them is reachable through the tree.
    /// Items are held under the id of the parent they are *waiting for*, and a
    /// parent that is in the tree has already discharged its waiters — so
    /// deleting a node can never strand one. What it can do is delete an item
    /// that is itself still waiting somewhere, and leaving that behind would
    /// resurrect the file the moment its parent turned up.
    fn forget_waiters(&mut self, id: &str) {
        let mut stack = vec![id.to_string()];
        while let Some(cur) = stack.pop() {
            if let Some(held) = self.waiting.remove(&cur) {
                for item in held {
                    if let Item::Upsert { id, .. } = item {
                        stack.push(id);
                    }
                }
            }
            // And the item itself, wherever it is queued.
            for bucket in self.waiting.values_mut() {
                bucket.retain(|it| match it {
                    Item::Root { id } | Item::Upsert { id, .. } | Item::Delete { id } => id != &cur,
                });
            }
            self.waiting.retain(|_, v| !v.is_empty());
        }
    }

    /// Whether attaching `id` under `parent` would make `id` its own ancestor.
    fn would_cycle(&self, id: &str, parent: &str) -> bool {
        let mut cur = parent.to_string();
        for _ in 0..MAX_DEPTH {
            if cur == id {
                return true;
            }
            match self.nodes.get(&cur).and_then(|n| n.parent.clone()) {
                Some(next) => cur = next,
                None => return false,
            }
        }
        true
    }

    /// Every file at or beneath `id`, as upserts at their current paths.
    fn collect_files(&self, id: &str, out: &mut Vec<Change>) {
        let mut stack = vec![id.to_string()];
        let mut seen = BTreeSet::new();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            let Some(node) = self.nodes.get(&cur) else {
                continue;
            };
            match &node.kind {
                Kind::File { size, ctag } => {
                    if let Some(path) = self.path_of(&cur) {
                        out.push(Change::Upserted {
                            cloud_id: cur.clone(),
                            path,
                            size: *size,
                            etag: ctag.clone(),
                        });
                    }
                }
                // Never walked into. Its contents are one document.
                Kind::Opaque => continue,
                Kind::Folder => {}
            }
            if let Some(kids) = self.children.get(&cur) {
                stack.extend(kids.iter().cloned());
            }
        }
    }

    /// Every id at or beneath `id`, excluding `id` itself.
    fn collect_ids(&self, id: &str, out: &mut Vec<String>) {
        let mut stack: Vec<String> = self
            .children
            .get(id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        let mut seen = BTreeSet::new();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            if let Some(kids) = self.children.get(&cur) {
                stack.extend(kids.iter().cloned());
            }
            out.push(cur);
        }
    }

    /// The root-relative path of an item, or `None` if the chain is broken.
    fn path_of(&self, id: &str) -> Option<String> {
        let mut parts = Vec::new();
        let mut cur = id.to_string();
        for _ in 0..MAX_DEPTH {
            let node = self.nodes.get(&cur)?;
            let Some(parent) = node.parent.clone() else {
                parts.reverse();
                return Some(parts.join("/"));
            };
            parts.push(node.name.clone());
            cur = parent;
        }
        None
    }
}

/// One change per object, parents before children.
///
/// The de-duplication is not tidiness: a batch renaming a folder and something
/// inside it emits the inner file twice, at two different paths, and the later
/// emission is the correct one. Leaving that to the reconciler's coalescing
/// would make this module depend on exactly what `PROVIDER.md` tells providers
/// not to depend on.
fn finalise(changes: Vec<Change>) -> Vec<Change> {
    let mut last: HashMap<&str, usize> = HashMap::new();
    for (i, c) in changes.iter().enumerate() {
        last.insert(id_of(c), i);
    }
    let mut kept: Vec<Change> = changes
        .iter()
        .enumerate()
        .filter(|(i, c)| last.get(id_of(c)) == Some(i))
        .map(|(_, c)| c.clone())
        .collect();
    kept.sort_by(|a, b| {
        depth_of(a)
            .cmp(&depth_of(b))
            .then_with(|| sort_key(a).cmp(sort_key(b)))
    });
    kept
}

/// Names that cannot be a single path component.
///
/// Rejected here, with a reason, because this is the only layer that knows the
/// item behind the name. The framework refuses them too — `safe_join` will not
/// build a path out of `..` — but it refuses silently and terminally.
fn bad_name(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("empty".into());
    }
    if name.contains('/') {
        // Would invent a directory level the service never described, and
        // collide with a real folder of that name.
        return Some("contains a path separator".into());
    }
    if name.contains('\0') {
        return Some("contains NUL".into());
    }
    if name == "." || name == ".." {
        return Some("is a directory reference".into());
    }
    if hydration_protocol::names::is_internal(name) {
        return Some("is one of the framework's own names".into());
    }
    None
}

fn id_of(c: &Change) -> &str {
    match c {
        Change::Upserted { cloud_id, .. } | Change::Removed { cloud_id } => cloud_id,
    }
}

fn sort_key(c: &Change) -> &str {
    match c {
        Change::Upserted { path, .. } => path,
        Change::Removed { cloud_id } => cloud_id,
    }
}

fn depth_of(c: &Change) -> usize {
    match c {
        // Removals carry no path and are not ordered against anything.
        Change::Removed { .. } => 0,
        Change::Upserted { path, .. } => path.matches('/').count() + 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(id: &str, parent: &str, name: &str) -> Item {
        Item::Upsert {
            id: id.into(),
            parent: parent.into(),
            name: name.into(),
            kind: Kind::Folder,
        }
    }

    fn file(id: &str, parent: &str, name: &str, size: u64) -> Item {
        Item::Upsert {
            id: id.into(),
            parent: parent.into(),
            name: name.into(),
            kind: Kind::File {
                size,
                ctag: Some(format!("v-{id}")),
            },
        }
    }

    fn paths(changes: &[Change]) -> Vec<String> {
        changes
            .iter()
            .filter_map(|c| match c {
                Change::Upserted { path, .. } => Some(path.clone()),
                _ => None,
            })
            .collect()
    }

    fn removed(changes: &[Change]) -> Vec<String> {
        let mut v: Vec<String> = changes
            .iter()
            .filter_map(|c| match c {
                Change::Removed { cloud_id } => Some(cloud_id.clone()),
                _ => None,
            })
            .collect();
        v.sort();
        v
    }

    /// `/Work/{a.txt, Notes/b.txt}`.
    fn tree() -> Namespace {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        ns.apply(folder("F", "R", "Work"));
        ns.apply(file("a", "F", "a.txt", 10));
        ns.apply(folder("G", "F", "Notes"));
        ns.apply(file("b", "G", "b.txt", 20));
        ns
    }

    #[test]
    fn a_file_arrives_at_its_full_path() {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        ns.apply(folder("F", "R", "Work"));
        assert_eq!(paths(&ns.apply(file("a", "F", "a.txt", 10))), ["Work/a.txt"]);
    }

    #[test]
    fn a_new_folder_is_not_a_change() {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        assert!(ns.apply(folder("F", "R", "Work")).is_empty());
    }

    /// The reason this module exists.
    #[test]
    fn moving_a_folder_moves_everything_beneath_it() {
        let mut ns = tree();
        let out = ns.apply(folder("F", "R", "Archive"));
        assert_eq!(paths(&out), ["Archive/a.txt", "Archive/Notes/b.txt"]);
    }

    /// A batch that renames a folder *and* something inside it must name each
    /// file once, at its final path.
    #[test]
    fn a_nested_rename_names_each_file_once() {
        // Built child-first, so the inner folder is still waiting for the outer
        // one when it arrives and both resolve inside a single `apply`. That is
        // the batch shape that names a file twice if nothing coalesces.
        let mut inner = Namespace::new();
        inner.apply(Item::Root { id: "R".into() });
        inner.apply(file("b", "G", "b.txt", 20));
        inner.apply(folder("G", "F", "Renamed"));
        let out = inner.apply(folder("F", "R", "Archive"));
        assert_eq!(
            paths(&out),
            ["Archive/Renamed/b.txt"],
            "a file was named more than once, or at a stale path: {out:?}"
        );
    }

    #[test]
    fn a_folder_reported_unchanged_produces_no_work() {
        let mut ns = tree();
        assert!(ns.apply(folder("F", "R", "Work")).is_empty());
    }

    #[test]
    fn deleting_a_folder_removes_every_file_beneath_it() {
        let mut ns = tree();
        assert_eq!(removed(&ns.apply(Item::Delete { id: "F".into() })), ["a", "b"]);
    }

    #[test]
    fn deleting_a_file_removes_only_it() {
        let mut ns = tree();
        assert_eq!(removed(&ns.apply(Item::Delete { id: "a".into() })), ["a"]);
    }

    /// A delta page is not guaranteed to be parent-first.
    #[test]
    fn an_item_whose_parent_has_not_arrived_is_held_and_replayed() {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        assert!(ns.apply(file("a", "F", "a.txt", 10)).is_empty());
        assert_eq!(ns.pending_ids(), ["a"]);

        assert_eq!(paths(&ns.apply(folder("F", "R", "Work"))), ["Work/a.txt"]);
        assert_eq!(ns.pending(), 0);
    }

    #[test]
    fn a_reversed_subtree_still_resolves() {
        let mut ns = Namespace::new();
        ns.apply(file("c", "G", "c.txt", 30));
        ns.apply(folder("G", "F", "Notes"));
        ns.apply(folder("F", "R", "Work"));
        assert_eq!(
            paths(&ns.apply(Item::Root { id: "R".into() })),
            ["Work/Notes/c.txt"]
        );
        assert_eq!(ns.pending(), 0);
    }

    /// The bug that hung a whole daemon: a parentless non-root item.
    ///
    /// It is now unrepresentable — `Item::Upsert` requires a parent — so this
    /// asserts the shape that replaced it: a parent nobody ever describes is
    /// held and *named*, not spun on.
    #[test]
    fn a_parent_that_never_arrives_is_named_rather_than_spun_on() {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        ns.apply(file("a", "NOWHERE", "a.txt", 10));
        assert_eq!(ns.pending_ids(), ["a"]);
        // And repeated passes neither loop nor lose it.
        for _ in 0..100 {
            ns.apply(folder("F", "R", "Work"));
        }
        assert_eq!(ns.pending_ids(), ["a"]);
    }

    /// A cycle must be refused *and visible*.
    ///
    /// Returning nothing and counting it nowhere left every file beneath it as a
    /// stale placeholder that no later pass could repair: the reconciler only
    /// removes what it is told to remove, and a full listing that omits them
    /// cannot tell it anything.
    #[test]
    fn a_cycle_is_refused_and_recorded() {
        let mut ns = tree();
        assert!(ns.apply(folder("F", "G", "Work")).is_empty());
        assert_eq!(ns.problems().get("F"), Some(&Problem::Cycle));
        // And the tree it would have broken is intact.
        assert_eq!(
            paths(&ns.listing()),
            ["Work/a.txt", "Work/Notes/b.txt"],
            "a refused cycle damaged the tree it was refused from"
        );
    }

    #[test]
    fn a_second_root_is_refused_and_the_first_tree_survives() {
        let mut ns = tree();
        ns.apply(Item::Root { id: "OTHER".into() });
        assert_eq!(ns.problems().get("OTHER"), Some(&Problem::ForeignRoot));
        assert_eq!(paths(&ns.listing()), ["Work/a.txt", "Work/Notes/b.txt"]);
    }

    /// Names the service may report and a path cannot hold.
    #[test]
    fn a_name_that_cannot_be_a_path_component_is_refused_with_a_reason() {
        for name in ["", "..", ".", "a/b", "\u{0}x", ".hydration-manifest"] {
            let mut ns = Namespace::new();
            ns.apply(Item::Root { id: "R".into() });
            let out = ns.apply(file("x", "R", name, 10));
            assert!(out.is_empty(), "{name:?} produced a path");
            assert!(
                matches!(ns.problems().get("x"), Some(Problem::BadName(_))),
                "{name:?} was dropped without a reason"
            );
        }
    }

    #[test]
    fn a_file_cannot_be_a_parent() {
        let mut ns = tree();
        assert!(ns.apply(file("c", "a", "c.txt", 1)).is_empty());
        assert_eq!(ns.problems().get("c"), Some(&Problem::ParentCannotContain));
    }

    /// A refused folder must not leave its contents waiting for it forever.
    ///
    /// They are waiting for a parent that will never exist, and reporting them
    /// as pending says "not yet" — which is untrue, and which a caller watching
    /// the pending set to drain would wait on indefinitely.
    #[test]
    fn refusing_a_folder_refuses_what_was_waiting_for_it() {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        // Two files arrive before the folder that will turn out to be unusable.
        ns.apply(file("a", "BAD", "a.txt", 1));
        ns.apply(file("b", "BAD", "b.txt", 1));
        assert_eq!(ns.pending(), 2);

        ns.apply(folder("BAD", "R", ".."));
        assert_eq!(
            ns.pending(),
            0,
            "items waiting on a refused folder are still reported as pending: {:?}",
            ns.pending_ids()
        );
        for id in ["BAD", "a", "b"] {
            assert!(
                ns.problems().contains_key(id),
                "{id} was neither placed nor recorded"
            );
        }
    }

    /// A package's contents are tracked, not refused.
    ///
    /// They must be *in* the tree — a package that later turns out to be an
    /// ordinary folder has to have its children, and pathing needs them — while
    /// never being emitted as files. Recording them as problems instead would
    /// be a refusal that nothing can ever clear: the entry is dropped only by a
    /// successful upsert or a delete, and neither will come. One OneNote
    /// notebook on the drive would then block a provider's cursor forever.
    #[test]
    fn a_packages_contents_are_tracked_without_being_refused() {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        ns.apply(Item::Upsert {
            id: "P".into(),
            parent: "R".into(),
            name: "Notebook".into(),
            kind: Kind::Opaque,
        });
        ns.apply(file("inner", "P", "section.one", 10));
        assert!(
            ns.problems().is_empty(),
            "a package's contents were refused: {:?}",
            ns.problems()
        );
        assert_eq!(ns.pending(), 0, "they were left waiting instead");
    }

    /// A package is tracked for pathing and never walked into.
    #[test]
    fn an_opaque_folder_yields_no_files() {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        ns.apply(Item::Upsert {
            id: "P".into(),
            parent: "R".into(),
            name: "Notebook".into(),
            kind: Kind::Opaque,
        });
        ns.apply(file("inner", "P", "section.one", 10));
        assert!(
            paths(&ns.listing()).is_empty(),
            "a package's internals were synced as files"
        );
    }

    /// A file that becomes a folder, or the reverse.
    #[test]
    fn a_kind_change_removes_the_old_shape() {
        let mut ns = tree();
        // `a.txt` becomes a folder.
        let out = ns.apply(folder("a", "F", "a.txt"));
        assert_eq!(removed(&out), ["a"], "the file was not removed: {out:?}");
        // And nothing now claims that path as a file.
        assert_eq!(paths(&ns.listing()), ["Work/Notes/b.txt"]);
    }

    /// A held item that is itself deleted must not come back when its parent
    /// eventually turns up.
    #[test]
    fn an_item_deleted_while_waiting_does_not_return() {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        ns.apply(file("a", "F", "a.txt", 10));
        assert_eq!(ns.pending_ids(), ["a"]);

        ns.apply(Item::Delete { id: "a".into() });
        assert_eq!(ns.pending(), 0);

        let out = ns.apply(folder("F", "R", "Work"));
        assert!(
            out.is_empty(),
            "a deleted item was resurrected when its parent arrived: {out:?}"
        );
    }

    /// A parent that never arrives keeps its waiters visible rather than
    /// discarding them — the service may still describe it on a later page, and
    /// a file dropped here would never sync and never be reported.
    #[test]
    fn a_deletion_elsewhere_does_not_discard_unrelated_waiters() {
        let mut ns = tree();
        ns.apply(file("d", "NEVER", "d.txt", 1));
        ns.apply(Item::Delete { id: "F".into() });
        assert_eq!(
            ns.pending_ids(),
            ["d"],
            "an item waiting on an unrelated parent was discarded by a delete"
        );
    }

    /// A snapshot restores to the same tree, and restoring is not news.
    #[test]
    fn a_snapshot_round_trips() {
        let mut ns = tree();
        ns.apply(folder("F", "R", "Archive"));
        let before = ns.listing();

        let restored = Namespace::restore(ns.snapshot());
        assert_eq!(restored.listing(), before);
        assert_eq!(restored.pending(), 0, "a snapshot was not parent-first");
        assert!(restored.problems().is_empty());
    }

    #[test]
    fn renaming_a_file_reports_it_at_the_new_name() {
        let mut ns = tree();
        assert_eq!(paths(&ns.apply(file("a", "F", "renamed.txt", 10))), ["Work/renamed.txt"]);
    }

    #[test]
    fn deleting_an_unknown_item_is_not_an_error() {
        let mut ns = tree();
        assert!(ns.apply(Item::Delete { id: "ghost".into() }).is_empty());
    }

    #[test]
    fn a_full_listing_names_every_file_at_its_current_path() {
        let mut ns = tree();
        ns.apply(folder("F", "R", "Archive"));
        assert_eq!(paths(&ns.listing()), ["Archive/a.txt", "Archive/Notes/b.txt"]);
    }

    #[test]
    fn a_subtree_is_reported_shallowest_first() {
        let mut ns = Namespace::new();
        ns.apply(Item::Root { id: "R".into() });
        ns.apply(folder("F", "R", "Work"));
        ns.apply(folder("G", "F", "Deep"));
        ns.apply(file("deep", "G", "z.txt", 1));
        ns.apply(file("shallow", "F", "a.txt", 1));
        assert_eq!(
            paths(&ns.apply(folder("F", "R", "Moved"))),
            ["Moved/a.txt", "Moved/Deep/z.txt"]
        );
    }

    /// Deleting the root leaves nothing claiming to be a tree.
    #[test]
    fn deleting_the_root_empties_the_tree() {
        let mut ns = tree();
        assert_eq!(removed(&ns.apply(Item::Delete { id: "R".into() })), ["a", "b"]);
        assert!(ns.is_empty());
        assert!(ns.listing().is_empty());
    }
}

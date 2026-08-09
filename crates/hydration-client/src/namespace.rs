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
//! It is deliberately not a cache of file *content* or state — the sync
//! directory is that, and §5.2 says the local copy is the truth. This is only
//! the shape of the remote namespace, which is the one thing the local side
//! cannot work out for itself.

use crate::delta::Change;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// What a service says about one item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// The item exists, with this parent, name and shape. Covers creation,
    /// rename, move and content change alike — which is what a delta feed
    /// actually gives you, and the reason the reconciler is written to work out
    /// the difference from the disk rather than be told.
    Upsert {
        id: String,
        /// `None` only for the root itself.
        parent: Option<String>,
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
    /// The tree's anchor. Its name is not part of any path.
    Root,
}

#[derive(Debug, Clone)]
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
    /// Items whose parent has not arrived yet.
    ///
    /// A delta page is not guaranteed to be parent-first, and an item with no
    /// known parent has no path — so it is held rather than guessed at, and
    /// replayed when its parent shows up. Guessing would mean placing a file at
    /// a path the service never named.
    orphans: BTreeMap<String, Item>,
}

/// Guards against a malformed tree rather than a deep one.
///
/// A parent chain that loops would otherwise hang the sync daemon inside a path
/// computation, which is a worse failure than refusing the item: a service that
/// reports a cycle is broken, and a client that hangs on it is broken too.
const MAX_DEPTH: usize = 512;

impl Namespace {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one item and return the file changes it implies.
    ///
    /// Order within the returned batch is stable and parent-before-child, so a
    /// caller feeding these into [`crate::delta::apply`] sees directories
    /// created before the files in them.
    pub fn apply(&mut self, item: Item) -> Vec<Change> {
        let mut out = Vec::new();
        self.apply_into(item, &mut out);
        // An arrival can unblock items that were waiting for it, and those can
        // unblock others. Bounded by the orphan count, which only shrinks here.
        loop {
            let ready: Vec<String> = self
                .orphans
                .iter()
                .filter(|(_, it)| self.parent_known(it))
                .map(|(id, _)| id.clone())
                .collect();
            if ready.is_empty() {
                break;
            }
            for id in ready {
                if let Some(held) = self.orphans.remove(&id) {
                    self.apply_into(held, &mut out);
                }
            }
        }
        out
    }

    /// Everything currently known, as a full listing.
    ///
    /// What a provider returns when its delta token has expired. The reconciler
    /// treats a replayed listing as a no-op, so this is cheap to send and is the
    /// honest answer to "I lost my place".
    pub fn listing(&self) -> Vec<Change> {
        let mut out = Vec::new();
        if let Some(root) = &self.root {
            self.collect_files(root, &mut out);
        }
        out
    }

    /// How many items are held waiting for a parent that has not arrived.
    ///
    /// Not zero is not an error — a delta page can legitimately split a subtree
    /// — but *staying* non-zero across a full pass means the service referenced
    /// a parent it never described, and a caller should say so rather than
    /// silently never syncing those files.
    pub fn pending(&self) -> usize {
        self.orphans.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn parent_known(&self, item: &Item) -> bool {
        match item {
            Item::Upsert { parent: None, .. } => true,
            Item::Upsert {
                parent: Some(p), ..
            } => self.nodes.contains_key(p),
            Item::Delete { .. } => true,
        }
    }

    fn apply_into(&mut self, item: Item, out: &mut Vec<Change>) {
        match item {
            Item::Upsert {
                id,
                parent,
                name,
                kind,
            } => self.upsert(id, parent, name, kind, out),
            Item::Delete { id } => self.delete(&id, out),
        }
    }

    fn upsert(
        &mut self,
        id: String,
        parent: Option<String>,
        name: String,
        kind: Kind,
        out: &mut Vec<Change>,
    ) {
        if matches!(kind, Kind::Root) {
            self.root = Some(id.clone());
            self.nodes.insert(
                id,
                Node {
                    parent: None,
                    name,
                    kind: Kind::Root,
                },
            );
            return;
        }

        let Some(parent_id) = parent.clone() else {
            // A non-root item with no parent has no path. Nothing to do with it
            // but hold it, and `pending()` is how a caller finds out.
            self.orphans.insert(
                id.clone(),
                Item::Upsert {
                    id,
                    parent,
                    name,
                    kind,
                },
            );
            return;
        };
        if !self.nodes.contains_key(&parent_id) {
            self.orphans.insert(
                id.clone(),
                Item::Upsert {
                    id,
                    parent,
                    name,
                    kind,
                },
            );
            return;
        }

        let moved = match self.nodes.get(&id) {
            Some(prev) => prev.parent.as_deref() != Some(parent_id.as_str()) || prev.name != name,
            None => false,
        };

        // Detach from wherever it was, then attach where it is now.
        if let Some(prev) = self.nodes.get(&id) {
            if let Some(old_parent) = prev.parent.clone() {
                if let Some(set) = self.children.get_mut(&old_parent) {
                    set.remove(&id);
                }
            }
        }
        self.children
            .entry(parent_id.clone())
            .or_default()
            .insert(id.clone());
        self.nodes.insert(
            id.clone(),
            Node {
                parent: Some(parent_id),
                name,
                kind: kind.clone(),
            },
        );

        match kind {
            Kind::File { size, ctag } => {
                if let Some(path) = self.path_of(&id) {
                    out.push(Change::Upserted {
                        cloud_id: id,
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
            Kind::Folder if moved => self.collect_files(&id, out),
            Kind::Folder => {}
            Kind::Root => unreachable!("handled above"),
        }
    }

    fn delete(&mut self, id: &str, out: &mut Vec<Change>) {
        self.orphans.remove(id);
        let Some(node) = self.nodes.get(id).cloned() else {
            return;
        };

        // Files first, gathered before anything is unlinked from the tree —
        // afterwards there is no way to walk it.
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
        }
        self.nodes.remove(id);
        self.children.remove(id);
        if let Some(parent) = node.parent {
            if let Some(set) = self.children.get_mut(&parent) {
                set.remove(id);
            }
        }
        if self.root.as_deref() == Some(id) {
            self.root = None;
        }
    }

    /// Every file at or beneath `id`, as upserts at their current paths.
    fn collect_files(&self, id: &str, out: &mut Vec<Change>) {
        let mut stack = vec![id.to_string()];
        let mut seen = BTreeSet::new();
        while let Some(cur) = stack.pop() {
            if !seen.insert(cur.clone()) {
                continue;
            }
            if let Some(node) = self.nodes.get(&cur) {
                if let Kind::File { size, ctag } = &node.kind {
                    if let Some(path) = self.path_of(&cur) {
                        out.push(Change::Upserted {
                            cloud_id: cur.clone(),
                            path,
                            size: *size,
                            etag: ctag.clone(),
                        });
                    }
                }
            }
            if let Some(kids) = self.children.get(&cur) {
                stack.extend(kids.iter().cloned());
            }
        }
        // Shallowest first, so a caller creating directories as it goes sees
        // parents before children.
        out.sort_by(|a, b| depth_of(a).cmp(&depth_of(b)).then_with(|| key(a).cmp(key(b))));
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
            if matches!(node.kind, Kind::Root) {
                parts.reverse();
                return Some(parts.join("/"));
            }
            parts.push(node.name.clone());
            cur = node.parent.clone()?;
        }
        // A cycle, or a tree deeper than any real one. Refused rather than
        // followed: hanging inside a path computation is a worse answer than
        // dropping an item a broken service described.
        None
    }
}

fn key(c: &Change) -> &str {
    match c {
        Change::Upserted { path, .. } => path,
        Change::Removed { cloud_id } => cloud_id,
    }
}

fn depth_of(c: &Change) -> usize {
    key(c).matches('/').count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(id: &str) -> Item {
        Item::Upsert {
            id: id.into(),
            parent: None,
            name: String::new(),
            kind: Kind::Root,
        }
    }

    fn folder(id: &str, parent: &str, name: &str) -> Item {
        Item::Upsert {
            id: id.into(),
            parent: Some(parent.into()),
            name: name.into(),
            kind: Kind::Folder,
        }
    }

    fn file(id: &str, parent: &str, name: &str, size: u64) -> Item {
        Item::Upsert {
            id: id.into(),
            parent: Some(parent.into()),
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

    /// Builds `/Work/{a.txt, Notes/b.txt}`.
    fn tree() -> Namespace {
        let mut ns = Namespace::new();
        ns.apply(root("R"));
        ns.apply(folder("F", "R", "Work"));
        ns.apply(file("a", "F", "a.txt", 10));
        ns.apply(folder("G", "F", "Notes"));
        ns.apply(file("b", "G", "b.txt", 20));
        ns
    }

    #[test]
    fn a_file_arrives_at_its_full_path() {
        let mut ns = Namespace::new();
        ns.apply(root("R"));
        ns.apply(folder("F", "R", "Work"));
        assert_eq!(paths(&ns.apply(file("a", "F", "a.txt", 10))), ["Work/a.txt"]);
    }

    /// A folder is not a change by itself: directories are implied by the paths
    /// of the files in them.
    #[test]
    fn a_new_folder_is_not_a_change() {
        let mut ns = Namespace::new();
        ns.apply(root("R"));
        assert!(ns.apply(folder("F", "R", "Work")).is_empty());
    }

    /// The reason this module exists.
    #[test]
    fn moving_a_folder_moves_everything_beneath_it() {
        let mut ns = tree();
        // One change from the service: "Work" is now called "Archive".
        let out = ns.apply(folder("F", "R", "Archive"));
        assert_eq!(
            paths(&out),
            ["Archive/a.txt", "Archive/Notes/b.txt"],
            "a folder move left its contents behind"
        );
    }

    /// And into a different parent, which is what dragging in a web UI does.
    #[test]
    fn moving_a_folder_into_another_folder_repaths_the_subtree() {
        let mut ns = tree();
        ns.apply(folder("H", "R", "Archive"));
        let out = ns.apply(folder("G", "H", "Notes"));
        assert_eq!(paths(&out), ["Archive/Notes/b.txt"]);
        // And the file that stayed behind is untouched.
        assert!(!paths(&out).iter().any(|p| p.contains("a.txt")));
    }

    /// A folder reported again with nothing changed must produce nothing —
    /// a delta feed replays, and a re-place of every file beneath a folder is
    /// how a hydrated tree gets silently dehydrated.
    #[test]
    fn a_folder_reported_unchanged_produces_no_work() {
        let mut ns = tree();
        assert!(
            ns.apply(folder("F", "R", "Work")).is_empty(),
            "an unchanged folder re-reported its whole subtree"
        );
    }

    #[test]
    fn deleting_a_folder_removes_every_file_beneath_it() {
        let mut ns = tree();
        let out = ns.apply(Item::Delete { id: "F".into() });
        assert_eq!(removed(&out), ["a", "b"]);
        assert!(ns.apply(file("c", "F", "c.txt", 1)).is_empty());
        assert_eq!(ns.pending(), 1, "the subtree was not forgotten");
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
        ns.apply(root("R"));
        // The file arrives before the folder it lives in.
        assert!(ns.apply(file("a", "F", "a.txt", 10)).is_empty());
        assert_eq!(ns.pending(), 1);

        let out = ns.apply(folder("F", "R", "Work"));
        assert_eq!(paths(&out), ["Work/a.txt"], "the held item was never replayed");
        assert_eq!(ns.pending(), 0);
    }

    /// And a whole chain of them, in the worst order.
    #[test]
    fn a_reversed_subtree_still_resolves() {
        let mut ns = Namespace::new();
        ns.apply(file("c", "G", "c.txt", 30));
        ns.apply(folder("G", "F", "Notes"));
        ns.apply(folder("F", "R", "Work"));
        let out = ns.apply(root("R"));
        assert_eq!(paths(&out), ["Work/Notes/c.txt"]);
        assert_eq!(ns.pending(), 0);
    }

    /// A parent the service never describes must not silently vanish.
    #[test]
    fn an_item_with_an_unknown_parent_stays_visible() {
        let mut ns = Namespace::new();
        ns.apply(root("R"));
        ns.apply(file("a", "NOWHERE", "a.txt", 10));
        assert_eq!(
            ns.pending(),
            1,
            "an unsyncable item disappeared instead of being reported"
        );
    }

    /// A service reporting a cycle is broken. Hanging on it would make us broken
    /// too, and a sync daemon that hangs inside a path computation stops
    /// answering hydration requests.
    #[test]
    fn a_cycle_is_refused_rather_than_followed() {
        let mut ns = Namespace::new();
        ns.apply(root("R"));
        ns.apply(folder("F", "R", "Work"));
        ns.apply(folder("G", "F", "Notes"));
        // G is now its own grandparent.
        ns.apply(folder("F", "G", "Work"));
        let out = ns.apply(file("a", "F", "a.txt", 10));
        assert!(
            out.is_empty(),
            "a cyclic parent chain produced a path: {:?}",
            paths(&out)
        );
    }

    /// The answer to an expired delta token.
    #[test]
    fn a_full_listing_names_every_file_at_its_current_path() {
        let mut ns = tree();
        ns.apply(folder("F", "R", "Archive"));
        assert_eq!(
            paths(&ns.listing()),
            ["Archive/a.txt", "Archive/Notes/b.txt"]
        );
    }

    /// Parents before children, so a caller creating directories as it goes is
    /// never asked for a file before the folder holding it.
    #[test]
    fn a_subtree_is_reported_shallowest_first() {
        let mut ns = Namespace::new();
        ns.apply(root("R"));
        ns.apply(folder("F", "R", "Work"));
        ns.apply(folder("G", "F", "Deep"));
        ns.apply(file("deep", "G", "z.txt", 1));
        ns.apply(file("shallow", "F", "a.txt", 1));
        let out = ns.apply(folder("F", "R", "Moved"));
        assert_eq!(paths(&out), ["Moved/a.txt", "Moved/Deep/z.txt"]);
    }

    /// A rename in place is a move as far as paths are concerned.
    #[test]
    fn renaming_a_file_reports_it_at_the_new_name() {
        let mut ns = tree();
        let out = ns.apply(file("a", "F", "renamed.txt", 10));
        assert_eq!(paths(&out), ["Work/renamed.txt"]);
    }

    /// Deleting something we never heard of is the state we wanted.
    #[test]
    fn deleting_an_unknown_item_is_not_an_error() {
        let mut ns = tree();
        assert!(ns.apply(Item::Delete { id: "ghost".into() }).is_empty());
    }
}

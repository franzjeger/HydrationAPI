# Groundwork: Sync-ignore — paths the framework never syncs in either direction

Design only. No sync-ignore code exists in either repo (grepped both: `is_ignored`,
`hydration-ignore`, `.gitignore`, and any path-based exclusion return nothing under
`crates/`; the only skip is the name-based `names::is_internal`,
`hydration-protocol/src/lib.rs:464`). This document is what that code will be written
from; the test lists in §6 are meant to be written *first* and to fail against the
current trees.

It follows the house style of `docs/KEEP-ON-DEVICE-GROUNDWORK.md` and
`docs/AUTO-EVICTION-GROUNDWORK.md`: every claim is cited to `file:line` because the
repo law is measured-not-recalled, the obvious-but-wrong alternative is named at each
fork, and the critique at the end is kept including what it says about this document's
own weaknesses.

---

## The problem, measured

On the live account there are 12 git repositories inside the sync root and **1,296
files under `.git/` directories**. Git rewrites `.git/index`, refs, and logs
constantly via atomic rename, and an atomic rename strips the framework's xattrs — so
each rewrite is a fresh inode carrying no `user.hydration.id`. On upload that new inode
collides by name with the cloud copy it has no lineage record for, and the create is
*safely* refused: the provider will not send a file "without overwriting that one
blind" (`hydration-graph/src/lib.rs:3826`, the collision-refusal arm; measured against
git pack files on a live account, `delta.rs:998-1001`). Nothing is corrupted today —
the refusal holds — but the queue keeps re-attempting, the count of unsent files
climbs and stays, and the log spams `-> Failed(...)` every cycle. Syncing an active
`.git/` is a known cross-device corruption anti-pattern besides. So `.git/` should not
be synced *at all*, in either direction: never uploaded when it changes locally, never
materialised as a placeholder when it appears in the cloud.

### The one thing to hold onto: this is a THIRD exclusion

The codebase already has two exclusions, and a sync-ignore is neither of them. Keeping
the three apart is the whole design, because they have opposite safety semantics and
folding any two together breaks one:

1. **`is_internal` — the framework's own files** (`lib.rs:431-489`; predicate at
   `:464`). MANIFEST, LINEAGE, scratch names, matched on the **leaf name alone** "so it
   holds at any depth" (`:462`). It is a fixed framework invariant, identical in both
   privileged and unprivileged halves, never configurable. In `safe_join` a match is a
   **terminal security refusal** — `Failure::PathRefused` (`delta.rs:1009-1013,546-547`)
   — because a cloud object claiming `.hydration-manifest` is an attack. Internal files
   are *swept, refused, and never real*.

2. **The §6c/§6d backup-exclusion policy** — a different axis entirely: it denies backup
   *tools* (keyed by cgroup) from hydrating placeholders on bulk reads, and governs the
   nodump flag + manifest so a backup is complete. It excludes *processes* and governs
   *backup completeness*; it says nothing about which *paths* sync.

3. **Sync-ignore (this document)** — user/product **policy**, path-based, matching a
   whole subtree. An ignored `.git/` object is *legitimate user data deliberately not
   synced*: it must be **skipped quietly**, and — the load-bearing difference from
   `is_internal` — **the local file must stay a real file**, never swept, never refused,
   never turned into a placeholder. Sync-ignore is the only one of the three that must
   *preserve* a real on-disk file rather than deny or destroy one.

Fold sync-ignore into `is_internal` and you (a) cannot express it — `is_internal` sees
only the leaf, and `.git/index`'s leaf is `index` (§2); (b) route ignored paths through
`safe_join`'s refusal, which several delta callers mark retryable and re-attempt
forever; and (c) put the manifest/lineage safety set one config edit away from breaking.
It is a separate predicate, in the same shared crate for the same reason `is_internal`
lives there.

---

## What this establishes before any code is written

Five things the five-investigator pass pinned down, each of which shapes the feature:

- **`is_internal` is the wrong shape and cannot be extended into this.** It is only ever
  handed `path.file_name()` — the last component (verified at every one of its 11
  callers: `store.rs:185`, `manifest.rs:79`, `delta.rs:1010`, `namespace.rs:716`,
  `daemon_loop.rs:270/1830/1885/2038`, `reclaim.rs:329/390`). For
  `Projects/foo/.git/index`, `file_name()` is `index`, and adding `".git"` to the
  `is_internal` list would only ever match a plain file literally named `.git`. The
  1,296 files whose basenames are `index`, `HEAD`, `config`, `packed-refs`,
  `refs/heads/main` are **not** caught. The correct test is component-wise, not
  basename-wise (§2).

- **The eviction data-loss defence is already there, but only from a clean start.** An
  ignored `.git/` file is never uploaded → gets no cloud id → and `collect_residents`
  refuses to evict any file without a cloud id: "The cloud must hold it, or evicting it
  destroys the only copy" (`reclaim.rs:414-419`), plus a `Clean`-stamp gate (`:421-425`).
  So *never upload it* is sufficient to keep it a real local file — **by composition, not
  by a single guard, and only on a tree that started clean** (§4 is the whole reason this
  qualifier matters).

- **The safety invariant reduces to one place: delta must never place() at an ignored
  path.** Placeholders are created only in `delta::apply_remembering`: `mat.place` at
  `delta.rs:621` (create, fresh placeholder) and `:716` (update, which **dehydrates an
  existing real local file** — an atomic inode replacement that destroys the working-tree
  file). If the framework then declines to hydrate ignored paths, that placeholder serves
  zeros — the §5.7 data-loss the whole framework exists to prevent. The gate is
  *required*, not incidental (§3).

- **Enabling the ignore can itself trigger mass cloud deletion.** `detect_offline_removals`
  (`daemon_loop.rs:1753`) builds a presence journal from the manifest **and the lineage**
  (`:1756-1761`), diffs it against the live scan, and withdraws anything in the journal
  but absent from disk, up to a ceiling of a tenth of the tree (`removal_ceiling`,
  `:1636`). `.git/` files uploaded before the rule, that kept their xattr, live in the
  lineage half. The first time the scan starts *skipping* `.git/`, those paths look
  deleted-offline and get withdrawn — 1,296 is far under the ~16,789 ceiling on a
  167,890-file account, so **all of them, silently**. This is the transition trap and §4
  is written around it.

- **The ignore must never reach the serve path.** `is_ignored` lives on the unprivileged
  client. The privileged helper answers reads and never sees it. A placeholder that
  already exists when a rule starts matching it must **still hydrate on read** — the
  DEHYDRATED xattr is the sole authority for "must hydrate," and consulting the ignore
  list on the fanotify serve path would serve zeros. This boundary is natural (the helper
  never learns the ignore set) but must be *written down* so nobody adds the check "for
  consistency."

---

## 1. The predicate: a separate `is_ignored`, in the shared crate

**Decision: a new pure predicate `is_ignored(rel: &Path) -> bool` in a new
`hydration_protocol::ignore` module, next to `names` (`lib.rs:447`), taking a
root-relative path and a loaded rule set — never folded into `names::is_internal`.**

It lives in the shared crate for the exact reason `is_internal` does: "the scan, the
manifest builder, the delta pass and the change watcher all need the same answer, and
four copies of it is how they come to disagree" (`lib.rs:444-446`). It differs from
`is_internal` in three structural ways, and each is why it is a sibling and not an
extension:

- **Signature.** `is_internal(name: &str)` matches one leaf; `is_ignored(rel: &Path)`
  matches a path component and its whole subtree.
- **Refusal semantics.** An `is_internal` hit in `safe_join` is `PathRefused`, a security
  event. An `is_ignored` hit is a *benign skip* with its own accounting, never pushed to
  `out.failed` (§3).
- **Authority.** `is_internal` is a fixed invariant in both halves. Sync-ignore is
  user/product policy that belongs in `Config` (`daemon_loop.rs:67`) and must never reach
  the privileged helper.

**Rejected: extend `is_internal`.** Named above and in §What-this-establishes: wrong
signature, wrong refusal semantics, and it puts policy inside the framework's safety
invariant.

---

## 2. The match: `.git` component default, plus an optional `.hydration-ignore`

### 2.1 `.git` is a directory-COMPONENT rule, not a basename

```
is_ignored(rel) is true iff any '/'-split component of rel equals ".git"
                (built-in), or matches a configured rule (§2.2).
```

This gives exactly the wanted verdicts, and each fork names what a looser test gets
wrong:

- `a/.git/index` → ignored (component `.git` present). **YES.**
- `.git/HEAD`, `a/.git/refs/heads/main` → ignored. **YES** — this is why one rule covers
  every repo at every depth, and why a basename test (which sees `index`, `HEAD`, `main`)
  cannot.
- worktree / submodule gitlink, where `.git` is a **regular file** containing `gitdir: …`
  → component `.git` (as the leaf) matches → ignored. **Correct, same rule** — match the
  component name regardless of file type.
- `foo.gitconfig`, `.gitignore`, `.gitattributes`, `.github/` → single component
  `!= ".git"` → **NOT ignored.** These are user content and must sync. A substring or
  prefix test would wrongly catch them.
- `foo.git` (a bare-repo directory) → `!= ".git"` → **NOT ignored** by the default.
  Correct for v1; keep the default narrow.
- **Case-sensitive, byte-exact.** The sync root is a case-sensitive Linux fs; `.git` and
  `.GIT` are different directories, and a case-insensitive match could silence a user's
  real `.GIT` data. Exact byte equality only.

### 2.2 The pure, testable predicate

A new module, pure and unit-testable, no I/O:

```rust
// hydration-protocol/src/lib.rs, new `pub mod ignore`, beside `names`
pub struct IgnoreSet { component: Vec<String>, prefix: Vec<String> }

impl IgnoreSet {
    /// Built-in `.git` component is always present; config cannot remove it.
    pub fn from_config(contents: &str) -> IgnoreSet;   // pure: parses file text
    pub fn is_ignored(&self, rel: &Path) -> bool;      // rel root-relative, no leading '/'
}
```

`is_ignored(rel)` returns true iff any `'/'`-split component equals a `component` rule,
**or** `rel == p` or `rel.starts_with(p + "/")` for an anchored `prefix` rule `p`.
`from_config` seeds `.git` into `component` **unconditionally**. Empty config → only the
built-in `.git` component, so the common case pays one component scan per path
(`O(path length)`, negligible — but §7/§Critique say measure it on the 167k-file tree,
not assume it).

### 2.3 The optional `.hydration-ignore` file

The smallest thing that solves `.git` and stays extensible, parsed once per pass from the
sync root (missing file = empty set, exactly as `manifest::entries` / `lineage::load`
treat a missing file):

- one pattern per line; `#`-comment lines and blank lines skipped; trailing whitespace
  trimmed.
- a line with **no `/`** → a component rule (matched at any depth): `node_modules`,
  `target`, `.venv`, `__pycache__`, `.direnv`. Component matching alone covers the
  overwhelming majority of what people actually exclude, because what people exclude are
  named build/cache directories.
- a line **with a `/`** → an anchored prefix rule, root-relative (`build/artifacts`
  ignores that subtree but **not** `src/build/artifacts`). Trivial to implement
  (`rel == p || rel.starts_with(p + "/")`) and the one extension worth shipping.
- a `..` in any pattern is **rejected at parse** — a prefix rule is never meant to escape
  the root, and rejecting is cheaper than reasoning about a normalised escape later.
- explicitly **NOT gitignore glob semantics**: no `*`/`?`/`**`/character-classes, no `!`
  negation, no order-dependent precedence, no dir-only trailing-slash rules. That surface
  is large, test-heavy, and a known source of subtle bugs. `is_ignored` is the seam behind
  which globs *could* be added later without touching a single call site.

**Rejected: a `.gitignore`-style glob engine now.** Deferred (§8). The motivating case is
12 repos and 1,296 files; per CLAUDE.md, do not build a pattern engine on speculation.

### 2.4 `.hydration-ignore` must itself be `is_internal`

Add `IGNORE = ".hydration-ignore"` to `names` and a clause to `is_internal`
(`lib.rs:464`), beside MANIFEST/LINEAGE. This buys four things off the existing machinery
for free: the file is never indexed/uploaded (`store.rs:185`), never listed in the §6d
manifest (`manifest.rs:79`), never carried by a rename (`daemon_loop.rs:2038`), and — the
security-relevant one — **a cloud object cannot claim the name `.hydration-ignore`**,
because `safe_join` refuses `is_internal` names (`delta.rs:1009-1013`). So a hostile or
buggy remote cannot push an ignore file that silences uploads of the user's own data.
Ignore rules are therefore per-device, exactly like lineage (`lib.rs:456-458`). The
framework **reads it only, never writes it** — a framework write to a file inside the
sync root by the process that answers its own events is the §6a-ter trap; keep it
user-authored (§7).

**Rejected: syncing the ignore rules across devices.** A separate decision with a real
injection cost (the remote could rewrite what the local device excludes); out of scope
for v1.

---

## 3. The two enforcement sites, and the safety invariant

One predicate, consulted at every sync boundary so a path cannot leak in one direction
while being ignored in the other. Two of these sites are **safety-critical**; the rest
are cheap pre-filters that keep ignored paths from churning the queue, the log, and the
inotify budget.

### 3.1 SAFETY-CRITICAL — the delta / materialise skip

**Add `if is_ignored(rel) { out.ignored += 1; continue; }` at the top of the
`for change in coalesce(changes)` loop in `apply_remembering`, right after
`let change = &change;` (`delta.rs:453`), before the `match change`.** It covers both
arms that create on-disk objects:

- `Change::Upserted` (`:540`) — skips **before** `safe_join` (`:546`), before the
  rename-by-cloud-id block, and before **both** `mat.place` calls (create `:621`, and the
  dehydrating update `:716`). No placeholder, no folder, no overwrite of a real file.
- `Change::FolderUpserted` (`:455`) — skips before `folder_path`, so no `.git/` directory
  is created from a cloud echo.

The `Change::Removed` arm (`:726`) resolves its victim from `by_cloud_id` (`:727`), never
from a cloud-declared path, and is covered structurally by the scan exclusion in §3.3: an
ignored path is never in the index, so `by_cloud_id.get()` returns `None` → `continue`
(`:730`) → `mat.remove` (`:759`) is never called on a real ignored file. Belt-and-braces,
add the same `is_ignored(&entry.path)` check in the Removed / FolderRemoved arms against
the *resolved* path.

**Do NOT bury this in `safe_join`.** `safe_join` returning `None` is `Failure::PathRefused`
(`:546-547`), which several callers mark retryable and re-attempt forever, and which the
fingerprint memo treats as unfinished. An ignored path is an *expected silent skip*, not a
failure. Keep the two concepts separate — a plain `continue` with an `ignored` counter, so
the pass still records its no-op fingerprint (`:397-403`) and the next identical batch is
skipped entirely.

Add `ignored: usize` to `Applied` (`delta.rs:286`, beside `created`/`updated`/`removed`/
`moved`). It is a benign count, not a failure and not a conflict.

**The safety invariant, stated once:** *no placeholder is ever created for an ignored
path.* Because §3.1 skips before every `place()`, this holds by construction — and because
no placeholder is created, none can be served as zeros, and an ignored path that is a real
local file is never overwritten, dehydrated, or removed by any delta arm.

### 3.2 SAFETY-CRITICAL — the upload drop

**In `run_upload` (`upload.rs:409`), right after `store.lookup(&file)` resolves
`entry.path` (`:414-419`), compute `rel` from the store root and return before
`sink.upload` if `is_ignored(rel)`.** This is the *one* choke every queued upload passes,
whatever fed it:

- live — `QueueChanges::changed` (`daemon_loop.rs:110`) calls `q.touch(f)` with only a
  `FileId`, no path; the Queue is `FileId`-only and structurally cannot filter by path
  (`upload.rs`). The path is first available here.
- resync — `dirty_files` (`daemon_loop.rs:252`).
- retry — `Queue::failed` backoff.

All three converge at the dequeue `run_upload(file, …)` (`daemon_loop.rs:1002`). Gating
here means no `sink.upload`, no Graph create, no collision refusal, no
`queue.failed`/backoff loop, no per-attempt log line — the ignored file leaves `pending()`
immediately. Return a new `Outcome::Ignored` (or reuse `NothingToDo`, `:417`).

### 3.3 Cheap producer-side pre-filters (churn, watches, cursor noise)

Each already filters by `is_internal` on the leaf; add `is_ignored` on the path beside it,
so ignored subtrees never enter the walks, the queue, or the watch set:

| Site | File:line | What to do |
|---|---|---|
| `Store::scan` index + fingerprint | `store.rs:129,185,237` | Do not descend an ignored dir. Effect: `.git/` never enters the index → the live `changed(FileId)` path resolves to `lookup==None`→`NothingToDo` naturally, **and** git's constant rewrites stop flipping the tree fingerprint that defeats the delta no-op skip (`delta.rs:397-403`). Keep §3.2 anyway — do not rely on not-indexing alone. |
| `dirty_files` (resync feed) | `daemon_loop.rs:252,270` | `is_ignored` beside the `is_internal` skip. |
| `unidentified_folders` (folder-create leak) | `daemon_loop.rs:1866,1885` | Skip the **subtree** — do not `stack.push`, do not queue. This closes a real upload-side leak: a `.git` dir has leaf `.git` (`is_internal` false), so today it is descended and every `.git/refs/...` is queued as a cloud folder-create. |
| `apply_renames` | `daemon_loop.rs:2028,2038` | Gate `from`/`to` (already has an `is_internal` from/to skip to mirror). |
| `apply_removals` | `daemon_loop.rs:2097` | Gate `g.path` — see §4; today it has **no** name filter at all. |
| `apply_folder_removals` / `apply_folder_creates` | `daemon_loop.rs:2173 / 1906` | Gate the path. |
| `removals::add_tree` | `removals.rs:268` | Do not watch ignored subtrees, so `.git`'s ~1,296 files do not consume inotify descriptors (§7 P4). |
| `manifest::build` | `manifest.rs:59,79` | Skip ignored paths — already benign (it lists only DEHYDRATED files, which ignored paths never are), but consistent. |
| `detect_offline_removals` journal | `daemon_loop.rs:1755-1761` | **The transition fix — §4.** |

### 3.4 Where `is_ignored` must NOT go: eviction serve, and the manifest as a lie

- **Eviction (`reclaim`)** already refuses a no-cloud-id file (`reclaim.rs:414-419`), so an
  ignored file cannot be evicted today. Add an explicit `is_ignored` skip to
  `collect_residents` (`:390`) and the manual `reclaim(rel)` entry anyway, so *"an ignored
  path stays a REAL local file, never a placeholder"* is a **rule** rather than an accident
  of the cloud-id gate — but this is defence-in-depth, not the primary guarantee (§3.1 is).
- **The hydration / serve path** — never. §What-this-establishes, point 5.
- **`Manifest::build` as a silencer** — do the skip for consistency, but do **not** treat
  it as hiding a bug: if a bug ever dehydrated an ignored path, silently omitting it from
  the manifest hides the failure, and listing it as "re-sync to restore" would invite
  fetching a stale cloud copy over the user's work. Prevent upstream (§3.1); keep the
  manifest honest.

---

## 4. The already-in-cloud transition — 1,296 objects, and what happens to them

The safety-by-construction argument ("ignored ⇒ no cloud id ⇒ cannot be evicted or
materialised over") holds **only from a clean start.** On the live account the old client
already uploaded `.git/` objects, so both of these pre-existing states exist and neither
is covered by §3's forward gates:

1. **A `.git/` placeholder the old client already materialised** (in the manifest half of
   the journal). If the ignore then *stops* materialising/hydrating it, its next read
   serves zeros — the §5.7 violation. **This is why the ignore gates sync only, never the
   serve path (§3.4):** an existing ignored placeholder must keep hydrating on read. Ignore
   means "stop syncing," **not** "make local." A user who wants an ignored subtree made
   fully local does that with Keep-on-Device / hydrate (a separate, existing action), not by
   adding the rule.

2. **A `.git/` real local file that was uploaded once and kept its xattr** (in the lineage
   half). This is where the two real hazards live.

### 4.1 The decision: leave the cloud copies, never dehydrate the local file, suppress withdrawal

Three parts, each grounded in what the code does today:

- **Leave the stale cloud copies. Do NOT auto-clean them.** Deleting 1,296 cloud objects is
  exactly the mass-withdrawal shape the removal design refuses on weak signals: the
  `removal_ceiling` (`daemon_loop.rs:1636,1781,2104`) and the stance that "retrying a
  removal in a loop is how one failure becomes a deletion nobody asked for." A cleanup sweep
  triggered *by a config edit* is the worst version of that. The stale copies are harmless
  and non-looping once both directions skip them: a delta pass over an ignored upsert does
  nothing (§3.1) — no place, no kept_local, no failed, no retryable — so the cursor advances
  and the fingerprint lets the next identical batch skip. Ignore is **prospective**: it
  governs future sync, it does not delete what is already in the cloud. If a cleanup is ever
  wanted it is an explicit, user-initiated, out-of-v1 action through the provider's normal
  delete with the ceiling guard — never automatic, never on the switch.

- **Never dehydrate the local file.** §3.1 (delta skip before both `place()` calls) and §3.3
  (scan exclusion) together guarantee no delta arm reaches `mat.place`/`mat.remove` on an
  ignored real file. This is the part that must be **measured, not assumed** — §4.2.

- **Suppress withdrawal, in both the online and offline paths.** Online: `apply_removals`
  (`daemon_loop.rs:2097`) does **no** name filtering today — it recovers a cloud id from the
  recent-sends map or the Registers/manifest (`:2128-2145`) and withdraws it. An ignored
  `.git/` file that *was* uploaded still has a recoverable cloud id, so a local `rm -rf
  .git` would withdraw it. Gate `g.path` on `is_ignored` (§3.3). Offline — **the load-bearing
  fix**: `detect_offline_removals` reads *last run's* on-disk journal (manifest + lineage,
  `:1756-1761`) before the first new scan runs, so the scan exclusion in §3.3 does **not**
  clean it retroactively. Add `journal.retain(|(p, _)| !is_ignored(Path::new(p)))` right
  after the journal is assembled (`:1761`). Without this, the first start after the ignore is
  switched on treats all 1,296 lineage/manifest `.git/` paths as offline deletions and
  withdraws them silently (they are under the ceiling). Going forward the lineage self-cleans
  (ignored paths stop being scanned/recorded); the read-time filter covers the first
  post-switch start. Belt **and** suspenders, because the trap is a one-time deletion of the
  user's cloud data.

### 4.2 What MUST be measured, not argued — delta over an existing real file

Do **not** assume the guard ladder is sufficient. `apply`'s `Ok(md)` branch (`delta.rs:627`)
decides, in order: `is_current` → no-op `continue` (`:663`); `waiting` → `EditWaiting` kept
(`:670`); no cloud id + `len>0` → `NeverUploaded` kept (`:691`); `Dirty` stamp →
`ChangedUnderneath` kept (`:713`); **else** `place()` overwrites the real file with a
placeholder (`:716`). Two states must be measured on a **real mount** before any test asserts
the ignore closes them (probe P1, §6):

- **Fresh git rewrite** — xattrs stripped by atomic rename, no cloud id, `len>0`. *Expected*
  to hit `NeverUploaded` (`:691`) and stay a real file. **Confirm** — this is the whole "safe
  today" claim, and it is the reason nothing is corrupted *yet*.
- **A static `.git/` file uploaded once** — carries a cloud id, `Clean` stamp, but the cloud
  etag/size has diverged. This falls **through every guard** to `place()` at `:716` and
  becomes a placeholder that, once evicted, is un-hydratable-as-the-user's-version. **This is
  the exact pre-existing data-loss path**, and the reason §3.1 must short-circuit *before* the
  ladder rather than trust it. Measure it to prove both the current hazard and that the ignore
  closes it.

Also measured, read-only, before code (probe P2, §6): a census of the live tree — how many
`.git/` cloud objects, local placeholders, and real files actually exist under the sync root
— so the size of the risk-1 population (existing ignored placeholders that would serve zeros)
is a number, not a guess.

---

## 5. Claim-by-claim

| # | Claim to eliminate | Enforcement | Where |
|---|---|---|---|
| 1 | Sync-ignore is just a bigger `is_internal` | **Design** — third exclusion, path-based, must *preserve* a real file | new `ignore` mod (`lib.rs:447`); §The-problem, §1 |
| 2 | Adding `.git` to `is_internal` catches `.git/` | **Measured** — `is_internal` sees only the leaf (`index`, `HEAD`) | component match, `is_ignored(rel)` (§2.1) |
| 3 | The match should be a prefix/substring | **Design** — `.gitignore`/`.github`/gitlink must be right | exact component equality, byte-exact, case-sensitive (§2.1) |
| 4 | A remote `.git/` upsert may materialise a placeholder | **Structural** — skip before both `place()` calls | `is_ignored` at top of the change loop (`delta.rs:453`, before `:621`/`:716`) |
| 5 | An ignored change is a failure/conflict | **Design** — benign skip, `Applied.ignored`, never `failed` | plain `continue`, not `safe_join`→`PathRefused` (`:546`) |
| 6 | A queued ignored upload still hits the provider | **Structural** — the one path-resolving choke | `run_upload` after `store.lookup` (`upload.rs:414`) |
| 7 | `.git` folders leak as cloud folder-creates | **Runtime** — skip the subtree, don't stack.push | `unidentified_folders` (`daemon_loop.rs:1885`) |
| 8 | A local `rm` of an ignored dir withdraws the cloud copy | **Design** — gate the removal paths | `apply_removals` (`:2097`), `apply_folder_removals` (`:2173`) |
| 9 | Enabling the rule mass-deletes the old cloud `.git/` | **Design** — the transition trap | `journal.retain(!is_ignored)` in `detect_offline_removals` (`:1761`) |
| 10 | Ignore should also make the path local / delete the cloud copy | **Design** — prospective, sync-only, leave cloud copies | §4.1 |
| 11 | Ignore gates hydration too, "for consistency" | **Design** — DEHYDRATED is the sole hydrate authority | never on the serve path (§3.4); helper never sees the set |
| 12 | An ignored path can still be evicted into a placeholder | **Runtime** — no cloud id ⇒ `reclaim` refuses, plus an explicit skip | `reclaim.rs:414-419`; `is_ignored` in `collect_residents` (`:390`) |
| 13 | A cloud object could push an ignore file that silences uploads | **Security** — `.hydration-ignore` is `is_internal` | `safe_join` refuses it (`delta.rs:1009`); per-device (§2.4) |

---

## 6. The edit list, smallest-first, and what each test must assert

**Groundwork before tests: the probes come first.** Nothing below is asserted by a test
until the measurement it rests on exists (CLAUDE.md). All live-rig probes are **read-only**;
do not mutate the rig.

### Probes (measured, not recalled) — write these first

- **P1 — delta over an existing real `.git/` file, per guard state. THE gate.** On a real
  mount (not tmpfs), construct a local real file and feed a matching `Change::Upserted`, in
  each of the two states of §4.2: (a) fresh-rewrite (no cloud id, `len>0`) → assert
  `NeverUploaded` kept, file byte-for-byte intact; (b) uploaded-once (cloud id, `Clean`,
  diverged cloud etag/size) → assert it reaches `place()` at `delta.rs:716` **without** the
  ignore, i.e. prove the current hazard, then assert the §3.1 skip prevents `place()` from
  ever being reached **with** it. This is the "measure before you assert" item and it is not
  resolvable from code.
- **P2 — live-tree census of `.git/`. Read-only walk on the live account** (per the MEMORY
  live-endurance methodology: record process context, functional over log proof). Count
  `.git/` paths that are: real local files, existing placeholders (carry DEHYDRATED), carry a
  cloud id in the lineage, appear in the manifest half of the journal. Sizes the risk-1
  population (existing ignored placeholders) and the risk-2 population (offline-withdrawal
  candidates) as numbers before any rollout.
- **P3 — the predicate dry-run over the real 12-repo tree.** Run `is_ignored` over a real
  walk of the sync root and assert: every `.git/` path (dirs, files, nested/submodule repos)
  matches; **no** `.gitignore`/`.gitattributes`/`.github`/`foo.gitconfig`/`foo.git` matches;
  a submodule gitlink `.git` *file* matches. No false positives before any withdrawal path is
  enabled.
- **P4 — inotify descriptor census (secondary).** Count the watches `add_tree`
  (`removals.rs:268`) places inside `.git/` across the 12 repos, to quantify the budget the
  subtree-prune recovers (`removals.rs` docs cite 524288 watches / 21395 dirs). Safe but not
  load-bearing.

### Framework — `/home/frank/Projects/HydrationAPI`

1. **`crates/hydration-protocol/src/lib.rs`** — new `pub mod ignore` (`IgnoreSet`,
   `from_config`, `is_ignored`, built-in `.git` component) beside `names` (`:447`); add
   `IGNORE = ".hydration-ignore"` to `names` (`:449`) and a clause to `is_internal` (`:464`).
   *Tests (pure, fail against no-code):*
   `git_component_matches_at_any_depth` (`a/.git/index`, `.git/HEAD` → true);
   `basename_lookalikes_are_not_ignored` (`.gitignore`, `.gitattributes`, `.github/x`,
   `foo.gitconfig`, `foo.git` → false);
   `a_gitlink_file_named_dot_git_is_ignored`;
   `case_sensitive_dot_GIT_is_not_ignored`;
   `component_rule_matches_at_any_depth_prefix_rule_is_anchored`
   (`node_modules` anywhere; `build/artifacts` but not `src/build/artifacts`);
   `comments_blank_lines_and_trailing_ws_are_ignored_lines`;
   `a_pattern_with_dotdot_is_rejected_at_parse`;
   `empty_config_still_ignores_git`. Rests on P3.

2. **`crates/hydration-client/src/store.rs`** — load the `IgnoreSet` per scan (beside
   lineage, `store.rs:129`); do not descend an ignored dir in `scan` (`:185`) so ignored
   paths never enter the index or fingerprint (`:237`).
   *Tests:* `scan_skips_ignored_subtrees` (a `.git/` file gets no `FileId`→path entry);
   `git_churn_does_not_move_the_tree_fingerprint` (touch `.git/index`, fingerprint
   unchanged). Rests on P3.

3. **`crates/hydration-client/src/delta.rs`** — add `ignored: usize` to `Applied` (`:286`);
   `if is_ignored(rel) { out.ignored += 1; continue; }` at the top of the change loop
   (`:453`), before the `match`; leave `safe_join` (`:989`) unchanged; add the resolved-path
   `is_ignored(&entry.path)` guard in the Removed/FolderRemoved arms (`:726`). Thread
   `&IgnoreSet` into `apply`/`apply_remembering` (`:354/:369`).
   *Tests (each must fail against current code):*
   `an_ignored_upsert_creates_no_placeholder` (Upserted at ignored path, no local file →
   nothing on disk, `ignored == 1`);
   `an_ignored_upsert_never_overwrites_a_real_file` (the P1(b) state → `mat.place` never
   called, file byte-for-byte intact, `st_ino` unchanged);
   `an_ignored_remote_delete_never_removes_the_real_file` (Removed resolving to an ignored
   path → `mat.remove` not called);
   `an_ignored_change_is_not_a_failure` (`out.failed` empty, fingerprint memo records the
   no-op). Rests on P1.

4. **`crates/hydration-client/src/upload.rs`** — add `Outcome::Ignored` (`:222`); in
   `run_upload`, after `store.lookup` resolves `entry.path` (`:414-419`), return before
   `sink.upload` when `is_ignored(rel)`.
   *Tests:* `run_upload_of_an_ignored_path_touches_no_sink` (a fake `Sink` records zero
   calls; outcome `Ignored`); `an_ignored_touched_file_leaves_pending_before_any_attempt`
   (no `failed()`, no backoff, no Graph collision). Mirror `tests/upload_rules.rs`.

5. **`crates/hydration-client/src/daemon_loop.rs`** — add `pub ignore: IgnoreSet` to `Config`
   (`:67`), loaded once per pass from `.hydration-ignore`; thread it to the walkers; add
   `is_ignored` beside the existing `is_internal` skips in `dirty_files` (`:270`),
   `unidentified_folders` (skip the subtree, `:1885`), `apply_renames` (`:2038`),
   `apply_removals` (`:2097`), `apply_folder_removals` (`:2173`), `apply_folder_creates`
   (`:1906`); and **`journal.retain(!is_ignored)`** in `detect_offline_removals` (`:1761`).
   *Tests (each must fail against current code):*
   `enabling_ignore_withdraws_nothing_offline` — seed a lineage/manifest with `.git/` cloud
   ids, enable ignore, assert `detect_offline_removals` returns **zero** candidates (**the
   highest-risk test** — get this wrong and the switch mass-deletes);
   `deleting_an_ignored_dir_withdraws_no_cloud_object` (`apply_removals` skips `g.path`);
   `unidentified_folders_does_not_descend_git` (the folder-create leak is closed);
   `config_default_ignores_only_git` (empty `.hydration-ignore`). Rests on P2.

6. **`crates/hydration-client/src/reclaim.rs`** — add `is_ignored` to `collect_residents`
   (`:390`) and the manual `reclaim(rel)` entry.
   *Test:* `an_ignored_never_uploaded_file_is_never_an_eviction_candidate` — pin the invariant
   that an ignored real file cannot become a placeholder (asserted today via the no-cloud-id
   gate `:414-419`; the explicit skip makes it a rule). A conformance-level assertion belongs
   under `conformance/`.

7. **`crates/hydration-client/src/manifest.rs`** — `is_ignored` skip in `build` (`:79`), for
   consistency; already benign. *Test:* `manifest_never_lists_an_ignored_path`.

8. **`DESIGN.md`** — a new numbered section beside §6e (`is_internal`): the sync-ignore
   predicate, the component-vs-basename distinction, the `.git` default, the
   `.hydration-ignore` format, the per-device (not-synced) rationale, the SYNC-only /
   never-hydration boundary, and the prospective (leave-the-cloud-copies) transition stance,
   plus P1/P2/P3's measurements. (Read-only in this task; not modified.)

9. **NOT `crates/hydrationd/*`** — intentionally untouched. The privileged helper never sees
   the ignore set; hydration is not gated by ignore (§3.4).

### Product — `/home/frank/Projects/OneDriveHydration`

1. **Docs only for v1.** Document the `.git` hard default and the `.hydration-ignore`
   location. **No selective-sync UI** in `onedrive-daemon` (main.rs / ctl / tray). If a
   surface is wanted later it is a settable control-socket verb persisted by the daemon (the
   pattern auto-eviction uses), never a tray-written config file the daemon also reads.

---

## 7. Open risks, and what a probe must measure before code

- **Pre-existing state is the whole risk (P1, P2).** The safety-by-construction argument
  holds only from a clean start. Existing `.git/` placeholders must keep hydrating (§3.4,
  risk 1); existing `.git/` lineage/manifest entries must not be withdrawn on the switch
  (§4.1). Rollout needs the census (P2) first, and — if P2 finds materialised `.git/`
  placeholders — a one-time reconciliation (hydrate-to-real, or leave marked-and-hydratable)
  *before* the ignore takes effect. The two choke points do not solve this.
- **Delta over a real file is unmeasured (P1).** The `Clean`-but-diverged fall-through to
  `place()` (`delta.rs:716`) is the sharpest pre-existing hazard; §3.1 closes it only if the
  skip precedes the ladder, which P1 must confirm on a real mount.
- **§6a-ter.** The changes only *add* early `continue`s and *prune* walks — they remove
  operations rather than add writes on the event-answering path — so deadlock risk is low.
  But `removals::add_tree` touches inotify and its overflow handling (`removals.rs`), and the
  `.hydration-ignore` read must stay read-only (a framework write to it inside the marked
  mount is the trap). Verify against the §6a-ter list before shipping the watcher change.
- **Removals watcher pruning changes event volume, not just cosmetics.** Confirm on the live
  rig that not watching `.git/` does not lose a legitimate deletion of a *tracked sibling*.
  It should not — tracked files are never inside `.git/` — but it is a measured check, not an
  argued one.
- **Predicate cost.** `is_ignored` runs per-change in delta and per-file in the walks; a
  component scan is `O(path length)`. Negligible in argument, but measure it on the
  167,890-file tree, not assume it (repo law).
- **Pin/ignore interaction.** A user could pin a file under `.git/`; ignore should take
  precedence (never sync), making the pin on an ignored path meaningless. Low stakes; make it
  an explicit decision rather than an accident.
- **Concurrent daemons / shared machine.** Any endurance run must isolate — `smoke.sh` pkills
  every `hydrationd`, `/mnt/scratch` is shared (MEMORY) — or contention reads as an ignore
  bug.

---

# Critique of the above

**(a) Claims argued rather than measured.**

- **The whole "safe today" story rests on P1, which is unrun.** The document asserts the
  fresh-rewrite case hits `NeverUploaded` (`delta.rs:691`) and the uploaded-once-diverged case
  falls through to `place()` (`:716`). Both are read from the guard ladder, not measured; a
  ladder is exactly the kind of ordered branch whose behaviour on a real inode with real
  xattrs has surprised this codebase before. Until P1 runs on a real mount, "the ignore closes
  a data-loss path" names a hazard it has not demonstrated exists in the state it claims.
- **The 1,296 number is the old client's, and P2 is what makes it current.** The census is
  described as read-only groundwork, but the document then reasons about "the first start after
  the switch withdraws all 1,296" as though the manifest/lineage split were known. It is not
  until P2 runs: how many of those paths are in the lineage half (real files, withdrawable),
  how many in the manifest half (placeholders, the serve-zeros risk), and how many kept their
  xattr at all is unmeasured. The offline-withdrawal test in §6 seeds a *synthetic* journal,
  which proves the retain-filter works but not that it covers the live shape.
- **Predicate cost is dismissed as "negligible" without a number**, the same move
  `KEEP-ON-DEVICE-GROUNDWORK.md` was criticised for on the ancestor walk. Per-change in a pass
  that already runs on a 167,890-file tree every few seconds, an unmeasured `O(path length)`
  per change is a real multiplier the reviewer should see measured, not asserted.

**(b) Structural gaps the edit list does not close.**

- **Nothing type-enforces "one predicate, every site."** §3 lists ~10 call sites that must each
  consult `is_ignored`; the document leans on the same shared-crate argument `is_internal` uses,
  but `is_internal` has 11 callers that drifted into existence one at a time, and the ignore
  adds a *second* per-site obligation with no compiler check that a future walk honours it. A
  walk added later that skips the predicate leaks in exactly one direction — the failure mode
  hardest to notice.
- **The scan-exclusion and the delta-skip are two guarantees of the same fact, and their
  interaction is unstated.** §3.3 excludes ignored paths from the index so `by_cloud_id` never
  holds them; §3.1 skips in delta anyway. Belt-and-braces is correct, but the document does not
  say what happens to `Lineage::absorb` when the scan set shrinks — whether dropping ignored
  paths from the live set can evict a still-wanted record for a *non-ignored* path as a side
  effect. That is the kind of coupling that turns a safe-looking prune into a regression.
- **"Leave the cloud copies" is a stance, not a mechanism.** The document refuses auto-cleanup
  and calls the stale copies "harmless and non-looping," which is true once *both* directions
  skip them — but it does not prove the stale cloud `.git/` objects never re-present as
  `Change::Upserted` in a way that some *other* (non-ignored) reconciliation acts on. The
  fingerprint no-op skip covers the identical-batch case; a provider that reorders or re-etags
  the stale objects is not obviously covered, and no test constructs it.

**(c) Smaller drift.**

- **`Applied.ignored` is a count with no consumer specified.** The document adds it to keep the
  skip out of `failed`, which is right, but does not say whether the daemon surfaces it (an
  "ignored N" in the status line) or drops it. An unconsumed count tends to become a lie the
  first time someone reads it expecting it to mean something.
- **The `.hydration-ignore` per-pass reload is a cost the document waves at.** "Parsed once per
  pass" is cheap for one small file, but the reload cadence relative to the delta pass, and
  what a *mid-pass* edit to the file does (rules changing under a running pass), is
  unspecified — the same shape as the lineage-reload-per-scan the code already does, but not
  stated to follow it.
- **v1 draws the `.git`-only line, and a `.hydration-ignore` that ships tends to grow.** The
  document ships component + anchored-prefix rules and defers globs, which is the right minimum
  — but the moment the file exists, users will put `*.log` and `!keep/` in it, and a parser
  that silently ignores an unrecognised glob line is its own quiet failure. Whether an
  unparseable line is rejected loudly or skipped is left unsaid, and "skipped" is the wrong
  default for a file whose whole job is to stop syncing the right things.

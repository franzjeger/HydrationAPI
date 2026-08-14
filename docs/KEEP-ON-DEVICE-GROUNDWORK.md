# Groundwork: Keep on Device — the `hydrate` verb and the pin xattr

Design only. No `pin`/`hydrate` code exists in either repo (grepped: "pinned" appears
only as English prose; the `hydrate` symbols under `crates/hydrationd/tests` are the
privileged fill primitive, not a verb). This document is what the code will be written
from, and the test lists in §5 are meant to be written *first* and to fail against the
current trees.

It follows the house style of `docs/GRAPH-GROUNDWORK.md`: every claim is cited to
`file:line` because the repo law is measured-not-recalled, the obvious-but-wrong
alternative is named at each fork, and the critique at the end is kept including what it
says about this document's own weaknesses.

---

## What this establishes before any code is written

Three things the five-investigator pass pinned down, each of which changes the shape of
the feature:

- **The product "Free Up Space" path never punches a hole and never touches the
  privileged helper.** It is `reclaim::reclaim` (`hydration-client/src/reclaim.rs:81`),
  which evicts by *inode replacement* on an anonymous `O_TMPFILE` inode
  (`reclaim.rs:194-195`) entirely in the unprivileged daemon — "the privileged half is
  not involved" (`reclaim.rs:1-14`). `hydrationd`'s `fallocate(PUNCH_HOLE)` in
  `evict.rs`, with its §6a-ter deadlock note, is a *separate* implementation used only by
  a caller that already holds the fanotify group (the conformance adapter). So the one
  place a pin must be honored is `reclaim::reclaim`, and no `hydrationd` change is
  needed.
- **One read does not fully hydrate.** The DEHYDRATED mark is cleared only when every
  byte is present — `if have.covers(Span::whole(size)) { finish_hydration }`
  (`daemon.rs:1214-1227`); a partial fill calls `settle_range`, which keeps the mark
  (`placeholder.rs:485-498`). A `read()` demands only its range (§8d); `count` is a
  demand, not a hint (`DESIGN.md:1669`). Therefore "hydrate" is *read the whole file to
  EOF*, not "touch it once."
- **No auto-eviction policy exists yet in either repo** (grepped lru/quota/statvfs/
  watermark/atime — the only `least_recently_used` hit is an in-memory FILL table,
  `partial.rs`). "Honored by a future policy" is a forward reference; only the
  manual-evict skip and the xattr storage are actionable now. The design below makes the
  one place that both the manual path and any future policy must pass through carry the
  check, so the future policy inherits it for free.

---

## 1. The pin xattr

### 1.1 Name and value semantics

```rust
// hydration-protocol/src/lib.rs, in `pub mod xattr`, beside DEHYDRATED (lib.rs:168)
/// Set while the user wants this file (or everything under this directory) kept
/// hydrated: skipped by manual eviction, and — when one exists — by the
/// auto-eviction policy.
///
/// Presence-only, exactly like DEHYDRATED. The value is `b"1"` by convention so a
/// `getfattr` at 2am is legible; every reader tests *presence* and ignores the
/// value.
///
/// Forging this is benign, and that is load-bearing. Every `user.*` xattr is
/// writable by any same-uid process (see the removed "under construction" note,
/// lib.rs:175-183). A forged pin can only make the framework KEEP more content or
/// decline an eviction — never make a placeholder serve zeros, never destroy data.
/// That is the safe direction, the same argument the stamp documents
/// (lib.rs:203-208). Do not "harden" this into something that fails closed: a pin
/// that failed closed would evict the data it exists to protect.
pub const PINNED: &str = "user.hydration.pinned";
```

The name `user.hydration.pinned` is free (grep of both repos found no `pin`/`pinned`
xattr or verb). It lives in `pub mod xattr` and not in either half because it is shared
vocabulary — the client writes it, the eviction ladder reads it — and "duplicating the
string in two crates is how they drift" (`lib.rs:157-160`).

**Rejected: a `"1"`/`"0"` value scheme.** It invents a third state (present-and-`"0"`)
that every reader would have to interpret, when the whole codebase already tests
presence: `mark_dehydrated(_, false)` is a `removexattr` that treats `ENODATA` as success
(`placeholder.rs:568`; `store::remove_xattr`, `store.rs:461-472`), and every reader
(`has_mark`, `is_dehydrated`) returns true on `rc >= 0` regardless of contents. Pin =
`setxattr "1"`; unpin = `removexattr` (`ENODATA` = already-unpinned = success).

### 1.2 Who writes it — the unprivileged client only

The writer is the unprivileged client, never `hydrationd`. §6b forbids handing the
privileged side a destination-by-path (`DESIGN.md:1314` — "the privileged side never
accepts a destination"); a pin request names a path, so it must not reach `hydrationd`,
and a pin needs no privilege — it is the user's own file, settable by `setfattr`.

It is routed through the daemon's control socket as new verbs `pin <path>` / `unpin
<path>` in `control()` (`daemon_loop.rs:541-601`, beside `evict` at 542), for the same
reason `evict` lives there (`daemon_loop.rs:490-494`): one place decides what an untrusted
path means (`delta::safe_join` + `canonicalize`, reused from `reclaim.rs:98-123`), and the
writer is co-located with the future auto-eviction policy that reads the mark.

**Read-only files.** A pinned file can be `0444` — a read-only cloud file, or a git pack
(`store.rs:388-392` measured this on a live account on 2026-08-13). The kernel gates
`user.*` on *inode* write permission, so a bare `setxattr` returns `EACCES` on those. The
write must therefore go through `write_xattr_even_if_read_only` (`store.rs:397-412`),
which `chmod|0o200` → `setxattr` → restores the original mode on both the success and the
failure path. Promote that fn to `pub`, or expose thin `store::set_pinned` /
`clear_pinned` / `is_pinned` wrappers over it + `remove_xattr` (461) + `get_xattr` (414).
No new syscall code — the read-only-defeating path already exists.

**No §6a-ter hazard.** Writing an xattr is a metadata op that touches no content, so it
fires no `FAN_PRE_ACCESS`/`FAN_PRE_MODIFY` — grounded, not reasoned in a vacuum: the same
fact is why the nodump flag is set *inside* `evict()`, in the very process that answers
events (`DESIGN.md:1263`). Doubly safe here: the client daemon is not the event-answerer
at all (only `hydrationd` is), so even the `chmod` inside `write_xattr_even_if_read_only`
cannot be the self-deadlock.

### 1.3 Directories

Set `user.hydration.pinned` on the directory inode directly. Storage is proven on the
whole matrix: the delta pass sets `user.hydration.id`/`user.hydration.etag` on directory
inodes in production (`delta.rs` `FolderUpserted`, read-back check included), and probe P1
(§6) has now measured `setfattr user.hydration.pinned` on both a directory and a file
reading back on **btrfs, ext4-with-a-128-byte-inode, and xfs** (tmpfs confirmed earlier) —
so directory pin storage needs no new mechanism on any supported filesystem.

`pin <path>` and `unpin <path>` must accept a directory. `reclaim::reclaim` rejects
non-files (`reclaim.rs:104-108`), so the pin/unpin resolution needs a directory-capable
`safe_join` + `canonicalize` path that does **not** inherit that `is_file` gate.

Whether a folder pin protects the files under it is *policy for the reader*, not a storage
question — see §3.2.

### 1.4 The one evict-path check that honors it

Add one variant and one guard to `reclaim::reclaim`, the eviction *decision* module
(`reclaim.rs:29`):

```rust
// reclaim.rs, enum Refused (45-60)
/// The user asked to keep this on device — directly, or via a pinned ancestor
/// directory. Refusing is the whole point of the pin.
Pinned { via: PathBuf },
```

The guard goes immediately after the AlreadyDehydrated check (`reclaim.rs:126`), before
`waiting`/`sending`, before the stamp read, and before `placer.place` (195):

```rust
// self, then every ancestor up to and including real_root
if let Some(via) = pinned_self_or_ancestor(path, &real_root)? {
    return Ok(Err(Refused::Pinned { via }));
}
```

This is the *only* enforcement point, and it is enough because both roads to eviction pass
through here: the manual path funnels `reclaim()` (`daemon_loop.rs:557`), and any future
auto-eviction policy must also call `reclaim()` — it is the only unprivileged code that
does the inode swap. A policy will read the same mark during its candidate walk to skip
pinned subtrees as an optimization, but the *authoritative* refusal stays inside
`reclaim()`.

**Rejected placement sites:** the Dolphin wrapper (a future policy bypasses it); the
`daemon_loop` `evict` arm (same); `TmpfilePlacer::place` (that is the shared placement
mechanism used for hydration and delta placeholder creation too — it must never refuse on
a pin).

The socket reply needs no new code: `daemon_loop.rs:559` already renders `kept: {why:?}`
verbatim, so a pinned file comes back as `kept: Pinned { via: "…" }`, and both the Dolphin
wrapper's default arm (`free-up-space.sh.in:99-111`) and the D-Bus `parse_evict_reply`
(`dbus.rs:314-328`, `Kept` case) surface it with zero change.

### 1.5 What manual "Free Up Space" does to a pinned file — REFUSE, do not clear-and-evict

**Decision: refuse with `kept: Pinned`, never silently un-pin and evict.** Three reasons,
all from the existing code:

1. `reclaim` is deliberately a set of refusals-that-surface-as-values (`reclaim.rs:43-45`),
   and the wrapper already quotes any non-`reclaimed` reply into a modal dialog
   (`free-up-space.sh.in:100-111`). `kept: Pinned` reaches the user with zero new
   machinery, saying exactly why.
2. The "Free Up Space" action appears on *every* file on the system — KIO cannot filter a
   servicemenu by path (`servicemenu.desktop.in:13`, `free-up-space.sh.in:67-69`, measured)
   — so it is trivially mis-clicked. Silently un-pinning as a side effect would defeat the
   pin's one job (surviving a sweep) the first time someone fat-fingers it.
3. It matches the house stance that a destructive step is an explicit decision, never a
   default (`evict.rs`: "No default, because there is no safe one … The caller has to have
   decided").

The genuine override stays cheap and explicit: `unpin` (a separate verb / "Un-pin" action)
removes the xattr, then `evict` — two deliberate acts, not one ambiguous one. The inverse
of "Keep on Device" is "Un-pin" (which does not evict), not "Free Up Space."

---

## 2. The `hydrate` verb

### 2.1 Who catches the event vs. who provides the bytes — the whole safety argument

A read of a placeholder fires `FAN_PRE_ACCESS`. That event is **caught and answered by the
privileged helper**'s worker (`daemon.rs:908` `decide_and_fill`), which writes bytes *in
through the event fd*, never by re-opening the path (`daemon.rs:1151-1165` spells out why).
The **bytes come from the unprivileged sync daemon**, which serves the helper's
`FetchRequest` on `run()`'s main thread — `for conn in listener.incoming() { … daemon.serve(&mut c) }`
(`daemon_loop.rs:1385`) — by fetching from the *cloud*, never from the mount. Control,
upload, and status run on *separate spawned threads* (`daemon_loop.rs:1281`, `1289`).

§6a-ter is: a write/read inside a marked mount, performed by the only process that could
answer the event it triggers (`DESIGN.md:735,1263`). The framework side is safe because the
answerer uses the event fd, never a path.

### 2.2 The deadlock-safe reader: a third-party process, not the daemon and not the helper

**Decision: the triggering read happens in the ctl-client / wrapper process — the same
short-lived, unprivileged process the user already runs — never inside the daemon and
never inside `hydrationd`.** Defined at the product layer, "hydrate" is: *open the file
`O_RDONLY` and read it sequentially from 0 to EOF.*

This is provably identical to a third-party `cat`, which is exactly the case §8d and §8e
already depend on:

- It is a different process from both the helper and the daemon. Its `read()` blocks; the
  helper answers by fetching from the daemon on the daemon's *own* threads; there is no
  shared state and no cycle.
- The existing "Free Up Space" wrapper is careful about this in reverse
  (`free-up-space.sh.in:60-64`: "on this mount a read is what hydrates a placeholder" — it
  refuses to open its argument). A hydrate wrapper is that same detached process doing the
  opposite on purpose.
- §8e is the precedent that a read of the mount *from the same daemon* is survivable only
  because the reading thread (upload) and the serving thread (main) are different and share
  no lock across the read (`DESIGN.md:1300`). Moving the read entirely out of the daemon
  removes even that constraint.

**This is the one thing code cannot prove on its own** — CLAUDE.md warns this deadlock
class has "appeared in eight distinct disguises." Probe P2 (§6) must measure it on a real
mount before the verb ships.

### 2.3 Whole file to EOF — and sequential, not `mmap`

Because the mark is cleared only at `have.covers(Span::whole(size))` (`daemon.rs:1214`),
the reader must reach EOF. Two ways, one right:

- **Sequential `read()` in ≥ `READAHEAD` (8 MiB, `daemon.rs:125`) blocks.** A read at
  offset 0, or one byte past a byte already present, is judged sequential
  (`daemon.rs:1139-1140`) and the worker widens the fetch by 8 MiB (`daemon.rs:1142-1146`).
  Cost is `size / 8 MiB` round trips, and each event is bounded, so there is **no per-file
  ceiling**. This is the recommendation.
- **`mmap(NULL, size)` of the whole object** would hydrate in one event held through the
  entire transfer, under the 10-minute per-event ceiling (§6a-bis) — dangerous for large
  files. **Rejected.**

Reading zero bytes fills nothing; a short read fills only its range. So "hydrate" is a
*strictly forward, large-block read to EOF*, never a read-modify-write (a partial-page
write into a placeholder blocks on a pre-content read event — `DESIGN.md:1657`).

### 2.4 Verb shape and reply discipline

The ctl client performs the read in its own process and reports, in the shape that lets the
wrapper reuse its existing verbatim-quoting arm:

- success: `hydrated <n> bytes`
- no-op (already resident): `hydrated 0 bytes`
- failure: `error: <reason>`

**`<n>` is a measured `st_blocks` delta** (`held_after - held_before`, mirroring
`reclaim.rs:175,201`), never the logical length and never the read `count`. §8d is explicit:
a short read still hydrates the whole object, so reporting `count` would make the reply lie
on partial-fill filesystems.

**Rejected: a daemon-mediated `hydrate` control verb.** It would re-import the read into a
process near the fetch-serving path, needing a lock-ordering audit (the queue `Mutex` is
shared with the serve thread via `QueueChanges::changed`, `daemon_loop.rs:100-108`; the
control accept loop has a 10 s read timeout a large hydrate would blow, `daemon_loop.rs:533`)
— and it buys nothing, because a read cannot destroy content, so the `safe_join` guarantee
that eviction genuinely needs (§6h) is not load-bearing for hydrate. No framework fill-path
or wire-format change is required: the helper already fully hydrates and clears the mark on
a whole-file read (`daemon.rs:1214-1227`, `placeholder.rs:454-470`).

### 2.5 How it reports completion and failure

The read *is* the synchronous wait. Each `read()` blocks until the helper has the range in
the event fd and answers `FAN_ALLOW`, or the transfer fails and the read returns `EIO`
(protocol `Abort` → helper `Failed` → deny). The verb returns:

- **success** when it reaches EOF with no read error. Confirm with metadata only, which
  fires no event (`DESIGN.md:1657`; `holds_data_fd` via `SEEK_DATA`, `placeholder.rs:378`):
  after EOF, `getfattr` that DEHYDRATED is absent. Reaching EOF cleanly is already
  sufficient (the last covered byte cleared the mark in `finish_hydration`,
  `daemon.rs:1214`); the `getfattr` is a cheap belt-and-suspenders that cannot re-trigger
  hydration.
- **failure** the moment any read returns `EIO`; report the errno/reason.

A useful side effect that comes for free from doing a *whole-file* read: `finish_hydration`
clears `nodump` (`placeholder.rs:462-463`). A file evicted with `Backup::Exclude` carries
`nodump`, which survives a write (`lib.rs:46-49`), so a kept file that was not read to EOF
would stay excluded from backups. Reading to EOF drives the normal fill path and clears it —
another reason the verb must not stop at a partial fill (`settle_range` does *not* clear
nodump, `placeholder.rs:485-487`).

---

## 3. Folder recursion

### 3.1 Where the tree walk lives — daemon enumerates, client reads

A "Keep on Device" on a folder is pin + hydrate over a subtree. The two halves split
differently:

- **Pin over a folder is one `setxattr` on the directory** (§1.3, §3.2). No walk.
- **Hydrate over a folder needs a walk, and the walk is split to honor the deadlock
  boundary:** *enumeration in the daemon, reads in the client.*

The enumeration — "which regular, dehydrated, non-internal files exist under this confined
subtree" — is a content-free operation (`Store::scan` "reads no content, so it never
hydrates anything", `store.rs`), and it carries the daemon's judgment: `safe_join` +
`canonicalize` confinement (`reclaim.rs:98-123`), and `names::is_internal` so the walk skips
the manifest/lineage/scratch files. The reads — the actual hydration — stay in the
third-party ctl process, one file at a time.

Concretely: a new content-free control verb (e.g. `pending <dir>`) returns the confined,
internal-name-skipped, dehydrated relative paths under a directory; the ctl client then runs
the §2 client-side read on each, sequentially. This is a Stage-2 refinement (§5); the
Stage-1 minimum is a wrapper `find -type f` under the already-confined absolute directory,
one client-side hydrate per file — honest but re-implementing `is_internal` in shell, which
is why the daemon enumeration is the endpoint.

**Rejected: the daemon performs the reads itself over the subtree.** That puts every read on
a daemon thread — the ninth disguise of §6a-ter — recoverable only with the fragile
spawned-thread-holding-no-lock discipline, for no benefit over the client-side read.
**Rejected: fan-out.** There is one helper→daemon fetch connection, one outstanding request
(`daemon_loop.rs:1385` serves one connection; §6a-bis). A folder hydrate must proceed one
file at a time; parallel whole-file reads would serialize on that connection anyway and
starve every other reader on the mount (a degradation, not a lockup — but avoidable).

### 3.2 Directory-pin inheritance — ancestor-walk at read time, not stamped children

**Decision: a file is pinned if it OR any ancestor directory up to (and including) the sync
root carries `user.hydration.pinned`. The pin is stored only where the user set it; the
inheritance is derived by an ancestor-walk in the reader (`reclaim.rs`, and the future
policy), never by copying the xattr onto every child.**

Linux does not propagate `user.*` to children, so "files created later under a pinned folder
are pinned too" is not free either way — the question is where the enforcement lives.
Ancestor-walk wins:

- It matches the house rule "a property of the file rather than a claim about it"
  (`lib.rs:183,203-208`): a pinned ancestor is structural and always re-derivable.
- Stamping children is a *claim that drifts* — a file moved *in* would not have the bit; a
  file moved *out* would wrongly keep it — and it would force every creation path (delta
  materialise, local create, rename-in) to remember, and it races the delta pass that
  already writes folder xattrs (`delta.rs`).
- A pinned directory then correctly protects files that arrive *later* via delta, with zero
  new code on the materialise path.

Cost: up to `depth` `getxattr` calls per eviction candidate — trivial, and eviction is rare.
The refusal names the pinning ancestor (`Refused::Pinned { via }`) so the reply is
`kept: Pinned { via: "Projects/keep-me" }`, which is intelligible.

Consequence for the UI: a child pinned only through an ancestor has no xattr of its own, so
"un-pin this file" has nothing local to remove. Un-pin must target where the xattr actually
lives, or the UI must say the pin is inherited (§6, open risks).

### 3.3 The servicemenu surface

Unlike "Free Up Space", "Keep on Device" should appear on directories, which needs
`MimeType=all/allfiles;inode/directory;` — `all/allfiles` alone was *measured not to match
directories* (`servicemenu.desktop.in:3-12`). **Whether `inode/directory` reaches
directories on this KIO build, and how it behaves on a mixed file+directory selection, is
UNMEASURED — probe P4 (§6) must re-run `probes/servicemenu-match.cpp` before the entry is
claimed to appear where intended.**

Ship it as a **second static entry, not a stateful toggle**: a servicemenu `.desktop`
cannot read per-item pin state to relabel itself (MimeType is the only condition —
measured), so a pin/unpin toggle is impossible at that layer. Two entries ("Keep on Device",
and optionally "Un-pin"); the daemon refuses the contradictory one. Name it "Keep on Device"
with no ellipsis, matching "Free Up Space"'s servicemenu form (`servicemenu.desktop.in`,
Dolphin has already chosen the target).

---

## 4. Claim-by-claim

| # | Claim to eliminate | Enforcement | Where |
|---|---|---|---|
| 1 | A pin is a privileged operation | **Design** — a pin needs no privilege and names a path, so §6b keeps it off `hydrationd` | client-only writer via `control()`; `crates/hydrationd/*` untouched |
| 2 | A pin can be set with a plain `setxattr` | **Runtime** — a pinned file may be `0444` | `write_xattr_even_if_read_only` (`store.rs:397`), mode restored both paths |
| 3 | Setting a pin fires a pre-content event / can deadlock | **Measured** — metadata op, no event; client is not the answerer | `DESIGN.md:1263`; probe P1 confirms no event on `setxattr` |
| 4 | A forged pin is dangerous | **Design** — pin only ever *keeps* content | doc-comment on `PINNED`, mirroring `lib.rs:203-208` |
| 5 | The pin must be checked in every eviction caller | **Structural** — one chokepoint both roads pass | `Refused::Pinned` in `reclaim::reclaim` (126→195) |
| 6 | Manual evict on a pinned file quietly un-pins | **Design** — refuse, surface `kept: Pinned` | §1.5; `free-up-space.sh.in:99-111` already quotes it |
| 7 | A directory pin needs a bit on every child | **Runtime** — ancestor-walk at read time | `pinned_self_or_ancestor` in `reclaim.rs` |
| 8 | Hydrate is a new framework/protocol verb | **Design** — a whole-file read already fully hydrates | no fill-path/wire change; `daemon.rs:1214`, `placeholder.rs:454` |
| 9 | The daemon should perform the hydrate read | **Deadlock** — the read is a third-party `cat` in the ctl process | §2.2; probe P2 measures it |
| 10 | One read hydrates the whole file | **Runtime** — mark clears only on `covers(whole)` | read to EOF, sequential ≥8 MiB (`daemon.rs:1139-1146,1214`) |
| 11 | Bytes hydrated == read `count` | **Measured** — §8d; report an `st_blocks` delta | `hydrated <n> bytes`, `n` from `blocks()*512` (`reclaim.rs:175,201`) |
| 12 | A folder hydrate may fan out / the daemon may read the subtree | **Deadlock + resource** — enumerate in daemon, read in client, one at a time | §3.1; one fetch connection (`daemon_loop.rs:1385`, §6a-bis) |
| 13 | A servicemenu can toggle pin/unpin per item | **Measured** — MimeType is the only condition | two static entries; re-probe `inode/directory` (P4) |

---

## 5. The edit list, smallest-first

Groundwork before tests: the probes in §6 come **first**. Nothing below should be asserted
by a test until the measurement it rests on exists.

### Framework — `/home/frank/Projects/HydrationAPI`

1. **`crates/hydration-protocol/src/lib.rs`** — add `pub const PINNED` in `pub mod xattr`
   after DEHYDRATED (`lib.rs:168`), with the presence-only + benign-forgery doc-comment
   (§1.1). No behavior test; the behavior lives in `reclaim`.

2. **`crates/hydration-client/src/store.rs`** — re-export `PINNED as XATTR_PINNED` (beside
   `store.rs:27-29`); make `write_xattr_even_if_read_only` (`store.rs:397`) `pub`, or add
   `pub fn set_pinned/clear_pinned/is_pinned` wrappers over it + `remove_xattr` (461) +
   `get_xattr` (414).
   *Tests must assert:* `pinning_a_read_only_placeholder_succeeds_and_restores_mode` — pin a
   `0444` file, PINNED present, mode back to `0444` (fails now: bare `setxattr` returns
   `EACCES`). `unpin_of_an_unpinned_file_is_ok` — `removexattr` `ENODATA` = success
   (mirrors `store.rs:468`).

3. **`crates/hydration-client/src/reclaim.rs`** — add `Refused::Pinned { via: PathBuf }`
   (enum 45-60) and the `pinned_self_or_ancestor` guard after the DEHYDRATED check
   (`reclaim.rs:126`), walking `path`'s parents up to and including `real_root`.
   *Tests must assert (each must fail against current code):*
   - `a_pinned_file_is_never_evicted` → `Err(Pinned{via: file})`, content intact.
   - `a_file_under_a_pinned_directory_is_never_evicted` → `Err(Pinned{via: dir})`, **with the
     child carrying no xattr of its own, and created *after* the pin** (the
     adversarial-order construction — a stamping design would miss it; this is the test that
     distinguishes ancestor-walk from stamping).
   - `the_pin_check_runs_before_placement` — the inode is unchanged (`st_ino` equal
     before/after), proving the refusal precedes `placer.place` (195), not after.
   - positive control `an_unpinned_file_in_an_unpinned_tree_is_still_evicted` — the guard is
     not blanket.
   - `unpinning_makes_a_file_eligible_again_but_does_not_itself_evict`.

4. **`crates/hydration-client/src/daemon_loop.rs`** — add `pin <path>` / `unpin <path>` to
   `control()`'s match (541-601), reusing a *directory-capable* `safe_join` + `canonicalize`
   resolution (must not inherit `reclaim`'s `is_file` gate at 104-108), writing via the
   read-only-safe pin writer. Update the verb doc-comment (496-510), stating that pin/unpin
   are pure `setxattr`/`removexattr`, fire no pre-content event, and must never trigger a
   read.
   *Tests must assert:* `pin_then_unpin_round_trips_over_the_socket`; `pin_confines_like_evict`
   — feed `../escape`, `/etc/passwd`, `.hydration-manifest`, `\0weird` → refused (mirror
   `reclaim.rs:408-430`); `a_directory_can_be_pinned` over the socket.

5. **(Stage 2) `crates/hydration-client/src/daemon_loop.rs` + a small module** — a
   content-free `pending <dir>` enumeration verb returning confined, `is_internal`-skipped,
   dehydrated regular-file relative paths under a directory (a `Store::scan`-scoped walk).
   *Tests must assert:* `enumeration_lists_only_dehydrated_regular_files_and_skips_internal_names`;
   `enumeration_confines_to_the_subtree` (a `..`/symlink cannot list outside).

6. **`DESIGN.md`, near §6h (~1314)** — documentation only: the symmetric fact that hydrate is
   a client-side full read and must never be issued from the daemon's fetch-serving thread.

7. **NOT `crates/hydrationd/*`** — intentionally untouched (§6b; the fill path already
   fully hydrates and clears the mark on a whole-file read).

### Product — `/home/frank/Projects/OneDriveHydration`

1. **`crates/onedrive-daemon/src/bin/onedrive-hydrationctl.rs`** — add `pin <path>` /
   `unpin <path>` to `usage()` (6-12) and the positional match (25-29), forwarding the line
   unchanged like `evict`, keeping the exit-code rule (50-52). Add `hydrate <path>` which
   **does not forward** — it resolves the sync root (substitute `@MOUNT@` at install like the
   wrapper, or add a one-line framework `root` verb answering `config.mount`), confines the
   path, opens `O_RDONLY`, reads sequentially to EOF in `READAHEAD`-sized blocks, prints
   `hydrated <n> bytes` (measured `st_blocks` delta) or `error: <reason>` on `EIO`, and
   `getfattr`-verifies DEHYDRATED is gone.
   *Tests must assert:* `pin_unpin_forward_verbatim` (mirror the existing evict-with-spaces
   forwarding test); `hydrate_reads_in_process_not_as_a_forwarded_line` — the crux test: the
   binary opens the file itself and sends **no** `hydrate` line to the daemon.

2. **`packaging/dolphin/keep-on-device.sh.in`** (NEW) — mirror `free-up-space.sh.in`:
   path-only `readlink -f` for the wrapper's own resolution, the same `$MOUNT` / `$MOUNT/*` /
   outside-mount confinement (59-86), then per-`%F` `"$CTL" pin "$rel"` and, for a
   placeholder, `"$CTL" hydrate "$rel"`; verbatim quoting of any `kept:`/`error:` reply
   (89-112); one file/dir at a time, no fan-out; a streaming acknowledgement rather than a
   byte total for a large subtree.
   *Test must assert:* extend the existing "no reader command in command position" test — the
   *wrapper* must not `cat`/`head`/`file` its argument (the deliberate read is inside the ctl
   binary, not the shell that also does path math).

3. **`packaging/dolphin/servicemenu.desktop.in`** — add `[Desktop Action
   onedriveHydrationKeepOnDevice]`, `Actions+=…KeepOnDevice`, `Name=Keep on Device` (no
   ellipsis), `Exec=@ACTION2@ %F`, `MimeType=all/allfiles;inode/directory;` — **after** P4.

4. **`packaging/dolphin/install-servicemenu.sh`** — substitute/install the new wrapper
   (`@ACTION2@`), same style.

5. **`packaging/dolphin/README.md:80-82`** — update the "A folder action / deliberately not
   here" note: "Keep on Device" is precisely the folder action, now justified because the
   daemon does the content-free walk with its judgment and the reads are client-side.

6. **(optional) `crates/onedrive-daemon/src/dbus.rs`** — `Pin`/`Hydrate` methods mirroring
   `evict` (475) and reply parsers mirroring `parse_evict_reply` (314) for the tray/plasmoid.
   Flagged, not required for the Dolphin path.

---

## 6. Groundwork: what a probe must measure before code

Ordered by how much rests on it.

- **P2 — the deadlock probe (the gate). DONE — measured on btrfs, ext4-128, and xfs.**
  On a *real mount, not tmpfs* (CLAUDE.md), a third-party process (neither daemon nor
  helper) opens a placeholder and reads it to EOF. Asserted: it completes (no §6a-ter
  hang), the bytes are correct (**not zeros — §8d's silent-zeros trap**), and DEHYDRATED is
  cleared. This is the ninth-disguise check for §6a-ter and it is not resolvable from code.
  It now lives in the maintained suite as
  `crates/hydrationd/tests/two_halves.rs::a_third_party_read_to_eof_clears_the_dehydrated_mark`,
  so CI re-runs it on all four filesystems on every push — not a one-off probe. Gate
  satisfied: §2/§3's hydrate path may proceed.
- **P3 — partial vs. whole read clears the mark.** Largely covered by `ranges.rs` (§8d-bis,
  resting on `probes/bigdemand.c`): a single-page read fills only its range and leaves the
  mark; a full read to EOF clears it (`finish_hydration`). P2 above measures the whole-file
  side directly. What remains genuinely un-asserted is the *`nodump`-cleared-only-on-whole*
  corollary — worth one explicit test when the verb lands.
- **P1 — `user.hydration.pinned` on a directory across the matrix. DONE.** `setfattr`/
  read-back on both a directory and a file now measured on **btrfs, ext4-128, and xfs**
  (tmpfs confirmed earlier) — reads back `1` on all. Directory `user.*` storage needs no new
  mechanism anywhere. (Still worth a one-line assertion that `setxattr` fires zero
  pre-content events when the pin verb is wired, so §1.2's no-deadlock claim is a test, not
  only a citation.)
- **P4 — servicemenu `inode/directory` matching on this KIO build.** Still open — a product
  packaging question, not a code gate. Re-run `probes/servicemenu-match.cpp` with
  `MimeType=all/allfiles;inode/directory;`: does the entry reach directories, does it survive
  a multi-file selection, what happens on a mixed file+directory selection. `all/allfiles`
  was measured; `inode/directory` has not been. Needed before the §3.3 servicemenu entry
  ships, not before the framework verbs.

## 7. What this deliberately does not do

- **No auto-eviction policy.** None exists (grepped). The pin is *stored* now and *enforced*
  only by the manual path (`reclaim()`); when a policy lands in the unprivileged daemon it
  inherits the `Refused::Pinned` guard by calling `reclaim()`, and reads the same ancestor-walk
  to skip pinned subtrees. Writing that policy is out of scope.
- **No `hydrationd` change.** The privileged side never takes a path (§6b) and the fill path
  already clears the mark on a whole-file read. Hydrate is a client-side read; adding a
  privileged verb would only re-import the read into the one process that must not do it.
- **No pin/hydrate coupling baked into the mark.** A pinned placeholder is a valid, expected
  state (pinned before first download, or a not-yet-downloaded child of a pinned dir). "Keep on
  Device" *sets the pin and then triggers a hydrate*; the pin does not imply the file is already
  resident, and the two verbs stay primitive so the product composes them (as the wrapper
  composes `readlink` + `evict`).
- **No manifest/§6d backup accounting for pinned files.** Whether the manifest should list
  pinned files distinctly is unexamined and left alone.
- **No cross-repo compile-time guarantee** that the product cannot add a second eviction entry
  point that bypasses `reclaim()`. Today it cannot (the product only forwards a line); that is a
  convention, not a type.

---

# Critique of the above

**(a) Claims still documented rather than enforced.**

- **The deadlock safety of §2.2 is prose until P2 runs.** "A third-party read is a `cat`" is a
  strong argument from the thread map (`daemon_loop.rs:1385` serve on main, control spawned at
  `1281`) plus the §8e precedent, but it is exactly the class CLAUDE.md says has fooled eight
  reviews. The document says "measure before ship," which is correct, but until then the whole
  hydrate feature rests on an unmeasured claim, and that should be uncomfortable.
- **`the_pin_check_runs_before_placement` asserts `st_ino` unchanged**, which a purely-refusing
  implementation passes even if the guard were accidentally placed *after* an early-return that
  never reaches `place()` for another reason. The honest version also asserts, on a *non-pinned*
  control run, that the ino *does* change — otherwise the test cannot distinguish "guard fired"
  from "placement never ran."
- **The ancestor-walk cost is dismissed as "trivial" without a number.** For a future policy
  walking the whole tree at scale it is `depth` `getxattr` per candidate on top of the walk that
  already visits every file; that is a real multiplier the eviction-policy author will feel, and
  "eviction is rare" is true of the manual path and unproven of a disk-pressure policy.

**(b) Input shapes the test list does not yet force.**

- **A pinned file the cloud deletes.** If a delta REMOVE arrives for a pinned file, the pin is
  metadata on a file that is going away. Removal should win and drop the pin with the file — this
  is not eviction, so `reclaim()` never sees it, and the delta/removals path must be checked to
  not treat a pin as a reason to keep a cloud-deleted file. No test here covers it.
- **Un-pin of an inherited pin.** §3.2 names the problem (no local xattr to remove) but the edit
  list has no test asserting what `unpin <child>` does when only an ancestor is pinned — no-op,
  error, or walk-up-and-refuse-with-guidance. Left unspecified is left to drift.
- **Hydrate racing eviction, and hydrate racing a delta update to the same file.** The design
  pairs pin+hydrate so a pin set *before* the read makes a concurrent evict skip it, but there is
  no test for hydrate landing while an upload of the same file is in flight, nor for a delta
  re-placeholdering a file mid-hydrate. A pure read tolerates both better than evict does, but
  "better" is not "measured."
- **A partial-fill filesystem in the `hydrated <n> bytes` reply.** P3 proves the mark behavior;
  no test yet asserts the *reported number* on a filesystem where `st_blocks` for a full file is
  not `len` rounded up (the §8z cases). The reply discipline is stated; its own test is missing.

**(c) Smaller drift.**

- `Refused::Pinned { via: PathBuf }` renders through `{why:?}` as a `Debug`-formatted `PathBuf`,
  which quotes and escapes — `kept: Pinned { via: "Projects/keep me" }`. The wrapper quotes it
  verbatim, so it is legible but not pretty, and the D-Bus `parse_evict_reply` `Kept` arm carries
  the whole `Debug` string into a UI. If the exact wording matters, it should be chosen here, not
  inherited from `derive(Debug)`.
- The Stage-1 shell `find` fallback for folder hydrate (§3.1) re-implements `is_internal` in
  shell, which is exactly the "inventing a bulk operation with none of the daemon's judgment"
  that `README.md:80-82` warns against. The document calls Stage-2 the endpoint but the edit list
  still lets Stage-1 ship, and a Stage-1 that ships tends to stay.

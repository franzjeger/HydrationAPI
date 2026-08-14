# Groundwork: Auto-eviction — dehydrating unpinned files under disk pressure

Design only. No auto-eviction code exists in either repo (grepped both: no
`statvfs`, `f_bavail`, `watermark`, `quota`, or `atime` anywhere under `crates/`;
DESIGN.md lists "Automatic eviction on disk pressure" as deliberately out of v1,
`DESIGN.md:1453`). This document is what that code will be written from; the test
lists in §6 are meant to be written *first* and to fail against the current trees.

It is the counterpart to Keep on Device, and it is written on top of it: the pin
(`user.hydration.pinned`), `reclaim::set_pin`, the `pending` enumeration, and the
`Refused::Pinned` guard all already landed (`reclaim.rs:61,142,237,262,298`;
`hydration-protocol/src/lib.rs:189`; `DESIGN.md:1331-1335`). Auto-eviction adds a
*selector* above the machinery those built, and no second eviction path.

It follows the house style of `docs/KEEP-ON-DEVICE-GROUNDWORK.md` and
`docs/GRAPH-GROUNDWORK.md`: every claim is cited to `file:line` because the repo
law is measured-not-recalled, the obvious-but-wrong alternative is named at each
fork, and the critique at the end is kept including what it says about this
document's own weaknesses.

---

## What this establishes before any code is written

Four things the five-investigator pass pinned down, each of which shapes the
feature:

- **`reclaim::reclaim` is the whole executor, already.** It is documented as "the
  one chokepoint both the manual path and any future auto-eviction policy pass
  through" (`reclaim.rs:134-141`; `DESIGN.md:1335`). It refuses every unsafe case
  as a *value*, not an error — `AlreadyDehydrated` (`reclaim.rs:130`), `Pinned`
  self-or-ancestor (`:142`), `UploadPending` from the waiting/sending snapshots
  (`:151`), `NotUploaded` (`:156`), `ChangedSinceUpload` unless the stamp reads
  `Clean` (`:167`), `NotEligible` for non-files and path escapes (`:108-127`). An
  auto policy that loops over `reclaim()` inherits **all** of these for free, and
  must not re-implement the swap. The selector is new; the executor is not.

- **§6a-ter is avoided by construction, and the same argument as manual evict.**
  Eviction is an anonymous-inode swap via `TmpfilePlacer`, "the privileged half is
  not involved" (`reclaim.rs:1-14,210-211`). The only fanotify-visible write is the
  `ftruncate` that sizes the *empty* anonymous inode, answered by `hydrationd` — a
  different process from the client — on the property that the inode is still empty
  (`place.rs`, "events during linkat: 0"). The auto driver runs in the unprivileged
  client, which is not the event answerer at all, so looping `reclaim()` per file
  is exactly as safe as the manual verb that ships today. **The policy must never
  route through `hydrationd/src/evict.rs`** — that path holds the fanotify group and
  carries the real §6a-ter deadlock; it exists only for the conformance adapter
  (`reclaim.rs:30-31`).

- **The mount is `noatime`, so LRU-by-atime is impossible — measured.** The
  installer composes the sync-root fstab line as `subvol={subvol},noatime,…`
  (`OneDriveHydration/crates/installer/src/probes.rs:538`), `findmnt` on the live
  `~/OneDrive` reports `rw,noatime,compress=zstd`, and reads were verified not to
  move atime. There is no read-recency signal on this mount at all — and the one
  place that could have supplied it is closed too (next point).

- **Re-reads of a resident file are invisible to the framework.** Once a file holds
  content, `finish_hydration` clears the mark and the worker installs an ignore mark
  — `self.group.ignore(p)` (`daemon.rs:1225`); a read already resident is ignored at
  `daemon.rs:963` — so every subsequent read fires **no** event (§2.4's zero-cost
  claim). The only access the framework can ever observe is the placeholder read
  that triggers the fill. This is not a gap to be closed: removing the ignore mark to
  see re-reads costs a cloud round trip on every read of every hydrated file forever,
  the exact trade §2.4 refuses.

Consequence: the ranking signal cannot be *last use*. The best obtainable signal is
*last acquisition* — when the framework last brought these bytes to the device — and
the honest limitation of that is stated plainly in §1 and never papered over.

---

## 1. The ranking signal, and its honest limit

**Decision: rank candidates oldest-first by a new `user.hydration.hydrated_at`
xattr holding `CLOCK_REALTIME` seconds, written fd-only at fill completion, with
`st_mtime` as the tiebreak and the fallback.**

### 1.1 What is available, and why each alternative loses

Signals readable with `stat`/`getxattr` during the walk the client already does,
none of which fire a pre-content event or hydrate anything:

- **`st_mtime`** — modification, never access. It is the whole change detector
  already (`stamp::of` is `<sec>.<nsec>:<size>`, `hydration-protocol/src/lib.rs:232`;
  §8z-bis). **Rejected as the primary key:** a large read-only file the user opens
  daily but never edits — a video, a VM image, a git pack — has an ancient mtime and
  would rank as a *top* eviction candidate. mtime answers "when was this written",
  which is the wrong question.
- **The stamp** (`user.hydration.stamp`) — its embedded mtime *is* the file mtime, so
  it adds nothing over `st_mtime` for ranking; it is a clean/dirty identity test, not
  a clock.
- **size** (`st_size` vs `st_blocks`) — says nothing about usefulness. **Rejected as a
  key** for the same reason it is kept in the *loop*: ranking by size-first frees space
  fastest but evicts precisely the big files the user most wants resident. Size meters,
  recency orders (§3).
- **A hydration timestamp** — does not exist today (grep of `user.hydration.*` returns
  `dehydrated/id/etag/mode/pinned/stamp` only). This is the missing signal, and the one
  that responds to access at all: it moves every time the file is fetched from the cloud,
  so a file the user actually pulls stays young, and a file fetched once long ago and not
  since is a genuine candidate.

### 1.2 Where it is recorded — the privileged helper, at the single fill-completion site

`hydrated_at` is written in `placeholder::finish_hydration`, immediately after the
existing `stamp::write_fd(fd)` (`placeholder.rs:468`), via `fsetxattr` on the *borrowed
event fd*:

```rust
// placeholder.rs, finish_hydration success arm, right after line 468
let _ = hydration_protocol::hydrated::write_fd(fd);   // best-effort, like the stamp
```

This is the **only** new write site, and the reasons it is correct are all already
proven at this exact call:

- It is the one place a placeholder becomes a full resident: `finish_hydration` is
  reached only under `have.covers(Span::whole(size))` (`daemon.rs:1214`). A partial fill
  takes `settle_range` (`placeholder.rs:488`) and stays a marked placeholder — **not** an
  eviction candidate — so `hydrated_at` must NOT be added there, nor to `abandon`
  (`:505`), nor to the fsync-failure branch (`:459`).
- It is a `user.*` metadata `fsetxattr`, so it fires **no** pre-content event and cannot
  deadlock. §6a-ter is about content, not metadata (`DESIGN.md:1263,1335`). The identical
  pattern is proven three ways here: the stamp is `fsetxattr`'d through this fd today
  (`:468`); `nodump` is cleared through it (`:463`); the dehydrated/pinned marks are
  presence-only setxattrs that fire nothing. Probe P2 (§6) measures the second attribute
  regardless — repo law is to measure before a test asserts.
- It is written through the event fd, never by re-opening the path — re-opening inside a
  marked mount is the §6a-ter trap `stamp::write_fd` already avoids (`lib.rs:256-259`).
- Like every other `user.*` xattr it is **not uploaded** (delta carries no xattrs), so it
  is correctly per-device — exactly right for a per-device disk-pressure policy.

The read side is unprivileged: the driver reads `hydrated_at` with `getxattr` during a walk
it already does (§3), no event, no hydration.

### 1.3 The fallback, and why it is a coarse tier and not "oldest"

Residents with no `hydrated_at` — files created locally then uploaded and never
dehydrated/rehydrated, and files hydrated before this feature shipped — rank by `st_mtime`.
**Do not treat "no `hydrated_at`" as automatically oldest:** that would preferentially
destroy the user's own authored content first. A file the framework has never had to fetch
is, on a disk-pressure axis, either the user's working file (mtime recent → keep) or long
cold (mtime old → fair game). So the fallback is `st_mtime`, ordered within the same
sequence, not a "sink everything unstamped to the front" rule.

### 1.4 The honest limitation — state it in the doc and the commit

`hydrated_at` is recency-of-**acquisition**, not recency-of-**use**. Because a resident file
carries the ignore mark and the mount is `noatime`, a file fetched a year ago and read every
day since is byte-for-byte indistinguishable from one fetched a year ago and never touched
(§What-this-establishes, point 4). The signal freezes at first full fetch. This is
unavoidable within the design.

Two things make the imperfect signal acceptable, and both must ship in the doc/commit:

1. Getting it wrong is a **bounded, self-correcting latency event, not data loss**. `reclaim`
   refuses `NotUploaded`/`ChangedSinceUpload`/`UploadPending`/`Pinned`, so a mis-evicted file
   simply re-hydrates on next access — one whole-object re-fetch (range hydration is out of v1,
   `DESIGN.md:1449`) — and rewrites its `hydrated_at`, which then shields it (§3, grace).
2. **Keep on Device is the escape hatch** for the file the heuristic keeps guessing wrong about
   (`reclaim.rs:142,237`). Same door, already built. The opt-in UI must make it discoverable.

The clock is `CLOCK_REALTIME` wall seconds — not monotonic (resets across reboot), not the file
mtime (the content's time, not the fetch time). Comparisons are cross-file recency, so a wall
clock that can step is acceptable: a mis-order costs one wrong eviction (latency), the safe
direction above.

---

## 2. The trigger, the default, and the config surface

### 2.1 Disk-pressure high/low watermark with hysteresis — the one design

**Trigger: two watermarks on free space, with hysteresis.** When free space falls below the
LOW mark, evict ranked candidates until free space rises above the HIGH mark, then stop. The
band is what stops thrash; a single threshold oscillates (evict one file, cross back, re-arm,
evict again). This matches OneDrive Files On-Demand and macOS "Optimize Storage".

Free space is one `libc::statvfs(config.mount)` per check: `free = f_bavail * f_frsize`
(`f_bavail` is the blocks available to a non-root user — the honest number). `libc` is already
a dependency of `hydration-client` (`Cargo.toml`), so no new crate. Greenfield: no `statvfs`
exists in either repo today.

**Rejected as the primary trigger — a footprint quota (cap held bytes at N).** Kept as a
documented *second mode* that shares the sweep loop with a different measurement, because it
cannot come from `statvfs`: a footprint cap must sum resident object sizes under the sync root,
which needs the walk (§3), and `statvfs` measures the whole filesystem (§2.2). Pressure ships
first because the physical device filling is the event the user actually feels.

**Rejected as a trigger — "older than N days".** That is a *ranking/filter* knob (the grace
floor, §3), never the thing that decides to run. A time rule that runs a sweep evicts on a clock
rather than on need.

### 2.2 Two honesties about the measurement, both requiring a probe (§6, P1)

- **`statvfs` measures the whole filesystem, not the subvolume.** On the live rig the `@onedrive`
  subvol shares one btrfs allocation pool with `@home`, so `f_bavail` falls because of unrelated
  data. For "free up space" that is arguably correct — the physical device is what fills — but it
  is surprising, and it is *why quota mode cannot read `statvfs`*. P1 must confirm what `f_bavail`
  reflects on this pool.
- **Compression skews the arithmetic, and — P1 measured — `f_bavail` is coarse and lags.** The mount
  is `compress=zstd`; `statvfs` reports raw allocated blocks and `reclaim` reports a measured
  `st_blocks*512` delta, not logical length (`reclaim.rs:191,217`). P1 (§6) then found `f_bavail` moves
  only in ~1 GiB steps and only after a transaction commit, never on the `unlink` itself. So the naive
  "re-measure `statvfs` after each swap and stop on it" **over-evicts**: `f_bavail` will not have moved
  yet, so the loop keeps going. The corrected rule from P1: **the summed measured `Reclaimed.bytes`
  drives the sweep** (block-accurate, immediate — never logical size, or a quota overshoots by one block
  per file on small-inode ext4: 390 MiB at 100k files, `DESIGN.md:1527-1533`), and **a post-commit
  `f_bavail` re-check arms the *trigger*** for the next sweep. `f_bavail` is the coarse gate between
  sweeps; `Reclaimed.bytes` is the fine meter within one.

### 2.3 Default OFF, opt-in

Ship the machinery **disabled**. Auto-destroying local availability is surprising, and every
shipping client gates it. This matches the house stance that a destructive step is an explicit
decision, never a default ("No default, because there is no safe one", `reclaim`'s ancestor
argument at `DESIGN.md`/`evict.rs`). Concretely: an *optional* eviction field on `Config`
(`daemon_loop.rs:66`), `None` preserving today's behaviour byte-for-byte, so the framework default
is off and the product turns it on.

### 2.4 Smallest config surface

Default thresholds when enabled: LOW = `free < min(10% of f_blocks, 10 GiB)`; HIGH = stop at
`free >= min(15%, 15 GiB)`. The `min(fraction, absolute)` is deliberate — 10% of a 4 TB pool is
400 GB (hoards); 10% of a 128 GB pool is 12 GB (too tight); `min()` behaves on both. Plus a
minimum inter-sweep interval and a per-sweep byte/count cap so one probe cannot dehydrate the
world.

Where the setting lives: a **control-socket verb the daemon persists to `--state-dir`**, not a
CLI flag and not a file the tray writes.

- The daemon is a long-lived systemd unit; a user cannot edit the unit to toggle a setting, and a
  flag cannot be changed from the tray.
- The control socket is already the owner-only (0600) in-daemon channel, and auto-eviction *must*
  coordinate with the queue the daemon owns — the same reason manual `evict` lives in the daemon
  (`daemon_loop.rs:552-572`).
- Exactly one writer (the daemon). The tray/D-Bus is a *caller* of the verb; a tray writing a
  config file the daemon also reads is a race.

Smallest verb set, added to `control()` (`daemon_loop.rs:551-642`) beside `evict`/`pin`:
`autoevict off` / `autoevict pressure <low%> <high%>` / `autoevict status`. The daemon writes the
chosen policy to a few-line file in `--state-dir`, loads it at startup into `Config`, and appends
one key `autoevict=off|pressure` to the `WatchState` line under its existing append-only contract
(`daemon_loop.rs:329-337` — "new keys may only ever be appended").

---

## 3. Candidate walk, reclaim interface, thrash, and the reader race

### 3.1 The walk, reusing the guards not re-deriving them

Under pressure (and only under pressure), enumerate resident, eligible files. The walk is a
`Store::scan`-shaped, content-free stat + xattr pass (measured 0.59s across 167,890 files,
`store.rs:110-113`) that emits, per hydrated file: `{ rel_path, st_blocks*512, hydrated_at or
mtime }`. Pre-filter to mirror `reclaim`'s cheap refusals so the walk does not propose files
`reclaim` will only refuse — skip files carrying `DEHYDRATED`; skip `pinned_self_or_ancestor`
(`reclaim.rs:237`, memoized per directory — §Critique); skip `Unstamped`/`Dirty`; skip no-cloud-id.
But `reclaim` stays the sole authority: the pre-filter is an optimization, never the enforcement.

The `pending` walk lists *dehydrated* files (`reclaim.rs:298`) — the exact opposite population — so
it is not reusable as an index, but its content-free shape is identical. No persistent index
initially: a rare, batched, sub-second walk does not justify an index kept coherent across
hydrate/evict/delta/upload and the new failure modes that brings. Revisit only if a probe shows
pressure rounds are frequent. Ideally the walk is folded into the delta pass's existing
`WALK_EVERY` scan rather than added as a fifth independent tree scan (`daemon_loop.rs:1298,1367` —
"one walk shared with the delta pass's" is already the noted right fix).

### 3.2 The loop: order pure, execute through `reclaim`

Keep the decision a **pure function** `plan(candidates, available, cfg, now) -> Vec<rel_path>` so
hysteresis, grace, and the `min(fraction, absolute)` arithmetic are unit-testable with no thread,
no disk, no sleep. `plan` sorts ascending by `hydrated_at` (else `mtime`), tie-broken by larger
`st_blocks` (reach the target in fewer swaps), drops anything inside the grace window, and returns
the ordered list.

The driver then loops `reclaim::reclaim(&mount, rel, &mut store, &waiting, &sending)` over that
list — reusing **one** scanned `Store` across the batch (reclaim only uses it to `forget` the
swapped inode) — summing `Reclaimed.bytes` as a lower-bound progress meter and re-measuring
`statvfs` to decide when to stop at the HIGH mark (§2.2). Stop the instant HIGH is reached, not
after draining the list; a second sweep at target must evict nothing (idempotence).

### 3.3 Thrash avoidance — two mechanisms, both free from the design

1. **Grace period T (min-residency).** Skip any candidate whose `hydrated_at` (or `mtime`
   fallback) is within the last T. This directly kills the evict→read→evict loop: a re-read runs
   `finish_hydration`, which rewrites `hydrated_at`, protecting the file for another T. Start with T
   on the order of hours; measure real re-access intervals before fixing it (§6). This is the only
   protection against dehydrating a file that is actively in use, because under `noatime` an in-use
   resident is indistinguishable from an abandoned one once past T.
2. **Hysteresis** (§2.1) plus a per-sweep cap to bound the re-hydration bandwidth if the user then
   reads the batch back.

A working set larger than the HIGH-mark headroom will evict-and-rehydrate forever; the driver must
detect "target unreachable" (everything left is pinned, unuploaded, or the live working set) and
**stop and log**, not spin.

### 3.4 The reader-vs-eviction race — already handled

`reclaim` replaces the inode; a reader holding the old file open keeps reading the content it opened
(old blocks freed on close), and a fresh open re-hydrates (`reclaim.rs:16-27`). No new code is
needed for re-hydration: an evicted placeholder's next read fires the event `hydrationd` already
answers. The delete-during-upload hazard (§5.5, `DESIGN.md:365`) is closed by the sending set —
replacing an in-flight file's inode would make the upload's post-send lookup delete the object it
just created (`upload.rs`) — which is exactly why `reclaim` refuses `UploadPending` (`:151`). The
auto driver **must** snapshot `waiting_set()`+`sending_set()` exactly as the `evict` verb does
(`daemon_loop.rs:561-564`) and must never hold the queue lock across the walk (`reclaim.rs:80-84`).

---

## 4. Where it runs, and how it is testable

### 4.1 A dedicated daemon thread, modelled on the status thread

Add a fifth spawned thread in `run()` beside the upload/delta/control/status threads
(`daemon_loop.rs:781,1066,1321,1339`), cloning `queue`, `stop`, `config.mount`, `delta_busy`, and
the eviction `Config` field. On the common path it does almost nothing: one `statvfs`. Only below
the LOW mark does it walk and evict — the same "cheap unless something is happening" discipline
`WALK_EVERY`/`POLL_EVERY` already follow, so it stays near-free on the 167,890-file live account and
expensive only under genuine pressure.

Gate the pass on `!delta_busy` (`daemon_loop.rs:719,920,1014,1183`), exactly as the upload thread
gates its structural writes, so eviction never fights a delta pass materialising placeholders over
the same tree. Take the queue snapshot the way `control()`'s `evict` arm does — lock only long
enough to copy the two sets, release, then loop `reclaim` — never the lock across the swap.

**Rejected — fold the sweep into the upload-driver thread.** It is tempting (running there makes
`waiting`/`sending` authoritative and serializes eviction against upload, closing even the snapshot
staleness window). But a 0.6s walk stalling the 200ms upload loop under pressure is a worse regression
than the residual race, which `reclaim`'s per-file stamp re-read already backstops (a local edit moves
mtime → `Dirty` → refused). Its own thread, gated and snapshotting, is the cleaner placement; the
snapshot-staleness residue is filed in §Critique.

### 4.2 Two injected collaborators, mirroring `SystemClock`/`TestClock`

The framework already proves the injection shape: `upload::Clock` with `SystemClock` and `TestClock`
(`upload.rs:41-75`). Mirror it twice, in a new `crates/hydration-client/src/evict_policy.rs`:

- **A read-only `FreeSpace` trait** — `available_bytes() -> io::Result<u64>` (and `total_bytes()` if
  thresholds are percentages). Real = `statvfs(mount)`; test = a `FakeDisk` wrapping an
  `Arc<Mutex<u64>>` with a `set(bytes)` beyond the trait. To make "disk fills → evict → disk recovers"
  deterministic, give `FakeDisk` a test-only `credit(bytes)` and have the loop feed each measured
  `Reclaimed.bytes` back to it; in production `statvfs` reflects freed blocks with no such call (and
  its *lag* is P1's other measurement).
- **A wall-clock `Clock`** — `now()` in `CLOCK_REALTIME` seconds, comparable to the persisted
  `hydrated_at`, driving the grace floor. This must be a **separate** trait from `upload::SystemClock`,
  because that one is `Instant::elapsed()` — monotonic from process start (`upload.rs:45-57`), not
  wall-clock and not durable across restart, so it cannot be compared against a persisted timestamp.

Keeping `plan()` a pure function of `(candidates, available, cfg, now)` means hysteresis, grace, and
the floor arithmetic are unit-testable with no thread, no disk, and no sleep — the whole reason those
two doubles exist.

---

## 5. Safety and UX

### 5.1 What the user sees

Auto-eviction changes local availability silently, so surface it as a passive aggregate state, never
a hazard. The wire is additively extensible — the tray's `apply_state_line` skips unknown keys
(`OneDriveHydration/.../dbus.rs`) — so add one key (an `autofreed` count and/or an "optimizing" flag)
and one low-precedence tray line, ranked **below** the correctness hazards (a mount exposing zeros,
sign-in), reusing the existing "cloud-only placeholder, re-downloads on first open" register. Space
management must never outrank a correctness warning.

No "undo" button is needed: opening re-hydrates, and Keep on Device makes it permanent. The honest
affordances are (i) the per-file placeholder overlay in the file manager so a now-slow-to-open file is
visibly cloud-only *before* the user opens it, and (ii) the pin as the durable opt-out.

### 5.2 Interaction with the pin

The pin is honored for free: the driver calls `reclaim`, and `reclaim` refuses `Pinned` self-or-ancestor
before the swap (`reclaim.rs:142`). A pinned file or subtree is never touched under any pressure. The
driver's candidate pre-filter also skips pinned subtrees, but that is an optimization; the authoritative
refusal stays inside `reclaim`.

### 5.3 The blast-radius guard

Invariants a test must assert (§6): a sweep never evicts below the LOW mark (bounded, no "evict all"); a
pinned file/subtree is never touched under maximum pressure; a `NotUploaded`/`ChangedSinceUpload`/
`UploadPending` file is never evicted (assert the policy does not bypass `reclaim`); a second sweep at
target evicts nothing; the sweep stops the instant the target is met; and — the structural one — the auto
path calls `reclaim::reclaim` only, **never** `hydrationd/src/evict.rs`. Nothing type-enforces that a
future entry point cannot bypass `reclaim`; that is convention, not a type (§Critique).

---

## 6. The edit list, smallest-first, and what each test must assert

**Groundwork before tests: the probes come first.** Nothing below is asserted by a test until the
measurement it rests on exists.

### Probes (measured, not recalled) — write these first

- **P1 — the free-space sensor on compressed, shared btrfs. DONE — read-only `statvfs` sample on the
  live `~/OneDrive` (2026-08-14). Three findings, and they change the loop.**
  1. **`statvfs` measures the whole pool, not the subvol.** `f_bavail` is byte-identical on `~/OneDrive`,
     `/home`, and `/` (3455.51 GiB free / 3811.45 GiB total; `df` agrees `/dev/nvme0n1p2` for all). So
     `@home` filling the disk triggers OneDrive eviction — arguably correct (the device is what fills), and
     the reason a footprint quota (§2.1) cannot come from `statvfs`.
  2. **`f_bavail` is coarse — ~1 GiB granularity.** A 300 MiB write did **not** move it at all (it fell
     inside an already-allocated data block group); a 5 GiB write moved it by exactly 5.00 GiB. So watermarks
     must be set in GiB, not MiB, and evicting one small file will not register.
  3. **Deletes reflect only after a transaction commit, not on `unlink`.** After deleting the 5 GiB file
     `f_bavail` did not move until a `sync`; the block freed then. Combined with (2), the loop must **not**
     chase `f_bavail` per file: evict a batch measured by summed `Reclaimed.bytes` (block-accurate and
     immediate), then re-check `f_bavail` after a commit (`sync`, or next tick) — the opposite emphasis to
     §2.2's first draft, which said "stop on the measured `statvfs` mark, never trust `Reclaimed.bytes`."
     The corrected rule: **`Reclaimed.bytes` drives the sweep, `f_bavail` (post-commit) arms the trigger.**
- **P2 — the fill-path timestamp fires no event. DONE (established, not newly probed).** `probes/nodump.c`
  is exactly the probe for "does setting a flag fire a pre-content event, and does it survive being written
  through the event fd" — and the answer for a `user.*` metadata write through the borrowed fd is zero
  events. The stamp already does `fsetxattr` through this fd in production (`hydration-protocol/src/lib.rs:269`,
  reached from `finish_hydration`) across the entire live endurance test with no deadlock, so a second
  `fsetxattr` beside it is the same proven operation. The implementation's own `hydrationd` fill-path tests
  (`two_halves`, `ranges`) re-confirm it: an extra event or a deadlock would hang them.
- **P3 — signal coverage. Candidate pool DONE (read-only walk, 2026-08-14); coverage + thrash are
  going-forward.** The walk over `~/OneDrive` (168,018 files in 0.5 s, matching `store.rs`'s 0.59 s) found
  **166,719 placeholders and 1,299 resident files (~1.55 GiB reclaimable)** — the account is already heavily
  dehydrated, so auto-eviction has little to reclaim *here*, though that is per-account. Only **4** of the
  1,299 residents lack a `user.hydration.id`, so the *no-cloud-id* fallback is negligible — but the true
  `hydrated_at`-vs-`mtime` split cannot be measured until `hydrated_at` exists (it is populated going
  forward), and the thrash/re-hydration-frequency count needs an endurance run per the MEMORY
  live-endurance methodology (record process start time, fresh per-cycle signals, functional over log
  proof). Both are deferred to after the xattr ships, not gates on it.

### Framework — `/home/frank/Projects/HydrationAPI`

1. **`crates/hydration-protocol/src/lib.rs`** — add `pub const HYDRATED_AT: &str =
   "user.hydration.hydrated_at";` in `pub mod xattr` beside `PINNED` (`:189`), with the same
   presence-plus-value, forge-benign doc (a forged value can only make the framework keep content longer or
   evict a clean, uploaded, unpinned file a re-read restores — never destroy data; do not fail closed). Add
   a sibling `pub mod hydrated` mirroring `mod stamp` (`:224`): `write_fd(fd)` doing `fsetxattr` of
   `CLOCK_REALTIME` seconds, and `at(path) -> io::Result<Option<u64>>` for the reader. *No behavior test; the
   behavior lives in the driver.*

2. **`crates/hydrationd/src/placeholder.rs`** — in `finish_hydration` (`:454`), after `stamp::write_fd(fd)`
   (`:468`), add `let _ = hydration_protocol::hydrated::write_fd(fd);` — best-effort, same `let _ =`
   discipline (a failed timestamp is not a failed hydration). The **only** new write site. *Test must assert:*
   `a_completed_hydration_records_hydrated_at` — after a whole-file fill the xattr is present and within a few
   seconds of now; `a_partial_fill_records_no_hydrated_at` — `settle_range` leaves it absent (the file is still
   a placeholder). Rests on P2.

3. **`crates/hydration-client/src/evict_policy.rs` (NEW)** — the `FreeSpace` trait (real `statvfs`, `FakeDisk`
   double), the wall-clock `Clock`, an `EvictionConfig` (low/high, grace, min-interval, per-sweep cap), and the
   pure `plan(candidates, available, cfg, now)`. Register `mod evict_policy` in `lib.rs`. *Tests must assert
   (each fails against no-code):* `plan_orders_oldest_hydrated_at_first`; `plan_uses_mtime_when_hydrated_at_is_absent`;
   `plan_never_selects_within_the_grace_window`; `plan_stops_at_the_high_mark_and_not_before`
   (fed a `FakeDisk` credited each `Reclaimed.bytes`); `plan_at_target_selects_nothing` (idempotence);
   `plan_never_drives_free_below_low` (blast radius); `size_breaks_ties_larger_first`.

4. **`crates/hydration-client/src/reclaim.rs`** — add a candidate enumerator (a resident-file analogue of
   `pending`/`collect_dehydrated`, `:298-350`) returning `{rel, blocks*512, hydrated_at or mtime}` for hydrated,
   unpinned (memoized `pinned_self_or_ancestor`), clean, uploaded files; reuse `safe_join`+canonicalize
   confinement. `reclaim()` itself is unchanged — it stays the per-file authority. *Tests must assert:*
   `enumerate_lists_only_evictable_residents` (skips dehydrated, pinned, dirty, no-id); `enumerate_confines_to_the_root`.

5. **`crates/hydration-client/src/daemon_loop.rs`** — add the fifth thread in `run()` (near `:1339`) cloning
   queue/stop/mount/delta_busy/eviction-config, gated on `!delta_busy`, snapshotting `waiting_set()`/`sending_set()`
   as `evict` does (`:561`), looping `reclaim` per `plan` entry, re-measuring free space; add `autoevict
   off|pressure|status` to `control()` (`:551-642`) persisting to `--state-dir` and loading at startup; append
   `autoevict=` to `WatchState`/`line()` (`:316-337`) under the append-only rule; add the optional eviction field
   to `Config` (`:66`, `None` = off). *Tests must assert:* `autoevict_verb_round_trips_and_persists`;
   `a_sweep_snapshots_the_queue_and_skips_uploading_files` (a file entering `sending` is refused via `reclaim`);
   `config_none_leaves_behaviour_unchanged` (default off).

6. **`DESIGN.md`** — promote automatic eviction out of the out-of-v1 list (`:1453`) into a numbered section under
   §6h, recording the `noatime` constraint, the least-recently-hydrated ranking with its honest limit, the
   hysteresis+grace design, and P1/P2's measurements alongside §6h/§8z.

7. **`probes/`** — P1 and P2 above.

### Product — `/home/frank/Projects/OneDriveHydration`

1. **`crates/onedrive-daemon/src/main.rs`** — load/save the small `--state-dir/autoevict` policy file and thread it
   into the `Config` eviction field at construction (`:199-207`); default off keeps current behaviour.

2. **`crates/onedrive-daemon/src/bin/onedrive-hydrationctl.rs`** — add an `autoevict …` verb to `usage()` and the
   positional match (`:38-50`), forwarding the line verbatim like `evict`/`pin`. *Test must assert:*
   `autoevict_forwards_verbatim` (mirror the existing evict-with-spaces forwarding test).

3. **`crates/onedrive-daemon/src/dbus.rs` + `tray.rs`** — the opt-in on/off + threshold surface (D-Bus owns the
   settable surface; the tray reflects state, staying GUI-toolkit-free), plus the additive `autofreed`/"optimizing"
   field and a low-precedence tray line ranked below exposures and sign-in. *Tests must assert:* `present` tests
   mirroring the existing precedence cases, with the storage-optimized line never outranking a correctness hazard.

---

## 7. Open risks, and what a probe must measure before code

- **`statvfs` on compressed, shared btrfs** (P1) — the biggest unknown: whole-fs vs subvol, promptness across the
  inode swap (fd-close lag), and whether the bytes `reclaim` claims freed and the bytes `statvfs` shows returned
  agree closely enough that watermark math neither over-evicts nor stalls. Do not hard-code a bytes model.
- **Thrash on a real workload** (P3) — false-eviction rate and whole-object re-fetch cost for a representative large
  file; whether a daily-opened file settles into "evicted overnight, one re-hydrate each morning" (acceptable) or a
  tight oscillation (not). Grace + per-file post-eviction backoff are the levers, and both need `hydrated_at` to exist
  first.
- **Signal coverage** (P3) — the resident split between cloud-hydrated (`hydrated_at` present) and locally-authored
  (fallback to mtime). If the fallback dominates, say so.
- **Snapshot staleness across a long sweep** — the sets are snapshotted once; a file that *starts* uploading mid-sweep
  is caught only by `reclaim`'s live stamp re-read (`Clean` gate, `:167`), because a local edit moves mtime → `Dirty`.
  A test must construct "queued for upload after the snapshot" and confirm the stamp backstop refuses it.
- **Eviction vs delta concurrency** — even gated on `!delta_busy`, a narrow window lets a delta place a newer
  placeholder just after the sweep read a file's id/stamp; the swap then installs a placeholder with the old id/etag.
  Worst case is a stale placeholder the next remote change corrects — never data loss (the bytes are in the cloud).
  Confirm on a real mount that the interleaving never leaves a *marked* file holding bytes.
- **Re-dehydration self-heal** — a cloud update swaps in a fresh placeholder inode, dropping the old `hydrated_at`
  (correct — the next hydration rewrites it; a re-dehydrated file is marked, so not a candidate until re-fetched).
  Assert it; there is no stale-timestamp hazard, but the test should prove it.
- **Concurrent daemons / shared machine** — auto-eviction adds a background writer to the sync root; endurance tests
  must isolate (`smoke.sh` pkills every `hydrationd`, `/mnt/scratch` is shared — MEMORY), record process start time, and
  use fresh per-cycle signals, not log-scraping, or contention reads as a policy bug.

---

# Critique of the above

**(a) Claims argued rather than measured.**

- **The whole trigger rests on P1, which is unrun.** "`f_bavail` tracks reclaimable space closely enough" is asserted
  from `reclaim`'s block accounting and general btrfs knowledge, but on a `compress=zstd` subvol sharing a pool with
  `@home` the number may move for reasons unrelated to eviction and may lag the swap by the lifetime of an open fd. Until
  P1 runs, the loop's stopping condition is guesswork, and a loop that stops on the wrong number either over-evicts (data
  latency) or stalls (never relieves pressure). The document says "re-measure and stop on the measured mark", which is the
  right shape, but the mark's *behaviour* is unmeasured.
- **`hydrated_at` is a coarse proxy and the document knows it, but ships it as "primary".** Under `noatime` with invisible
  re-reads, recency-of-acquisition is the best obtainable signal, not a good one. The honest framing — bounded latency, not
  data loss, with the pin as escape hatch — is correct, but "primary ranking" oversells a signal that P3 may show is mostly
  the mtime fallback in practice. If P3 finds the fallback dominates, the design is *mtime-with-a-thin-hydration-tier*, and
  the doc should be rewritten to say that rather than leading with `hydrated_at`.
- **The grace period T and the watermarks are named without numbers.** "On the order of hours", "10% or 10 GiB" are
  placeholders. The correct T is a function of real re-access intervals (P3), and the correct band must exceed the per-file
  block floor times the per-sweep cap or a sweep frees less than `statvfs` says it needs and re-fires. All three are chosen
  constants awaiting measurement, exactly the pattern CLAUDE.md warns turns a green test into one that never had to change.

**(b) Structural gaps the edit list does not close.**

- **Nothing type-enforces "call `reclaim`, never `hydrationd/evict.rs`".** §5.3 makes it a test and a convention. A future
  product entry point could still add a second eviction path with none of `reclaim`'s guards, and the type system would not
  stop it — the same residual the Keep on Device groundwork flagged and left open (`KEEP-ON-DEVICE-GROUNDWORK.md:540-542`).
- **The pin ancestor-walk cost is dismissed as it was for the manual path, but this is the disk-pressure policy it was
  dismissed *for*.** `pinned_self_or_ancestor` is `depth` × `getxattr` per candidate; "eviction is rare" was true of the
  manual verb and is precisely what auto-eviction stops being true. The document says "memoize per directory", which is the
  fix, but the memoization is described, not designed — where the per-directory cache lives across the walk, and whether it
  survives the fold-into-the-delta-walk, is unspecified.
- **Snapshot staleness is filed, not removed.** Rejecting the upload-thread placement (§4.1) trades away the one placement
  that closes the mid-sweep-upload window, keeping a race the doc then covers with "the stamp backstop refuses it". That
  backstop is real (a local edit moves mtime → `Dirty`), but it does *not* cover a file that entered `sending` with no local
  edit — a resync-driven upload of a clean file. Whether such a path exists (a clean file queued without a mtime change) is
  unexamined, and if it does, per-candidate re-snapshot of `sending` before each `reclaim` is required, which the edit list
  does not include.

**(c) Smaller drift.**

- **`plan()` purity vs the re-measure loop are in tension.** The document wants ordering/grace/blast-radius unit-testable as
  a pure function *and* wants the driver to re-measure `statvfs` after each swap to decide when to stop. Those are two
  stopping authorities; if `plan` returns a list "down to LOW" computed from one `available` reading and the driver also
  stops on live `statvfs`, the two can disagree under lag, and which wins is not stated. The `FakeDisk.credit()` test double
  papers over exactly the lag P1 exists to measure, so a green `plan_stops_at_the_high_mark` test proves the arithmetic, not
  the behaviour on the real filesystem.
- **`hydrated_at` durability across metadata writes is asserted, not guarded.** It lives on the inode and the eviction swap
  drops it (correct), but any `setxattr` (an etag adoption, a pin) moves ctime — so the doc's insistence that the signal is a
  *dedicated* xattr and never ctime is right, yet nothing asserts a pin or an id-adoption leaves `hydrated_at` untouched. One
  test should.
- **"Off by default" is a `Config` `Option`, which is a weaker guarantee than it sounds.** `None` preserves behaviour only as
  long as no thread reads the field unconditionally; the fifth thread must not even `statvfs` when the policy is off, or an
  "off" daemon still wakes to sample a disk it will never act on. The edit list spawns the thread and gates the *sweep*, not
  the thread's existence — a small waste, and a place where "off" is not quite off.

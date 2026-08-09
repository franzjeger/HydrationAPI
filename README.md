# HydrationAPI

A hydration framework for cloud files on Linux — the equivalent of macOS' File
Provider and Windows' Cloud Files API. Files appear as ordinary local files with
their real size and metadata; their content is fetched on first access.

**Status: the framework is built and hardened. A Microsoft Graph provider is
half written.** 294 tests, eight privileged suites against a real kernel, and an
end-to-end smoke run with both real binaries. What is *not* done is the part that
needs a real OneDrive account, and nothing here has met live Graph — see
[Where this actually stands](#where-this-actually-stands).

## The finding

Linux already has the mechanism, and it is not FUSE.

`FAN_CLASS_PRE_CONTENT` + `FAN_PRE_ACCESS` — fanotify pre-content events — are a
blocking permission hook that fires *before* a file's content is read, built for
exactly this and in production at Meta for HSM. Files stay on a real ext4, btrfs
or xfs filesystem, so the kernel keeps owning the POSIX contract.

That matters more than the I/O path. A FUSE client has to reimplement `stat`,
`rename`, `fsync` and file identity in userspace, and that is where cloud clients
on Linux get things subtly wrong — not in reading bytes. On a real filesystem
several of those problems stop existing rather than getting solved.

[DESIGN.md](DESIGN.md) is the full document: what is in the kernel today
(`fs/netfs`, `cachefiles` on-demand, `FUSE_PASSTHROUGH`, fanotify pre-content),
what each one can and cannot do, the recommended architecture, what it costs, and
the contract a cloud client must satisfy.

Everything in it was measured on Linux 7.1.6 / btrfs rather than recalled. Where
something was not measured, it says so.

## Layout

| Path | What it is |
|---|---|
| [DESIGN.md](DESIGN.md) | The design document and the contract (§5) |
| `conformance/` | The contract as executable tests, against a `Harness` trait |
| `adapters/onedrive-reference/` | Runs the suite against a real FUSE client |
| `crates/hydrationd/` | The privileged helper: fanotify pre-content, fail-closed |
| `crates/hydration-client/` | The unprivileged sync daemon: credentials, cloud access |
| `crates/hydration-protocol/` | The wire format across the privilege boundary |
| `crates/hydration-graph/` | A Microsoft Graph provider: the mapping layer and the delta driver |
| [PROVIDER.md](PROVIDER.md) | What a provider must uphold, and what the framework guarantees back |
| `docs/` | The groundwork the Graph layers were written from, with their critiques kept verbatim |
| `probes/` | Feasibility probes that settled specific questions |

## The framework

`crates/hydrationd` is the privileged half — the part that
holds `CAP_SYS_ADMIN`, watches a mount for pre-content events, fills
placeholders, and refuses rather than serving zeros. It never opens a socket to
the network and never sees a credential.

It is split into a supervisor and a worker sharing one fanotify group, because
bare fanotify fails *open*: kill the daemon and a dehydrated file reads back as
zeros with exit 0. Three failure modes are covered and one is not:

| | |
|---|---|
| worker dies between events | supervisor denies with `EIO` |
| worker dies holding an event | supervisor answers it by fd number |
| a fetch returns the wrong length | refused, placeholder left untouched |
| a worker that stops answering | supervisor takes over and detaches the mount |
| a fetch that never completes | abandoned; the placeholder is punched back |
| **both processes die at once** | **not covered** — needs the mount torn down (§6.4a) |

```bash
cargo test -p hydrationd                     # unit + placeholder behaviour
sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch \
  cargo test -p hydrationd --test fail_closed  # needs root and a real mount
```

Both halves now exist and talk to each other. The process holding
`CAP_SYS_ADMIN` never sees a credential; the process holding the credential can
never choose where the root helper writes — the protocol carries `(fsid, ino)`
and bytes, and has no field that could name a destination.

State lives in extended attributes on the files themselves, not in a table
beside them, because **the inode is the identity**. A locally created file has
an inode from `creat(2)` and keeps it; learning its cloud ID later is writing
one attribute onto a file that has not moved. The client this replaces had to
swap identities at that moment, and that swap produced three data-loss bugs and
three later races.

### Upload

Local changes go back to the cloud under four rules, each one a shipped
data-loss bug in the client this replaces:

1. **Upload when the file goes quiet, not when it closes.** An atomic save
   closes a temp file it is about to rename away; a scratch file is written and
   deleted seconds later; ten saves start ten uploads that collide.
2. **An upload is addressed by inode, never by a captured name.** The name is
   resolved when the bytes are sent — after the rename has landed.
3. **A missing local file is a positive statement.** The delete is the newer
   intention and wins, including removing the object the upload just created.
4. **The pending count includes edits still waiting.** Omitting them shows
   "everything synced" over work that has not left the machine.

They run on a clock the tests move, so the races are arranged rather than
waited for — sleeping through a 900-second debounce is why they stayed hidden
the first time.

### Conformance

The framework is measured by the same eight invariants as the FUSE client, plus
6a — which is `N/A` for a FUSE client and is the whole point here:

```bash
sudo -E HYDRATION_TEST_MOUNT=/mnt/scratch cargo test -p adapter-framework
```

**9 of 9**, stable across ten consecutive runs. Getting there took finding three
causes, none of them the kernel: a placeholder that ignore-marked itself while
being created, an index scanned once and never again, and a name collision the
harness resolved by hash order.

Everything in §8's v1 scope is now built: the exposure watch, the backup
manifest, per-event deadlines and a supervisor that watches progress rather than
liveness (§6a-bis), streaming hydration (§8c–§8d), eviction with a trigger a user
can run, and the two binaries the systemd units point at.

```bash
sudo ./deploy/smoke.sh /mnt/scratch    # both real binaries, end to end
```

Nine checks: a placeholder hydrates on first read; the framework creates its own
placeholder live inside the marked mount and that one hydrates too; a local edit
reaches the cloud; a rename-edit reaches the cloud; the framework's own writes do
not come back as changes; a file is evicted and gives its disk back; the evicted
file hydrates again; a file the cloud does not have is refused; and with the
worker gone a read fails rather than returning zeros.

## The Graph provider

`crates/hydration-graph` turns Microsoft Graph's delta feed into the changes the
framework consumes. Two of the five pieces are done — the mapping layer (60
tests) and the delta driver (55) — and both were written the same way: the attack
suite first, by authors who had not seen the implementation, then falsified by
someone whose only job was to find the tests that *cannot fail*.

That order paid for itself immediately. In the mapping layer, five tests took
design decisions the opposite way from mine and each time they were right. In the
driver, the reverse happened: nineteen tests encoded a data-loss bug, and only an
experiment could settle it —

> A tombstone the framework never applied was unrecoverable after a restart. The
> round had written its tree and its token, so the restart resumed past the
> deletion, `listing()` cannot express one, and the persisted tree already agreed
> the file was gone. The file stayed as a placeholder forever, and every read of
> it fetched an object that no longer existed.

Both writes are now held until the framework proves it accepted the batch, by
coming back with a different cursor than the one it was handed.

The hardest piece is not the API. It is that **a service reports one change when
a folder moves and does not re-enumerate the thousand files inside it** — so a
provider that forwards changes one-for-one splits the local tree, and no single
change looks wrong. `namespace.rs` holds the remote tree and derives paths from
it; a root-level move of 100,000 files expands in about 50 ms, and an unchanged
folder costs nothing, which matters more.

[PROVIDER.md](PROVIDER.md) is the contract, including the six Graph mapping traps
that have each bitten somebody.

## Where this actually stands

Honest, because the interesting number is not the test count.

**Done and hardened.** The framework: seven adversarial review rounds, every
finding fixed, 294 tests, 8/8 privileged suites against a real kernel. Two of the
five Graph pieces.

**Not done.** The upload half — no Graph `Sink` exists. Authentication. And there
is no seam to plug a provider into `hydration-sync`, which is still wired to the
demo `FolderCloud` in six places.

**Not verifiable here.** Nothing in this repository has spoken to live Microsoft
Graph. The provider layers are tested against scripted responses, which catches
the logic and cannot catch the world. Three consecutive modules in this project
shipped with blocking defects that only an adversarial review found — an infinite
loop, a use-after-close that wrote one object's bytes into another file, a rename
that failed all six of its own batch shapes. First contact with a real account
will find things nobody predicted.

## The contract

Eight invariants, each one a real data-loss bug in a shipped client — except
§5.8, which the suite found on its own. They are written against a trait that
knows nothing about any implementation, so they outlive the architecture:

1. **Identity** — a locally created file keeps one `st_ino` for its whole life
2. **Size and mtime** — the local copy is the truth, immediately
3. **POSIX mode** — the exec bit survives dehydration and rehydration
4. **Atomic save** — no upload succeeds under a name the file no longer has
5. **Delete during upload** — the delete is the newer intention and wins
6. **`fsync`** — never claims durability it did not deliver
7. **Hydration mismatch** — all of the promised content, or `EIO` and no residue
8. **Placeholder disk usage** — metadata-only files report zero blocks

```bash
cargo test -p hydration-conformance
```

Against the reference client as it was when the contract was written
(`f1f090c`), five passed and three failed. Two of those passes were bugs the
client had fixed recently — the suite confirmed independently that those fixes
held, rather than only accusing.

The three failures are fixed in
[OneDriveForLinux#55](https://github.com/franzjeger/OneDriveForLinux/pull/55),
and the suite now runs 8/8 against that client.

```bash
cargo test -p adapter-onedrive-reference -- --nocapture
```

Needs `/dev/fuse`. A skip is reported as "did not run", never as a pass; set
`HYDRATION_REQUIRE_FUSE=1` to make a skip fail instead.

## Probes

Small programs that answered one question each and are kept because the answers
are load-bearing. Both need `CAP_SYS_ADMIN`, which is itself one of the findings.

```bash
gcc -O1 -Wall -o probes/build/dirmark probes/dirmark.c
```

- `pidfd_cgroup.c` — can a hydration policy tell a backup daemon from the user's
  own shell? Yes, but only via cgroup: two readers were identical in `comm` and
  `exe`.
- `dirmark.c` — can `FAN_PRE_ACCESS` be set on a single directory? No. The mark
  is accepted and delivers nothing, which is worse than being rejected.
- `demand.c` — is the event's `count` a hint or a demand? A demand. Answer
  `FAN_ALLOW` having written less than it asked for and the reader gets zeros,
  silently, with no second event. A mapped read demands the whole object in one
  event, which is why streaming moves the size ceiling rather than removing it.
- `stream.c` — is a half-filled placeholder observable? No: a second reader's
  event queues behind the one being served. That is what makes filling
  incrementally safe rather than merely convenient.
- `mmapread.c` — does a mapped read hydrate? Yes, and so does `truncate`. Both
  were the last open questions that could have produced silently wrong data.

## Non-goals for v1

Multi-account, shared folders, bandwidth limits, encryption. One user, one
account, one machine — done correctly.

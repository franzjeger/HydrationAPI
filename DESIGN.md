# Hydration API for cloud files on Linux — design document

**Status:** Phase 1, basis for a decision. No implementation.
**Verified against:** Linux 7.1.6 (CachyOS), btrfs, FUSE protocol 7.45, libfuse 3.18.2.
**Reference client:** `github.com/franzjeger/OneDriveForLinux` @ `f1f090c` (Rust, FUSE, 2,241 lines in `crates/vfs`).

---

## 1. Recommendation

**Do not write kernel code. Do not build further on FUSE either.**

Build the framework on **fanotify pre-content events** (`FAN_CLASS_PRE_CONTENT` +
`FAN_PRE_ACCESS`) over a *real* local filesystem — ext4, btrfs or xfs. The files
sit as ordinary sparse files in the home directory. The kernel owns the POSIX contract.
The framework owns only two things: filling in content on first access, and sending
changes upward.

This is Linux's actual equivalent of Windows' Cloud Files API. It is a filter role
over a real filesystem, not a filesystem — exactly as CFAPI is a filter driver over
NTFS, not an NTFS replacement. The mechanism is in the kernel today, it is in
production at Meta for HSM, and I have verified that it works on this machine.

The price is three things, and all three are mandatory in v1 — not polish that can be
pushed back:

1. **`CAP_SYS_ADMIN`**, which FUSE passthrough also requires. You pay that price
   regardless if you want native performance. It must be handled with privilege
   separation (§6b).
2. **Bare fanotify fails open** — a dehydrated file reads as silent zeros if the
   daemon dies. That is worse than FUSE. Solvable, measured, but only with the
   supervisor/worker pattern in §6a.
3. **No "do not hydrate" hint in the API.** Windows and macOS have it; Linux does not.
   Bulk reads must be handled with a policy we design ourselves (§6c), and that policy
   is part of the product, not an implementation detail.

Without all three this is no better than what you have. With them it is substantially
better.

**The decisive argument:** all six bugs you fixed this week sit in metadata, identity
and naming paths — not in reading bytes. FUSE with passthrough removes the I/O cost,
but leaves you carrying the *entire* correctness burden. You pay `CAP_SYS_ADMIN` and
are still left with all six bug classes. With fanotify four of them disappear by
construction, because ext4/btrfs/xfs already implement them correctly.

---

## 2. What is in the kernel today

Everything below is verified against source or measured on this machine. I distinguish
explicitly between the two.

### 2.1 `fs/netfs` — not available to us

netfslib is a **purely kernel-internal API**. It can only be used by filesystem modules
in the kernel. It is not exposed to userspace in any form.

It does much of what we want — subrequests, sparse fetching, retry, coordination with
the page cache, and writing to several destinations at once. But to reach it you must
write a kernel filesystem. That is the expensive route, and it is assessed in §6.

**Conclusion:** relevant only if we write kernel code. Gives userspace nothing.

### 2.2 `fscache` / `cachefiles` on-demand — wrong shape, and read only

`CONFIG_CACHEFILES_ONDEMAND=y` on this machine. The mechanism exists and is real: a
userspace daemon polls `/dev/cachefiles` and answers requests.

Two things disqualify it:

1. **Only three opcodes: `OPEN`, `CLOSE`, `READ`.** There is no write/writeback path.
   It is built for container images (erofs over fscache) — read-only, immutable
   content. A cloud client has to upload.
2. **It is driven by a kernel filesystem.** cachefiles is a *cache underneath* a netfs
   client (AFS, NFS, Ceph, 9p, erofs). It is not something you mount yourself. Without
   a kernel filesystem above it, it has nobody to issue the requests.

So "placeholder → fetch on access" is admittedly the same problem in practice — but
this implementation of it is locked to reading and to kernel filesystems.

**Conclusion:** not usable. Solves half the problem, in a form we cannot reach.

### 2.3 `FUSE_PASSTHROUGH` — works, but requires root, and solves the wrong problem

FUSE protocol 7.45 on this machine. Passthrough arrived in 7.40 (kernel 6.9).
The mechanism: the daemon registers a backing file with `FUSE_DEV_IOC_BACKING_OPEN`,
gets a `backing_id`, and returns it in `fuse_open_out` together with
`FOPEN_PASSTHROUGH`.

I wrote a minimal passthrough daemon and measured it. Results:

| Path | Throughput (256 MB, tmpfs) |
|---|---|
| Direct read of the backing file (baseline) | 21.9 / 24.3 / 22.0 GB/s |
| Through FUSE **with** passthrough | 20.6 / 20.0 / 21.6 GB/s |
| Through FUSE **without** passthrough (daemon-served) | 10.2 / 9.3 / 10.5 GB/s |

Passthrough is thus ~2× faster than daemon-served I/O and lands within ~8% of native.
The reader got a correct SHA-256 over 256 MB while the daemon's `read` handler returned
`EIO` on every call — the kernel never went through userspace. The mechanism is real
and it is good.

**But it requires `CAP_SYS_ADMIN`.** From `fs/fuse/backing.c`:

```c
/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
res = -EPERM;
if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
	goto out;
```

Measured: as an unprivileged user `FUSE_DEV_IOC_BACKING_OPEN` fails with `EPERM` even
though `FUSE_PASSTHROUGH` was negotiated in INIT. As root it returns a valid
`backing_id`. Note that it is `capable()`, not `ns_capable()` — a user namespace does
not help.

Two traps worth knowing about if we go this way anyway:

- **Only four FOPEN flags may accompany passthrough:** `FOPEN_PASSTHROUGH`,
  `FOPEN_DIRECT_IO`, `FOPEN_PARALLEL_DIRECT_WRITES`, `FOPEN_NOFLUSH`. Set anything
  else — `keep_cache`, for example — and `open(2)` fails with **`EIO` and no
  diagnostics**. The kernel comment calls `FOPEN_KEEP_CACHE` "a strange and undesired
  combination". I walked into this trap during the measurement; it took a read of the
  source to find.
- **Passthrough is decided at `open`, per open.** You have to know whether the file is
  hydrated at the moment `FUSE_OPEN` is handled. One `backing_id` per inode.

**Conclusion:** technically good, but it solves only the I/O cost. It does not touch
`getattr`, `rename`, `unlink`, identity or `fsync` — which is where all your bugs
were. And it costs just as much privilege as the alternative in §2.4.

### 2.4 fanotify pre-content — this is the hydration API

This was not on your list, and it is a finding of this investigation.

`FAN_CLASS_PRE_CONTENT` + `FAN_PRE_ACCESS` is a blocking permission event that fires
**before** the content of a file is read. It was made for exactly this purpose —
hierarchical storage management that fills in file content on first access — by Amir
Goldstein and Josef Bacik, and it is in production at Meta.

Verified on this machine, on btrfs:

```
[hsm] fanotify_init(FAN_CLASS_PRE_CONTENT) OK
[hsm] marked mount hsm for FAN_PRE_ACCESS
[hsm] FAN_PRE_ACCESS pid=573286 fd=4 range=offset=0 count=262144
[hsm] hydrated 36 bytes -> OK
```

The sequence: a sparse file with `size=36 blocks=0` that read back as nothing but
zeros. With the daemon running, `cat` gave the real content, and the file went to
`blocks=8`. The reader noticed nothing. That is hydration, on a real btrfs file,
without a single FUSE layer.

Properties, from source and from measurement:

- **Covers more than reading.** `fsnotify_file_area_perm()` fires on
  `MAY_READ | MAY_WRITE | MAY_ACCESS`. In addition there is `fsnotify_mmap_perm()` for
  `mmap` and `fsnotify_truncate_perm()` for `truncate`. A partial write into a
  dehydrated file therefore triggers hydration first — the hole is filled before the
  write lands. (There is no separate `FAN_PRE_MODIFY` in this kernel; writing goes
  through `FAN_PRE_ACCESS`.)
- **The byte range comes with it.** `FAN_EVENT_INFO_TYPE_RANGE` gives `offset` and
  `count`. Note from the measurement: `count` was 262,144 for a `cat` of a 36-byte
  file — that is the *readahead window*, not the syscall size, and two overlapping
  events arrived. Hydration must be idempotent and tolerate overlap.
- **Filesystem support is broad.** The superblock must set `SB_I_ALLOW_HSM`. Verified
  unconditionally set in **btrfs**, **ext4** and **xfs**. Not set in tmpfs/shmem,
  bcachefs or gfs2. The three that matter for a home directory are covered.
- **Errors can be reported precisely.** `FAN_DENY_ERRNO(EIO)` lets you give the reader
  a real error when the download fails, instead of silent zeros.
- **Hydrated files cost nothing. Measured.** `FAN_MARK_IGNORE_SURV` removes events for
  a file that is already full. `probes/ignoremark.c` confirms all three parts: the
  ignore mark is accepted alongside the mount mark, the next read gives zero events, and
  the suppression survives the file being modified — that last one is what `SURV` means,
  and without it a hydrated file that gets written would silently start generating
  hydration events again. After hydration the file is a perfectly ordinary btrfs file:
  no daemon in the data path, native performance, not even the 8% that passthrough
  costs.

**Requires `CAP_SYS_ADMIN`** — measured: `fanotify_init(FAN_CLASS_PRE_CONTENT)` gives
`EPERM` as an unprivileged user. Same price as passthrough.

---

## 3. Why FUSE is the wrong starting point

Your six invariants are not I/O problems. They are POSIX contract problems. A FUSE
filesystem has to implement that entire contract itself, in userspace, with network
latency and a database in the way. That is why every Linux client that tries gets it
subtly wrong — not because the developers are careless, but because the job is to
reimplement something ext4 has spent twenty years getting right.

The reference client is a clean example. `crates/vfs/src/filesystem.rs` implements
`lookup`, `getattr`, `setattr`, `readdir`, `readdirplus`, `open`, `read`, `write`,
`release`, `mkdir`, `unlink`, `rename`, `getxattr`, `create`, `statfs`, `readlink`.

It does **not** implement `fsync`. Nor `flush`, `fallocate`, `rmdir`, `fsyncdir`,
`lseek` (`SEEK_HOLE`/`SEEK_DATA`) or `copy_file_range`. This is not an omission you
spot by reading the code — `fuse3` answers `ENOSYS`, the kernel remembers it and stops
sending `FSYNC`, and every single `fsync()` returns success without anything having been
done. That is exactly invariant 6, and it is broken from the outset, not by a mistake in
some edge case.

Put this next to what happens on a real filesystem:

| Invariant | On FUSE | On a real fs with fanotify |
|---|---|---|
| Size/mtime with unsent changes | You answer `getattr` from a database that lags behind the upload. Bug #50: `stat` gave 0 bytes, the file read empty, `fsync` lied. | `stat(2)` reads the inode. The local copy *is* the file. Correct by construction. |
| POSIX mode, exec bit | You have to store and recreate the mode yourself. The reference client accepts `setattr` and discards it silently. | Real inode, real mode bits. `chmod +x` works because it is `chmod`. |
| Atomic save (`rename` over target) | Bug #52: the upload started under the temp name and won. The file disappeared and the temp name held the content. | `rename(2)` is atomic in the kernel. There is no window to lose. |
| `fsync` | Not implemented. Returns success for data that is not durable anywhere. | `fsync(2)` on btrfs. Real durability, real error code. |
| The file's identity | Bug #50 and #53: `_local_*` → real OneDrive ID. Three data-loss bugs, then three more races between reading and the ID swap. | The inode is stable from birth. The cloud ID is a column in a side table. **There is no identity swap.** |
| Deletion during upload | Bug #51: the upload completed, found no row, restored the file from its own stale copy. | Still ours — but without a simultaneous ID swap it is one race, not three. |

Four of six disappear because we stop pretending to be a filesystem. The two that remain
— identity and deletion-during-upload — are real distributed systems problems that have
no kernel solution under any architecture. They belong in the framework, and §5
specifies them.

For comparison: `--vfs-cache-mode full` in rclone uses sparse files as a range cache
internally, but still presents everything through FUSE — it reimplements the contract
the same way. JuiceFS does its own POSIX implementation over an object store with its
own metadata engine. gocryptfs is an encryption overlay, not on-demand. None of them
does the CFAPI model. That is not because it is bad — it is because the mechanism did
not exist on Linux until now.

---

## 4. Recommended architecture

```
┌────────────────────────────────────────────────────────────┐
│ User's files: ~/OneDrive on real ext4/btrfs/xfs             │
│ Dehydrated file = sparse file, correct size, 0 blocks       │
│ Cloud ID and state in xattr (user.hydration.*)              │
└────────────────────────────────────────────────────────────┘
        │ FAN_PRE_ACCESS (blocking)         │ FAN_MODIFY / FAN_CLOSE_WRITE
        ▼                                    ▼
┌──────────────────────────┐        ┌──────────────────────────────┐
│ hydrated (privileged)    │        │ Change detector              │
│ ~1–2k lines, root        │        │ (unprivileged)               │
│ Owns the fanotify fd.    │        └──────────────────────────────┘
│ Does NOTHING else:       │                    │
│ no HTTP, no auth,        │◄── D-Bus/UNIX ────►│
│ no cloud logic.          │   (narrow, typed)  │
└──────────────────────────┘                    ▼
                                   ┌──────────────────────────────┐
                                   │ Client daemon (unprivileged) │
                                   │ Auth, Graph/S3/…, upload     │
                                   │ Implements the Provider API  │
                                   └──────────────────────────────┘
```

**The split in two is the point.** The privileged half is small enough to audit in an
afternoon: it holds the fanotify descriptor, translates an event into a request, takes
bytes over a socket, writes them into the file and answers `FAN_ALLOW`. It never talks
to the network. All cloud logic — OAuth, tokens, delta sync, conflict resolution — runs
as the user, with no special privileges. The precedent is `fusermount3`, which is setuid
root on this machine for exactly the same reason.

**The client implements a narrow interface.** Sketched, not final:

```rust
trait CloudProvider {
    /// Fetch [offset, offset+len) for this file. Called with the hydration pending.
    async fn fetch_range(&self, id: &CloudId, offset: u64, len: u64) -> Result<Bytes>;
    /// Upload the content. Returns the ID the cloud gave it.
    async fn upload(&self, path: &Path, expect: Option<&CloudId>) -> Result<CloudId>;
    async fn remove(&self, id: &CloudId) -> Result<()>;
    async fn list_changes(&self, cursor: &Cursor) -> Result<(Vec<Change>, Cursor)>;
}
```

Everything else — when hydration happens, what is true about size, who wins a deletion —
is the framework's responsibility and must not be possible for the client to get wrong.

---

## 5. The contract

This is the product. For each invariant: who owns it, what the framework guarantees, and
which test makes breaking it impossible.

### 5.1 The file's identity

**The framework owns it. The client never sees it swap.**

The local inode is the identity, from `create(2)` and for life. The cloud ID is an
*attribute* on it, stored in `user.hydration.id`, which starts empty.

This is the structural win of sitting on a real filesystem: in the reference client the
identity *had* to be swapped, because the row was the key and `local_path` was unique,
so `_local_*` and the real ID could never exist at the same time. Hence three data-loss
bugs and later three races between reading and adoption. Here the swap does not exist:
`upload()` returns a `CloudId`, the framework writes it into an xattr on a file that has
had the same inode the whole time. No row moves. No reader can see an intermediate
state, because there is none.

*Guarantee:* a file created locally has a stable `st_ino` from `create` to `unlink`,
regardless of the state of the upload.
*Test:* create a file, `stat` it, upload, `stat` again — same inode; read it continuously
in a thread throughout the upload without a single failure.

### 5.2 Size and mtime for a file with unsent changes

**The kernel owns them. The framework has no opinion.**

The truth is the local copy because the local copy *is* the file. `stat(2)` goes straight
to the inode. The framework never answers a `getattr`, because it is never asked.

The one thing the framework must watch: a **dehydrated** file shall have the correct size
with zero allocated blocks. That is `truncate(2)` to the right length — verified in §2.4:
`size=36 blocks=0`. The server's metadata is written to the size *only* when the file is
clean. The moment there are unsent changes, no sync path touches size or mtime.

*Guarantee:* `stat` always reflects the latest local write, immediately, whatever the
upload state.
*Test:* write 23 bytes, `stat` right away — `st_size == 23`. (The reference client's bug
gave `left: 0, right: 23` here.)

**Note:** this is about a file with *local* changes. The case where the placeholder's
size is wrong because the file changed in the cloud before anyone read it is a separate
invariant — see §5.7.

### 5.3 POSIX mode

**The kernel owns it. The framework keeps a shadow copy.**

`chmod +x` is a real `chmod` on a real inode. The exec bit works because it is the exec
bit. The cloud does not store it, so the framework mirrors the mode in
`user.hydration.mode` so that it survives a dehydration/rehydration round and can be
recreated on a new machine.

Note that this is *strictly better* than CFAPI, which has to do the same job against
NTFS ACLs.

*Guarantee:* the mode survives dehydration, rehydration and a full resync from scratch.
*Test:* `chmod +x`, dehydrate, rehydrate, `test -x` — and run the program.

### 5.4 Atomic save

**The kernel owns `rename`. The framework owns the rule that no upload may refer to a name.**

`write temp → rename over target` is the norm. On a real filesystem `rename(2)` is atomic
and the framework cannot break it.

The remaining danger is the one the reference client hit in bug #52: an upload that
*started* under the temp name and landed there. The solution is a rule, not a repair:

> **An upload is never addressed by name. It is addressed by inode, and the name is
> looked up at the moment the request is built.**

That is why `upload()` in the interface takes a `&Path` that is resolved late, not a name
captured when the job was queued. Combined with the fact that no upload starts before the
file has been quiet (§5.6), the case is gone by construction: by the time the upload
starts, the temp file *has* become the real one.

*Guarantee:* no upload can succeed under a name the file does not have when the bytes are
sent.
*Test:* atomic save with the upload held open so the `rename` lands in the middle of it —
the target file exists with the right content, the temp name is gone, and neither of the
two reverts.

### 5.5 Deletion during upload

**The framework owns it. The deletion always wins.**

The deletion is the more recent intent. The rule:

> **The absence of a local file is a positive statement, not missing data.** An upload
> that completes and finds the file gone shall delete what it just uploaded — never
> restore from its own in-memory copy.

The reference client's bug #51 was exactly `.unwrap_or(item)`: it treated "the row is
gone" as "I am missing information" and fell back on stale data. The framework shall not
give the client the option of making that choice — which is why `upload()` returns only
an ID, and the framework, not the client, decides what happens to it.

*Guarantee:* once `unlink` has returned, the file does not exist in the cloud afterwards —
not even if the upload was in flight and succeeded.
*Test:* create, write, close, delete inside the upload window (with the PUT held open so
the race is deterministic) — the `DELETE` reached the cloud, nothing came back.

### 5.6 `fsync`

**The kernel owns it — but only if we do not lie about it.**

`fsync(2)` on a real file is real durability. We do not need to implement anything. We
only need to refrain from breaking it, which is the one way this goes wrong: a FUSE
daemon that answers `ENOSYS` and gets `fsync` to succeed for free.

The clarification that has to be in the specification: **`fsync` guarantees local
durability, not upload.** The data is durably stored on this machine and survives a
reboot. That is exactly what POSIX promises, and it is all an application asks for.
Upload is a subsequent, asynchronous state — it shall be visible in the status API, not
smuggled into `fsync`.

This also puts the debounce mechanics (the reference client's #53, 900 s default) in the
right light. Waiting until the file is quiet is correct — it removes three races at the
source instead of repairing them. But it means a change lives only on this machine for up
to 15 minutes, and the framework **must** say so plainly: the queue is flushed at
shutdown, pending changes are counted as unsent in the status, and "everything is synced"
is never shown over work that has not left the machine.

*Guarantee:* `fsync` returns success only when the data survives `reboot -f`. The number
of unsent changes is always correct, including those waiting for quiet.
*Test:* write, `fsync`, hard power cut (or `echo b > /proc/sysrq-trigger` in a VM) — the
data is there. And: a file written and deleted inside the quiet period never reaches the
cloud.

### 5.7 Hydration that does not match the placeholder

**The framework owns it. The reader shall never see partial or wrong content.**

The placeholder's `st_size` is set from server metadata at creation. If the file changes
in the cloud before anyone reads it, we hydrate into a file whose size is wrong — and the
reader is already blocked inside `read()` when we discover it. On a delta-synced
filesystem this is not a corner case; it is Tuesday.

**Correcting the size under a live reader is not safe.** The reader has already `stat`ed
the file and may have sized a buffer from it. Worse: if the file is `mmap`ed, an
`ftruncate` downwards gives **SIGBUS** on access past the new end. We cannot repair our
way out of this while someone is watching.

**The rule is therefore:**

> **A placeholder is either hydrated in full with the content it promised, or it stays
> unchanged and the reader gets `EIO`. There is no third exit.**

The placeholder carries the cloud's version in `user.hydration.etag` from the moment it
was created. The hydration verifies against it, and the two cases are handled like this:

- **Mismatch detected before anything is written** — the provider reports a different
  length or etag than the placeholder promises. Nothing is written. Answer
  `FAN_DENY_ERRNO(EIO)`, mark the inode for a metadata resync, and let the next delta pass
  correct the size. The reader tries again and then meets a placeholder that matches.
- **Mismatch detected along the way** — the stream ends too early, or the etag changes
  mid-transfer. The file is now partially filled and *looks* hydrated. Punch hole back to
  the fully dehydrated state before answering, then `FAN_DENY_ERRNO(EIO)`. A partially
  filled placeholder must never survive the answer.

This is the same invariant the reference client arrived at for cache files — "a cache file
is only ever whole, downloads land via rename from `.tmp`" — but enforced on the hydration
side, where `rename` is not available to us because we are filling a file that already has
an identity and a reader.

*Guarantee:* a reader never gets bytes from a version other than the one `stat` described,
and never a partially filled file. When placeholder and cloud disagree, neither of them
wins — the reader gets `EIO` and the metadata is resynced.
*Test:* create a placeholder of size *N*, have the provider return *N−k* bytes, read —
require `EIO`, and require that a subsequent honest read gives the whole object, so that
no remnant of the failed hydration survived. Same test with the etag changed while the
stream is open.

### 5.8 A placeholder occupies no disk space

**The kernel owns it — if we do not report otherwise.**

> A file that exists as metadata alone reports zero allocated blocks.

This was not in the specification when the contract was written. It came out of running
the suite against the reference client, which reports 128 blocks for a 64 KB placeholder
it has no content for.

Why it belongs in the contract: on-demand exists to save disk, and `du` is how a user
checks whether it worked. A placeholder that reports blocks for content it does not have
makes `du -sh ~/OneDrive` show the full cloud size — the feature cannot be observed to
work even when it does. Worse for us: every disk-space policy we build on top, including
eviction under pressure, reads numbers that are wrong.

On a real filesystem this is free — a sparse file reports what it actually uses, and the
measurement in §2.4 showed exactly `size=36 blocks=0`. A FUSE client has to choose to
report it, and may just as well not. It is the same pattern as the rest of §3: the kernel
is already right, userspace has to recreate it.

*Guarantee:* `st_blocks` is zero for a dehydrated file and reflects actual usage for a
hydrated one.
*Test:* seed a 64 KB placeholder, `stat` — `st_size` 65536, `st_blocks` 0.

**Costs nothing in the recommended architecture.** A sparse file on ext4/btrfs/xfs already
reports what it actually uses — the measurement in §2.4 gave `size=36 blocks=0` without
anything being implemented for it. Locking it in therefore widens the contract without
widening the work, and it catches a whole class of bugs if we should ever consider an
implementation that does not sit on a real filesystem.

---

## 6. What we lose, and what kernel code would have bought

Your question was whether FUSE covers 90 % without kernel code. The answer is that **fanotify covers more than 90 %**, and here are the remaining percentage points, honestly:

**1. Requires `CAP_SYS_ADMIN`.** The small privileged helper. There is no way around this in any variant — FUSE passthrough requires the same. Kernel code could introduce a finer-grained capability, but that is an upstream discussion already under way (the `TODO` comment in `backing.c`), not something we should drive ourselves.

**2. Fail-open on daemon death — solved, but only with one specific pattern.** See §6a. This was the architecture's largest open risk and is now measured and answered.

**3. Blocking events are an availability liability.** If the daemon hangs, access hangs. It needs a watchdog, a timeout and a safe failure path (`FAN_DENY_ERRNO(EIO)` is the right answer, not hanging). I built this into the test probe — auto-exit and `FAN_ALLOW` on every error path — precisely because a blocking filter on a live filesystem can otherwise stop the machine.

**4. You cannot mark a directory. Measured, and the trap is worse than the limitation.**

`probes/dirmark.c` tries all four mark types on the same directory, with one file directly in it and one in a subdirectory:

| Mark type | `fanotify_mark` | `top.txt` | `sub/nested.txt` |
|---|---|---|---|
| `FAN_MARK_ADD` (inode) | **accepted** | no event | no event |
| `FAN_MARK_ADD` + `FAN_EVENT_ON_CHILD` | accepted | hydrated | **no event** |
| `FAN_MARK_MOUNT` | accepted | hydrated | hydrated |
| `FAN_MARK_FILESYSTEM` | accepted | hydrated | hydrated |

Three things follow:

- **A plain directory mark is accepted and delivers nothing.** Not an error code, not a
  warning — `fanotify_mark` returns 0 and every dehydrated file reads as zeros. It is the
  same family as §6a and §6d: something answered "fine" to something it did not do.
  Building on it would have looked right until the first real file.
- **`FAN_EVENT_ON_CHILD` covers direct children only.** A sync folder with subdirectories —
  that is, any real sync folder — is not covered.
- **Only `FAN_MARK_MOUNT` and `FAN_MARK_FILESYSTEM` work.**

Between the two, `FAN_MARK_MOUNT` is the right choice. `FAN_MARK_FILESYSTEM` on `/home`
would have sent *every single* file access in the user's home directory through a blocking
handler — the whole blast radius from §6a, extended to everything the user owns.

**Consequence: the sync folder on its own mount point is a requirement, not a
recommendation.** It was already the second line of defense in §6a; now it is also the only
way to get coverage at all. One measure, two independent justifications.

### 6.4a A bind mount is not enough. The requirement is stricter than "its own mount point".

Measured, because the choice determines the systemd setup. A mount mark is per `vfsmount`,
and the question is whether some *other* path reaches the same files.

| Setup | Coverage through the intended path | Is there a bypass? |
|---|---|---|
| `mount --bind sync alt`, mark `alt` | yes | **yes** — the original path `sync/` went straight past, `blocks=0` |
| `mount --bind sync sync` (over itself) | yes, subdirectories too | **yes** — a `mount --bind` of the *parent* exposes the shadowed directory |
| Separate btrfs subvolume, mounted separately | yes | **yes, if** the btrfs root (`subvolid=5`) is mounted |

All three bypasses were verified by reading a placeholder through them: `blocks=0`, no event
delivered, the content was zeros. A bind mount over itself is therefore not enough — a
non-recursive bind of the parent is enough to get around it, and that is exactly what
container runtimes and systemd sandboxing (`BindPaths=`, `ProtectHome=`) do routinely.

**The correct formulation of the requirement is therefore not "its own mount point", but:**

> No other mount in the system may expose the sync folder's files.

That is a property of the machine's entire mount table, not of our own setup — and it is
worth saying plainly: **we cannot enforce it.** A user or a container can create a bypass
afterwards, at any time.

**Practical recommendation: a separate btrfs subvolume.** On an ordinary Arch/CachyOS setup
the btrfs root is not mounted — verified on this machine, where `@`, `@home`, `@root`, `@srv`,
`@cache` and `@log` are mounted individually and `subvolid=5` does not appear in the table.
Then an `@onedrive` subvolume mounted at `~/OneDrive` has no other path. It is cheap, it fits
the setup that already exists, and it requires no separate partition.

**And since we cannot enforce it, we have to detect it. Measured that we can.**
`probes/mntwatch.c` catches the exact bypass above:

```
[mnt] ATTACH  -> 2 mount(s) now expose loop0
      …/hsm  (root /)
      …/hsm2 (root /)      <- the bypass
[mnt] DETACH  -> 1 mount(s) now expose loop0
```

Two things the probe settled, both of which affect the code:

- **`FAN_REPORT_MNT` cannot be combined with `FAN_CLASS_PRE_CONTENT`** — the call returns
  `EINVAL`. The hydration group therefore cannot also watch mounts; the supervisor needs its
  own descriptor with `FAN_CLASS_NOTIF | FAN_REPORT_MNT`, marked with `FAN_MARK_MNTNS` on
  `/proc/self/ns/mnt`.
- **The event's `mnt_id` is not a source of truth.** It is the 64-bit unique ID, not the
  reused one in field 1 of `/proc/self/mountinfo`, and on `DETACH` the mount is gone and
  cannot be looked up at all. The right shape is to use the event as a *trigger to go look
  again* — scan the mount table and count how many mounts now expose the files. That is
  namespace-correct, tolerates the event arriving before the mount is visible, and works the
  same for attach and detach.

It is the same principle as §6d: we cannot make the mistake impossible, but we refuse to let
it be silent.

**5. No ready-made eviction policy.** The kernel does not tell us under disk pressure that it
wants space back. We have to implement dehydration (`FALLOC_FL_PUNCH_HOLE` + removing the
ignore mark) under our own policy — LRU, quota, or manual choice.

**What would kernel code have bought?** Realistically only points 1 and 5, and both are small
gains. A new filesystem or a netfs extension would have given us `fs/netfs`'s subrequests and
an integrated eviction path — but at a price that is out of proportion. `ksmbd` is the right
reference point: years, with Samsung behind it, for something with a clearer justification
than this. A hydration filesystem would in addition have to defend why it is not just
fanotify HSM, to maintainers who have just received fanotify HSM and who asked that question
already.

**The recommendation is categorical: no kernel code, not in v1 and probably never.**

---

## 6a. Fail-open on daemon death

**Status: measured, and solved with one specific pattern that has to go into v1.**

The starting point is as bad as feared. With the hydration daemon `kill -9`ed, a dehydrated
placeholder reads back as zeros, with **exit 0**:

```
$ cat hsm/d.txt        # daemon killed with -9
                       # 36 zero bytes, no error
[cat exit=0]
$ stat -c 'blocks=%b' hsm/d.txt
blocks=0
```

For comparison, the same test on FUSE:

```
$ cat mnt/hydrated     # FUSE daemon killed with -9
cat: mnt/hydrated: Transport endpoint is not connected
```

FUSE fails closed by construction — `ENOTCONN` because the connection is gone. Bare fanotify
fails open, because a file without a pre-content mark simply *is* a sparse file. That is
silent data corruption, and it is worse than what we are replacing.

**The solution: the fanotify group lives for as long as one fd references it.** Split the
privileged helper into two processes that share the group descriptor:

```
super  ── fanotify_init() + fanotify_mark()
   │       fork()
   │
   ├── worker   hydrates, talks to the unprivileged daemon
   └── super    holds its copy of the fd, never touches it
               ── on worker death: takes over the loop, answers FAN_DENY_ERRNO(EIO)
```

Measured, with the worker `kill -9`ed and the supervisor alive:

```
[super] *** WORKER DIED (signal=9) - taking over, failing closed ***
$ cat hsm/w2.txt
cat: hsm/w2.txt: Input/output error
[cat exit=1]
$ stat -c 'blocks=%b' hsm/w2.txt
blocks=0
```

`EIO` instead of silent zeros, and the file stays dehydrated. It is the same error class FUSE
gives, and it is the right behavior.

**The residual risk is that both die at once** — an OOM kill of the whole cgroup, `SIGKILL` to
the process group, a kernel panic. Then we are back to silent zeros. Layered defenses:

1. The supervisor holds the group. That covers a crash in the worker, which is where all the
   complexity and therefore nearly all the crash risk sits.
2. The supervisor is almost code-free: open, mark, `fork`, `waitpid`, deny loop. No HTTP, no
   parsing, no allocation in steady state. `OOMScoreAdjust=-1000` and
   `Restart=always` in the systemd unit.
3. The sync folder on its own mount point, with `BindsTo=`/`StopPropagatedFrom=` so that the
   mount point is torn down when the unit dies. Then the files are *unavailable* instead of
   wrong. That covers the window where nothing of ours is running at all.

   This point originally stood as the second line of defense. After the measurement in §6.4
   it is mandatory regardless: a directory mark delivers no events, so its own mount point
   is the only way to get coverage. Two independent reasons for the same measure.

**A third failure mode, found by measuring afterwards.** The supervisor covers worker death
*between* events. It does not cover an event the worker has already read out of the queue:

```
[worker] HOLDING event unanswered (pid=644293)
[super]  *** WORKER DIED (signal=9) - taking over, failing closed ***
   reader: STILL BLOCKED ... rc=124   (killed by timeout, did not return)
```

The event left the queue together with the worker, so the supervisor never sees it and cannot
answer. The reader hangs unbounded. The file stayed dehydrated, so there is no corruption —
but an infinite hang is not a better outcome than `EIO`.

**Closed by having the worker publish what it is holding.** Measured: a response is matched on
fd number within the group, not against the responder's fd table. The supervisor can therefore
answer an event it never read itself:

```
[super] answering stranded event fd=4 for the dead worker: accepted
   reader: rc=1        (EIO, not a hang)
```

So the worker writes the fd number to a shared location before it does anything that can hang,
and the supervisor answers `FAN_DENY_ERRNO(EIO)` for everything standing there when the worker
dies. It is a small mechanism, and without it the fail-closed design has a hole that looks like
a hung machine.

**Conformance tests that must exist:** `kill -9` the worker between events, read a placeholder,
require `EIO`. `kill -9` the worker *while* it is holding an event, require `EIO` and not a
hang. And: kill both, require that the mount point is gone within N seconds.

---

## 6a-bis. A hung worker is worse than a dead worker

Found during implementation, and it extends §6a in a way the design did not
anticipate.

**A process stuck in a pre-content event cannot be killed with a signal.**
The event has to be answered first. Measured: `SIGKILL` against a blocked reader does
nothing; the process only becomes reapable once someone answers the event, or when
the group is closed.

The consequence is unpleasant. §6a solves the worker *dying* — the supervisor holds the group
and denies. It does not solve the worker **hanging**: then the event stands unanswered,
the process cannot be killed, and the group cannot be closed because the dead process
still holds its descriptor. Every later operation on the mount blocks,
including `ftruncate` and file creation. "Restart the daemon" is not an
available answer.

It happened several times during development, and every time the symptom was the same:
the mount looked healthy, `mountpoint` said yes, `touch` worked, and everything else hung.

**What had to go into v1 — now built and pinned by tests** (`tests/deadlines.rs`):

- **A deadline per event.** The fetch runs on its own thread and the worker waits
  on a channel, so a `Fetch` that never returns costs the reader `EIO` after
  the deadline instead of holding it forever. The deadline cannot be enforced by asking
  clients to respect one — that is exactly the kind of rule the framework exists
  to avoid. Default 30 s.
- **The supervisor watches progress, not liveness.** The shared page now carries a counter
  the worker increments for every answered event. If the worker is holding an event without
  the counter having moved for 90 s, it is treated as dead. Only a worker
  that *is holding something* can be stuck; an idle worker makes no progress either,
  and tearing down the mount every time nobody is reading would be worse than the bug.
- **The order during teardown is the whole point.** Signal first: a worker stuck
  in a network fetch dies there. If it does not, it is stuck in a
  pre-content event it triggered itself (§6a-ter), and then no signal reaches it —
  it is only released when the event is answered. So the answer comes *after* the kill,
  not before.
- **The mount is torn down without failing open.** Exiting the process would have closed
  the group, and a mount without a group fails *open*: every placeholder becomes a
  source of zeros. So the mount is detached with `MNT_DETACH` while the process
  stays up and denies everything already in flight, and exits only once
  it has been quiet for 10 s. `BindsTo=` covers the same thing from systemd's side;
  the helper does it itself as well, so the guarantee does not depend on having been
  deployed with the accompanying units.

**A bug the first version introduced, worth writing down because it was
invisible.** The counter of missed deadlines short-circuited *before* the request was sent, so
no answer could arrive, so the counter could never be reset. Three misses turned
the mount into instant `EIO` forever — served by two processes that looked
perfectly healthy, with the supervisor's stall watchdog that would never fire, because a worker
that denies quickly is not stuck. An outage that looks like a working system.

Two things fixed it:

- **The lockout is reversible.** Abandoned fetches keep running, and an answer
  from one of them is proof of life. They are now drained where the short circuit sits, so a
  fetcher that comes back is used again.
- **It is time-bounded.** If it stays unanswered for five minutes, the worker
  stops. Every reader has already been answered — the loop only gets here between
  events — so nothing hangs, and the supervisor tears down the mount from there. That is
  §6a-bis's third requirement reached by the other route.

**Streaming is now built** (§8c, §8d). The fetch is delivered in chunks into
the event fd as the bytes arrive, with three limits that ask
different questions: 30 s to say *anything*, 60 s to say *more*, and 10 minutes
in total. The ceiling is therefore chosen from how long a filesystem operation may
block, not from how large a file may be — and it has to exist, since the reader
cannot be signaled away. The helper buffers one chunk rather than the whole object, so
the memory cost is `MAX_CHUNK` and not the file size.

Eight bugs were found in the first version of this, and the worst was a
use-after-close: the fetch thread got the event fd as a raw number, the worker
closed it the moment it answered, and an abandoned transfer went on writing to a
number the kernel had in the meantime handed to the *next* event. Measured: 8 MiB of one
object written into a different 4096-byte placeholder, the mark removed, reported
as `Hydrated`. Not a race that needs luck — event fds are allocated
lowest-free-first, and the worker holds almost none. The fetch thread now owns its
own `dup`.

The supervisor got a second counter for this. The progress counter only moves when an
event has been fully answered, so a legitimate five-minute download looked exactly
like a hung worker. The new heartbeat sits in the worker's own wait loop —
deliberately *not* on bytes, because a heartbeat that follows the network lets a provider that
dribbles one byte per stall window hold the mount effectively forever.

**One limitation that remains, measured and deliberate.** Fetches are serialized —
one connection to the sync daemon, one outstanding request. A fetch that has
passed its deadline therefore holds the queue until it actually returns, and reads behind
it get `EIO` rather than content. That is a *degradation*, not a lockup, and that is
the distinction §6a-bis is about: every reader is answered quickly. Removing it requires
pipelining, which the protocol's `id` field already allows for and the transport does not yet
implement.

---

## 6a-ter. Writing into a marked mount is the project's sharpest edge

The same bug has appeared **eight times, in eight disguises**, every time by
someone who knew about the previous ones. They are numbered because the count
kept drifting as the table grew, and a later section referring to "the sixth"
had no way to be checked:

| # | Where | What was written |
|---|---|---|
| 1 | The worker's hydration | reopened the path to fill the file |
| 2 | Dehydration | punched holes without an ignore mark |
| 3 | The eviction test | filled the file after the mount was marked |
| 4 | The `eventtrace` probe | created the placeholder after the marking |
| 5 | Delta sync | had to give a new placeholder a size inside the mount |
| 6 | The `placeholder_creation` test | dehydrated *after* the marking — in the test that exists to catch exactly this, and it locked the whole suite for 300 s |
| 7 | The `nodump` and `mmapread` probes | opened the file inside the mount from the process that answers |
| 8 | **Partial fill** | answering `FAN_ALLOW` after writing less than `count` — see §8d |

The shape is always the same: **a write inside a marked mount, performed by the
only process that could have answered the event it triggers.** The result is a
permanent lockup, with no error message, with a handler that looks perfectly
healthy in `poll()`.

Eight times is not eight careless mistakes. It is the shape of the API, and the
framework has to make it impossible to hit rather than warn against it:

- Never write by opening a path inside the marked mount. Use the event's own fd,
  which is not intercepted — that is why the kernel hands it out.
- Where a path must be opened, the ignore mark is set first and removed
  afterwards, and the two belong inside the same function. `evict()` does this;
  no one should be able to sequence it themselves.
- Test harnesses must create and fill files **before** the mount is marked.

### The fifth disguise, and why it got an answer of its own

The first four were bugs. The fifth was a requirement: delta sync **must**
create placeholders, and creating a placeholder means giving a file a size. So
it could not simply be avoided.

The two obvious ways out were both worse than they looked:

- **Let the privileged helper create the file at a path the daemon picks.** That
  is a real privilege escalation, not a theoretical one: root walks a path the
  unprivileged side controls (symlink/TOCTOU), the result is owned by root, and
  since `mode` is set by whoever creates the file, `06755` becomes a
  setuid-root binary whose content *the same daemon* delivers afterwards.
- **Let the privileged helper lend out an ignore mark** on an inode the daemon
  points at. That is the ability to make an arbitrary file read as zeros —
  exactly the failure the framework exists to prevent.

`O_TMPFILE` removes the dilemma instead of managing it. The placeholder is built
on an **anonymous inode with no name**, and `linkat` gives it a name only once it
is finished. Measured on 7.1.6 (`probes/tmpfile.c`):

```
events after create:            0
events observed while sizing:   1   <- nlink=0, size=0
events during linkat:           0
result: size=4096 blocks=0, dehydrated mark present
```

So setting the size is **not** silent. The worker answers the one event it
triggers with a single narrow rule — but which rule is the whole point, and the
first attempt was exploitable.

**What did not work, and why it is worth writing down.** The first version let
through an inode with `nlink == 0` that carried a mark `user.hydration.building`,
set by the daemon while it was building. The argument was that an inode with no
name cannot be opened, so no reader can be served wrongly. The argument is false:
`nlink == 0` means *unreachable via a new name*, not *no open descriptors*. A
file that is opened and then unlinked has `nlink == 0` with a reader parked in
`read()`. The only thing separating the safe case from the dangerous one was the
mark — and a `user.*` xattr can be set by any process with the file's uid, which
in this threat model is the adversary. Measured attack:

1. attacker sets the mark on a real placeholder it owns — no privileges
2. the victim opens and reads; the read blocks on the pre-content event
3. attacker unlinks the file — not a content access, so no event
4. the worker sees `nlink == 0` and the mark, and lets it through without hydrating
5. the victim gets zeros and archives them as content

It also bypassed §6c completely, since the shortcut sat in front of the policy
gate: a backup that should have been refused with `EIO` — the safe answer — was
let through with zeros instead.

**The rule that holds** uses no claim, only a property the kernel itself
reports: **`nlink == 0 && st_size == 0`.** The event fires *before* `ftruncate`
takes effect, so the inode is still empty when the worker sees it (measured). An
empty file has no byte anyone can be served in place of real content, so letting
it through is not a shortcut past hydration — it is exactly what hydrating an
empty file would have done. `nlink == 0` does not carry the security; it only
confines the rule to the case that needs it.

The difference is not cosmetic. A mark is something someone *says*; a size is
something the file *is*. There is nothing here for an attacker to assert.

The gain is structural, not just practical: **there is no destination in the
protocol at all.** §6b is no longer a rule someone has to remember to follow on
the privileged side — the privileged side never gets to see a path.

A clarification, since the first formulation was too generous: creation does
*not* sit entirely on the unprivileged side. `ftruncate` still triggers an event
only the privileged helper can answer, so the daemon cannot create a placeholder
on its own inside a marked mount. What is true is narrower, and it is what
matters: **the privileged helper never gets a destination, and takes no
instruction during creation.** It answers what the kernel tells it about a file
it holds the fd for itself.

The same finding forced another fix. The worker looked up the placeholder mark
via the *path* the event resolved to. A placeholder unlinked while open has no
path, and was therefore refused with `EIO` even though the content was fully
fetchable. The worker now works from the event fd (`fgetxattr`/`fstat`), and the
path is used only for what it is actually needed for: the ignore mark and the
refusal log. That removes a TOCTOU at the same time, since a path can change
between lookup and use.

---

## 6b. Privilege separation

This is sketched in §4 and is to stand as a requirement, not an illustration:
**the process that holds `CAP_SYS_ADMIN` must never see the OAuth token.**

The interface between the two is the whole point, so it has to be specified in v1:

| | Privileged (`hydrated`) | Unprivileged (client daemon) |
|---|---|---|
| Runs as | root, `CAP_SYS_ADMIN` alone, otherwise stripped | the user |
| Owns | the fanotify group, writing into placeholders | OAuth token, Graph API, sync state, database |
| Never sees | credentials, the network, URLs | the fanotify fd, other users' files |
| Amount of code | 1–2k lines, audited in an afternoon | the rest of the client |

The protocol over the socket is to be as boring as possible — that is where a
privilege escalation would live:

- `hydrated` → daemon: "inode *X* on fsid *Y*, range *[o, o+n)*, requested by pidfd *P*".
  Never a path. Never anything the client can influence into pointing somewhere else.
- daemon → `hydrated`: bytes, or an error code. Not a file path, not an fd, not a
  command.
- `hydrated` validates that the inode lies under the mount point it marked itself, before
  it writes anything at all.

So the privileged side never accepts a *destination* from the unprivileged one —
only content for a destination it decided itself. That is the one invariant that
keeps a compromised client daemon from becoming root.

The precedent is `fusermount3`, which is setuid root on this machine for exactly the
same reason: a small, audited bridge across a privilege fence.

---

### Who the boundary actually runs against

The fix above raised a question it did not answer, and it has to stand explicitly
in the contract rather than be left implied: **is a compromised `hydration-sync`,
running as the user, in scope for the guarantee that no read silently returns
zeros?**

The recommendation is **no**, and the reason is not convenience:

- The mark `user.hydration.dehydrated` is what tells the worker that a file is a
  placeholder. All `user.*` attributes can be written by any process with the
  file's uid. Remove the mark and the worker concludes the content is already
  there, and serves the hole. **Measured and pinned by a test**
  (`stripping_the_placeholder_mark_does_not_permanently_disable_interception`).
- It is no new capability. The same process can write zeros straight over the
  file. The difference is that removing the mark is quieter: no byte is written,
  so mtime stays put, no upload is triggered, and no disk is used.
- Closing it requires the mark to live in `trusted.*`, which requires
  `CAP_SYS_ADMIN` to write. Then the privileged helper has to set the mark, which
  means taking part in creation — and then we are back at exactly the escalation
  §6a-ter just removed: root walking a daemon-chosen path, and `mode = 06755`
  becoming a setuid-root binary.

The boundary the framework **actually** enforces is therefore narrower, and worth
saying outright:

> The privileged helper never becomes a write-anywhere-as-root primitive,
> and a read never returns zeros because of **failure** — daemon death,
> network error, hung worker, policy refusal. Against a *malicious process with
> the user's own uid* the framework is not a defense, because that process owns
> the files anyway.

What was done anyway, because it is cheap and limits the damage: the worker no
longer sets a permanent ignore mark on a file that reports a size but occupies
no disk. Without that, one xattr removal turned into silent zeros *forever*,
with no further involvement and nothing to observe. Now the damage lasts only as
long as the mark is gone, and the file heals when the mark comes back. The price
is one round trip per read of a genuinely sparse hydrated file, which is rare and
is the safe direction to be wrong in. It does not reach small files — btrfs
stores them inline, so a stripped small placeholder still reports blocks.

**If this answer is wrong**, the consequence is a design round of its own: the
mark has to move to `trusted.*`, the privileged helper has to set it, and
creation has to go back across the privilege boundary with the costs §6a-ter
describes. That is not a small change, and that is why the choice stands here
rather than in a commit message.

---

## 6c. Bulk reading hydrates everything

**This is the one that decides whether the framework is usable in practice, and fanotify has no built-in notion of "do not hydrate".** A nightly `restic` run pulls 300 GB.

The investigation produced four layers, and the first two remove most of the problem without any policy list at all.

**Layer 1 — metadata does not hydrate. Measured.**

```
$ stat hsm/a.txt; ls -l hsm/a.txt; du -sh hsm/a.txt
$ stat -c 'blocks=%b' hsm/a.txt
blocks=0
```

`FAN_PRE_ACCESS` fires on content access, not on `stat(2)`. That means `find`, `ls`, `du`, `tree`, `rsync --dry-run` and the first pass of most indexers are free. That is a substantial narrowing of the problem: only tools that actually read bytes are in danger.

**Layer 2 — `chattr +d` (nodump). Measured in practice, and the layer holds almost nothing.**

The flag can be set on btrfs (`------d---------------`), but it only helps if the tools read it. Measured on the ones installed, and looked up for the two most common:

| Tool | Respects nodump |
|---|---|
| GNU `tar` | **no** — no support at all |
| `bsdtar` | only with an explicit `--nodump` |
| `rsync` | **no** |
| `borg` | only with an explicit `--exclude-nodump` |
| `restic` | **no** — does not support `chattr` attributes |
| `dump` | yes (the flag comes from it) |

None of them skip the files unless the user asks for it, and the two that are most common on a Linux machine today — `restic` and `rsync` — cannot do it at all.

**Layer 2 therefore fails as an automatic mitigation.** Setting the flag is still worth it: it costs nothing, and for anyone running `borg --exclude-nodump` or `bsdtar --nodump` it does exactly what you want. But it cannot be leaned on. The consequence is that the manifest in §6d is not extra safety — it is *the* mechanism that makes a backup complete, and layer 3 has to cover the rest.

**Layer 3 — policy on the systemd unit, not on the pid. Verified end to end.**

`md->pid` alone is the wrong key: pids are reused, and the lookup in `/proc/<pid>/` races the process dying. A pidfd pins the pid for as long as it is open, and makes the lookup safe. `probes/pidfd_cgroup.c` runs all the way through and confirms that it works:

```
[pidfd]   event->pid (racy key)  = 584386
[pidfd]   pidfd = 5 -> pid 584386
[pidfd]   comm   = cat
[pidfd]   exe    = /usr/bin/cat
[pidfd]   CGROUP = 0::/user.slice/.../app-com.anthropic.Claude-13945.scope

[pidfd]   event->pid (racy key)  = 584391
[pidfd]   pidfd = 5 -> pid 584391
[pidfd]   comm   = cat
[pidfd]   exe    = /usr/bin/cat
[pidfd]   CGROUP = 0::/system.slice/restic-probe.scope
```

Note what this actually shows. The two readers are **identical** in everything but the cgroup: same `comm`, same `exe`, same binary. A policy based on executable path cannot tell them apart — it would either let the backup through or deny the user their own `cat`. The cgroup separates them cleanly: `restic-probe.scope` against the user's app scope.

That is exactly the distinction that matters — `rsync` run by the backup unit against `rsync` run by the user in a terminal window — and it is now measured, not assumed. The cgroup is the policy key.

**Layer 4 — deny, never silent zeros.** `FAN_DENY_ERRNO(EPERM)` for a denied reader. The backup tool then logs an error instead of writing 300 GB of zeros into its archive — which is the truly bad outcome, since it destroys the backup silently.

**And you are right that the list is a product.** It needs a default list covering the common cases (restic, borg, duplicity, baloo, tracker, clamav, updatedb), a way for the user to add to it, and — most importantly — a **visible log of what was denied**. A user who does not understand why the backup is complaining should find the answer in one place. Without that log the policy becomes an invisible trap instead of a feature.

This is also where Windows and macOS have a real advantage: they have hints in the API, so the app says "do not hydrate" itself. We have to guess from the outside. The guess is good enough when it is cgroup-based and visible, but it will never be as precise, and that belongs in the specification as a known limitation.

---

## 6d. The backup contract: nodump must never be silent

**A backup that skips dehydrated files does not contain your cloud files.**

That may be correct — they *are* in the cloud — but a user who believes `restic` is protecting `~/OneDrive`, and who on restore finds that every dehydrated object was missing, has lost data for exactly the same reason as every bug in §5: something answered "fine" to something it did not do. `chattr +d` is technically elegant and semantically a trap, and it has to be treated accordingly.

**Rule: nodump is never set as a side effect of dehydration.** It is a stated policy with three legal values, chosen at setup, with no silent default:

| `backup_policy` | Behavior | Consequence the user must see |
|---|---|---|
| `exclude` | nodump is set, backup tools skip | "*N* files omitted from backup because they are cloud-stored" |
| `hydrate` | no nodump, backup reads and hydrates everything | full backup, full download, full disk usage |
| `deny` | no nodump, the policy denies with `EPERM` | the backup tool fails loudly and logs it |

The default is `exclude` — but only because the other two are worse, not because it is safe. `hydrate` defeats the whole point of on-demand, and `deny` makes a nightly backup fail in its entirety. `exclude` is the least wrong choice, and the price is that it **must** be visible.

**Three requirements follow, and they belong to the contract:**

1. **The number is always in the status.** Not in a log file, not behind a flag. In the same place "everything is synced" is shown, it must say "412 files omitted from backup because they are cloud-stored". The framework owns the counter; the client cannot choose not to display it.
2. **The choice is made at setup, not inherited.** The first time the sync folder is configured, the question is asked explicitly, with the consequence spelled out. A user who never took a position on this has not taken one.
3. **A manifest file that is itself always dense.** The framework maintains `.hydration-manifest` in the root of the sync folder: path, cloud ID, size, hash and version for every dehydrated file. It is small, it is never dehydrated, and it therefore comes along in the backup. The backup is then *complete in the sense that matters* — a restore can fetch the content again, instead of discovering a hole.

Point 3 is what makes `exclude` defensible at all. Without the manifest, a backup with nodump is just a hole with a counter next to it. With it, it is a complete description of what existed and where it lives.

**And after the measurement in §6c, point 3 is no longer just what makes `exclude` defensible — it is the whole mechanism.** Almost no backup tool respects nodump unless the user asks for it, and `restic` cannot at all. That means the default `exclude` behaves in practice like `hydrate` for most people: the tool reads the files, the policy in §6c has to deny them, and the manifest is the only thing that says what is missing.

**Conformance test:** dehydrate *N* files, run a backup with a tool that respects nodump, and require that (a) the status reports exactly *N*, and (b) the manifest in the backup lists all *N* with hashes that allow them to be fetched again.

---

## 6e. The framework's own files are never the user's

One rule, and it is easy to leave out because nothing fails loudly when you do:

> **The framework's own files are never synced.**

The manifest is rewritten every time the number of placeholders changes. Treat it as user content and it becomes an ordinary local file: change detection sees the write, the queue debounces it, the upload gives it a cloud id, the next delta pass fetches it back down, and the rewrite after that starts over. Nothing fails. The two ends just never stop talking about a file the user has never heard of.

Worse in the other direction: a cloud object could be named `.hydration-manifest`, and a delta pass would then replace the §6d mechanism with a placeholder — the file that tells a restoring user what is missing would itself become a file with no content. `safe_join` rejects that now, rather than renaming it: a renamed path silently means something other than what the cloud said.

The predicate lives in the shared crate for the same reason as the xattr names. The scan, the manifest builder, the delta pass and the change supervisor all need the same answer, and four copies of it is how they come to disagree.

---

## 6f. `nodump` has an owner

The flag had a setter and no lifecycle. Measured first (`probes/nodump.c`, 7.1.6, btrfs), because all three answers shape the code:

```
set nodump: completed, events fired: 0
survives a hole punch:            yes
survives being written through:   yes
```

- **No event** is what makes it safe to set inside `evict()`, which runs in the marked mount in the process that answers events (§6a-ter). The flag is therefore set right next to the dehydrated mark, in the same function.
- **Survives being written through** is the important one: hydration does *not* clear it on its own. Without an explicit step, a hydrated file would still be skipped by every backup that respects the flag — the §6d damage in through the back door, that is, content that exists only here and is nevertheless left out of the backup. It is now cleared in `hydrate_fd`, through the event fd, in the same operation that fills the file.

The clearing is unconditional, not conditional on our having set it ourselves. The narrow cost is a user who set `nodump` by hand on a file that later turns out to be a placeholder: hydration removes their flag. That errs in the direction of *more* data in the backup, which is the direction §6d exists to protect.

`Backup::Exclude` / `Backup::Include` is now an argument to `evict()` with no default value, because there is no safe one — excluding means the backup silently lacks the content, including means every backup sweep pulls down the entire disk.

---

## 6g. Change detection: the channel is an optimization, never an authority

The change supervisor existed and was tested, but no binary ever created one. A local edit was therefore never uploaded in a real run. That is now wired up, and its shape is dictated by two measurements.

**Sending cannot happen in the event loop.** An AF_UNIX stream accepts ~278 short messages on the default `SO_SNDBUF` before the sender blocks — the kernel charges a whole skb per small send, not the payload. A worker that blocks in `write()` stops answering pre-content events, and worse: the supervisor from §6a-bis does not see it. The stall supervisor fires on *holding an event without progress*, and a worker that blocks between events is holding nothing. It is classified as idle, forever, while every reader on the mount hangs. The mount looks healthy. Nothing recovers.

Hence three threads, all started after `fork`:

```
drainer  ── reads the notification group, folds each event into a dirty set
              never blocks on anything but a mutex
sender   ── swaps the set out, writes one coalesced line
              may block freely; blocks only itself, while the set absorbs
worker   ── answers pre-content events, touches neither
```

Folding into a set is not an addition: it is the same coalescing the kernel already does. Measured — 10 000 alternating writes to two files produced two events, with `MODIFY` and `CLOSE_WRITE` merged per object. The set continues that past the kernel's limit of 16 384 objects, and its size is bounded by the number of files on the mount, not by how much is written.

**No destructive path may trust silence.** Change detection is lossy upstream of the socket no matter what is built: the notification queue overflows in under two seconds during an archive extraction, `truncate(2)` produces no event at all, and edits made while the privileged helper is down never produce any. Every one of those holes ends in the same place — in a `place()` that renames a placeholder over content that exists nowhere else, and counts it as a successful update.

So the file is asked directly. At the three moments the framework itself makes content clean — placement, hydration, upload — it writes down the size and the mtime it just produced (`user.hydration.stamp`). Anything else that writes moves the mtime, and the disagreement is visible without having been told about it. The delta pass now refuses to overwrite a file that is `Dirty`, regardless of what the queue says.

**Two rules came out of the review afterwards, both because the first version broke them.**

*A pass with no news must do nothing.* `apply` had no "already up to date" check, so an upsert for a path that existed locally fell through every guard and landed unconditionally in `place()`. A real delta stream echoes your own uploads back on the next page, and `Discover` itself promises that a full listing behaves like an incremental one — so this is not exotic input, it is the normal case. The consequence was not churn, but that a file the user had just written and had uploaded was turned into a placeholder seconds later. On a machine that is offline the next morning, that is their content, gone. Identity is now checked first, then size, then version — and size regardless of what the etags say, because a provider that reports the same version with a different size contradicts itself, and believing the etag over the bytes would have left a placeholder promising a length the object does not have.

*The clean-state stamp must describe content that is no newer than what was actually sent.* The upload stamped from the file as it was *afterwards*. An edit that landed during the transfer was thereby blessed as sent — it would never have been queued again, and the next change from the cloud would have destroyed it. A stale stamp costs a redundant upload; a fresh one costs the edit. The state is now observed before the sender reads a single byte.

For the same reason the framework stamps after *its own* punches — eviction, dehydration, and the rollback in a failed hydration. Punching moves the mtime, and a placeholder left standing as `Dirty` would have been refused a refresh by the delta pass *and* queued for upload by a resync walk — where uploading it means reading it, and reading it hydrates it back.

`Unstamped` is deliberately not the same as `Dirty` as far as the delta pass is concerned: a file the framework has never written must not be overwritten. But for the *upload direction* it is the signal that was missing, and it took a review to see. Most editors write by creating a temporary file and renaming it over the target. A rename swaps the inode, and the clean-state stamp lives on the inode — so the replacement carries neither a stamp nor a cloud id. The event path catches them; the resync walk, which exists precisely for when the event path did not, skipped the most common form of editing there is.

The walk now takes two kinds: `Dirty`, and `Unstamped` with content and without a cloud id. The second is by definition a file the framework has never *sent* — either because the user just created it, or because a rename replaced one that had been sent. It does not queue the whole directory, because everything the framework has placed, hydrated or uploaded is stamped. It also picks up uploads that failed, which nothing else did.

The channel says so when it has holes. `FromHelper::Resync` is sent on queue overflow — the marker arrives without a descriptor and was previously discarded along with everything else that lacked an fd, so the one signal that says "you have lost changes" was the only one that was silently thrown away. The client then walks the directory and compares the stamp against `stat`. The same happens at startup and every time the privileged helper reconnects, since both are states in which changes happened that no event will ever mention.

---

## 6h. Eviction does not need the privileged side

This was the last item in §8 without a trigger, and the reason was §6b. A trigger has to name a file, and the privileged side never accepts a destination. Giving root a path to punch holes in is worse than giving it a path to write to — it is arbitrary destruction as root — and lending out the ability to suppress events on a named inode is the ability to make any file read as zeros.

The answer was already in creation. A placeholder does not have to be made by hollowing out the file that is there; it can be built on an anonymous inode and swapped in. `place()` does exactly that, without privileges — so eviction is just placement over a file that happens to have content, and the privileged half is not involved at all.

The difference from punching in place, and both are worth knowing:

- **The inode is swapped.** Anyone holding the old file open goes on reading the content they opened — better than having it removed out from under them — and the blocks are freed when they let go. Hard links to the old inode keep the content, so eviction frees nothing for them until the last link is gone. That is the honest outcome, since the content is still reachable under another name.
- **No ignore mark has to be removed.** The old mark dies with the inode, and the new one never had one — so the file is intercepted again by construction rather than by a privileged call that has to be sequenced correctly.

The containment is structural, not checked, and it took a review to get right. The first version took an absolute path and asked whether it *started* with the root. `Path::starts_with` compares components lexically and does not resolve `..` — so every path that escaped began with the root and got through. `evict ../SECRET.txt` replaced a file outside the sync directory with a placeholder whose cloud id resolves nowhere, that is, that file's content destroyed and read as zeros forever. And that is not an exotic situation: a rename out of the sync tree keeps the xattrs, and another sync root under the same parent is `../andre/x`.

`safe_join` already existed for exactly this, on the delta side, and was not used. `reclaim` now takes a relative path and walks it — and then walks the filesystem, since a symlinked subdirectory yields a path that is entirely `Normal` and still lands outside.

The trigger lives in the running daemon, not in the tool, and that is the point: a standalone tool could evict a file the daemon is uploading right now, and the delete-during-upload rule (§5.5) would then see that the inode had swapped and remove the object it had just created. Only the process that owns the queue can refuse that.

`hydrationd`'s own `evict` still exists, for a caller that *does* hold the group — the conformance adapter is one — and punches in place there.

---

## 7. Cost

Assuming the client (auth, Graph API, delta sync) already exists, as it does in the
reference implementation.

| Part | Scope | Estimate |
|---|---|---|
| Privileged helper, supervisor/worker split | fanotify loop, range handling, fail-closed supervisor (§6a) | 2 weeks |
| Privilege boundary and protocol | socket protocol, inode validation, threat model (§6b) | 1 week |
| State store | xattr schema, cloud ID ↔ inode, state machine | 1 week |
| Placeholder/dehydration | sparse creation, `PUNCH_HOLE`, ignore marks, nodump flag | 1 week |
| Change detection and upload queue | debounce, cancellation, queue accounting | 1–2 weeks |
| Mount point setup and systemd | subvolume, ordered mount, `BindsTo`, OOM hardening | 1 week |
| **Hydration policy (§6c)** | pidfd→cgroup, default list, user config, denial log | **2 weeks** |
| **Conformance test suite (§5, §6a)** | the eight invariants, fail closed, deterministic races | **3 weeks** |
| Integration with the reference client | replace `crates/vfs` with a provider implementation | 1–2 weeks |

**Total: 12–15 weeks** to a v1 that is useful for one real cloud client.

The estimate is revised up from 8–12 weeks after this round. The policy and the fail-closed
supervisor are new, mandatory functionality, not decoration — and the policy has a product
part (list, config, visible log) that is not pure programming.

The test suite is the single largest item, and that is right. The six bugs were only
caught because someone wrote tests that hold a PUT open to make the race
deterministic. That technique has to be in the framework from day one — that is the
difference between a framework that makes the bugs impossible and one that merely moves them.

Skills: this is systems programming in userspace. No kernel development, no
upstream submission, no waiting on merge windows. That is a completely different
risk profile from the `ksmbd` comparison.

---

## 8. Minimum useful version

One user, one account, one machine — but correct.

**In:**
1. Sync folder on its **own btrfs subvolume** (or a separate volume), mounted only together
   with the daemon, marked with `FAN_MARK_MOUNT`. Not optional: a directory mark delivers no
   events (§6.4), a bind mount has a detour (§6.4a), and `FAN_MARK_FILESYSTEM` would put all
   of `/home` under a blocking handler.
2. `FAN_MNT_ATTACH` monitoring that speaks up if a new mount exposes the sync files.
   The requirement in §6.4a cannot be enforced, only detected — and then it must not be silent.
3. **Supervisor/worker-split privileged helper with a fail-closed supervisor (§6a).** Not optional —
   without it the architecture is less safe than FUSE.
4. **A deadline per event, and a supervisor that watches progress (§6a-bis).** A hung
   worker cannot be killed and locks up the whole mount; that is a different failure from a
   dead worker, and §6a covers only the latter.
5. **Privilege separation with a specified protocol (§6b).** The root side never sees a token.
6. Placeholder: sparse file, correct size, cloud ID and mode in xattrs, `chattr +d`.
7. Hydration on `FAN_PRE_ACCESS` — the whole file, not ranges (see below).
8. `FAN_MARK_IGNORE_SURV` on hydrated files, so they cost nothing.
9. Change detection → debounce → upload, with the five rules in §5.
10. Dehydration: `PUNCH_HOLE` + remove the ignore mark + set nodump, and a trigger
   the user can run (`hydration-ctl evict <path>`). See §6h — the trigger looked like
   it required the privileged side to accept a destination, and it did not.
11. **Hydration policy (§6c):** pidfd→cgroup, default list, `FAN_DENY_ERRNO(EPERM)`,
   visible denial log.
12. The conformance test suite. All eight invariants, plus the fail-closed test from §6a.
13. `FAN_DENY_ERRNO(EIO)` on download failure — never silent zeros.

**Out of v1, deliberately:**
- **Range-based hydration.** The event gives `offset`/`count`, but the measurement showed that
  `count` is the readahead window, not what the app asked for. Fetching the whole file on first
  access is the right v1: it is what CFAPI and File Provider do by default, and it
  removes a whole class of partial-content bugs. Range-based is an optimization for
  later, when there is measurement data that justifies it.
- Multi-account, shared folders, bandwidth limits, encryption — as you said.
- Automatic eviction on disk pressure.
- Filesystems other than ext4/btrfs/xfs.

---

## 8a. A read past EOF triggers an event

Worth writing down because the opposite assumption is the natural one, and wrong.
`probes/emptyread.c`, 7.1.6:

```
empty (0)      size=0     events=1  read completed
sized (4096)   size=4096  events=1  read completed
```

A read of a file with no bytes therefore fires a pre-content event, exactly like a
read of a file with content. Two consequences:

- **Every empty file in the sync directory costs a round trip** on first read, until
  the ignore mark is set. Unavoidable, and cheap.
- **The empty-file rule in §6a-ter loses no race**, but not for the reason you
  first think. The blocked reader does exist. What closes it is that the rule applies
  only to inodes without a name: a placeholder with content has `st_size > 0` and
  never hits that branch, and an anonymous inode has no cloud object to fetch. There
  is therefore no state in which the rule skips a hydration that should have
  happened.

---

## 8b. `BindsTo=` tears down and does not come back

The units were written with `BindsTo=` because it expresses the requirement precisely: a
marked mount must not outlive the process that answers its events. And it does
express it. But the privileged helper detaches the mount itself on the way out (§6a-bis), and
then systemd reads the resulting stop as *deliberate* and suppresses the restart entirely.

Measured with throwaway units mirroring the pair:

| Dependency | After the privileged helper detaches and exits with 75 |
|---|---|
| `BindsTo=` (as shipped) | service inactive, mount inactive, **0 restarts** |
| `Requires=` | service inactive, mount inactive, **0 restarts** |
| `Wants=` | service active, **mount inactive** |
| `RequiresMountsFor=` | service active, mount active, 2 restarts |

With `BindsTo=`, then, any unrecoverable state — a wedged fetcher, a sync daemon
that disappeared — would take the deployment down permanently. `Wants=` starts the
service again without the mount, which only gives a restart loop.
`RequiresMountsFor=` recovers fully, three out of three, and keeps the safety
property: an administrator's `umount` still stops the service (measured).

The difference is invisible in the unit file and total in practice, which is why it
is written down rather than just fixed.

---

## 8c. Partial filling is safe — measured before it was built

The ceiling on what the framework can serve is today the whole object in memory within a
single deadline. Raising it means filling the placeholder as the bytes arrive, and that
creates a state that does not exist today: a placeholder that is *partially* filled, still
marked, with its reader parked inside the pre-content event.

Four questions decided whether that state is safe. `probes/stream.c`, 7.1.6,
btrfs:

```
event held for a 1 MiB placeholder
  wrote 262144 of 1048576 bytes so far
  events fired by our own partial writes: 0
  a second reader: BLOCKED (its own event is queued behind ours)
  after rollback: size=1048576 blocks=0
  the reader got an error, as it should
```

- **Another reader cannot see the half-written content.** Its own event is queued
  behind the one being served. That was the decisive one: could a bystander read the
  half, streaming would let someone believe a half file, which is exactly the outcome
  the framework exists to prevent.
- **Our own partial writes trigger no events**, so the trap in §6a-ter does not turn
  up in a ninth disguise here.
- **Rollback restores exactly**: size kept, blocks back to zero. §5.7's "the whole
  object or nothing" therefore holds at the filesystem level, not just in the buffer
  logic.
- And the reader gets an error, not zeros.

Measured before anything was built, because the answer to the first question would have
decided whether streaming is a possible path at all.

---

## 8d. `count` is a demand, not a hint — and it changes what streaming can promise

This was stated wrongly in the document. §8 said that `count` is the readahead window
rather than what the app asked for, and used that as an argument for fetching the whole
file. The first is true; the second did not follow, and the difference is dangerous.

`probes/demand.c`, 7.1.6, btrfs — the worker fills exactly what the event asks
for, or half of it, and answers `FAN_ALLOW`:

```
case                                     events    first off  first cnt  reader
read(), fill exactly what was asked           1        36864       4096  real content
read(), fill HALF of what was asked           1        36864       4096  ZEROS
mmap(), fill exactly what was asked           1            0    4194304  real content
mmap(), fill HALF of what was asked           1            0    4194304  ZEROS
```

**Answering `FAN_ALLOW` after writing less than `count` gives the reader zeros.**
Silently: no new event, no error, nothing to see in a log. It is §6a-ter's
trap in its eighth disguise, and the most tempting one so far — it looks like an
optimization ("we have the first part, let the reader start") rather than a shortcut.

Two things follow, and they point in opposite directions:

- **`read()` demands only its page.** A read at offset 40000 gave
  `off=36864 count=4096`. A 10 GB file read sequentially is therefore tens of thousands of
  small, bounded demands — not one big one. For reads the size ceiling disappears
  entirely if hydration becomes *range-based*, without the supervisor, the deadlines or
  §6a-bis having to be touched, and with a reader that can be killed between ranges.
- **`mmap()` demands the whole object in one event.** No streaming can decompose
  that. One event, held through the entire transfer. And mmap is not a corner case:
  it is every ELF loader, every language runtime loading a library, sqlite, `grep` on a
  large file.

Streaming therefore does **not** remove the ceiling. It moves it, from "the whole object
within 30 seconds" to "the whole object within a deadline the framework chooses", and for
mapped reads it is still one demand held through the entire transfer. That is a real
improvement of a couple of orders of magnitude, and it is *not* the same as the limit being
gone. §8 and PROVIDER.md are to state that number, not claim the ceiling has been removed.

Range-based hydration is the real solution for reads, and it is deliberately not
bundled with this change: it introduces a third file state — partially present —
which the store, the manifest, the delta pass, eviction and §5.8 are all two-state
about today.

---

## 9. What I did not get verified

There is no reconnection in the process. A client restart survives by the pair being
built up again, not by the connection being repaired.

In the interest of honesty, since this is meant to be the basis for a decision:

- ~~Directory marks~~ — **closed.** `probes/dirmark.c` measures all four mark types: a plain
  directory mark is accepted and delivers nothing, `FAN_EVENT_ON_CHILD` covers only direct children.
  A mount point of its own is therefore a requirement (§6.4).
- ~~Bind mount~~ — **closed, and the answer came back stricter than the question.** Neither a bind to
  a separate path nor a bind over itself holds; both have a way around that delivers zeros (§6.4a).
  The requirement is that no other mount exposes the files, and that we cannot enforce — only
  detect, with `FAN_MNT_ATTACH`. I have **not** run a probe on the
  `FAN_MNT_ATTACH` subscription itself in isolation, but the exposure guard built on it
  has four tests that run against a real mount (`tests/exposure.rs`).
- ~~`FAN_MARK_IGNORE_SURV`~~ — **closed.** `probes/ignoremark.c`: accepted, it suppresses,
  and it survives modification. The performance claim stands.
- ~~mmap and `truncate` hydration~~ — **closed, and both answers were the good ones.**
  `probes/mmapread.c`, 7.1.6: a *mapped* read of a placeholder fires one event and
  the reader gets hydrated content. That was the most dangerous open point here — most
  language runtimes, databases and every ELF loader map rather than read, and an uncovered
  mmap would have handed them the hole with no error. `truncate` fires too, and what
  survives a truncation is the real content, not zeros. Uncovered, a truncated
  placeholder would have become the first N *zeros* — worse than zeros, because the
  result looks like a deliberate edit and would have been uploaded.
- ~~In-flight events when the worker dies~~ — **closed, and it was a real hole.**
  An event the worker had already read out of the queue left the reader hanging
  unbound; the supervisor could not answer something it never saw. Closed by having the worker
  publish its fd number — responses are matched on the number within the group. See §6a.
- ~~`FAN_REPORT_PIDFD`~~ — **closed.** `probes/pidfd_cgroup.c` gets the pidfd from the event,
  looks up the pid and reads the cgroup. Verified that the cgroup distinguishes two readers with
  identical `comm` and `exe`. §6c no longer rests on an assumption.
- ~~nodump in practice~~ — **closed, and the answer was "almost none."** GNU `tar` and `rsync`
  have no support; `bsdtar` and `borg` only with an explicit flag; `restic` not at all.
  Layer 2 in §6c falls as an automatic mitigation, and the manifest in §6d carries
  completeness alone.
- §5.7 is written from what is safe (the SIGBUS risk of `ftruncate` under an
  `mmap`ed reader is real and well known), but I have **not** run a probe that
  demonstrates the mismatch case end to end. It should go into the conformance suite before §5
  is locked.
- The performance numbers in §2.3 are on tmpfs with a trivial C daemon. A real Rust/tokio daemon
  with database lookups is substantially slower, and on NVMe the ratio looks different.
  The numbers show the structure — passthrough removes the userspace round trip — not absolute
  values you can plan capacity from.
- The kernel source I read was `torvalds/linux` master, not exactly 7.1.6-cachyos.
  The headline findings (`CAP_SYS_ADMIN` in `backing.c`, `SB_I_ALLOW_HSM` in the three
  filesystems, `FOPEN_PASSTHROUGH_MASK`) match the local uapi header and the
  measurements, so I consider them reliable.

All probes ran in the scratchpad area on isolated mount points (loopback btrfs
for the HSM test, never on `/home`), and everything is cleaned up — no mount points,
loop devices or processes are left behind.

---

## 10. Next steps

> **Status as of now:** everything in §8's v1 scope is built and verified — 294 tests,
> eight privileged suites against a real kernel, and an end-to-end smoke run
> with both real binaries. Two of five parts of a Graph provider are written
> (`crates/hydration-graph`): the mapping layer and the delta driver. The upload
> side, authentication and the seam that lets a provider plug into
> `hydration-sync` remain, and nothing here has talked to real Graph.
> The tracks below are kept as they were written, because the order they proposed is
> the one that was actually followed.


If you agree with the direction, the natural order is:

Two tracks, in parallel.

**Track A — the conformance suite.** ✅ **Built and run against the reference client.**

`conformance/` contains the invariants written against a `Harness` trait that knows
no implementation, and `adapters/onedrive-reference/` runs them against a real FUSE mount,
a real sync engine and real SQLite, against a fake Graph API the suite can drive.

The suite was first run against `f1f090c` — the client as it was when the contract was written —
and then against `a6312a8`, where the three findings are fixed and merged.

| Invariant | `f1f090c` | `a6312a8` |
|---|---|---|
| 5.1 identity is stable | PASS | PASS |
| 5.2 size is local truth | PASS | PASS |
| 5.3 mode survives dehydration | **FAIL** | PASS |
| 5.4 atomic save keeps the name | PASS | PASS |
| 5.5 deletion kills an in-flight upload | PASS | PASS |
| 5.6 `fsync` does not lie | PASS | PASS |
| 5.7 hydration mismatch fails closed | **FAIL** | PASS |
| 5.8 a placeholder occupies no disk | **FAIL** | PASS |
| 6a worker death fails closed | N/A | N/A — no separable worker |

**The first run is the interesting one.** Five of eight already passed, including 5.4 and
5.5 — exactly the two bugs the client fixed in #51 and #52. The suite independently confirmed that
those fixes held, and so separated what was solved from what was not, instead of
just accusing.

The three that failed are fixed in
[#55](https://github.com/franzjeger/OneDriveForLinux/pull/55). 5.3 was `setattr` accepting
a mode change and discarding it — and, less visibly, the mode being orphaned when
the upload adopted the real OneDrive ID. 5.7 was a download that ended early
and was served as a short file. 5.8 was `blocks` computed from `size`.

**The second half of 5.3 is the argument for the suite.** It was not visible from
reading the source; it showed up because the test kept failing after the obvious fix
was in place. That is a class of bug — something that works right up until an async operation
completes — that the client has had four of before, and that no code review caught.

**Track B — the probes that could overturn the architecture (§9).** ✅ **All run.**

| Probe | Answer |
|---|---|
| pidfd→cgroup | works; the cgroup distinguishes readers that are identical on `comm` and `exe` |
| Directory marks | does not work — the mark is accepted and delivers nothing (§6.4) |
| Bind mount | does not hold — every variant has a way around (§6.4a) |
| `FAN_MNT_ATTACH` | works, but needs its own group; the event is a trigger, not a lookup |
| `FAN_MARK_IGNORE_SURV` | works, and survives modification — the performance claim stands |
| In-flight events | was a real hole; closed by publishing the fd number (§6a) |
| nodump in practice | almost no tool respects it — layer 2 falls (§6c) |

None of them overturned the architecture. Three of them made a requirement stricter, and two found a
silent failure of the same family as the eight invariants: something that answered "fine" to something
it had not done.

**Next:** the privileged helper — super/worker from §6a — as the smallest thing
that makes the fail-closed test and the first invariant from Track A pass.

The probes and the logs from this investigation are in the scratchpad area
(`ptprobe.c`, `hsmprobe.c` and measurement logs) if you want to run them yourself.

---

## 11. Build the framework, or fix the client?

**Recommendation: fix the three findings in the client now. Build the framework only as a deliberate
product bet — not as a rescue operation.**

The conformance run produced information the design document did not have when §1 was written, and it
points a different way than I expected.

**The client is closer to correct than it looked.** Five of eight invariants pass, and the two
that pass and were hardest — atomic save and deletion during upload — are real
distributed races that no architecture gives you for free. They were solved in userspace, in FUSE, and
the fixes hold under an independent test that was not written by the person who fixed them.

**The three that fail are ordinary bugs, not architectural impossibilities.** Each of them
is days, not weeks:

| Finding | What it takes in FUSE |
|---|---|
| 5.3 mode | Store the mode in the database and answer with it from `getattr`. `setattr` is already accepted; it is just discarded. |
| 5.7 hydration mismatch | Verify length and etag before the content is served; discard a partial download instead of delivering it. |
| 5.8 blocks | Report `blocks = 0` for placeholders in `getattr`. |

**And the fanotify path is no safe harbor.** Three of the last four probes found a silent
failure of exactly the family this project exists to kill: a directory mark that is
accepted and delivers nothing, a bind mount that looks like it covers and has a way around it, a
worker death that hangs the reader instead of answering. All are solvable — but they are *new*
things to get right, and they come on top of what the client has already gotten right.

It is worth saying plainly, since §1 and §3 argue the other way: **it is still true
that the kernel owns the POSIX contract better than we can, but that is a smaller part of the total
than the document assumed.** The framework moves which things you have to get right — it does not
remove the list. The POSIX part goes away; mount topology, privilege separation, fail-closed
supervision and hydration policy come in its place, and the last three do not exist in a FUSE client
at all.

### What the framework actually buys

Two things, and both are long-term:

1. **The bug classes become impossible, not fixed.** Five of eight invariants are free on a real
   filesystem. Over years of changes that is the difference between not being able to introduce the
   bug and having to test for it every time.
2. **Zero cost in the data path.** Measured: a hydrated file carrying the ignore mark is an ordinary
   btrfs file. No daemon, not even the 8 % FUSE passthrough costs.

### The decision rule

- **Is OneDrive-on-Linux the product?** Fix the three. 12–15 weeks on a framework is not
  defensible for three bugs that take days.
- **Is *cloud files on Linux* the product** — several providers, or a foundation others can
  build on? Then the framework is right, and then it is worth the full price in §7.

That is a product decision, not a technical one. Technically both paths are viable, and this
investigation has made both of them safer than they were.

### Either way

The conformance suite is what makes both safe, and it is done. It is also the only thing
here that does not have to be traded away: it runs against the client today, it runs against the
framework if it gets built, and it survives the choice being reversed.

# HydrationAPI

A hydration framework for cloud files on Linux — the equivalent of macOS' File
Provider and Windows' Cloud Files API. Files appear as ordinary local files with
their real size and metadata; their content is fetched on first access.

**Status: phase 1 — design and feasibility. No framework implementation yet.**

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
| `crates/hydration-protocol/` | The wire format across the privilege boundary |
| `probes/` | Feasibility probes that settled specific questions |

## The framework

Under construction. `crates/hydrationd` is the privileged half — the part that
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
| **both processes die** | **not covered** — needs the mount torn down (§6.4a) |

```bash
cargo test -p hydrationd                     # unit + placeholder behaviour
sudo -E HYDRATIOND_TEST_MOUNT=/mnt/scratch \
  cargo test -p hydrationd --test fail_closed  # needs root and a real mount
```

What is not built yet: the unprivileged sync daemon, the socket that connects
the two halves, the state store, change detection and upload, and eviction.
See DESIGN.md §8 for the v1 scope.

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

## Non-goals for v1

Multi-account, shared folders, bandwidth limits, encryption. One user, one
account, one machine — done correctly.

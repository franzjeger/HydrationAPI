# Working in this repository

A hydration framework for cloud files on Linux, built on fanotify pre-content
events, plus a Microsoft Graph provider on top of it. [DESIGN.md](DESIGN.md) is
the real document — 1700 lines, numbered sections, and it is kept accurate. When
this file and DESIGN.md disagree, DESIGN.md wins and this file is stale.

Read [README.md](README.md) for what is built and what is not.

## Before you claim something works

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --no-fail-fast
```

And, for anything touching the kernel path, placeholders, or eviction — on a real
mount, not tmpfs:

```bash
sudo ./deploy/run-privileged-tests.sh /mnt/scratch /path/to/fs.img
sudo ./deploy/smoke.sh /mnt/scratch      # needs the binaries built first
```

CI runs all of this on four filesystems. It is `.github/workflows/ci.yml` and it
is expected to be green; a red CI is a thing to fix, not a thing to note.

`HYDRATION_TEST_DIR` chooses the filesystem the tests run on. Not
`CARGO_TARGET_TMPDIR` — that is a compile-time macro and exporting it is silently
ignored, which once turned a four-filesystem matrix into the same filesystem four
times, all green.

## Traps that have already cost real time

**Block counts do not answer "does this file hold its content."** `st_blocks`
reports the same number for an empty file and for a placeholder truncated to its
object's size, on every filesystem — and on ext4 with a small inode a placeholder
is charged a block for its extended attributes. Ask `placeholder::holds_data`
(`SEEK_DATA`). This was a production bug, not just a test bug, and it survived
several rounds of review. See §8z for the measurements.

**Test helpers do not go in crates that ship.** There was a public
`occupies_disk` with no callers, documented as "not a placeholder test", sitting
in a runtime crate. A documented trap is still a trap. Test-only helpers live in
`crates/test-scratch`, a dev-dependency.

**A write inside a marked mount, by the only process that can answer the event it
fires, is a deadlock.** This is §6a-ter and it has appeared in eight distinct
disguises so far, each of which looked like a different problem. Any new code
that writes inside the sync root needs checking against that list first.

**`count` in a pre-content event is a demand, not a hint.** Fill less than it
asks and answer `FAN_ALLOW`, and the reader silently gets zeros — no second
event, no error. §8d, `probes/demand.c`.

**Never invent a diagnostic.** A script that reports "could not build" because it
sent the compiler's stderr to `/dev/null` cost two CI rounds; the real message
was "cargo: not found". Print what actually happened, or say explicitly that
there was no output.

## How to work here

**Groundwork before tests.** Write down what the kernel or filesystem actually
does — measure it, with a probe in `probes/` if needed — before writing a test
that asserts it. Tests written the other way round have repeatedly passed while
being unable to fail for the reason they claimed. A green test that has never had
to change is not evidence that it still measures anything.

**Prefer a measurement to an argument.** Most of the hard questions here were
settled by a fifty-line C program, and `probes/` is where they live. Add to it.

**Commit messages carry the reasoning.** They are long on purpose: what was
wrong, what was measured, what was rejected and why. Match that.

Comments explain *why*, and especially why the obvious alternative is wrong.
There is a lot of load-bearing subtlety here and the code is written for someone
who does not already know it.

## Layout

| | |
|---|---|
| `crates/hydrationd/` | privileged helper: fanotify, supervisor/worker split, fail-closed |
| `crates/hydration-client/` | unprivileged sync daemon: delta, uploads, eviction, placement |
| `crates/hydration-protocol/` | the wire format between the two halves |
| `crates/hydration-graph/` | Microsoft Graph: auth, delta, upload |
| `crates/test-scratch/` | dev-dependency; scratch dirs and the block-floor probe |
| `conformance/` | the invariants a provider must satisfy |
| `probes/` | C programs that measure kernel behaviour; the source of most claims |
| `deploy/` | privileged test runner, end-to-end smoke, systemd units |

## What is next

The Graph provider. The seam is `CloudAccess` in
`hydration-client/src/daemon_loop.rs`; nothing but the demo `FolderCloud` has
been through it end to end, and nothing has met a live account yet.
`docs/GRAPH-GROUNDWORK.md` and `docs/GRAPH-DISCOVER-GROUNDWORK.md` are the
groundwork, with the critiques kept verbatim.

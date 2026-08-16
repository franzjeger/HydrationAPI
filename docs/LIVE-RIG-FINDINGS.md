# Findings and planned work from the OneDriveHydration live rig

Measured against this framework on a production mount (165 424 files,
btrfs subvolume, KDE Plasma 6.7.4), 2026-08-16. The product-side
observations and the user-facing feature list live in the OneDriveHydration
repo (`docs/LIVE-RIG-FINDINGS.md`); this file records what the framework
itself shows and what changing it would cost.

## Measured per-hydration cost

- A **0-byte** placeholder takes **~300 ms** to hydrate
  (359/292/315 ms over three runs). A bare `open+read` of the same file from
  C costs the same ~300 ms, and `onedrive-hydrationctl` with no arguments
  costs 0 ms — so the time is the framework's round trip, not the shell or
  the Rust spawn.
- A 39 KB file takes **~609 ms**: the same ~300 ms base plus the fetch.
- The control-socket call `status` takes **~865 ms** — the socket round
  trip itself is not cheap.

## The serialisation, cited

`crates/hydrationd/src/daemon.rs:387` creates one request channel
(`req_tx`/`req_rx`), and `daemon.rs:401` spawns **one** fetch thread that
loops on `req_rx.recv_timeout(HEAL_EVERY)` and serves jobs strictly in
order, each `fetch.fetch_into(...)` (`daemon.rs:416`) to completion before
the next `recv`. There is no queue of in-flight fetches and no second
thread. This is what makes the ~300 ms per-file floor *serial*: 17 224
files ≈ **87 minutes**, and no batching on the product side removes it
because the latency is per network round trip.

## EIO while busy (observed live)

With a pull in flight, a `hydrate` for a file in a *different* folder
returns `error: Input/output error (os error 5)` rather than queueing or
blocking. The product wrappers currently surface this as a per-file
failure. Two readings:

- **As a bug:** a busy daemon should answer "wait", not "I/O error".
- **As intended:** EIO is the fail-closed answer for a request the daemon
  cannot serve right now, and the *caller* is the one that knows whether to
  retry. The product-side fix (retry with backoff on EIO) is cheap and
  needs no framework change; this file records it so the framework is not
  also "fixed" into queueing, which would change the fail-closed property.

## Planned framework work (each needs a threat-model pass)

1. **Request pipelining / fetch concurrency.** The protocol already carries
   an `id` per request, which is the seam: a fetch-thread pool (or a
   pipelined connection) keyed on `id`, plus daemon-side concurrency for the
   `write_at`/`tick` callbacks. This is the *only* thing that breaks the
   ~300 ms serial floor. It weakens the single-flight property — one
   connection, one request outstanding — that keeps two files from
   substituting each other's content, so it is a security-relevant change,
   not a config toggle. Nothing in this file is a commitment to do it.
2. **Byte-level progress on the wire.** The daemon reports fetch progress
   per job (`Step::Progress(total)`, `daemon.rs:412-413`), but the
   product-facing D-Bus surface only exposes the *count* of downloads in
   flight. Exposing bytes-transferred/bytes-total per file (and per batch)
   is a daemon+protocol change; the product's tray/flyout and progress box
   are waiting on it.
3. **Batch progress push.** The "N of T" batch state lives in the product's
   shell wrapper, invisible to the daemon. A `BatchStart(total)` /
   `BatchTick(n, bytes)` pair on the D-Bus surface would let the tray show
   the same number the box shows. Product-side, this is the wrapper calling
   a new method; framework-side, it is a new verb to define and test.
4. **Quota / storage-used.** Not in the D-Bus surface; the flyout wants it.
   Framework-side: expose it from the daemon. Product-side: render it.
5. **Pause/resume.** Not implemented anywhere. Framework-side: a verb that
   stops new fetches and (decision needed) either lets in-flight ones finish
   or fails them. Product-side: a button.

## What this file deliberately does not do

It does not change `daemon.rs`, the protocol, or the fetch thread. The
measurements above are the input to the threat-model pass each item needs;
the house rule is that these are written down *before* the code, with the
obvious-but-wrong reading named at each fork.

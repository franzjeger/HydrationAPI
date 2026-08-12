# Writing a provider

What the framework guarantees, and what it demands of you.

A worked example is in `crates/hydration-graph`: the Microsoft Graph mapping
layer and delta driver, with `namespace::Namespace` doing the folder-move
expansion described below. The groundwork both were written from — including the
critiques of that groundwork, kept verbatim — is in `docs/`.

Everything here is enforced by tests you can run — `cargo test -p hydration-client
--test hostile_cloud` is a cloud that breaks each rule on purpose. If your
provider passes against a real service what that file asserts against a fake one,
you are most of the way there.

There are three traits. None of them are about POSIX; the framework owns all of
that.

```rust
trait Provider { fn fetch(&mut self, cloud_id: &str, size: u64, tag: Option<&str>,
                          span: Span, out: &mut Body<'_>) -> io::Result<()>; }
trait Sink     { fn upload(&mut self, path: &Path, existing: Option<&str>) -> io::Result<Uploaded>;
                 fn remove(&mut self, cloud_id: &str) -> io::Result<()>; }
trait Discover { fn changes(&mut self, cursor: &Cursor) -> io::Result<(Vec<Change>, Cursor)>; }
```

And one factory that hands them out, which is the whole of how a provider is
plugged in:

```rust
trait CloudAccess: Send + 'static {
    type Fetch: Provider; type Upload: Sink; type Changes: Discover;
    fn provider(&self) -> io::Result<Self::Fetch>;
    fn sink(&self) -> io::Result<Self::Upload>;
    fn discover(&self) -> io::Result<Self::Changes>;
    fn preflight(&self) -> io::Result<()> { Ok(()) }  // defaulted
}
```

Three roles rather than one object because the daemon runs them on separate
threads — the fetch loop, the upload driver and the delta pass each get their own
instance, and none of them shares a lock with the others. **If your roles share
state — a token cache, most obviously — that state has to be `Sync` and it has to
refresh single-flight**, because three instances will be alive at once and a
token that expires expires for all three at the same moment.

`preflight` is called once at startup and nowhere else. Put the credential check
there: a missing token should stop the daemon starting, not surface as an `EIO`
on somebody's first read an hour later.

Then a binary is an argument parser and one call:

```rust
daemon_loop::run(Config { mount, socket, debounce }, MyCloudAccess::new(..))?;
```

`Config` carries no cloud directory, endpoint or credential — those are yours,
and `hydration-sync` (about eighty lines, all of it argument parsing) is the
worked example. See `providers::FolderAccess` for the smallest possible
implementation.

---

## The one rule everything else serves

**A read must never quietly return the wrong bytes.**

Not "rarely". A wrong byte that arrives with an error is a bad day; a wrong byte
that arrives with success is a corrupted backup nobody notices for a year. Every
rule below exists because some way of being helpful turns into that.

---

## `Provider::fetch`

**Verify the content, not just its length.** The framework's only integrity
check is the length, in both halves — so a service that returns the right number
of wrong bytes passes. OneDrive supplies `quickXorHash` and often `sha1`; check
one. "A wrong byte that arrives with success" is the failure this whole project
is arranged against, and length alone does not catch it.

**Write the object into `out`, and let `out` hold you to it.** Usually the whole
implementation:

```rust
fn fetch(&mut self, id: &str, _size: u64, _tag: Option<&str>,
         span: Span, out: &mut Body<'_>) -> io::Result<()> {
    let mut body = self.http.get(self.url(id))
        .header("range", format!("bytes={}-{}", span.offset, span.end() - 1))
        .send()?;
    std::io::copy(&mut body, out)?;
    Ok(())
}
```

`span` is what a reader actually demanded, and it is usually far smaller than the
object — opening a 2.77 GiB archive to look at its header is a 4096-byte demand
(§8d-bis). If your service has no ranged reads, fetch the object and write only
the span out of it; that is correct, and no worse than what every fetch did before
ranges existed. It is not optional, though: `Body` refuses bytes past the span,
and a whole-object transfer behind a small read is what made multi-gigabyte files
unreadable.

`Body` knows how much you owe before you start, because the framework took the
size from the placeholder rather than from you and the span from the kernel.
Writing past it fails at the offending byte; finishing short becomes an abort
rather than a truncated file. There is no
partial success here and adding one is not a small change — §5.7 exists because a
half-hydrated file is indistinguishable from a real one afterwards. Returning
`Err` abandons the transfer cleanly: the placeholder is put back exactly as it
was and the reader gets an error.

**Keep sending, or fail.** Three limits bound a transfer, and they ask different
questions: the service has 30 seconds to send anything at all, 60 seconds to send
anything *more* once it has started, and 10 minutes in total. So a slow link is
fine and a stopped one is not — but a silent retry inside `fetch` looks exactly
like a stall to the framework. Retry at the sync level, where nobody is waiting,
and keep writing while you are being read.

**`cloud_id` is whatever you returned from `upload` or put in a `Change`.** The
framework never parses it. It can be a Graph item id, a URL, a JSON blob — but it
must survive a round trip through an extended attribute, so keep it under a few
hundred bytes and free of NUL.

## `Sink::upload`

**Read the file at call time, not when the job was queued.** You are given a path
that was resolved *now*. Upload rule 2: the content that goes up is the content
at send time, because the user may have saved three more times while the debounce
ran.

**Return the id the service actually used.** If an update produces a new id —
some services renumber — return the new one. The framework records what you
return, and a file pointing at an object the service has replaced can never be
fetched again.

**An error means "not sent".** If the object was created but the response failed,
returning `Ok` is worse than returning the error: the framework stamps a
successful upload as clean, and a clean file with an unsent edit is one a later
remote change will overwrite. Return the error and let it be retried; a duplicate
object is recoverable, a lost edit is not.

**`existing` is the id you gave last time, if any.** Use it to make the write
conditional if the service supports that — it is how you avoid clobbering a
change somebody else made.

## `Sink::remove`

**Already-gone is success.** The framework calls this when the local file was
deleted, and a `remove` for something that is not there means the state you
wanted. Returning an error makes the framework retry forever.

## `Discover::changes`

**Report everything you know about, not only what changed.** The reconciler
decides what to do by looking at the disk, and it is written so that a full
listing and an incremental one behave identically — a replayed listing produces
no work. Filtering to "things the service says are new" means a placeholder the
user deleted locally never comes back.

**Paths are relative to the sync root, with `/` separators.** They are treated as
untrusted input: `..`, absolute paths, and the framework's own names are refused,
not sanitised. A refused path is reported in `Applied::failed` and the rest of the
batch still applies, so one unusable item does not halt sync.

**Supply an `etag` if you possibly can.** Without one the framework falls back to
comparing sizes, and a same-size remote edit is then invisible. With one, it
knows precisely when to refresh. It is opaque — any string that changes when the
content changes.

**`size` must be the object's real size.** It becomes the placeholder's size, and
a placeholder whose size disagrees with what `fetch` returns is refused on every
read (§5.7) — a file that exists and can never be opened. If your service does
not report sizes reliably, that is a reason not to create the placeholder yet.

**A moved object keeps its id.** Report it at its new path with the same
`cloud_id` and the framework renames the local file. Report it with a *new* id and
you get two local files claiming one object, which is how a later delete removes
the wrong one.

**`Cursor` is yours, and it does not survive a restart.** The framework holds it
in memory and hands it back for the life of the process; it does not persist it.
Every restart is therefore a full enumeration — for a 100k-item drive that is
several hundred paged requests against a throttling endpoint. **Persist it
yourself** if that matters, which it will.

If your token expires — Graph's do — return a full listing and a fresh cursor.
That is a supported outcome, not a failure, and it costs nothing because a
replayed listing is a no-op.

**At most one change per object per batch.** If you page through a delta
enumeration and concatenate the pages, deduplicate first: Microsoft documents
that one enumeration may return the same item more than once, last occurrence
authoritative. The framework coalesces defensively, but a provider that relies on
that is relying on an implementation detail.

**Use a *content* version tag, not `eTag`.** On Graph, `eTag` changes when an
item is renamed or its metadata is touched; `cTag` changes when the content
does. Map `eTag` and every remote move looks like a new version — which for a
*hydrated* file means the framework discards the local copy and replaces it with
a placeholder. A folder move in the web UI would dehydrate the whole tree, on a
laptop that may be offline by evening.

**Folder moves are yours to expand, and the framework now does it for you.**
Graph's delta does not re-enumerate a folder's descendants when the folder moves:
you get one change for the folder and nothing for the thousand files inside it.
Skip that and the local tree splits — old files stay under the old directory, new
ones appear under the new, and no single change looks wrong.

`hydration_client::namespace::Namespace` holds the remote tree and turns items
into the changes they actually mean. Feed it `Item::{Root, Upsert, Delete}` and
it returns `Change`s at correct paths, expanding a folder move into one
`Upserted` per descendant and a folder delete into one `Removed` per file.

Mapping Graph onto it has six traps, and each one has bitten somebody:

- **Detect the `root` facet** and emit `Item::Root`. The drive root genuinely has
  no `parentReference`, so a provider that misses the facet has an item with no
  parent — which the type will not let you express, deliberately.
- **`parentReference.id` can be absent** on shared items, `remoteItem` links and
  some recycle-bin entries. That is not a root. Hold or refuse it; do not invent
  a parent.
- **`root` appears in every delta page.** Re-sending it is fine; sending a
  *different* id is a second drive, and one tracker holds one drive.
- **A delete is a `deleted` facet on an otherwise normal item**, not a separate
  object — it still carries `parentReference` and `name`. Check facets in the
  wrong order and a deletion maps as an upsert, which resurrects the file.
  Recycle-bin moves arrive as deletes with no counterpart create.
- **`remoteItem`**: the `file`/`folder`/`name`/`size` facets live *inside* it;
  the top-level item is a link. Read the top level and a shared folder looks like
  a file. Its children live on another `driveId`, so item ids are unique only per
  drive — key your own state by `(driveId, itemId)`.
- **The `package` facet** (a OneNote notebook) is a folder that must be opaque.
  Map it to `Kind::Opaque`: tracked for pathing, never walked into. As a folder
  you sync a notebook's internals and corrupt it; as a file its size is not real
  and every read is refused by the length check.

**Reject names the path grammar cannot hold** — empty, `.`, `..`, anything
containing `/` or NUL — before they reach the framework. `Namespace` does this
and records why in `problems()`. The framework refuses them too, but silently and
terminally: the change lands in `Applied::failed`, the pass is not marked
retryable, the cursor advances, and the service never mentions the item again.

**Persist the tree, and persist it before the token.** A delta token is worthless
without the tree it described. `Namespace::snapshot()` and `restore()` round-trip
through the public `Item` type, so store them however you already store anything.
The ordering is not a preference:

> Write the tree first, then the token. On any doubt, discard the token and keep
> the tree.

A tree newer than its token is harmless — the replayed items are no-ops. A token
newer than its tree is unrecoverable: every move in between is lost, and a delta
feed never re-reports an unchanged item, so nothing self-corrects. And note what
recovery cannot do: `listing()` says what exists, never what stopped existing, so
a provider resuming after an expired token must diff a fresh enumeration against
its previous snapshot to find remote deletions it slept through.

**Report each object at its full root-relative path**, not its basename. The
framework translates a path change into a local rename, so a provider that
reports `report.pdf` for a file it was given as `Documents/report.pdf` will have
the user's file moved to the sync root on the next pass.

---

## What the framework guarantees you

- **It asks for exactly the range a reader demanded, and never more.** The
  measured `count` in a pre-content event is what the application asked for, not a
  readahead window: a 4 KiB read of a 2.77 GiB object demands 4096 bytes, at any
  object size (§8d-bis, `probes/bigdemand.c`). Spans never run past the object,
  and a span may legitimately be the whole object — check `span.is_whole(size)`
  before verifying a whole-object content hash, because a range cannot be checked
  against one.
- **A file is only reported hydrated when every byte of it has arrived.** Ranges
  accumulate across reads; until the object is complete the file keeps its
  placeholder mark and you may be asked for more of it.
- **Each instance is called from one thread at a time.** The shipped daemon
  builds a *separate* instance per role — the startup check, the upload thread,
  the delta thread, the fetch loop — and three of those run concurrently. So one
  instance never races itself, but your implementation does race itself, and for
  a Graph provider that is the difference between working and signing the user
  out: MSAL rotates the refresh token on use, and two concurrent refreshes of a
  single-use token produce `invalid_grant`. **Share the token cache across
  instances and make the refresh single-flight.**
- **It never hands you a path outside the sync root**, and never a path it
  constructed from something you said without checking it first.
- **It handles every POSIX question**: identity across renames, size and mtime
  with unsent changes, atomic save, delete during upload, `fsync`, backup
  visibility. If you find yourself thinking about inodes, something is wrong.
- **It fails closed.** If your provider is unreachable, readers get `EIO`. They
  never get zeros.

## What it does not do for you

- **Credentials, tokens, refresh.** Yours entirely, and deliberately: the
  privileged helper never sees them (§6b).
- **Conflict resolution.** When the framework refuses to overwrite local content
  it reports it in `Applied::kept_local`. Presenting that to a user is your job.
- **Rate limiting.** If the service throttles you, back off inside your own
  scheduling. The framework will keep offering the file until it is sent, because
  a failed upload leaves it visibly unsent rather than silently dropped.

---

## Before you ship

Run these against your provider, not against a fake:

0. Move a folder with a thousand children in the web UI. You must end with the
   tree moved, not split.
1. Kill the network mid-fetch. A reader must get `EIO`, never a short file.
2. Kill the sync daemon while a file is dehydrated. Reading it must fail, not
   return zeros. (`deploy/smoke.sh` does this against the reference provider.)
3. Edit a file while its upload is in flight. The edit must still be sent
   afterwards.
4. Move a file in the web UI. You must end with one local file, not two.
5. Let the delta token expire. Sync must resume without re-downloading the world
   or re-uploading it.
6. Edit the same file on two machines, then let both sync. Decide what you want
   to happen *before* you find out what does — the framework protects the local
   copy on the way down and has no opinion on the way up.
7. Create a file the service will refuse — `aux.c`, `report .pdf`, `a:b.txt`.
8. Read a file bigger than 30 seconds of your bandwidth. It will fail; see the
   size ceiling below.
9. Fill the disk during a hydration. The placeholder must be left as it was, not
   half-filled.

The conformance suite (`conformance/`) covers the framework's side of all eight
contract invariants. These six are the provider's side, and nothing else checks
them.

---

## Two ceilings to know about before you design around them

**There is a total transfer cap, and it is not going away.** Ten minutes by
default. It is chosen from *how long a filesystem operation may block*, not from
how big a file may be — because the reader is inside `read()` the whole time and
cannot be killed by a signal (§6a-bis), so an uncapped transfer means a user with
an unkillable process for hours.

So the ceiling is `cap × bandwidth`: tens of gigabytes on a decent link, rather
than the few hundred megabytes the old whole-object design allowed. That is a
real improvement of roughly sixty-fold, and it is **not** the same as no limit.
Above it, refuse the object with a clear error rather than spending ten minutes
to fail anyway.

The cap now bounds **one span**, not the object, so an ordinary `read()` of any
size of any object is nowhere near it. What is still bounded by it is a single
large *demand* — and the one that matters is `mmap` over a whole object, which
asks for the whole object in one event. Mapping a *window* or a *segment* demands
only that window (measured, §8d-bis — this corrects §8d, which could not tell the
two apart on a 4 MiB file), so a segment-mapping ELF loader is fine. A program
that maps a multi-gigabyte file in one call is not, and for it the cap is the
ceiling, exactly.

While a large span is in flight the worker reports progress every five seconds,
because a transfer that is working and one that is wedged are otherwise
indistinguishable from outside for as long as either lasts.

**Restoring from a backup needs a procedure you have to write.** A restore
reproduces content without extended attributes, so every restored file looks like
content the framework has never seen: it will be uploaded as a *new* object,
while the delta side still reports the old objects at the same paths. The result
is duplicates remotely and permanent conflicts locally. The manifest (§6d) tells
a user what a backup was missing; nothing yet helps them come back. If your
client offers restore, it needs an adopt step that reattaches ids before sync
resumes.

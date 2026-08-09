# Writing a provider

What the framework guarantees, and what it demands of you.

Everything here is enforced by tests you can run — `cargo test -p hydration-client
--test hostile_cloud` is a cloud that breaks each rule on purpose. If your
provider passes against a real service what that file asserts against a fake one,
you are most of the way there.

There are three traits. None of them are about POSIX; the framework owns all of
that.

```rust
trait Provider { fn fetch(&mut self, cloud_id: &str, size: u64, out: &mut Body<'_>) -> io::Result<()>; }
trait Sink     { fn upload(&mut self, path: &Path, existing: Option<&str>) -> io::Result<Uploaded>;
                 fn remove(&mut self, cloud_id: &str) -> io::Result<()>; }
trait Discover { fn changes(&mut self, cursor: &Cursor) -> io::Result<(Vec<Change>, Cursor)>; }
```

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
fn fetch(&mut self, id: &str, _size: u64, out: &mut Body<'_>) -> io::Result<()> {
    let mut body = self.http.get(self.url(id)).send()?;
    std::io::copy(&mut body, out)?;
    Ok(())
}
```

`Body` knows the object's size before you start, because the framework took it
from the placeholder rather than from you. Writing past it fails at the offending
byte; finishing short becomes an abort rather than a truncated file. There is no
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

**Folder moves are yours to expand, and this is the largest hidden piece of
work.** Graph's delta does not re-enumerate a folder's descendants when the
folder moves: you get one change for the folder and nothing for the thousand
files inside it. The framework only knows about files. So a provider has to keep
its own id→path map of the remote namespace and turn a folder move into one
`Upserted` per descendant. Skip this and the local tree splits — old files stay
under the old directory, new ones appear under the new.

**Report each object at its full root-relative path**, not its basename. The
framework translates a path change into a local rename, so a provider that
reports `report.pdf` for a file it was given as `Documents/report.pdf` will have
the user's file moved to the sync root on the next pass.

---

## What the framework guarantees you

- **It never asks for a range.** v1 fetches whole objects. The pre-content event
  does carry an offset, but the measured `count` is the readahead window rather
  than what the application asked for, so range-based fetching would be guessing.
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

Note what streaming does *not* fix. A `read()` demands only the page it needs, so
a sequentially-read file produces many small demands — but a **mapped** read
demands the whole object in one event (measured, §8d), and nothing can decompose
that. `mmap` is every ELF loader, every runtime loading a library, sqlite, `grep`
on a large file. For those the cap is the ceiling, exactly.

**Restoring from a backup needs a procedure you have to write.** A restore
reproduces content without extended attributes, so every restored file looks like
content the framework has never seen: it will be uploaded as a *new* object,
while the delta side still reports the old objects at the same paths. The result
is duplicates remotely and permanent conflicts locally. The manifest (§6d) tells
a user what a backup was missing; nothing yet helps them come back. If your
client offers restore, it needs an adopt step that reattaches ids before sync
resumes.

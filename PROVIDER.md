# Writing a provider

What the framework guarantees, and what it demands of you.

Everything here is enforced by tests you can run — `cargo test -p hydration-client
--test hostile_cloud` is a cloud that breaks each rule on purpose. If your
provider passes against a real service what that file asserts against a fake one,
you are most of the way there.

There are three traits. None of them are about POSIX; the framework owns all of
that.

```rust
trait Provider { fn fetch(&mut self, cloud_id: &str, size: u64) -> io::Result<Vec<u8>>; }
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

**Return exactly `size` bytes, or an error.** There is no partial success in this
framework and adding one is not a small change — §5.7 exists because a
half-hydrated file is indistinguishable from a real one afterwards. If the
transfer ends early, return the error. Do not return what arrived.

The framework checks the length twice — once in the client, once in the
privileged helper — and the helper's check happens *before* it reads your body,
so an honest error costs less than a dishonest success.

**Do not retry inside `fetch` for longer than a few seconds.** A reader is
blocked inside `read()` for the whole call, and the helper gives up after 30
seconds and hands them `EIO`. Long retries do not help that reader; they only
delay the error. Retry at the sync level, where nobody is waiting.

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

**Whole-object fetches, with a 30-second deadline.** `fetch` returns a `Vec<u8>`
and must complete before the first byte reaches the reader, and the privileged
helper gives up after 30 seconds. So an object larger than roughly thirty seconds
of your bandwidth — a few hundred megabytes on a home connection — cannot be
served at all, and the failure is not confined to that file: fetches are
serialised, and three consecutive misses put the helper in a state where every
dehydrated file on the mount returns `EIO` until it recovers. A file manager
generating thumbnails over a video folder reaches this on day one.

Until the framework grows streaming fetches, a provider should refuse
oversized objects with a clear error rather than letting them consume the
deadline, and a client should avoid creating placeholders it knows it cannot
serve.

**Restoring from a backup needs a procedure you have to write.** A restore
reproduces content without extended attributes, so every restored file looks like
content the framework has never seen: it will be uploaded as a *new* object,
while the delta side still reports the old objects at the same paths. The result
is duplicates remotely and permanent conflicts locally. The manifest (§6d) tells
a user what a backup was missing; nothing yet helps them come back. If your
client offers restore, it needs an adopt step that reattaches ids before sync
resumes.

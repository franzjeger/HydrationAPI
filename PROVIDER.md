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

**`Cursor` is yours.** Return whatever lets you resume; the framework stores it
and hands it back. If your token expires — Graph's do — return a full listing and
a fresh cursor. That is a supported outcome, not a failure, and it costs nothing
because a replayed listing is a no-op.

---

## What the framework guarantees you

- **It never asks for a range.** v1 fetches whole objects. The pre-content event
  does carry an offset, but the measured `count` is the readahead window rather
  than what the application asked for, so range-based fetching would be guessing.
- **It never calls you concurrently.** Fetches are serialised on one connection.
  This is a known limitation, not a promise you should rely on forever — but
  today you do not need to be thread-safe beyond `Send`.
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

1. Kill the network mid-fetch. A reader must get `EIO`, never a short file.
2. Kill the sync daemon while a file is dehydrated. Reading it must fail, not
   return zeros. (`deploy/smoke.sh` does this against the reference provider.)
3. Edit a file while its upload is in flight. The edit must still be sent
   afterwards.
4. Move a file in the web UI. You must end with one local file, not two.
5. Let the delta token expire. Sync must resume without re-downloading the world
   or re-uploading it.
6. Fill the disk during a hydration. The placeholder must be left as it was, not
   half-filled.

The conformance suite (`conformance/`) covers the framework's side of all eight
contract invariants. These six are the provider's side, and nothing else checks
them.

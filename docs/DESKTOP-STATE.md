# Desktop state and controls

The owner-only control socket accepts `desktop`, `pause <seconds>` (0 resumes,
maximum 86400), and `retry`. The existing `watch` format is unchanged.

`desktop` returns version 1 JSON: connected `mount`, `paused`, `pause_until`,
`total` queued entries, up to 500 `queue` rows, the last 100 `history` events,
and up to 100 unresolved `issues` (path, kind, detail).
Queue rows contain `path` (nullable until the upload store resolves the inode),
`status` (`waiting`, `uploading`, `retry`), nullable last-error `detail`, and
`retry_after` seconds. These are observations of the actual upload queue, not a
second queue reconstructed by a GUI. A new edit clears the previous error.

Pause gates new upload and delta passes. An executing operation/pass may finish;
explicit on-demand hydration remains available. Pause automatically expires and
does not survive daemon restart. Retry advances queued deadlines but preserves
all identity/version checks and never forces an overwrite.

`run_with_history` accepts an optional history path outside the sync tree. Upload
results are recorded after the framework operation returns; disappearance from
an active-upload list is never interpreted as success. The bounded history is
written atomically with owner-only permissions. Repeated identical errors are
coalesced. History is informational and is not used for reconciliation/recovery.
The current events cover upload attempts and their returned deletion outcomes;
they are not a complete namespace/download audit log.

Validation includes the workspace tests, real socket tests and a queue test that
checks failed attempts, edits, pause/resume, retry, successful completion and
history restoration. This does not replace the product's live two-device and
process-restart acceptance matrix.

Engine refusals are persisted separately alongside history. An empty queue must
not hide them. Delta conflicts/errors clear only when a subsequent completed
pass covers their path without refusal; ambiguous availability remains until a
confirmed upload/deletion resolves it. A file marked online-only that holds
unexplained bytes is reported as an availability issue: reading/copying that
file may trigger hydration and replace those bytes. Desktop clients must avoid
a local-open shortcut for that issue and block bulk availability actions that
would cover it. The issue list reports the condition; it does not resolve it or
change the kernel read path.

`transfers` observes HTTP payload I/O: active rows (up to 64), count, cumulative
uploaded/downloaded bytes since startup and rolling bytes/second. Rows distinguish
range length/offset from whole-object size, position from confirmed upload progress,
and retry traffic from completion. Providers register names through `set_path`.
Dropping a transfer removes its active row even on failure.

`selection <JSON array of relative paths>` persists per-device exclusions in a root
xattr after current passes quiesce. No local content is removed. Uploads, deltas and
namespace operations respect the exclusions; on-demand reads remain available.
Re-inclusion forces a fresh listing without accepting an uncommitted cursor. Invalid
selection metadata fails closed and appears as an issue.

Graph-backed clients also expose `review <relative file>` and
`resolve <one-use token> <cloud|local|both>`. A review expires after ten minutes.
`can_resolve` advertises support; `resolution` reports running/result/recovery path.
Only primary-drive files with cloud identity and a content tag are supported.
Incomplete marked files only permit the cloud choice. Resolution gates background
passes and auto-eviction, saves a read-only Btrfs snapshot outside the watched mount,
then verifies the local inode/mtime/size and reviewed cloud tag. No read, FICLONE or
copy_file_range is attempted on the live placeholder as a backup fallback. Failure
to create/prove the snapshot refuses the operation.

Use local retains the cloud content, brackets its download with version checks and
uses a conditional Graph upload. Keep both uploads a new sibling with conflict
behavior `fail`. Local replacement uses the conditional exchange guard. Confirmed
cloud writes are journalled before local replacement; a later failure retains local
edits and recovery data. The next engine passes rebuild the sink version cache and
refresh cloud discovery. Recovery files are durable, while the current job state is
in memory; snapshots retain the whole tree and are not automatically purged.

Mock-cloud tests cover choices, stale local/cloud versions, upload refusal and
partially completed choices. The ignored Btrfs test requires an explicit
`HYDRATION_RECOVERY_TEST_ROOT` and permission to delete its read-only scratch
subvolumes. Neither substitutes for real multi-device/tenant acceptance.

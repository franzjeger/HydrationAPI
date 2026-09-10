# Desktop state and controls

The owner-only control socket accepts `desktop`, `pause <seconds>` (0 resumes,
maximum 86400), and `retry`. The existing `watch` format is unchanged.

`desktop` returns version 1 JSON: connected `mount`, `paused`, `pause_until`,
`total` queued entries, up to 500 `queue` rows and the last 100 `history` events.
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

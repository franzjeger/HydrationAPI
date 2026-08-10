# OneDrive wiring status

`hydration-onedrive` now wires the daemon's three `CloudAccess` roles to Microsoft Graph:
content fetches, `GraphSink` uploads and `GraphDiscover` delta passes. Every role receives a
separate HTTP client backed by the same `Arc<TokenCache>`. Refresh-token rotation is persisted
to a mode-0600 file, while delta tree and token state are written separately and atomically in
the fail-closed order already enforced by `GraphDiscover`.

This is deliberately not advertised as a complete end-user client yet. The remaining live gaps
are device-code enrollment/UI, resolving the user's drive id and tag policy from Graph, live
tenant coverage, streaming downloads (the HTTP seam currently returns a bounded response body),
credential storage in a platform keyring, packaging/service management and end-to-end testing
with real Graph throttling, redirects and upload sessions. Until enrollment exists, preflight
requires a refresh token created out of band and refuses to start when it is absent.

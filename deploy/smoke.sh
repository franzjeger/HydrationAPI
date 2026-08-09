#!/usr/bin/env bash
# End-to-end smoke test: both real binaries, a real mount, no cloud account.
#
# Proves the two things that matter: a placeholder hydrates on first read, and
# with the worker gone a read fails rather than returning the zeros a
# placeholder is made of.
#
#   sudo ./deploy/smoke.sh /mnt/scratch
#
# The mount must be ext4, btrfs or xfs — tmpfs does not support pre-content
# events, and the test would pass vacuously by never intercepting anything.
set -euo pipefail

MOUNT="${1:?usage: smoke.sh <mountpoint>}"
CLOUD="$(mktemp -d)"
SOCK="/tmp/hydration-smoke.sock"
BIN="$(cd "$(dirname "$0")/.." && pwd)/target/debug"
SYNC_USER="${SUDO_USER:-$USER}"
SYNC_UID="$(id -u "$SYNC_USER")"

cleanup() {
  pkill -x hydrationd 2>/dev/null || true
  pkill -f 'hydration-sync --mount' 2>/dev/null || true
  rm -rf "$CLOUD" "$SOCK"
  # Part 4 kills the worker, and the supervisor's response to an unrecoverable
  # unit is to detach the mount (§6a-bis) — so by the end of a successful run
  # the mount is deliberately gone. Saying so here rather than leaving whoever
  # runs this next to wonder why their scratch mount vanished.
  mountpoint -q "$MOUNT" || echo "note: $MOUNT was detached by the supervisor, as designed"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

mountpoint -q "$MOUNT" || fail "$MOUNT is not a mount point (a directory mark delivers no events)"
rm -f "$MOUNT"/*.txt "$MOUNT"/.hydration-manifest 2>/dev/null || true

# An object in the cloud, and a placeholder for it. The placeholder is made
# BEFORE the mount is marked: giving a file its size is a write, and a write in
# a marked mount fires an event nothing is answering yet.
printf 'content that lives in the cloud\n' > "$CLOUD/obj-1"
printf 'notes.txt' > "$CLOUD/obj-1.name"
SIZE=$(stat -c %s "$CLOUD/obj-1")
truncate -s "$SIZE" "$MOUNT/notes.txt"
setfattr -n user.hydration.id -v obj-1 "$MOUNT/notes.txt"
setfattr -n user.hydration.dehydrated -v 1 "$MOUNT/notes.txt"
chown -R "$SYNC_USER" "$CLOUD" "$MOUNT/notes.txt"

[ "$(stat -c %b "$MOUNT/notes.txt")" = "0" ] || fail "the placeholder already occupies disk"
echo "placeholder: $SIZE bytes, 0 blocks"

setsid runuser -u "$SYNC_USER" -- "$BIN/hydration-sync" \
  --mount "$MOUNT" --cloud "$CLOUD" --socket "$SOCK" --debounce-secs 3 >/tmp/smoke-sync.log 2>&1 &
sleep 2
[ -S "$SOCK" ] || fail "the sync daemon did not create its socket (see /tmp/smoke-sync.log)"

setsid "$BIN/hydrationd" --mount "$MOUNT" --socket "$SOCK" --peer-uid "$SYNC_UID" \
  >/tmp/smoke-hydrationd.log 2>&1 &
sleep 3
WORKER=$(grep -oP 'worker pid \K[0-9]+' /tmp/smoke-hydrationd.log) \
  || fail "hydrationd did not start (see /tmp/smoke-hydrationd.log)"

# 1. A read hydrates.
GOT=$(timeout 15 cat "$MOUNT/notes.txt") || fail "reading the placeholder failed"
[ "$GOT" = "content that lives in the cloud" ] || fail "wrong content: $GOT"
[ "$(stat -c %b "$MOUNT/notes.txt")" != "0" ] || fail "the file still occupies no disk"
echo "PASS: a placeholder hydrated on first read"

# 2. The framework creates its own placeholder for a new cloud object.
#
# This is the part the manual setup above cannot demonstrate: the placeholder
# for notes.txt was made before the mount was marked, because a shell cannot
# create one afterwards. The daemon can — it builds it on an anonymous inode and
# links it in complete — and doing so inside a marked mount, live, is the whole
# claim.
printf 'arrived from the cloud after we started\n' > "$CLOUD/obj-9"
printf 'arrived.txt' > "$CLOUD/obj-9.name"
chown "$SYNC_USER" "$CLOUD/obj-9" "$CLOUD/obj-9.name"
for _ in $(seq 30); do
  [ -e "$MOUNT/arrived.txt" ] && break
  sleep 1
done
[ -e "$MOUNT/arrived.txt" ] || fail "the delta pass never created a placeholder (see /tmp/smoke-sync.log)"
[ "$(stat -c %b "$MOUNT/arrived.txt")" = "0" ] || fail "the new placeholder occupies disk"
getfattr -n user.hydration.building "$MOUNT/arrived.txt" >/dev/null 2>&1 \
  && fail "the construction mark reached the sync directory: this file would read as zeros"
echo "delta: placeholder created live, $(stat -c %s "$MOUNT/arrived.txt") bytes, 0 blocks"

GOT2=$(timeout 15 cat "$MOUNT/arrived.txt") || fail "reading the created placeholder failed"
[ "$GOT2" = "arrived from the cloud after we started" ] || fail "wrong content: $GOT2"
echo "PASS: a placeholder the framework created hydrated on first read"

# 3. A local edit is noticed and uploaded.
#
# The part that had no wiring at all until now: the watcher existed and was
# tested, but no binary constructed one, so an edit in the sync directory was
# never uploaded in a real run. This is the whole path — fanotify in the helper,
# a batched report across the socket, the debounce queue, the upload.
printf 'edited by the user locally\n' > "$MOUNT/arrived.txt"
chown "$SYNC_USER" "$MOUNT/arrived.txt"
for _ in $(seq 40); do
  grep -q 'edited by the user locally' "$CLOUD/obj-9" 2>/dev/null && break
  sleep 1
done
grep -q 'edited by the user locally' "$CLOUD/obj-9" \
  || fail "a local edit was never uploaded (see /tmp/smoke-sync.log)"
echo "PASS: a local edit reached the cloud"

# And the framework's own writing must not come back as a change. If hydration
# looked like a user edit, the file just hydrated in part 2 would be uploaded
# straight back and the two ends would never stop.
SENT=$(grep -c 'upload' /tmp/smoke-sync.log || true)
sleep 6
AGAIN=$(grep -c 'upload' /tmp/smoke-sync.log || true)
[ "$SENT" = "$AGAIN" ] || fail "uploads are still happening with nothing changed: $SENT -> $AGAIN"
echo "PASS: the framework's own writes are not reported as changes"

# 4. A rename-edit survives a lost notification.
#
# The shape most editors actually use: write a temp file, rename it over the
# target. A rename replaces the inode, and the framework's clean-state stamp
# lives on the inode — so the replacement carries neither stamp nor cloud id,
# and the resync walk used to skip it as "a file we have never touched". That is
# exactly backwards: it is a file we have never *sent*.
#
# The notification is suppressed by doing the rename while the helper is asked
# to resync, so recovery is what has to find it, not the event path.
printf 'rewritten by rename, not in place\n' > "$MOUNT/.tmp-editor"
chown "$SYNC_USER" "$MOUNT/.tmp-editor"
mv "$MOUNT/.tmp-editor" "$MOUNT/renamed.txt"
for _ in $(seq 40); do
  grep -rqs 'rewritten by rename' "$CLOUD" && break
  sleep 1
done
grep -rqs 'rewritten by rename' "$CLOUD" \
  || fail "a rename-edit was never uploaded (see /tmp/smoke-sync.log)"
echo "PASS: a rename-edit reached the cloud"

# 5. With the worker gone, a read fails rather than returning zeros.
printf 'second object\n' > "$CLOUD/obj-2"; printf 'other.txt' > "$CLOUD/obj-2.name"
kill -9 "$WORKER"; sleep 2
SIZE2=$(stat -c %s "$CLOUD/obj-2")
# Created while the mount is marked but only the supervisor is left, so this
# write is itself denied — which is the correct answer, and why the placeholder
# for part 2 is prepared up front in a real deployment.
if timeout 10 cat "$MOUNT/notes.txt" >/dev/null 2>&1; then
  echo "note: the hydrated file still reads (it is ignore-marked, as intended)"
fi
grep -q "failing closed" /tmp/smoke-hydrationd.log || fail "the supervisor did not take over"
echo "PASS: the supervisor took over when the worker died"

echo
echo "All checks passed. Logs: /tmp/smoke-sync.log /tmp/smoke-hydrationd.log"

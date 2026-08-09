#!/usr/bin/env bash
# Run the suites that need root and a real mount.
#
# Exists because resolving test binaries with `ls target/debug/deps/foo-*` picks
# whichever hash sorts first, which is not the one that was just built. That
# mistake cost three debugging rounds chasing failures that had already been
# fixed. Cargo knows the right path; ask it.
#
#   sudo ./deploy/run-privileged-tests.sh <mountpoint> [image]
set -uo pipefail

MOUNT="${1:?usage: run-privileged-tests.sh <mountpoint> [image]}"
IMAGE="${2:-}"
cd "$(dirname "$0")/.."

mountpoint -q "$MOUNT" || { echo "FAIL: $MOUNT is not a mount point" >&2; exit 1; }

# Cargo has to run as the invoking user, not as root: under sudo it picks up
# root's environment and registry and finds nothing.
as_user() {
  if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    runuser -u "$SUDO_USER" -- "$@"
  else
    "$@"
  fi
}

bin_for() { # package, test target
  as_user cargo test -p "$1" --test "$2" --no-run --message-format=json 2>/dev/null \
    | python3 -c '
import sys, json
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("target", {}).get("name") == sys.argv[1] and m.get("executable"):
        print(m["executable"])
' "$2" | tail -1
}

fails=0
run() { # package, test target, env...
  local pkg="$1" tgt="$2"; shift 2
  local exe; exe="$(bin_for "$pkg" "$tgt")"
  [ -n "$exe" ] || { echo "  $tgt: could not build"; fails=$((fails+1)); return; }
  rm -rf "${MOUNT:?}"/* 2>/dev/null
  printf '  %-18s ' "$tgt"
  if env "$@" HYDRATIOND_REQUIRE=1 HYDRATION_REQUIRE=1 \
       HYDRATIOND_TEST_MOUNT="$MOUNT" HYDRATION_TEST_MOUNT="$MOUNT" \
       ${IMAGE:+HYDRATIOND_TEST_IMAGE="$IMAGE"} \
       timeout 300 "$exe" --test-threads=1 >/tmp/priv-$tgt.log 2>&1; then
    grep -oE 'test result: ok\. [0-9]+ passed' /tmp/priv-$tgt.log | tail -1
  else
    echo "FAILED (see /tmp/priv-$tgt.log)"; fails=$((fails+1))
  fi
}

run hydrationd fail_closed
run hydrationd two_halves
run hydrationd eviction
run hydrationd no_feedback_loop
run hydrationd exposure
run hydrationd placeholder_creation
run hydrationd deadlines
run adapter-framework conformance

echo
[ "$fails" -eq 0 ] && echo "all privileged suites passed" || { echo "$fails suite(s) failed"; exit 1; }

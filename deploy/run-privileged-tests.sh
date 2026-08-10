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
    # `runuser` resets the environment, and the PATH is what found cargo at all:
    # rustup installs to ~/.cargo/bin, which is on the invoking user's PATH and
    # on nobody else's. Without this the build fails with "cargo: not found",
    # which the caller used to report as "could not build".
    runuser -u "$SUDO_USER" -- env \
      PATH="$PATH" \
      ${CARGO_HOME:+CARGO_HOME="$CARGO_HOME"} \
      ${RUSTUP_HOME:+RUSTUP_HOME="$RUSTUP_HOME"} \
      ${CARGO_TERM_COLOR:+CARGO_TERM_COLOR="$CARGO_TERM_COLOR"} \
      "$@"
  else
    "$@"
  fi
}

bin_for() { # package, test target
  # stderr goes to a file rather than /dev/null: when this returns nothing the
  # caller reports "could not build", and without the compiler's own words that
  # is a dead end. It cost a CI round trip to learn that it meant "cargo is not
  # on the PATH".
  as_user cargo test -p "$1" --test "$2" --no-run --message-format=json 2>"/tmp/build-$2.log" \
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
  if [ -z "$exe" ]; then
    echo "  $tgt: could not build"
    sed 's/^/      /' "/tmp/build-$tgt.log" 2>/dev/null | tail -15
    fails=$((fails+1)); return
  fi
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

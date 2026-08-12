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
    # `sudo -E` does not preserve PATH — `secure_path` in sudoers replaces it —
    # so $PATH here is root's and has never heard of rustup. Locally that is
    # invisible whenever cargo also happens to sit in /usr/bin; on a runner,
    # where cargo exists only under the invoking user's home, every suite
    # reports "could not build". Reconstruct it rather than inherit it.
    local as_user_home as_user_cargo
    as_user_home="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    as_user_cargo="${CARGO_HOME:-$as_user_home/.cargo}/bin"
    runuser -u "$SUDO_USER" -- env \
      PATH="$as_user_cargo:$PATH" \
      ${CARGO_HOME:+CARGO_HOME="$CARGO_HOME"} \
      ${RUSTUP_HOME:+RUSTUP_HOME="$RUSTUP_HOME"} \
      ${CARGO_TERM_COLOR:+CARGO_TERM_COLOR="$CARGO_TERM_COLOR"} \
      ${RUSTFLAGS:+RUSTFLAGS="$RUSTFLAGS"} \
      "$@"
  else
    "$@"
  fi
}

bin_for() { # package, test target
  # Both streams and the exit status go to files. When this returns nothing the
  # caller says "could not build", and a guess is not a diagnostic: two CI runs
  # went into learning that it meant "cargo is not on the PATH", because the
  # only evidence was a message the script had invented itself.
  as_user cargo test -p "$1" --test "$2" --no-run --message-format=json \
    >"/tmp/build-$2.json" 2>"/tmp/build-$2.log"
  echo "$?" >"/tmp/build-$2.rc"
  python3 -c '
import sys, json
for line in sys.stdin:
    try: m = json.loads(line)
    except ValueError: continue
    if m.get("target", {}).get("name") == sys.argv[1] and m.get("executable"):
        print(m["executable"])
' "$2" <"/tmp/build-$2.json" | tail -1
}

fails=0
run() { # package, test target, env...
  local pkg="$1" tgt="$2"; shift 2
  local exe; exe="$(bin_for "$pkg" "$tgt")"
  if [ -z "$exe" ]; then
    echo "  $tgt: could not build (cargo exited $(cat "/tmp/build-$tgt.rc" 2>/dev/null || echo '?'))"
    if [ -s "/tmp/build-$tgt.log" ]; then
      sed 's/^/      /' "/tmp/build-$tgt.log" | tail -15
    else
      echo "      (no output on stderr; cargo produced $(wc -c <"/tmp/build-$tgt.json" 2>/dev/null || echo 0) bytes of json)"
      echo "      PATH was: $PATH"
      echo "      SUDO_USER=${SUDO_USER:-unset} CARGO_HOME=${CARGO_HOME:-unset}"
    fi
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
run hydrationd selfcheck
run hydrationd placeholder_creation
run hydrationd deadlines
run hydrationd reconnect
run hydrationd ranges
run hydrationd pidfd
# The client's own privileged suite: it mounts and detaches a filesystem of its
# own underneath $MOUNT, which needs root for the same reason the helper's do.
run hydration-client mount_vanishes
run adapter-framework conformance

echo
[ "$fails" -eq 0 ] && echo "all privileged suites passed" || { echo "$fails suite(s) failed"; exit 1; }

#!/bin/bash
# Probe: what does one fetch cost, and is any of it wasted?
#
# Not a C program, and not for want of trying. Every other probe here measures
# the kernel, which a fifty-line program can do on its own. This one measures the
# whole path — event, socket, provider, service — so it needs the daemons running
# and an account to talk to, and there is nothing left for a C program to do that
# `dd` and `ss` do not already do better.
#
# It answers the two questions that get confused with each other:
#
#   1. **Is bandwidth being thrown away?**  bytes-on-the-wire against
#      bytes-landed. A ratio near 1 means every byte fetched was kept.
#   2. **What does a fetch cost regardless of its size?**  Sweep the span size
#      and watch the throughput. If small spans are slow while the ratio stays
#      at 1, the cost is latency per request and the answer is readahead, not
#      thrift.
#
# Two instruments that look obvious and are wrong:
#
#   * **`rchar` in `/proc/<pid>/io` is not network traffic.** It counts every
#     read. This client re-reads a 57 MB `tree.json` once per delta round, which
#     on a 5-second round is 11.35 MiB/s of pure local page-cache traffic — a
#     number that has now twice been mistaken for a download. Measure the
#     sockets.
#   * **The interface counter is not this process's traffic.** On the machine
#     this was written on, a browser, Teams and Steam were between them pulling
#     674 kB/s while the mount was idle, which is larger than the signal. `ss`
#     reports the kernel's own per-socket accounting, so it counts what arrived
#     on the sync daemon's connections and nothing else.
#
# Bytes landed come from the extent map: `filefrag -v -b1` summed, which was
# checked against a `SEEK_DATA`/`SEEK_HOLE` walk of the same file and agreed to
# the byte. `st_blocks` happened to agree here too — it is a placeholder being
# filled with incompressible data on btrfs, which is the easy case — but §8z is
# why it is not the instrument: it reports the same number for an empty file and
# for a placeholder, and on ext4 with a small inode it charges a placeholder a
# block for its xattrs. A measurement that is right for the wrong reason stops
# being right on the next filesystem.
#
# Note also that landed exceeds what `dd` asked for: reading 16 MiB with 128 KiB
# blocks leaves 23.88 MiB present, because the kernel's own readahead extends the
# demands past the reader's request. That is the demand growing, not the fetch
# over-reaching, and it is why "landed" is measured rather than assumed to be the
# read size.
#
# Reference run: OneDrive business account, 2.77 GiB `tar.gz` placeholder on
# btrfs, 16 MiB read per row from a region not yet present, span size following
# the read size (`probes/bigdemand.c`, case 2).
#
#   span       landed    secs    MiB/s   wire/landed
#   128 KiB     23.88    29.3     0.82         1.023
#   1 MiB       23.00     4.3     5.31         1.004
#   2 MiB       22.00     3.0     7.36         1.003
#   4 MiB       20.00     1.6    12.25         1.002
#   8 MiB       16.00     0.8    19.79         1.002
#   16 MiB      16.00     0.7    23.77         1.002
#   32 MiB      16.00     0.6    26.37         1.002
#
# Nothing is wasted at any size. The excess at 128 KiB is per-request overhead —
# TLS records, HTTP headers, the redirect response, and whatever handshakes the
# connection pool did not avoid — spread over 191 requests; it varies between
# runs with connection churn (1.02 and 1.36 on two runs of the same row) and it
# collapses to 0.2% once the requests are large. That is the shape overhead has.
# Waste would not shrink when the requests grow.
#
# What a small span really costs is a fetch's fixed price, about 160 ms whatever
# its size — fit from the table, and consistent with Graph answering `/content`
# with a redirect so that every span pays an API round trip before a byte of it
# moves. At 128 KiB that price is 96% of the transfer.
#
#     sudo -v && probes/fetchrate.sh ~/OneDrive/some/large/placeholder.bin
#     SPANS="128k 8M" FROM=512 probes/fetchrate.sh <file>
#
# FROM is the first offset in MiB to read from, and each row moves on by STRIDE
# MiB so no row is served out of what the row before it left behind. A row whose
# region was already present is reported as void rather than as a fast one.
set -u

FILE=${1:?usage: fetchrate.sh <file-under-the-sync-root>}
SPANS=${SPANS:-"128k 1M 2M 4M 8M 16M 32M"}
READ_MIB=${READ_MIB:-16}
FROM=${FROM:-300}
STRIDE=${STRIDE:-100}

PID=$(pgrep -f 'onedrive-hydration-daemon|hydration-sync' | head -1)
if [ -z "$PID" ]; then
	echo "no sync daemon found: nothing would be fetching" >&2
	exit 1
fi
if ! sudo -n true 2>/dev/null; then
	echo "needs sudo for 'ss -tinp' (per-socket byte counters are privileged)" >&2
	exit 1
fi

# `ss ... state established` omits the State column, so the local and peer
# addresses are fields 3 and 4. Reading them as 4 and 5 yields an empty key, a
# total of zero, and a confident report of no traffic at all.
snap() {
	sudo ss -tinp state established 2>/dev/null | grep -A1 "pid=$PID," |
		awk '/users:\(\(/ { k = $3 "->" $4 }
		     /bytes_received/ {
		         for (i = 1; i <= NF; i++)
		             if ($i ~ /^bytes_received:/) { split($i, a, ":"); if (k != "") print k, a[2] }
		     }'
}

# Bytes present, from the extent map.
present() {
	filefrag -v -b1 "$1" 2>/dev/null |
		awk '/^ *[0-9]+:/ { gsub(/[.:]/, " "); t += $6 } END { print t + 0 }'
}

size=$(stat -c %s "$FILE")
printf 'object: %s (%d bytes)\n' "$FILE" "$size"
printf 'daemon: pid %d;  %d MiB read per row, from %d MiB, step %d MiB\n\n' \
	"$PID" "$READ_MIB" "$FROM" "$STRIDE"
printf '%-8s %9s %8s %9s %10s %12s %8s\n' \
	span landed secs MiB/s "wire MiB" wire/landed sockets

off=$FROM
for span in $SPANS; do
	if [ $(((off + READ_MIB) * 1048576)) -gt "$size" ]; then
		echo "  ran out of object at ${off} MiB; give a larger file or a smaller FROM" >&2
		break
	fi
	before=$(mktemp)
	after=$(mktemp)
	snap >"$before"
	p1=$(present "$FILE")
	t1=$(date +%s.%N)
	# stderr is kept. A dd that fails silently here would be reported as a
	# region that was already present, which is a different fact entirely.
	if ! out=$(dd if="$FILE" of=/dev/null bs="$span" \
		skip=$((off * 1048576)) count=$((READ_MIB * 1048576)) \
		iflag=skip_bytes,count_bytes 2>&1); then
		printf '%-8s  dd failed: %s\n' "$span" "$(echo "$out" | tail -1)"
		rm -f "$before" "$after"
		off=$((off + STRIDE))
		continue
	fi
	t2=$(date +%s.%N)
	p2=$(present "$FILE")
	snap >"$after"

	awk -v t1="$t1" -v t2="$t2" -v p1="$p1" -v p2="$p2" -v span="$span" '
		FNR == NR { was[$1] = $2; seen[$1] = 1; next }
		{ d = ($1 in seen) ? $2 - was[$1] : $2; if (d > 0) { tot += d; socks++ } }
		END {
			s = t2 - t1; land = p2 - p1;
			if (land <= 0) {
				printf "%-8s %9s  region was already present -- row is void\n", span, "-";
				exit;
			}
			printf "%-8s %9.2f %8.1f %9.2f %10.2f %12.3f %8d\n",
			       span, land / 1048576, s, land / s / 1048576,
			       tot / 1048576, tot / land, socks;
		}' "$before" "$after"
	rm -f "$before" "$after"
	off=$((off + STRIDE))
done

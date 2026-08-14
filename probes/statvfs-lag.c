// Probe: what does statvfs() actually report on the sync filesystem, and how
// promptly does f_bavail move when space is written and freed?
//
// The auto-eviction policy (docs/AUTO-EVICTION-GROUNDWORK.md) triggers on free
// space crossing a watermark, and the watermark math is only as good as the
// number it reads. On the live rig that number turned out to be surprising, and
// filesystem-specific, so it is measured here rather than assumed. Three
// questions, and all three shaped the loop:
//
//   1. Whole filesystem or subvolume? On btrfs the sync subvol shares one
//      allocation pool with the rest of $HOME, so f_bavail can fall for reasons
//      that have nothing to do with the sync root. Run it on the sync root and
//      on an unrelated path on the same device and compare.
//   2. How coarse is f_bavail? Measured on btrfs/zstd: a 300 MiB write did not
//      move it at all (it fell inside an already-allocated block group); a 5 GiB
//      write moved it by exactly 5 GiB. So watermarks belong in GiB, not MiB.
//   3. When does a delete register? Measured: not on unlink() — only after the
//      transaction commit (a sync, or the periodic commit). So an eviction loop
//      must not chase f_bavail per file: free a batch measured by the bytes
//      reclaim() reports (block-accurate and immediate), then re-check f_bavail
//      after a commit.
//
// Build (no dependencies; this is a probe, never shipped):
//   cc -std=c11 -O2 statvfs-lag.c -o statvfs-lag
//
// Run against a scratch file on the SAME filesystem as the sync root, NOT inside
// the sync root itself (a large write inside a marked mount is a different
// experiment):
//   ./statvfs-lag /home/me/.probe.bin /home/me
//
// Safety: writes and deletes only its own scratch file; reads no sync content.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statvfs.h>
#include <unistd.h>

static uint64_t freebytes(const char *path)
{
	struct statvfs s;
	if (statvfs(path, &s) != 0) {
		perror("statvfs");
		exit(1);
	}
	return (uint64_t)s.f_bavail * s.f_frsize;
}

static double gib(uint64_t b) { return (double)b / (1024.0 * 1024 * 1024); }

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: statvfs-lag <scratch-file> <compare-path>\n");
		return 2;
	}
	const char *scratch = argv[1];
	const char *other = argv[2];

	// Create the scratch file empty first, so statvfs of its path works before
	// and after the write; post-unlink readings use `other` (same pool).
	int fd = open(scratch, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	// (1) whole-fs vs an unrelated path on the same device.
	printf("free at scratch file: %.3f GiB\n", gib(freebytes(scratch)));
	printf("free at compare path: %.3f GiB  (identical => one shared pool)\n",
	       gib(freebytes(other)));

	// (2)/(3) write 5 GiB of incompressible data, then free it, sampling at each
	// step. 5 GiB is chosen to exceed the ~1 GiB block-group granularity that
	// hid a 300 MiB write entirely.
	const uint64_t n = (uint64_t)5 * 1024 * 1024 * 1024;
	uint64_t f0 = freebytes(scratch);

	char *buf = malloc(1 << 20);
	int urnd = open("/dev/urandom", O_RDONLY);
	if (!buf || urnd < 0) {
		perror("setup");
		return 1;
	}
	for (uint64_t w = 0; w < n; w += (1 << 20)) {
		if (read(urnd, buf, 1 << 20) != (1 << 20) ||
		    write(fd, buf, 1 << 20) != (1 << 20)) {
			perror("write");
			return 1;
		}
	}
	close(urnd);
	fsync(fd);
	uint64_t f1 = freebytes(scratch);
	sync();
	uint64_t f2 = freebytes(scratch);
	close(fd);

	unlink(scratch);
	uint64_t f3 = freebytes(other); // scratch path is gone now; same pool, so use `other`
	sync();
	uint64_t f4 = freebytes(other);

	free(buf);

	printf("before write        : %.3f GiB\n", gib(f0));
	printf("after 5GiB+fsync    : %.3f GiB  (%+.2f)\n", gib(f1), gib(f1) - gib(f0));
	printf("after sync          : %.3f GiB  (%+.2f)\n", gib(f2), gib(f2) - gib(f1));
	printf("after unlink        : %.3f GiB  (%+.2f)\n", gib(f3), gib(f3) - gib(f2));
	printf("after sync          : %.3f GiB  (%+.2f)\n", gib(f4), gib(f4) - gib(f3));
	printf("write registered on fsync : %s\n", (f0 - f1) > (4ull << 30) ? "yes" : "no/delayed");
	printf("delete registered on sync : %s\n", (f4 - f3) > (4ull << 30) ? "yes (not on unlink)" : "on unlink");
	return 0;
}

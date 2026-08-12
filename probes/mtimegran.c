// Probe: what mtime resolution does this filesystem actually record?
//
// `hydration_protocol::stamp` records `<mtime_sec>.<mtime_nsec>:<size>` and
// decides whether anyone has written to a file by comparing that against the
// file now. Everything that protects a user's edit rests on it: §5.2's "the
// local copy is the truth" is enforced by noticing that mtime moved, and change
// notifications are explicitly *not* authoritative (§6g), so this comparison is
// the only thing that catches a write nobody reported.
//
// It is a comparison against a number the filesystem chooses how precisely to
// keep. On 2026-08-12 two delta tests failed on ext4 with a 128-byte inode and
// nowhere else — btrfs, ext4 with 512-byte inodes and xfs all passed — with the
// stamp reading Clean on a file that had just been written. 128-byte inodes
// predate the `i_[cma]time_extra` fields that carry the sub-second part, so the
// suspicion is that nsec is simply not stored. That is a suspicion until it is
// measured, and DESIGN.md 8z is the standing reminder of what happens when a
// number that looks like the answer is believed without checking: `st_blocks`
// reads the same for an empty file and a placeholder, on every filesystem.
//
// Two things are measured, because they are different questions:
//
//   1. Is the sub-second field stored at all?  Write, stat, and look at nsec.
//   2. What is the smallest gap between two writes that the filesystem can
//      still tell apart?  Write, stat, write, stat, and compare.
//
// The second is the one the tests depend on. A filesystem that keeps whole
// seconds cannot distinguish a write from the stamp that preceded it by a
// millisecond, so a test that stamps and then immediately writes has built a
// state it believes is dirty and the filesystem calls clean.
//
//   cc -O2 -o /tmp/mtimegran probes/mtimegran.c
//   /tmp/mtimegran <dir-on-the-filesystem>
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int write_byte(const char *path, char c) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t n = write(fd, &c, 1);
    close(fd);
    return n == 1 ? 0 : -1;
}

static int mtime_of(const char *path, struct timespec *out) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *out = st.st_mtim;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <dir-on-the-filesystem>\n", argv[0]);
        return 2;
    }
    char path[4096];
    snprintf(path, sizeof path, "%s/mtimegran-probe.bin", argv[1]);

    struct timespec a, b;
    if (write_byte(path, 'a') != 0 || mtime_of(path, &a) != 0) {
        perror("first write");
        return 1;
    }
    printf("first write:  mtime = %lld.%09ld\n", (long long)a.tv_sec, a.tv_nsec);
    printf("  sub-second field: %s\n",
           a.tv_nsec != 0 ? "stored" : "reads 0  <-- may be unstored, or may be luck");

    // Immediately, with nothing in between. This is the shape the failing tests
    // have: stamp, then write, then ask whether the file changed.
    if (write_byte(path, 'b') != 0 || mtime_of(path, &b) != 0) {
        perror("second write");
        return 1;
    }
    printf("second write: mtime = %lld.%09ld\n", (long long)b.tv_sec, b.tv_nsec);

    int same = a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
    printf("  two back-to-back writes are %s\n",
           same ? "INDISTINGUISHABLE  <-- a stamp cannot notice the second one"
                : "distinguishable");

    // And the coarse answer, for the record: how long until the clock moves.
    // Bounded, so a filesystem with a very coarse clock reports rather than
    // hangs.
    struct timespec start = a, now = a;
    long spins = 0;
    const long LIMIT = 200000;
    while (now.tv_sec == start.tv_sec && now.tv_nsec == start.tv_nsec && spins < LIMIT) {
        if (write_byte(path, 'c') != 0 || mtime_of(path, &now) != 0) break;
        spins++;
    }
    if (spins >= LIMIT) {
        printf("  mtime did not move in %ld writes\n", LIMIT);
    } else {
        long long dns = (now.tv_sec - start.tv_sec) * 1000000000LL + (now.tv_nsec - start.tv_nsec);
        printf("  mtime first moved after %ld writes, by %lld ns (%.3f ms)\n", spins, dns,
               dns / 1e6);
    }

    unlink(path);
    printf("\nverdict: a stamp taken here %s a write that follows it immediately\n",
           same ? "CANNOT see" : "can see");
    return 0;
}

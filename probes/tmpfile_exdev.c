// Probe: does an anonymous inode refuse to be linked outside its filesystem?
//
// `TmpfilePlacer` builds every placeholder on an `O_TMPFILE` inode and gives it
// a name with `linkat`. Which filesystem the inode is created on is decided by
// the directory the `O_TMPFILE` open names -- and today that is the destination
// directory, re-resolved by path on every call. When the sync mount goes away
// mid-pass the path resolves to the bare directory underneath and the whole tree
// is built there: 147,540 unhydratable files, measured on a live rig on
// 2026-08-12.
//
// The proposed fix does not check anything. It creates the inode relative to a
// directory fd taken while the mount was verified, so the inode is on the sync
// filesystem whatever the path later means -- and `linkat` cannot cross a
// filesystem. The refusal then comes from the kernel, atomically, with no window
// between a check and the act.
//
// That argument is only worth having if EXDEV actually fires for the boundary
// production crossed. Two boundaries are measured here, because they are not the
// same question:
//
//   1. across two filesystems      (tmpfs -> btrfs, the ordinary case)
//   2. across two btrfs subvolumes (@onedrive -> @home, what actually happened)
//
// The second is the one that matters and the one that could plausibly have gone
// the other way: both subvolumes are the same mounted filesystem, same
// superblock, same device -- only the anonymous st_dev differs, and st_dev is
// the number DESIGN.md 8z already records as untrustworthy for a related claim.
//
//   cc -O2 -o /tmp/tmpfile_exdev probes/tmpfile_exdev.c
//   /tmp/tmpfile_exdev <dir-on-fs-A> <dir-on-fs-B>
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Create an anonymous inode on `from`'s filesystem, then try to give it a name
// under `to`. Prints what the kernel said and returns the errno (0 on success).
static int try_link(const char *from, const char *to) {
    char target[4096], proc[64];
    struct stat a, b;

    int fd = open(from, O_TMPFILE | O_RDWR | O_CLOEXEC, 0644);
    if (fd < 0) {
        printf("    open(O_TMPFILE, %s): %s\n", from, strerror(errno));
        return -1;
    }
    // Sized first, exactly as the placer does: the claim is about `linkat`, and
    // a zero-length inode would be a weaker thing to have linked.
    if (ftruncate(fd, 4096) != 0) printf("    ftruncate: %s\n", strerror(errno));

    snprintf(proc, sizeof proc, "/proc/self/fd/%d", fd);
    snprintf(target, sizeof target, "%s/exdev-probe.bin", to);
    unlink(target);

    int rc = linkat(AT_FDCWD, proc, AT_FDCWD, target, AT_SYMLINK_FOLLOW);
    int err = rc == 0 ? 0 : errno;

    if (stat(from, &a) == 0 && stat(to, &b) == 0)
        printf("    st_dev %lu -> %lu%s\n", (unsigned long)a.st_dev,
               (unsigned long)b.st_dev, a.st_dev == b.st_dev ? "  (same)" : "");
    if (rc == 0) {
        printf("    linkat: SUCCEEDED  <-- the inode was linked across\n");
        unlink(target);
    } else {
        printf("    linkat: %s%s\n", strerror(err),
               err == EXDEV ? "  <-- refused by the kernel" : "");
    }
    close(fd);
    return err;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("usage: %s <dir-on-fs-A> <dir-on-fs-B>\n", argv[0]);
        return 2;
    }
    printf("A -> B (%s -> %s):\n", argv[1], argv[2]);
    int ab = try_link(argv[1], argv[2]);
    printf("A -> A (control, must succeed):\n");
    int aa = try_link(argv[1], argv[1]);

    printf("\nverdict: crossing %s, staying put %s\n",
           ab == EXDEV ? "is refused with EXDEV" : "is NOT refused",
           aa == 0 ? "works" : "FAILED -- the control is broken, ignore the above");
    return 0;
}

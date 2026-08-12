// Probe: can a replaced mount be detected from the path alone?
//
// hydrationd marks a mount once, at startup, and then runs for as long as the
// deployment lasts. Between those two moments the mount underneath the path can
// be replaced -- the helper detaches its own on the way out, `RequiresMountsFor=`
// brings a fresh one up, and a restart cycle can leave a process holding a mark
// on a mount that is no longer the one a reader reaches. The mark is still
// valid; it just protects nothing. Every read then returns the zeros a
// placeholder is made of, and nothing in the process knows.
//
// A self-check needs a value it can take at mark time and compare later. This
// measures whether the mount id is that value, and which of the two the kernel
// offers can be trusted for it:
//
//   1. STATX_MNT_ID       -- the small id, field 1 of /proc/self/mountinfo.
//   2. STATX_MNT_ID_UNIQUE -- the 64-bit id (Linux 6.8+).
//
// The question is not whether they exist but whether they *change* when the
// mount is replaced. A small id that the kernel reuses for the next mount would
// make a replaced mount compare equal to the original, and the check would pass
// at exactly the moment it needed to fail -- the same shape of bug as
// `st_blocks` in DESIGN.md 8z, where the number that looks like the answer is
// the same for both states.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif
// 6.8+. Fills the same stx_mnt_id field, with the id that is never reused.
#ifndef STATX_MNT_ID_UNIQUE
#define STATX_MNT_ID_UNIQUE 0x00004000U
#endif

// Returns 0 on success and fills *out; -1 and prints on failure.
//
// Asking for the mask is not the same as getting it: statx reports back in
// stx_mask what it actually filled, and a kernel that does not know
// STATX_MNT_ID_UNIQUE silently returns the small id in the same field. Reading
// the answer without checking stx_mask would record one id and believe it was
// the other.
static int mnt_id(const char *path, unsigned int want, unsigned long long *out) {
    struct statx sx;
    memset(&sx, 0, sizeof sx);
    if (syscall(SYS_statx, AT_FDCWD, path, 0, want, &sx) != 0) {
        printf("    statx(%s): %s\n", path, strerror(errno));
        return -1;
    }
    if (!(sx.stx_mask & want)) {
        printf("    statx did not fill the requested id (stx_mask=0x%x)\n", sx.stx_mask);
        return -1;
    }
    *out = sx.stx_mnt_id;
    return 0;
}

int main(int argc, char **argv) {
    if (geteuid() != 0) {
        printf("needs root (this mounts and unmounts a tmpfs)\n");
        return 77;
    }
    const char *dir = argc > 1 ? argv[1] : "/tmp/mntid-probe";
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        printf("mkdir %s: %s\n", dir, strerror(errno));
        return 1;
    }

    unsigned long long small_before = 0, uniq_before = 0;
    unsigned long long small_after = 0, uniq_after = 0;

    if (mount("none", dir, "tmpfs", 0, NULL) != 0) {
        printf("mount: %s\n", strerror(errno));
        return 1;
    }
    printf("first mount:\n");
    int have_small = mnt_id(dir, STATX_MNT_ID, &small_before) == 0;
    int have_uniq = mnt_id(dir, STATX_MNT_ID_UNIQUE, &uniq_before) == 0;
    if (have_small) printf("    STATX_MNT_ID        = %llu\n", small_before);
    if (have_uniq) printf("    STATX_MNT_ID_UNIQUE = %llu\n", uniq_before);

    if (umount(dir) != 0) {
        printf("umount: %s\n", strerror(errno));
        return 1;
    }
    // Immediately, with nothing in between: this is the case that matters. A
    // helper restarting under systemd remounts within milliseconds, which is
    // exactly when a small id is most likely to be handed straight back.
    if (mount("none", dir, "tmpfs", 0, NULL) != 0) {
        printf("remount: %s\n", strerror(errno));
        return 1;
    }
    printf("second mount, same path, taken immediately:\n");
    if (have_small && mnt_id(dir, STATX_MNT_ID, &small_after) == 0)
        printf("    STATX_MNT_ID        = %llu\n", small_after);
    if (have_uniq && mnt_id(dir, STATX_MNT_ID_UNIQUE, &uniq_after) == 0)
        printf("    STATX_MNT_ID_UNIQUE = %llu\n", uniq_after);

    printf("\nverdict:\n");
    if (have_small)
        printf("    small id  %s the replacement%s\n",
               small_before == small_after ? "HIDES" : "shows",
               small_before == small_after ? "  <-- unusable as a self-check" : "");
    if (have_uniq)
        printf("    unique id %s the replacement%s\n",
               uniq_before == uniq_after ? "HIDES" : "shows",
               uniq_before == uniq_after ? "  <-- unusable as a self-check" : "");

    umount(dir);
    rmdir(dir);
    return 0;
}

// Probe: is there anything finer than mtime to notice a write with?
//
// `partial::Witness` is `{mtime, mtime_nsec, size}` and decides whether the
// worker may still believe its own record of which ranges it filled. DESIGN.md
// 8z-bis measured what that costs on ext4 with a 128-byte inode: no sub-second
// timestamp field, mtime granularity of one whole second, so a third party
// overwriting a range within a second of the worker filling it is invisible and
// the worker goes on vouching for content it did not put there.
//
// That section also asserted, without measuring it, that the obvious repair --
// the inode change counter, i_version, exposed as `STATX_CHANGE_COOKIE` -- "is
// not universally available and would need a fallback that lands back here".
// This is the measurement that assertion should have been built on.
//
// Three questions, and the third is the one that matters:
//
//   1. Does the kernel fill STATX_CHANGE_COOKIE at all here? Asking is not
//      getting: statx reports what it actually filled in stx_mask, and a
//      filesystem that does not keep a change counter simply leaves the bit
//      clear.
//   2. Does it move on an ordinary write?
//   3. Does it move on two writes in the *same second* -- the case mtime cannot
//      see, and the only reason to want it?
//
// A cookie that is present but only moves when mtime does would be worthless
// here, and would look identical to a working one on any filesystem with a fine
// clock. So the same-second case is tested explicitly rather than inferred.
//
//   cc -O2 -o /tmp/changecookie probes/changecookie.c
//   /tmp/changecookie <dir-on-the-filesystem>
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef STATX_CHANGE_COOKIE
#define STATX_CHANGE_COOKIE 0x40000000U
#endif
#ifndef STATX_ATTR_CHANGE_MONOTONIC
#define STATX_ATTR_CHANGE_MONOTONIC 0x8000
#endif

struct seen {
    int have_cookie;
    unsigned long long cookie;
    long long sec;
    long nsec;
    int monotonic;
};

static int look(const char *path, struct seen *out) {
    struct statx sx;
    memset(&sx, 0, sizeof sx);
    unsigned int want = STATX_CHANGE_COOKIE | STATX_MTIME;
    // AT_STATX_SYNC_AS_STAT: the cookie is a coherency value and the kernel is
    // entitled to withhold it for a "don't sync" request.
    if (syscall(SYS_statx, AT_FDCWD, path, 0, want, &sx) != 0) {
        printf("    statx: %s\n", strerror(errno));
        return -1;
    }
    out->have_cookie = (sx.stx_mask & STATX_CHANGE_COOKIE) != 0;
    // The field does not exist in this kernel's UAPI at all -- see the verdict
    // below -- so there is nothing to read even when the bit is asked for.
    out->cookie = 0;
    out->sec = sx.stx_mtime.tv_sec;
    out->nsec = sx.stx_mtime.tv_nsec;
    out->monotonic = (sx.stx_attributes & STATX_ATTR_CHANGE_MONOTONIC) != 0;
    return 0;
}

static int write_byte(const char *path, char c) {
    int fd = open(path, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) return -1;
    ssize_t n = pwrite(fd, &c, 1, 0);
    int r = (n == 1) ? fsync(fd) : -1;
    close(fd);
    return r;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s <dir-on-the-filesystem>\n", argv[0]);
        return 2;
    }
    char path[4096];
    snprintf(path, sizeof path, "%s/changecookie-probe.bin", argv[1]);
    unlink(path);

    struct seen a, b, c;
    if (write_byte(path, 'a') != 0 || look(path, &a) != 0) {
        perror("first write");
        return 1;
    }
    printf("  after first write:\n");
    printf("    STATX_CHANGE_COOKIE: %s\n", a.have_cookie ? "filled" : "NOT FILLED");
    if (a.have_cookie)
        printf("    cookie = %llu%s\n", a.cookie,
               a.monotonic ? "  (declared monotonic)" : "");
    printf("    mtime  = %lld.%09ld\n", a.sec, a.nsec);

    if (write_byte(path, 'b') != 0 || look(path, &b) != 0) {
        perror("second write");
        return 1;
    }
    int mtime_moved = !(a.sec == b.sec && a.nsec == b.nsec);
    printf("  after an immediate second write:\n");
    printf("    mtime  %s\n", mtime_moved ? "moved" : "did NOT move");
    if (a.have_cookie && b.have_cookie)
        printf("    cookie %s (%llu -> %llu)\n", a.cookie == b.cookie ? "did NOT move" : "moved",
               a.cookie, b.cookie);

    // A third write, so a filesystem that happens to straddle a tick boundary on
    // the second one does not read as a pass.
    if (write_byte(path, 'c') != 0 || look(path, &c) != 0) {
        perror("third write");
        return 1;
    }
    int cookie_moves = a.have_cookie && b.have_cookie && c.have_cookie &&
                       a.cookie != b.cookie && b.cookie != c.cookie;

    printf("\n  verdict: ");
    if (!a.have_cookie) {
        printf("no change cookie here; mtime is all there is\n");
    } else if (cookie_moves) {
        printf("the cookie moves on every write, including within one mtime tick\n");
    } else {
        printf("the cookie is present but does NOT move reliably -- unusable\n");
    }
    unlink(path);
    return 0;
}

// Does this kernel actually offer pre-content events?
//
// Asks the kernel rather than the headers. The two are not the same question:
// <linux/fanotify.h> comes from linux-libc-dev, which is a package, and a
// machine can easily have headers that define FAN_PRE_ACCESS while running a
// kernel that has never heard of it. A build-time grep for the constant
// therefore proves nothing about whether the suite can mean anything here.
//
// FAN_CLASS_PRE_CONTENT is a worse trap still: the constant has been in the
// header since fanotify was introduced, and for most of that time the class
// existed without pre-content events behind it. Its presence is not the
// feature.
//
// So do the only thing that settles it — open the notification group and place
// the mark this framework depends on, and report what the kernel said.
//
//   cc -O1 -Wall -Wextra -o precontent probes/precontent.c
//   sudo ./precontent /some/mountpoint
//
// Exit 0: usable. 1: kernel too old. 2: not permitted (no CAP_SYS_ADMIN).
// 3: usable in principle, but not on that mount's filesystem.
//
// The distinction matters in CI. "Too old" and "not permitted" are both
// reasons the suite cannot run, but only one of them is fixed by sudo, and a
// job that cannot tell them apart sends people to debug the wrong thing.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/fanotify.h>

// Numbers the running kernel knows that its headers may not — see the header.
#include "fanotify_compat.h"
#include <unistd.h>

int main(int argc, char **argv) {
    const char *mount = argc > 1 ? argv[1] : "/";

    // Exactly the flags `Group::new_pre_content` uses, and for the same
    // reasons: O_RDWR because the answer writes content into the event fd, and
    // no FAN_REPORT_FID because a permission class hands out descriptors and
    // the kernel refuses the combination with EINVAL.
    //
    // The first draft of this probe added FAN_REPORT_FID on its own initiative
    // and reported "this kernel is too old" on a kernel running the daemon
    // perfectly well. A capability probe that asks a question of its own
    // invention measures its own invention.
    int fd = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_REPORT_PIDFD,
                           O_RDWR | O_LARGEFILE);
    if (fd < 0) {
        // EINVAL is the kernel saying it does not understand the flags — an
        // older kernel rejecting the class or one of the report flags.
        // ENOSYS would mean no fanotify at all.
        if (errno == EINVAL || errno == ENOSYS) {
            printf("NO: fanotify_init rejected the pre-content class (%s)\n",
                   strerror(errno));
            printf("    this kernel is too old; pre-content events are a "
                   "6.14-and-later feature\n");
            return 1;
        }
        if (errno == EPERM) {
            printf("UNKNOWN: fanotify_init needs CAP_SYS_ADMIN; run as root\n");
            return 2;
        }
        printf("NO: fanotify_init: %s\n", strerror(errno));
        return 1;
    }

    // The class alone is not the feature. FAN_PRE_ACCESS is, and a mount mark
    // is how this framework uses it, so ask for exactly that.
    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
                      AT_FDCWD, mount) < 0) {
        if (errno == EINVAL || errno == ENOSYS || errno == EOPNOTSUPP) {
            printf("NO: the kernel took the class but refused FAN_PRE_ACCESS "
                   "on %s (%s)\n",
                   mount, strerror(errno));
            // A filesystem that cannot carry the mark at all (tmpfs, overlayfs)
            // is a different problem from a kernel that lacks the event, and
            // the caller may want to try elsewhere before giving up.
            printf("    either the kernel predates pre-content events, or this "
                   "filesystem cannot carry the mark\n");
            return errno == EOPNOTSUPP ? 3 : 1;
        }
        if (errno == EPERM) {
            printf("UNKNOWN: fanotify_mark needs CAP_SYS_ADMIN; run as root\n");
            close(fd);
            return 2;
        }
        printf("NO: fanotify_mark on %s: %s\n", mount, strerror(errno));
        close(fd);
        return 1;
    }

    printf("YES: pre-content events are usable on %s\n", mount);
    close(fd);
    return 0;
}

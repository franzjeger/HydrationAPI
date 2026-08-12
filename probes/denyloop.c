// Can the supervisor's teardown drain loop ever finish?
//
// The teardown path (§6a-bis, `bin/hydrationd.rs`) detaches the mount and then
// keeps answering with EIO until nothing has arrived "for long enough", on the
// stated reasoning that "a process that never exits is one systemd never
// restarts". Read the loop and that rule is a *sliding* window: every event that
// arrives pushes the deadline out again. Its termination is therefore not a
// property of the supervisor at all — it is a property of whatever else on the
// machine happens to be touching the mount.
//
// This probe asks whether that is a real risk or a theoretical one, by running
// the loop verbatim against two readers:
//
//   quiet : one access, denied once. The window closes. This is the control, and
//           it is what the loop was evidently written against.
//   storm : a reader that keeps accessing after each EIO. The window never
//           closes, the supervisor never exits, Restart=always never fires, and
//           a deployment designed to fail closed sits mount-down forever while
//           systemd still reports it active.
//
// WHAT WAS MEASURED IN THE FIELD, because it is worse than "storm" implies and
// the numbers belong next to the code. During a live incident on 2026-08-12 the
// supervisor answered denials for 23 minutes without ever seeing a quiet 10
// seconds — roughly 500 million of them, at ~300,000/s, burning half a core.
// The two processes responsible were KDE thumbnail workers, and they were not
// retrying in any loop they had written: their `syscr` was frozen at 222 and 194
// for their entire lifetimes and their `minflt` never moved either, so they were
// making no read syscalls and completing no faults. SIGSTOP on the pair took the
// supervisor's denial rate from 295,932/s to exactly 0, and SIGCONT restored it,
// so the attribution is not in doubt. The generator was a page-fault retry on a
// mapping established while hydration was still working; the precise kernel hook
// was not isolated, and this probe does not claim to reproduce that mechanism.
// It reproduces the consequence, which is what the fix has to survive.
//
// The distinction matters for the fix. If only a badly written program could hold
// the loop open, a note in the docs would do. What actually held it open was
// Dolphin generating thumbnails — nothing unusual, nothing hostile, and nothing
// the framework can ask not to happen. So the loop needs an absolute cap that
// does not depend on the rest of the machine cooperating.
//
//   cc -O1 -Wall -Wextra -I probes -o denyloop probes/denyloop.c
//   sudo ./denyloop /mnt/scratch quiet
//   sudo ./denyloop /mnt/scratch storm
//
// Exit 0: the window closed. Exit 1: it did not, within the cap.
// Exit 2: not permitted (no CAP_SYS_ADMIN). 3: this mount cannot carry the mark.
//
// An incidental finding, recorded because the first two versions of this probe
// were built on getting it wrong and it is not written down anywhere else:
// FAN_PRE_ACCESS is decided at open() time. A descriptor opened before the mark
// exists is exempt for its whole life — placing the mark afterwards produces no
// events for it at all, no matter what is read through it. So the mark must
// precede the open here, and in `mmapread.c`, and on a real mount it means a
// process holding a descriptor from before hydrationd started bypasses hydration
// entirely. Denying the single event that mmap() itself fires makes mmap() fail
// with MAP_FAILED rather than producing a faulting mapping, which is why the
// obvious way to write the mmap case measures the wrong thing.
//
// NOTE ON CLEANUP, and it is the reason this probe is safe to run: a process
// blocked in a pre-content event cannot be killed with a signal (§6a-bis,
// measured). It is released when the event is answered, or when the group is
// closed. This probe therefore always closes the group before waiting for the
// child, and reports whether SIGKILL alone was enough. Without that close it
// would leave an unkillable D-state process behind.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// Numbers the running kernel knows that its headers may not.
#include "fanotify_compat.h"

// The supervisor's own rule, and the cap it is missing. Both shortened from the
// shipped 10s so the probe answers in seconds; the shape is what is under test.
#define QUIET_SECS 2.0
#define CAP_SECS 10.0
#define PLACEHOLDER_SIZE 65536

static double now_secs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: denyloop <mountpoint> [quiet|storm]\n");
        return 2;
    }
    const char *mount = argv[1];
    const char *mode = argc > 2 ? argv[2] : "storm";
    int storm = strcmp(mode, "storm") == 0;
    if (!storm && strcmp(mode, "quiet") != 0) {
        fprintf(stderr, "denyloop: mode must be 'quiet' or 'storm'\n");
        return 2;
    }

    char path[4096];
    snprintf(path, sizeof(path), "%s/denyloop-placeholder", mount);

    // Created *before* the mark goes on, deliberately. A write inside a marked
    // mount by the only process that can answer the event it fires is §6a-ter,
    // and this probe is that process.
    int wfd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (wfd < 0) {
        fprintf(stderr, "denyloop: cannot create %s: %s\n", path, strerror(errno));
        return 3;
    }
    // A placeholder: the size is real, the content is a hole. Reading it without
    // a fetcher is exactly the "silent zeros" this framework exists to prevent.
    if (ftruncate(wfd, PLACEHOLDER_SIZE) != 0) {
        fprintf(stderr, "denyloop: ftruncate: %s\n", strerror(errno));
        close(wfd);
        return 3;
    }
    close(wfd);

    int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC | FAN_REPORT_PIDFD,
                            O_RDWR | O_LARGEFILE);
    if (fan < 0) {
        fprintf(stderr, "denyloop: fanotify_init: %s\n", strerror(errno));
        unlink(path);
        return errno == EPERM ? 2 : 1;
    }
    // Before the child exists, so the child's open() is covered — see the note
    // on open-time decision in the header.
    if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS, AT_FDCWD, mount) != 0) {
        fprintf(stderr, "denyloop: cannot mark %s with FAN_PRE_ACCESS: %s\n", mount,
                strerror(errno));
        close(fan);
        unlink(path);
        return 3;
    }

    pid_t child = fork();
    if (child < 0) {
        fprintf(stderr, "denyloop: fork: %s\n", strerror(errno));
        close(fan);
        unlink(path);
        return 1;
    }
    if (child == 0) {
        char buf[4096];
        do {
            int rfd = open(path, O_RDONLY);
            if (rfd < 0)
                _exit(11);
            // Denied, so this returns EIO. A reader that treats that as
            // transient — a retry, a next file, a directory walk that carries
            // on — comes straight back. Nothing in the framework can stop it.
            if (read(rfd, buf, sizeof(buf)) >= 0) {
                close(rfd);
                _exit(22); // read succeeded: zeros, i.e. failed open
            }
            close(rfd);
        } while (storm);
        _exit(20);
    }

    // The supervisor's drain loop, transcribed from bin/hydrationd.rs. Deny
    // everything, and exit once nothing has arrived for QUIET_SECS. The cap is
    // the thing under test — the real loop has no equivalent, so where this
    // probe gives up, hydrationd goes on spinning.
    unsigned long long events = 0, reads = 0;
    double started = now_secs();
    double quiet_since = started;
    int went_quiet = 0;
    char buf[64 * 1024];

    while (now_secs() - started < CAP_SECS) {
        if (now_secs() - quiet_since >= QUIET_SECS) {
            went_quiet = 1;
            break;
        }
        struct pollfd pfd = {.fd = fan, .events = POLLIN, .revents = 0};
        if (poll(&pfd, 1, 500) <= 0)
            continue;
        // The real loop resets its window on the poll return alone and never
        // looks at revents. POLLERR and POLLHUP are reported whether or not they
        // were asked for, so there an error condition counts as traffic too.
        if (!(pfd.revents & POLLIN))
            continue;
        ssize_t len = read(fan, buf, sizeof(buf));
        if (len <= 0)
            continue;
        reads++;
        quiet_since = now_secs();
        for (char *p = buf; p < buf + len;) {
            struct fanotify_event_metadata *m = (struct fanotify_event_metadata *)p;
            if (m->event_len < sizeof(*m) || p + m->event_len > buf + len)
                break;
            if (m->fd >= 0) {
                struct fanotify_response r = {.fd = m->fd, .response = FAN_DENY | (EIO << 24)};
                if (write(fan, &r, sizeof(r)) == sizeof(r))
                    events++;
                close(m->fd);
            }
            p += m->event_len;
        }
    }
    double elapsed = now_secs() - started;

    printf("denyloop: %s [%s]\n", mount, mode);
    printf("  reader           : %s\n",
           storm ? "keeps accessing after each EIO" : "one access, then stops");
    printf("  denials answered : %llu\n", events);
    printf("  group reads      : %llu\n", reads);
    printf("  elapsed          : %.1fs (cap %.0fs)\n", elapsed, CAP_SECS);
    printf("  rate             : %.0f denials/s\n", elapsed > 0 ? events / elapsed : 0.0);
    printf("  went quiet       : %s (rule: nothing for %.0fs)\n", went_quiet ? "yes" : "NO",
           QUIET_SECS);

    // Cleanup, in the only order that works. SIGKILL first so we can report
    // whether it was enough; the close is what actually frees the reader.
    kill(child, SIGKILL);
    int status = 0;
    int reaped_by_signal = waitpid(child, &status, WNOHANG) == child;
    printf("  SIGKILL alone    : %s\n",
           reaped_by_signal ? "reaped the reader" : "did NOT reap the reader (§6a-bis)");
    close(fan);
    waitpid(child, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 22)
        printf("  reader outcome   : read returned data — zeros, i.e. failed open once the\n"
               "                     group closed. This is the cost the cap accepts.\n");
    unlink(path);

    if (!went_quiet) {
        printf("\n  VERDICT: the window never closed. A drain loop whose only exit is a\n");
        printf("  sliding quiet window does not terminate under sustained access, so the\n");
        printf("  supervisor never exits, Restart=always never fires, and the mount stays\n");
        printf("  down. It needs an absolute cap.\n");
        return 1;
    }
    printf("\n  VERDICT: the window closed.\n");
    return 0;
}

// Probe: when a read of a well-formed placeholder returns zeros, was the
// pre-content event never generated, or generated and not delivered?
//
// Two independent observations per round:
//   1. /proc/self/fdinfo/<group fd> — the kernel's own view of this group's
//      marks. If the mount mark is present and the inode carries no ignored
//      mask, the kernel is set up to generate the event.
//   2. Whether poll() ever reports one while a reader is blocked.
//
// Run in a loop, because the failure is intermittent and a single green round
// proves nothing.
#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/xattr.h>

static void dump_marks(int fan, const char *when) {
    char p[64]; snprintf(p, sizeof(p), "/proc/self/fdinfo/%d", fan);
    FILE *f = fopen(p, "re"); char line[512];
    if (!f) { printf("      (fdinfo unreadable)\n"); return; }
    while (fgets(line, sizeof(line), f))
        if (strstr(line, "fanotify")) printf("      %s: %s", when, line);
    fclose(f);
}

int main(int argc, char **argv) {
    const char *mnt = argv[1];
    int rounds = argc > 2 ? atoi(argv[2]) : 5;
    int generated = 0, missing = 0;

    for (int r = 0; r < rounds; r++) {
        // The placeholder is made BEFORE the mount is marked.
        //
        // `ftruncate` is a write, and a write inside a marked mount generates a
        // pre-content event. In a single-threaded probe the only process that
        // could answer it is the one now blocked inside the syscall, so making
        // the file after marking wedges permanently — and the kernel stack says
        // so plainly:
        //
        //   do_ftruncate -> fsnotify_pre_content -> fanotify_handle_event
        //
        // Fourth time this trap has appeared in this project, in a fourth
        // disguise.
        char path[512]; snprintf(path, sizeof(path), "%s/probe-%d.bin", mnt, r);
        unlink(path);
        int fd = open(path, O_CREAT|O_WRONLY, 0644);
        if (ftruncate(fd, 4096) < 0) fprintf(stderr, "  ftruncate: %s\n", strerror(errno));
        close(fd);
        if (setxattr(path, "user.hydration.dehydrated", "1", 1, 0) < 0)
            fprintf(stderr, "  setxattr: %s\n", strerror(errno));

        int fan = fanotify_init(FAN_CLASS_PRE_CONTENT|FAN_CLOEXEC, O_RDWR|O_LARGEFILE);
        if (fan < 0) { perror("init"); return 2; }
        if (fanotify_mark(fan, FAN_MARK_ADD|FAN_MARK_MOUNT, FAN_PRE_ACCESS, AT_FDCWD, mnt) < 0) {
            perror("mark"); return 3;
        }
        printf("  round %d\n", r);
        dump_marks(fan, "before");

        fprintf(stderr, "[%d] forking reader\n", r);
        pid_t c = fork();
        if (c == 0) {
            int f2 = open(path, O_RDONLY);
            char buf[4096];
            ssize_t n = read(f2, buf, sizeof(buf));
            // Report what the reader actually got, so "no event" can be told
            // apart from "event denied".
            fprintf(stderr, "      reader: read()=%zd errno=%s\n", n, n<0?strerror(errno):"-");
            _exit(0);
        }

        struct pollfd pfd = { .fd = fan, .events = POLLIN };
        int got = poll(&pfd, 1, 2000);
        if (got > 0) {
            printf("      EVENT GENERATED and delivered\n");
            generated++;
            char buf[8192];
            ssize_t len = read(fan, buf, sizeof(buf));
            struct fanotify_event_metadata *md = (void*)buf;
            if (len > 0 && md->fd >= 0) {
                struct fanotify_response resp = { .fd = md->fd, .response = FAN_ALLOW };
                write(fan, &resp, sizeof(resp));
                close(md->fd);
            }
        } else {
            printf("      NO EVENT within 2s — reader was not intercepted\n");
            missing++;
            dump_marks(fan, "after ");
        }
        int st; waitpid(c, &st, 0);
        close(fan);
        unlink(path);
    }
    printf("\n  %d/%d rounds generated an event, %d produced none\n",
           generated, generated+missing, missing);
    return 0;
}

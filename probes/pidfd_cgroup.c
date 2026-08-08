// Probe: does pidfd -> pid -> cgroup actually work from a pre-content event?
//
// The whole hydration policy in DESIGN.md §6c rests on this path. md->pid alone
// is the wrong key: pids get recycled, so looking up /proc/<pid>/cgroup after the
// event arrives races a dying process. A pidfd pins the pid for as long as it is
// open, which makes the lookup safe.
//
// This probe answers three things:
//   1. Does FAN_REPORT_PIDFD deliver a usable pidfd on a FAN_PRE_ACCESS event?
//   2. Can we get from that pidfd to a cgroup path?
//   3. Does the cgroup actually name the systemd unit, so it can be a policy key?
//
// Safety: marks ONE mount, auto-exits, answers FAN_ALLOW on every path.
#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>

// A pidfd pins the pid, so this lookup cannot race pid reuse.
static int pid_from_pidfd(int pidfd)
{
	char path[64], line[256];
	FILE *f;
	int pid = -1;

	snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
	f = fopen(path, "re");
	if (!f) return -1;
	while (fgets(line, sizeof(line), f))
		if (sscanf(line, "Pid:\t%d", &pid) == 1) break;
	fclose(f);
	return pid;
}

static void read_proc_field(int pid, const char *what, char *out, size_t outlen)
{
	char path[64];
	FILE *f;
	size_t n;

	out[0] = '\0';
	snprintf(path, sizeof(path), "/proc/%d/%s", pid, what);
	f = fopen(path, "re");
	if (!f) { snprintf(out, outlen, "(unreadable: %s)", strerror(errno)); return; }
	n = fread(out, 1, outlen - 1, f);
	out[n] = '\0';
	while (n > 0 && (out[n - 1] == '\n')) out[--n] = '\0';
	fclose(f);
}

int main(int argc, char **argv)
{
	int fan;
	char buf[8192];
	time_t deadline;

	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint> [seconds]\n", argv[0]); return 1; }

	fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_REPORT_PIDFD | FAN_CLOEXEC,
			    O_RDWR | O_LARGEFILE);
	if (fan < 0) {
		fprintf(stderr, "[pidfd] fanotify_init(PRE_CONTENT|REPORT_PIDFD) FAILED: %s\n",
			strerror(errno));
		return 2;
	}
	fprintf(stderr, "[pidfd] fanotify_init with FAN_REPORT_PIDFD OK\n");

	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, argv[1]) < 0) {
		fprintf(stderr, "[pidfd] fanotify_mark FAILED: %s\n", strerror(errno));
		return 3;
	}
	fprintf(stderr, "[pidfd] marked %s, waiting for reads\n", argv[1]);
	fflush(stderr);

	deadline = time(NULL) + (argc > 2 ? atoi(argv[2]) : 60);
	while (time(NULL) < deadline) {
		struct pollfd pfd = { .fd = fan, .events = POLLIN };
		ssize_t len;
		char *ptr;

		if (poll(&pfd, 1, 500) <= 0) continue;
		len = read(fan, buf, sizeof(buf));
		if (len <= 0) continue;

		for (ptr = buf; FAN_EVENT_OK((struct fanotify_event_metadata *)ptr, len);
		     ptr = (char *)FAN_EVENT_NEXT((struct fanotify_event_metadata *)ptr, len)) {
			struct fanotify_event_metadata *md =
				(struct fanotify_event_metadata *)ptr;
			struct fanotify_response resp;
			char *rec = (char *)md + sizeof(*md);
			char *end = (char *)md + md->event_len;
			int pidfd = FAN_NOPIDFD;

			while (rec + sizeof(struct fanotify_event_info_header) <= end) {
				struct fanotify_event_info_header *h =
					(struct fanotify_event_info_header *)rec;
				if (h->len == 0 || rec + h->len > end) break;
				if (h->info_type == FAN_EVENT_INFO_TYPE_PIDFD)
					pidfd = ((struct fanotify_event_info_pidfd *)rec)->pidfd;
				rec += h->len;
			}

			fprintf(stderr, "\n[pidfd] --- FAN_PRE_ACCESS ---\n");
			fprintf(stderr, "[pidfd]   event->pid (racy key)  = %d\n", md->pid);

			if (pidfd == FAN_NOPIDFD) {
				fprintf(stderr, "[pidfd]   pidfd = FAN_NOPIDFD (none delivered)\n");
			} else if (pidfd == FAN_EPIDFD) {
				fprintf(stderr, "[pidfd]   pidfd = FAN_EPIDFD (creation failed)\n");
			} else {
				int pid = pid_from_pidfd(pidfd);
				char comm[128], cgroup[512], exe[512];
				ssize_t n;

				fprintf(stderr, "[pidfd]   pidfd = %d -> pid %d\n", pidfd, pid);
				if (pid > 0) {
					read_proc_field(pid, "comm", comm, sizeof(comm));
					read_proc_field(pid, "cgroup", cgroup, sizeof(cgroup));
					n = readlink(("/proc/self/exe"), exe, 0); (void)n;
					snprintf(exe, sizeof(exe), "/proc/%d/exe", pid);
					char target[512];
					n = readlink(exe, target, sizeof(target) - 1);
					if (n > 0) target[n] = '\0'; else strcpy(target, "(unreadable)");

					fprintf(stderr, "[pidfd]   comm   = %s\n", comm);
					fprintf(stderr, "[pidfd]   exe    = %s\n", target);
					fprintf(stderr, "[pidfd]   CGROUP = %s\n", cgroup);
				}
				close(pidfd);
			}

			if (md->fd >= 0) {
				resp.fd = md->fd;
				resp.response = FAN_ALLOW;
				if (write(fan, &resp, sizeof(resp)) < 0)
					fprintf(stderr, "[pidfd] response failed: %s\n",
						strerror(errno));
				close(md->fd);
			}
			fflush(stderr);
		}
	}
	fprintf(stderr, "\n[pidfd] done\n");
	close(fan);
	return 0;
}

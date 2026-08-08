// Probe: can the daemon detect a new mount that exposes the sync files?
//
// DESIGN.md §6.4a concluded that the requirement -- no other mount exposes the
// sync directory -- cannot be enforced, only detected. This checks that the
// detection actually exists, and what it costs structurally.
//
// Two questions:
//   1. Does FAN_REPORT_MNT really refuse to coexist with FAN_CLASS_PRE_CONTENT?
//      If so the hydration group cannot also watch mounts, and the supervisor
//      needs a second descriptor.
//   2. Does a mount-namespace mark actually deliver FAN_MNT_ATTACH, with enough
//      information to tell whether the new mount exposes our files?
#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/syscall.h>
#include <linux/mount.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>

/// What the daemon actually needs to know: does anything other than our own
/// mount currently expose the sync files?
///
/// Resolving the event's mnt_id directly turned out to be the wrong shape. The
/// id fanotify reports is the 64-bit unique one, not the small reused id in
/// field 1 of /proc/self/mountinfo, and by the time a DETACH arrives the mount
/// is gone and cannot be resolved at all.
///
/// So the event is treated as a trigger to re-examine, not as a source of
/// truth. That is namespace-correct, survives events arriving before a mount is
/// fully visible, and works identically for attach and detach.
static int exposures_of(const char *device_suffix, char *out, size_t len)
{
	FILE *f = fopen("/proc/self/mountinfo", "re");
	char line[4096];
	size_t used = 0;
	int count = 0;

	out[0] = '\0';
	if (!f) return 0;
	while (fgets(line, sizeof(line), f)) {
		char root[1024], point[1024], rest[2048];
		if (sscanf(line, "%*u %*u %*u:%*u %1023s %1023s %2047[^\n]",
			   root, point, rest) != 3)
			continue;
		if (!strstr(rest, device_suffix))
			continue;
		count++;
		if (used < len - 1)
			used += snprintf(out + used, len - used, "%s      %s (root %s)\n",
					 count == 1 ? "" : "", point, root);
	}
	fclose(f);
	return count;
}

int main(int argc, char **argv)
{
	int fan;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <device-substring> [secs]\n", argv[0]);
		return 1;
	}
	char buf[8192];
	time_t deadline;

	// Question 1: does the hydration group get to do this too?
	int both = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_REPORT_MNT | FAN_CLOEXEC,
				 O_RDONLY);
	if (both < 0)
		fprintf(stderr, "[mnt] PRE_CONTENT + REPORT_MNT together: REFUSED (%s)\n",
			strerror(errno));
	else {
		fprintf(stderr, "[mnt] PRE_CONTENT + REPORT_MNT together: ACCEPTED\n");
		close(both);
	}

	// Question 2: a separate notification-class group for mounts.
	fan = fanotify_init(FAN_CLASS_NOTIF | FAN_REPORT_MNT | FAN_CLOEXEC, O_RDONLY);
	if (fan < 0) {
		fprintf(stderr, "[mnt] fanotify_init(NOTIF|REPORT_MNT) FAILED: %s\n",
			strerror(errno));
		return 2;
	}
	fprintf(stderr, "[mnt] separate NOTIF|REPORT_MNT group created\n");

	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MNTNS,
			  FAN_MNT_ATTACH | FAN_MNT_DETACH,
			  AT_FDCWD, "/proc/self/ns/mnt") < 0) {
		fprintf(stderr, "[mnt] mark on mount namespace FAILED: %s\n", strerror(errno));
		return 3;
	}
	fprintf(stderr, "[mnt] watching this mount namespace for attach/detach\n");
	fflush(stderr);

	deadline = time(NULL) + (argc > 2 ? atoi(argv[2]) : 20);
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
			char *rec = (char *)md + sizeof(*md);
			char *end = (char *)md + md->event_len;
			const char *what = (md->mask & FAN_MNT_ATTACH) ? "ATTACH" : "DETACH";

			while (rec + sizeof(struct fanotify_event_info_header) <= end) {
				struct fanotify_event_info_header *h =
					(struct fanotify_event_info_header *)rec;
				if (h->len == 0 || rec + h->len > end) break;
				if (h->info_type == FAN_EVENT_INFO_TYPE_MNT) {
					struct fanotify_event_info_mnt *m =
						(struct fanotify_event_info_mnt *)rec;
					char list[4096];
					int n = exposures_of(argv[1], list, sizeof(list));
					fprintf(stderr,
						"[mnt] %s (mnt_id=%llu) -> %d mount(s) now expose %s\n%s",
						what, (unsigned long long)m->mnt_id,
						n, argv[1], list);
				}
				rec += h->len;
			}
			fflush(stderr);
		}
	}
	fprintf(stderr, "[mnt] done\n");
	close(fan);
	return 0;
}

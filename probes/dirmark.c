// Probe: can FAN_PRE_ACCESS be set on a single directory, or does hydration
// require marking a whole mount?
//
// This decides whether DESIGN.md's "sync folder on its own mount point" is a
// requirement or merely a recommendation, and therefore how much systemd work
// v1 carries.
//
// Two questions, and the second is the one that matters:
//   1. Does fanotify_mark accept FAN_PRE_ACCESS with this mark type at all?
//   2. If it does, are events delivered for files *inside* the directory --
//      direct children, and files further down?
//
// A mark that is accepted but delivers nothing for children is worse than a
// rejected one: it looks like it works.
//
// Safety: marks exactly what it is told, auto-exits, answers FAN_ALLOW always.
#define _GNU_SOURCE
#include <sys/fanotify.h>

// Numbers the running kernel knows that its headers may not — see the header.
#include "fanotify_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>

static const char *FILL = "HYDRATED";

struct mode {
	const char *name;
	unsigned int flags;
	uint64_t extra_mask;
};

static const struct mode MODES[] = {
	{ "inode",       FAN_MARK_ADD,                       0 },
	{ "inode-child", FAN_MARK_ADD,                       FAN_EVENT_ON_CHILD },
	{ "mount",       FAN_MARK_ADD | FAN_MARK_MOUNT,      0 },
	{ "filesystem",  FAN_MARK_ADD | FAN_MARK_FILESYSTEM, 0 },
};

static const struct mode *lookup(const char *name)
{
	for (size_t i = 0; i < sizeof(MODES) / sizeof(MODES[0]); i++)
		if (strcmp(MODES[i].name, name) == 0)
			return &MODES[i];
	return NULL;
}

/// Which file an event fd refers to, so we can tell whether children and
/// nested files are covered.
static void name_of(int fd, char *out, size_t len)
{
	char link[64];
	ssize_t n;
	snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
	n = readlink(link, out, len - 1);
	if (n < 0) snprintf(out, len, "(unknown: %s)", strerror(errno));
	else out[n] = '\0';
}

int main(int argc, char **argv)
{
	int fan;
	const struct mode *m;
	char buf[8192];
	time_t deadline;

	if (argc < 3) {
		fprintf(stderr, "usage: %s <dir> <inode|inode-child|mount|filesystem> [secs]\n",
			argv[0]);
		return 1;
	}
	m = lookup(argv[2]);
	if (!m) { fprintf(stderr, "unknown mode %s\n", argv[2]); return 1; }

	fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) {
		fprintf(stderr, "[dirmark] fanotify_init FAILED: %s\n", strerror(errno));
		return 2;
	}

	if (fanotify_mark(fan, m->flags, FAN_PRE_ACCESS | m->extra_mask,
			  AT_FDCWD, argv[1]) < 0) {
		fprintf(stderr, "[dirmark] mode=%-12s MARK REJECTED: %s (errno=%d)\n",
			m->name, strerror(errno), errno);
		return 3;
	}
	fprintf(stderr, "[dirmark] mode=%-12s MARK ACCEPTED on %s\n", m->name, argv[1]);
	fflush(stderr);

	deadline = time(NULL) + (argc > 3 ? atoi(argv[3]) : 30);
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
			char path[512];

			if (md->fd >= 0) {
				name_of(md->fd, path, sizeof(path));
				fprintf(stderr, "[dirmark] EVENT for %s\n", path);
				pwrite(md->fd, FILL, strlen(FILL), 0);
				resp.fd = md->fd;
				resp.response = FAN_ALLOW;
				if (write(fan, &resp, sizeof(resp)) < 0)
					fprintf(stderr, "[dirmark] response failed: %s\n",
						strerror(errno));
				close(md->fd);
			}
			fflush(stderr);
		}
	}
	fprintf(stderr, "[dirmark] done\n");
	close(fan);
	return 0;
}

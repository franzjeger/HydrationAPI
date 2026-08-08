// Probe: does FAN_MARK_IGNORE_SURV actually stop events for a hydrated file?
//
// DESIGN.md claims hydrated files cost nothing -- once a file is full, the
// daemon leaves the data path entirely and the file is an ordinary btrfs file
// again. That claim rests on being able to suppress further pre-content events
// for one inode without dropping the mount mark that covers everything else.
//
// If suppression does not work, every read of every already-hydrated file pays
// a blocking round trip to userspace forever, and the performance story in §2.4
// is wrong.
//
// Three questions:
//   1. Is an ignore mark accepted alongside a mount mark?
//   2. Does it actually suppress the next read?
//   3. Does it survive the file being modified? (that is what SURV means, and
//      it matters: a hydrated file that gets written must not silently start
//      generating hydration events again)
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

static int events = 0;

static void drain(int fan, int ms, const char *fill)
{
	time_t end = time(NULL) + (ms / 1000) + 1;
	char buf[8192];

	while (time(NULL) < end) {
		struct pollfd pfd = { .fd = fan, .events = POLLIN };
		ssize_t len;
		char *ptr;

		if (poll(&pfd, 1, 200) <= 0) continue;
		len = read(fan, buf, sizeof(buf));
		if (len <= 0) continue;
		for (ptr = buf; FAN_EVENT_OK((struct fanotify_event_metadata *)ptr, len);
		     ptr = (char *)FAN_EVENT_NEXT((struct fanotify_event_metadata *)ptr, len)) {
			struct fanotify_event_metadata *md =
				(struct fanotify_event_metadata *)ptr;
			struct fanotify_response resp;
			if (md->fd < 0) continue;
			events++;
			if (fill) pwrite(md->fd, fill, strlen(fill), 0);
			resp.fd = md->fd;
			resp.response = FAN_ALLOW;
			if (write(fan, &resp, sizeof(resp)) < 0)
				fprintf(stderr, "  response failed: %s\n", strerror(errno));
			close(md->fd);
		}
	}
}

int main(int argc, char **argv)
{
	int fan;
	pid_t child;

	if (argc < 3) { fprintf(stderr, "usage: %s <mountpoint> <file>\n", argv[0]); return 1; }

	fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("fanotify_init"); return 2; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, argv[1]) < 0) { perror("mark mount"); return 3; }
	fprintf(stderr, "[ign] mount marked\n");

	// A helper that reads the file on cue, so the parent can stay in its loop.
	child = fork();
	if (child == 0) {
		char cmd[2048];
		snprintf(cmd, sizeof(cmd), "sleep 2; cat %s >/dev/null 2>&1; "
			 "sleep 3; cat %s >/dev/null 2>&1; "
			 "sleep 3; printf modified > %s 2>/dev/null; "
			 "sleep 1; cat %s >/dev/null 2>&1", argv[2], argv[2], argv[2], argv[2]);
		execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
		_exit(1);
	}

	// 1. First read: the mount mark should deliver an event.
	events = 0;
	drain(fan, 3000, "HYDRATED");
	fprintf(stderr, "[ign] phase 1 (first read, no ignore mark): %d event(s)%s\n",
		events, events > 0 ? "  <- expected" : "  <- UNEXPECTED");

	// 2. Add the ignore mark for this one file and read again.
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_IGNORE_SURV, FAN_PRE_ACCESS,
			  AT_FDCWD, argv[2]) < 0) {
		fprintf(stderr, "[ign] IGNORE_SURV mark REJECTED: %s\n", strerror(errno));
		return 4;
	}
	fprintf(stderr, "[ign] ignore mark accepted on the hydrated file\n");

	events = 0;
	drain(fan, 3000, "HYDRATED");
	fprintf(stderr, "[ign] phase 2 (read with ignore mark): %d event(s)%s\n",
		events, events == 0 ? "  <- suppressed, as claimed" : "  <- NOT suppressed");

	// 3. Modify the file, then read: does the ignore mark survive?
	events = 0;
	drain(fan, 5000, "HYDRATED");
	fprintf(stderr, "[ign] phase 3 (read after modify): %d event(s)%s\n",
		events, events == 0 ? "  <- survived the modify" : "  <- lost on modify");

	close(fan);
	return 0;
}

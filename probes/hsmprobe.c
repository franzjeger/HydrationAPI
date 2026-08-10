// Feasibility probe only -- not implementation code.
// Question: on this kernel + btrfs, can a userspace daemon hydrate a sparse
// placeholder file on first read using fanotify pre-content events, so that
// the reader transparently sees real content?
//
// Safety: marks ONE mount (argv[1]), auto-exits after a timeout, and answers
// FAN_ALLOW on every path including errors, so it can never wedge the mount.
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

static const char *FILL = "REAL-CLOUD-CONTENT-FETCHED-ON-DEMAND";

int main(int argc, char **argv)
{
	int fan, ret;
	char buf[8192];
	time_t deadline;

	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]); return 1; }

	fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) {
		fprintf(stderr, "[hsm] fanotify_init(FAN_CLASS_PRE_CONTENT) FAILED: %s (errno=%d)\n",
			strerror(errno), errno);
		return 2;
	}
	fprintf(stderr, "[hsm] fanotify_init(FAN_CLASS_PRE_CONTENT) OK\n");

	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, argv[1]) < 0) {
		fprintf(stderr, "[hsm] fanotify_mark(FAN_PRE_ACCESS) FAILED: %s (errno=%d)\n",
			strerror(errno), errno);
		return 3;
	}
	fprintf(stderr, "[hsm] marked mount %s for FAN_PRE_ACCESS\n", argv[1]);
	fflush(stderr);

	deadline = time(NULL) + (getenv("HSM_TIMEOUT") ? atoi(getenv("HSM_TIMEOUT")) : 25);
	while (time(NULL) < deadline) {
		struct pollfd pfd = { .fd = fan, .events = POLLIN };
		ssize_t len;
		char *ptr;

		ret = poll(&pfd, 1, 1000);
		if (ret <= 0) continue;

		len = read(fan, buf, sizeof(buf));
		if (len <= 0) continue;

		for (ptr = buf; FAN_EVENT_OK((struct fanotify_event_metadata *)ptr, len);
		     ptr = (char *)FAN_EVENT_NEXT((struct fanotify_event_metadata *)ptr, len)) {
			struct fanotify_event_metadata *md = (struct fanotify_event_metadata *)ptr;
			struct fanotify_response resp;
			unsigned long long off = 0, cnt = 0;
			int have_range = 0;
			char *rec = (char *)md + sizeof(*md);
			char *end = (char *)md + md->event_len;

			// Walk the info records looking for the requested byte range.
			while (rec + sizeof(struct fanotify_event_info_header) <= end) {
				struct fanotify_event_info_header *h =
					(struct fanotify_event_info_header *)rec;
				if (h->len == 0 || rec + h->len > end) break;
				if (h->info_type == FAN_EVENT_INFO_TYPE_RANGE) {
					struct fanotify_event_info_range *r =
						(struct fanotify_event_info_range *)rec;
					off = r->offset; cnt = r->count; have_range = 1;
				}
				rec += h->len;
			}

			if (md->mask & FAN_PRE_ACCESS) {
				fprintf(stderr, "[hsm] FAN_PRE_ACCESS pid=%d fd=%d range=%s",
					md->pid, md->fd, have_range ? "" : "(none) ");
				if (have_range)
					fprintf(stderr, "offset=%llu count=%llu", off, cnt);
				fprintf(stderr, "\n");

				// This is the hydration moment: fill the placeholder.
				if (md->fd >= 0) {
					ssize_t w = pwrite(md->fd, FILL, strlen(FILL), 0);
					fprintf(stderr, "[hsm] hydrated %zd bytes -> %s\n",
						w, w < 0 ? strerror(errno) : "OK");
					fsync(md->fd);
				}
			}

			if (md->fd >= 0) {
				resp.fd = md->fd;
				resp.response = FAN_ALLOW;
				if (write(fan, &resp, sizeof(resp)) < 0)
					fprintf(stderr, "[hsm] response write failed: %s\n",
						strerror(errno));
				close(md->fd);
			}
			fflush(stderr);
		}
	}
	fprintf(stderr, "[hsm] timeout reached, exiting cleanly\n");
	close(fan);
	return 0;
}

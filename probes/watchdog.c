// Feasibility probe only -- not implementation code.
// Question: if the hydration worker dies, can a supervisor holding the same
// fanotify group fd keep the marks alive and fail CLOSED (EIO) instead of
// letting dehydrated files read back as silent zeros?
//
// Layout: parent opens the group + mark, then forks. Child is the hydrator.
// Parent holds its copy of the fd and does nothing until the child dies, then
// takes over the event loop and denies everything with EIO.
#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>

static const char *FILL = "REAL-CLOUD-CONTENT-FETCHED-ON-DEMAND";

// Returns after `secs`; if `deny` is set, answers FAN_DENY_ERRNO(EIO) instead
// of hydrating.
static void event_loop(int fan, int secs, int deny, const char *who)
{
	time_t deadline = time(NULL) + secs;
	char buf[8192];

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

			if (md->fd < 0) continue;

			if (getenv("PROBE_HOLD_EVENT")) {
				// Publish the in-flight event fd. The question is
				// whether a response is matched by fd number alone,
				// in which case the supervisor can answer for a
				// worker that died holding it.
				FILE *pub = fopen("/tmp/hydration-inflight", "we");
				if (pub) { fprintf(pub, "%d\n", md->fd); fclose(pub); }
				// Dequeue the event and deliberately never answer it,
				// then wait to be killed. The reader stays blocked in
				// read() for the whole of this. The question is what
				// the supervisor can still do about an event that has
				// already left the queue.
				fprintf(stderr, "[%s] HOLDING event unanswered (pid=%d)\n",
					who, md->pid);
				fflush(stderr);
				for (;;) pause();
			}

			if (deny) {
				fprintf(stderr, "[%s] DENYING pid=%d with EIO\n", who, md->pid);
				resp.fd = md->fd;
				resp.response = FAN_DENY_ERRNO(EIO);
			} else {
				pwrite(md->fd, FILL, strlen(FILL), 0);
				fprintf(stderr, "[%s] hydrated for pid=%d\n", who, md->pid);
				resp.fd = md->fd;
				resp.response = FAN_ALLOW;
			}
			if (write(fan, &resp, sizeof(resp)) < 0)
				fprintf(stderr, "[%s] response failed: %s\n", who, strerror(errno));
			close(md->fd);
			fflush(stderr);
		}
	}
}

int main(int argc, char **argv)
{
	int fan;
	pid_t child;

	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]); return 1; }

	fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("fanotify_init"); return 2; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, argv[1]) < 0) { perror("fanotify_mark"); return 3; }

	fprintf(stderr, "[super] group created and mount marked\n");
	fflush(stderr);

	child = fork();
	if (child < 0) { perror("fork"); return 4; }

	if (child == 0) {
		fprintf(stderr, "[worker] pid=%d handling events (hydrating)\n", getpid());
		fflush(stderr);
		event_loop(fan, 120, 0, "worker");
		_exit(0);
	}

	fprintf(stderr, "[super] worker pid=%d; holding fd, idle\n", child);
	fflush(stderr);

	// Supervisor does NOT touch the fd until the worker dies.
	int status;
	waitpid(child, &status, 0);
	fprintf(stderr, "[super] *** WORKER DIED (signal=%d) - taking over, failing closed ***\n",
		WIFSIGNALED(status) ? WTERMSIG(status) : 0);
	fflush(stderr);

	{
		FILE *pub = fopen("/tmp/hydration-inflight", "re");
		int stranded = -1;
		if (pub) { if (fscanf(pub, "%d", &stranded) != 1) stranded = -1; fclose(pub); }
		if (stranded >= 0) {
			struct fanotify_response resp = {
				.fd = stranded,
				.response = FAN_DENY_ERRNO(EIO),
			};
			ssize_t n = write(fan, &resp, sizeof(resp));
			fprintf(stderr,
				"[super] answering stranded event fd=%d for the dead worker: %s\n",
				stranded, n < 0 ? strerror(errno) : "accepted");
			fflush(stderr);
		}
	}
	event_loop(fan, 60, 1, "super");
	fprintf(stderr, "[super] exiting\n");
	close(fan);
	return 0;
}

// Probe: does reading a file that has no bytes fire a pre-content event?
//
// This is the one question left open by the placeholder-creation rule. That rule
// allows an event when the inode is nameless and empty, on the grounds that an
// empty file has no bytes anyone could be served instead of real content. The
// residual worry is a race: if a size-0 read blocks on an event, a concurrent
// grow could land between the worker's allow and the reader's copy, and the
// reader would see unhydrated bytes past the old EOF.
//
// If a past-EOF read fires no event at all, there is no blocked reader, no
// window, and the worry is not merely unlikely but absent.
#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/wait.h>

static int drain(int fan, int ms)
{
	struct pollfd pfd = { .fd = fan, .events = POLLIN };
	char buf[8192];
	int seen = 0;
	while (poll(&pfd, 1, ms) > 0) {
		ssize_t len = read(fan, buf, sizeof(buf));
		if (len <= 0) break;
		for (char *p = buf; FAN_EVENT_OK((struct fanotify_event_metadata *)p, len);
		     p = (char *)FAN_EVENT_NEXT((struct fanotify_event_metadata *)p, len)) {
			struct fanotify_event_metadata *md = (void *)p;
			if (md->fd < 0) continue;
			seen++;
			struct fanotify_response r = { .fd = md->fd, .response = FAN_ALLOW };
			if (write(fan, &r, sizeof(r)) < 0) perror("respond");
			close(md->fd);
		}
	}
	return seen;
}

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]); return 1; }
	const char *mnt = argv[1];
	setbuf(stdout, NULL);

	char empty[512], sized[512];
	snprintf(empty, sizeof(empty), "%s/probe-empty.bin", mnt);
	snprintf(sized, sizeof(sized), "%s/probe-sized.bin", mnt);
	unlink(empty); unlink(sized);

	// Both created before the mark, so creating them fires nothing.
	int f = open(empty, O_CREAT | O_WRONLY, 0644); close(f);
	f = open(sized, O_CREAT | O_WRONLY, 0644);
	if (ftruncate(f, 4096) < 0) perror("ftruncate");
	close(f);

	int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("fanotify_init"); return 2; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, mnt) < 0) { perror("mark"); return 3; }
	drain(fan, 200);

	// The control: a sized file must fire, or the probe proves nothing.
	for (int which = 0; which < 2; which++) {
		const char *path = which ? sized : empty;
		pid_t c = fork();
		if (c == 0) {
			char buf[64];
			int fd = open(path, O_RDONLY);
			ssize_t n = fd >= 0 ? read(fd, buf, sizeof(buf)) : -1;
			fprintf(stderr, "    reader got %zd bytes\n", n);
			_exit(0);
		}
		int st, events = 0, done = 0;
		for (int i = 0; i < 15; i++) {
			events += drain(fan, 200);
			if (waitpid(c, &st, WNOHANG) == c) { done = 1; break; }
		}
		if (!done) { kill(c, 9); waitpid(c, &st, 0); }
		printf("  %-14s size=%d  events=%d  read %s\n",
		       which ? "sized (4096)" : "empty (0)",
		       which ? 4096 : 0, events, done ? "completed" : "BLOCKED");
	}

	unlink(empty); unlink(sized);
	printf("\nIf the empty file fired 0 events while the sized one fired at least 1,\n"
	       "a past-EOF read never blocks, and the empty-file rule has no race to lose.\n");
	return 0;
}

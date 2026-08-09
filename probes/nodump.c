// Probe: does setting the nodump flag fire a pre-content event?
//
// It has to be answered before nodump can be given an owner, because the flag is
// set exactly where the trap in §6a-ter lives: inside `evict()`, which runs in
// the marked mount, in the process that answers events. If FS_IOC_SETFLAGS
// counts as a content access, setting the flag deadlocks eviction against
// itself — the seventh disguise.
//
// Also measures whether the flag survives a hole punch, since eviction punches
// immediately afterwards, and whether it survives being written through (the
// hydration path), which decides whether clearing it needs its own step.
#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/fs.h>
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

static int flags_of(const char *p)
{
	int fd = open(p, O_RDONLY), f = 0;
	if (fd < 0) return -1;
	if (ioctl(fd, FS_IOC_GETFLAGS, &f) < 0) f = -1;
	close(fd);
	return f;
}

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]); return 1; }
	const char *mnt = argv[1];
	setbuf(stdout, NULL);

	char path[512];
	snprintf(path, sizeof(path), "%s/nodump-probe.bin", mnt);
	unlink(path);
	int fd = open(path, O_CREAT | O_RDWR, 0644);
	if (fd < 0) { perror("create"); return 2; }
	if (write(fd, "content that will be evicted\n", 29) != 29) perror("write");

	int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("fanotify_init"); return 3; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, mnt) < 0) { perror("mark"); return 4; }
	drain(fan, 200);

	// The question. In a child, so a block presents as a timeout rather than
	// wedging the probe — and answered while we wait, because inferring "an
	// event fired" from a hang has been wrong in this project before.
	pid_t c = fork();
	if (c == 0) {
		int f = 0;
		int d = open(path, O_RDONLY);
		if (d < 0) { perror("  open"); _exit(1); }
		if (ioctl(d, FS_IOC_GETFLAGS, &f) < 0) { perror("  GETFLAGS"); _exit(1); }
		f |= FS_NODUMP_FL;
		if (ioctl(d, FS_IOC_SETFLAGS, &f) < 0) { perror("  SETFLAGS"); _exit(1); }
		close(d);
		_exit(0);
	}
	int st, during = 0, done = 0;
	for (int i = 0; i < 20; i++) {
		if (waitpid(c, &st, WNOHANG) == c) { done = 1; break; }
		during += drain(fan, 200);
	}
	if (!done) {
		kill(c, 9); waitpid(c, &st, 0);
		printf("RESULT: setting nodump BLOCKED inside a marked mount.\n"
		       "        It cannot be done by the process that answers events.\n");
		unlink(path); return 0;
	}
	printf("set nodump: completed, events fired: %d\n", during);
	printf("  flag present: %s\n",
	       (flags_of(path) & FS_NODUMP_FL) ? "yes" : "NO");

	// The remaining two questions both need the file opened for writing inside
	// the marked mount, which the answering process must never do itself — the
	// first version of this probe did and hung, which is §6a-ter demonstrating
	// itself for the seventh time. So they run in children while we answer.
	for (int which = 0; which < 2; which++) {
		pid_t k = fork();
		if (k == 0) {
			int d = open(path, O_RDWR);
			if (d < 0) { perror("  open"); _exit(1); }
			if (which == 0) {
				if (fallocate(d, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
					      0, 29) < 0) perror("  punch");
			} else {
				if (pwrite(d, "refilled by hydration........\n", 29, 0) != 29)
					perror("  refill");
			}
			close(d);
			_exit(0);
		}
		int ks, kdone = 0;
		for (int i = 0; i < 25; i++) {
			if (waitpid(k, &ks, WNOHANG) == k) { kdone = 1; break; }
			drain(fan, 200);
		}
		if (!kdone) { kill(k, 9); waitpid(k, &ks, 0); }
		printf("  survives %-24s %s\n",
		       which ? "being written through:" : "a hole punch:",
		       !kdone ? "(blocked)" :
		       (flags_of(path) & FS_NODUMP_FL) ? "yes" : "NO");
	}

	close(fd);
	unlink(path);
	return 0;
}

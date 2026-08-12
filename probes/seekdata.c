// Probe: is asking "does this file hold data" free, or does asking hydrate it?
//
// `placeholder::holds_data` is `open(O_RDONLY)` + `lseek(fd, 0, SEEK_DATA)`, and
// it is the framework's answer to "is there content here" — §5.8, because
// `st_blocks` gives the same number for an empty placeholder and a full one.
// Every existing caller either runs outside a marked mount or asks through the
// event fd, which the kernel exempts. Asking it about an ordinary fd, inside the
// mount, from the unprivileged daemon, is a different question.
//
// It matters because the answer decides whether the resync walk may report *why*
// a placeholder is dirty. A marked file that holds bytes is either a transfer
// that was cut off or a user's edit that the next read will discard; a marked
// file that holds nothing is a placeholder whose mtime moved. Only the first is
// worth telling anyone about. But if `SEEK_DATA` fires a pre-content event, then
// the diagnostic hydrates the very multi-gigabyte object the walk exists to
// leave alone — the diagnostic becomes the harm, and the distinction cannot be
// drawn at all.
//
// `fsnotify_file_area_perm()` is reached from `rw_verify_area()`, which `lseek`
// does not go through — so the expected answer is zero events. Expected is not
// measured, and this file is the difference.
#define _GNU_SOURCE
#include <sys/fanotify.h>

// Numbers the running kernel knows that its headers may not — see the header.
#include "fanotify_compat.h"
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

// What the child did, reported back through its exit status so the parent can
// say whether the syscall answered at all. A probe that counts events for a
// syscall that failed with EBADF measures nothing.
enum { ACT_OPEN, ACT_SEEK, ACT_READ };

static const char *act_name(int a)
{
	return a == ACT_OPEN ? "open only" : a == ACT_SEEK ? "open+SEEK_DATA" : "open+read";
}

// Run one action in a child, so a blocking pre-content event blocks something
// the parent can still answer for. Returns the event count; `*outcome` gets a
// one-line description of what the syscall actually returned.
static int measure(int fan, const char *path, int action, char *outcome, size_t n)
{
	int pipefd[2];
	if (pipe(pipefd) < 0) { perror("pipe"); return -1; }

	pid_t c = fork();
	if (c == 0) {
		close(pipefd[0]);
		char msg[128] = "";
		int fd = open(path, O_RDONLY);
		if (fd < 0) {
			snprintf(msg, sizeof(msg), "open failed: %s", strerror(errno));
		} else if (action == ACT_SEEK) {
			off_t r = lseek(fd, 0, SEEK_DATA);
			if (r >= 0)
				snprintf(msg, sizeof(msg), "SEEK_DATA -> %lld (holds data)",
					 (long long)r);
			else if (errno == ENXIO)
				snprintf(msg, sizeof(msg), "SEEK_DATA -> ENXIO (all hole)");
			else
				snprintf(msg, sizeof(msg), "SEEK_DATA -> %s", strerror(errno));
		} else if (action == ACT_READ) {
			char buf[64];
			ssize_t got = read(fd, buf, sizeof(buf));
			snprintf(msg, sizeof(msg), "read -> %zd", got);
		} else {
			snprintf(msg, sizeof(msg), "opened");
		}
		if (fd >= 0) close(fd);
		if (write(pipefd[1], msg, strlen(msg) + 1) < 0) { /* parent reports it */ }
		close(pipefd[1]);
		_exit(0);
	}
	close(pipefd[1]);

	// Drain while the child runs. A pre-content event is blocking, so a child
	// that never finishes is itself the measurement.
	int st, events = 0, done = 0;
	for (int i = 0; i < 15; i++) {
		events += drain(fan, 200);
		if (waitpid(c, &st, WNOHANG) == c) { done = 1; break; }
	}
	if (!done) { kill(c, 9); waitpid(c, &st, 0); }

	char buf[128] = "";
	ssize_t got = read(pipefd[0], buf, sizeof(buf) - 1);
	close(pipefd[0]);
	if (got > 0) buf[got] = 0;
	snprintf(outcome, n, "%s%s", done ? buf : "BLOCKED", done ? "" : "");
	return events;
}

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]); return 1; }
	const char *mnt = argv[1];
	setbuf(stdout, NULL);

	char hollow[512], residue[512];
	snprintf(hollow, sizeof(hollow), "%s/probe-seek-hollow.bin", mnt);
	snprintf(residue, sizeof(residue), "%s/probe-seek-residue.bin", mnt);
	unlink(hollow); unlink(residue);

	// Both created before the mark, so creating them fires nothing.
	//
	// `hollow` is what a placeholder is: sized and entirely a hole, so SEEK_DATA
	// has to scan the whole extent map before it can answer ENXIO. `residue` is
	// what a transfer cut off mid-stream leaves: the same size with bytes at the
	// front, where SEEK_DATA answers 0 immediately. If either shape fires an
	// event the answer is the same, but they are different code paths in the
	// filesystem and measuring only one would be measuring half of it.
	const long SZ = 1 << 20;
	int f = open(hollow, O_CREAT | O_WRONLY, 0644);
	if (f < 0 || ftruncate(f, SZ) < 0) perror("hollow");
	close(f);

	f = open(residue, O_CREAT | O_WRONLY, 0644);
	if (f < 0 || ftruncate(f, SZ) < 0) perror("residue");
	char chunk[4096];
	memset(chunk, 'x', sizeof(chunk));
	if (pwrite(f, chunk, sizeof(chunk), 0) != sizeof(chunk)) perror("residue write");
	close(f);

	int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("fanotify_init"); return 2; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, mnt) < 0) { perror("mark"); return 3; }
	drain(fan, 200);

	printf("  %-16s %-14s %-8s %s\n", "file", "action", "events", "syscall said");
	int read_events = 0;
	for (int which = 0; which < 2; which++) {
		const char *path = which ? residue : hollow;
		const char *name = which ? "residue (1 MiB)" : "hollow (1 MiB)";
		// `open` first, then `SEEK_DATA`, then the control. The control has to
		// come last: a read hydrates nothing here, but it does install nothing
		// either, and running it first would leave the earlier cases explaining
		// a file the kernel had already had its hands on.
		for (int action = ACT_OPEN; action <= ACT_READ; action++) {
			char said[160];
			int events = measure(fan, path, action, said, sizeof(said));
			if (action == ACT_READ) read_events += events;
			printf("  %-16s %-14s %-8d %s\n", name, act_name(action), events, said);
		}
	}

	unlink(hollow); unlink(residue);
	printf("\nThe control is the last row of each pair: if `open+read` fired no event,\n"
	       "the mark is not working and every zero above means nothing.\n");
	if (read_events == 0) {
		printf("CONTROL FAILED: reads fired no events; this probe measured nothing.\n");
		return 4;
	}
	printf("Otherwise: a zero for `open+SEEK_DATA` means `holds_data` can be asked\n"
	       "of a placeholder from inside a marked mount without hydrating it.\n");
	return 0;
}

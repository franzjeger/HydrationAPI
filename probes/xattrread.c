// Probe: does reading an xattr inside a marked mount hydrate the file, or is it
// free? The Dolphin overlay plugin (OneDriveHydration, Feature 1) draws a
// per-file "on device / cloud only" badge, and its whole answer for one file is
// a single presence probe:
//
//     lgetxattr(path, "user.hydration.dehydrated", NULL, 0)
//
// exactly the call `placeholder::has_mark` makes (crates/hydration-protocol,
// `has_mark`). The plugin runs it for every file the file manager is currently
// drawing — tens to hundreds at a time, and at 166k placeholders a wrong answer
// here does not mislabel one badge, it hydrates or deadlocks a whole visible
// directory the moment the user opens it.
//
// The argument that it is free is strong: `FAN_PRE_ACCESS` is reached through
// `fsnotify_file_area_perm()` from `rw_verify_area()`, on MAY_READ/MAY_WRITE of
// *content*; getxattr/lgetxattr/llistxattr are metadata syscalls that never go
// near it (DESIGN.md §"content, not metadata"). `seekdata.c` already measured
// that even `lseek(SEEK_DATA)` — which does open the file — fires zero events,
// and an xattr read is lighter still: it reads no bytes and, for the `l`/path
// forms, does not even open. But CLAUDE.md's law is measured-not-recalled, and
// "getxattr is metadata" is precisely the class of claim that has fooled review
// eight times. This file is the difference between arguing it and knowing it.
//
// It mirrors seekdata.c's shape deliberately: files made before the mark, one
// action per forked child so a blocking pre-content event blocks something the
// parent can still answer for, and the control (open+read) LAST, because a read
// that fires proves the mark is live and every zero above it means something.
#define _GNU_SOURCE
#include <sys/fanotify.h>

// Numbers the running kernel knows that its headers may not — see the header.
#include "fanotify_compat.h"
#include <sys/stat.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/wait.h>

#define MARK "user.hydration.dehydrated"

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

// The four things a status-drawing plugin might do to a file, plus the control.
// LGETXATTR is the plugin's actual call; LLISTXATTR is the neighbour the design
// critique flagged as asserted with even less basis (a different syscall — it
// must be in the probe, not assumed); FGETXATTR is the fd-based form, in case a
// caller already holds an open fd; READ is the control that must fire.
enum { ACT_LGETXATTR, ACT_LLISTXATTR, ACT_FGETXATTR, ACT_READ };

static const char *act_name(int a)
{
	switch (a) {
	case ACT_LGETXATTR:  return "lgetxattr";
	case ACT_LLISTXATTR: return "llistxattr";
	case ACT_FGETXATTR:  return "open+fgetxattr";
	default:             return "open+read (control)";
	}
}

// Run one action in a child. Returns the event count; `*outcome` gets a one-line
// description of what the syscall actually returned, so a zero for a call that
// failed with EBADF is not mistaken for a zero for a call that answered.
static int measure(int fan, const char *path, int action, char *outcome, size_t n)
{
	int pipefd[2];
	if (pipe(pipefd) < 0) { perror("pipe"); return -1; }

	pid_t c = fork();
	if (c == 0) {
		close(pipefd[0]);
		char msg[160] = "";
		char val[256];
		if (action == ACT_LGETXATTR) {
			// The plugin's exact call: NULL buffer, size 0 — presence only,
			// no value fetched, no open. rc>=0 is the mark present (cloud-only
			// placeholder); ENODATA/ENOATTR is absent (resident / on device).
			ssize_t r = lgetxattr(path, MARK, NULL, 0);
			if (r >= 0)
				snprintf(msg, sizeof(msg), "lgetxattr -> present (len %zd) = cloud-only", r);
			else if (errno == ENODATA)
				snprintf(msg, sizeof(msg), "lgetxattr -> ENODATA = resident");
			else if (errno == ENOTSUP)
				snprintf(msg, sizeof(msg), "lgetxattr -> ENOTSUP (fs has no user xattrs)");
			else
				snprintf(msg, sizeof(msg), "lgetxattr -> %s", strerror(errno));
		} else if (action == ACT_LLISTXATTR) {
			ssize_t r = llistxattr(path, NULL, 0);
			if (r >= 0)
				snprintf(msg, sizeof(msg), "llistxattr -> %zd bytes of names", r);
			else
				snprintf(msg, sizeof(msg), "llistxattr -> %s", strerror(errno));
		} else if (action == ACT_FGETXATTR) {
			int fd = open(path, O_RDONLY);
			if (fd < 0) {
				snprintf(msg, sizeof(msg), "open failed: %s", strerror(errno));
			} else {
				ssize_t r = fgetxattr(fd, MARK, val, sizeof(val));
				if (r >= 0)
					snprintf(msg, sizeof(msg), "fgetxattr -> present (len %zd)", r);
				else if (errno == ENODATA)
					snprintf(msg, sizeof(msg), "fgetxattr -> ENODATA = resident");
				else
					snprintf(msg, sizeof(msg), "fgetxattr -> %s", strerror(errno));
				close(fd);
			}
		} else { // ACT_READ, the control
			int fd = open(path, O_RDONLY);
			if (fd < 0) {
				snprintf(msg, sizeof(msg), "open failed: %s", strerror(errno));
			} else {
				char buf[64];
				ssize_t got = read(fd, buf, sizeof(buf));
				snprintf(msg, sizeof(msg), "read -> %zd", got);
				close(fd);
			}
		}
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

	char buf[160] = "";
	ssize_t got = read(pipefd[0], buf, sizeof(buf) - 1);
	close(pipefd[0]);
	if (got > 0) buf[got] = 0;
	snprintf(outcome, n, "%s", done ? buf : "BLOCKED (pre-content event, never returned)");
	return events;
}

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]); return 1; }
	const char *mnt = argv[1];
	setbuf(stdout, NULL);

	char placeholder[512], resident[512];
	snprintf(placeholder, sizeof(placeholder), "%s/probe-xattr-placeholder.bin", mnt);
	snprintf(resident, sizeof(resident), "%s/probe-xattr-resident.bin", mnt);
	unlink(placeholder); unlink(resident);

	// Both created and marked-up before the fanotify mark, so nothing here fires.
	//
	// `placeholder` is the shape the plugin will meet most: a sized hole carrying
	// the dehydrated xattr — the file whose badge must say "cloud only" without
	// the drawing of that badge pulling its bytes down. `resident` is a real file
	// with bytes and no mark — the "on device" case, and also the one whose
	// control read is guaranteed to have something to return.
	const long SZ = 1 << 20;
	int f = open(placeholder, O_CREAT | O_WRONLY, 0644);
	if (f < 0 || ftruncate(f, SZ) < 0) perror("placeholder");
	close(f);
	// Set the mark the same way the privileged side does: a user.* xattr, empty
	// value, presence is the whole signal. If the backing fs refuses user xattrs
	// the probe is on the wrong filesystem and says so via ENOTSUP below.
	if (setxattr(placeholder, MARK, "", 0, 0) < 0)
		fprintf(stderr, "warning: could not set %s on placeholder: %s\n",
			MARK, strerror(errno));

	f = open(resident, O_CREAT | O_WRONLY, 0644);
	char chunk[4096];
	memset(chunk, 'x', sizeof(chunk));
	if (f < 0 || pwrite(f, chunk, sizeof(chunk), 0) != sizeof(chunk)) perror("resident");
	close(f);

	int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("fanotify_init (needs CAP_SYS_ADMIN)"); return 2; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, mnt) < 0) { perror("fanotify_mark"); return 3; }
	drain(fan, 200);

	printf("  %-24s %-22s %-8s %s\n", "file", "action", "events", "syscall said");
	int read_events = 0, xattr_events = 0;
	for (int which = 0; which < 2; which++) {
		const char *path = which ? resident : placeholder;
		const char *name = which ? "resident (has bytes)" : "placeholder (hole+mark)";
		// xattr forms first, control (read) last: the read is the only action
		// that should fire, and putting it last means the earlier rows explain a
		// file the kernel has not yet had its hands on.
		for (int action = ACT_LGETXATTR; action <= ACT_READ; action++) {
			char said[192];
			int events = measure(fan, path, action, said, sizeof(said));
			if (action == ACT_READ) read_events += events;
			else xattr_events += events;
			printf("  %-24s %-22s %-8d %s\n", name, act_name(action), events, said);
		}
	}

	unlink(placeholder); unlink(resident);

	printf("\nThe control is the last row of each pair. If `open+read` fired no event,\n"
	       "the mark is not working and every zero above means nothing.\n");
	if (read_events == 0) {
		printf("CONTROL FAILED: reads fired no events; this probe measured nothing.\n");
		return 4;
	}
	if (xattr_events != 0) {
		printf("FAIL: an xattr read fired %d pre-content event(s). The overlay plugin\n"
		       "cannot read the mark this way — it would hydrate the files it is badging.\n",
		       xattr_events);
		return 5;
	}
	printf("PASS: the mark is live (reads fired %d event(s)) and every xattr read fired\n"
	       "zero. The overlay plugin can probe `%s` for the files the user is looking\n"
	       "at without hydrating one byte.\n", read_events, MARK);
	return 0;
}

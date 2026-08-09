// Probe: can an unprivileged process build a complete placeholder with no name,
// then link it into a watched mount — so the privileged side is never involved
// in creation at all?
//
// Why it matters: giving a file its size inside a marked mount fires a
// pre-content event, and closing that window needs the fanotify group, which
// only the root helper has. That forces either "root creates files at a path the
// unprivileged side chose" (a real escalation: symlink races on the path walk,
// root-owned results, and a `mode` of 06755 becoming a setuid-root binary once
// the daemon serves its content) or a two-process ignore-mark dance.
//
// O_TMPFILE gives an anonymous inode on the mount's filesystem with **no name**.
// Nothing can traverse to it. If `ftruncate` on it is quiet, the daemon can size
// it, set every xattr, and `linkat` it into place already complete — and there is
// no destination for the privileged side to accept, so the rule holds by
// construction.
//
// Two questions, and the first is the one that decides:
//   1. Does ftruncate on an anonymous O_TMPFILE inode fire a pre-content event?
//   2. Does linkat into the marked mount fire one?
#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <sys/xattr.h>

/// Anything queued right now, without blocking.
static int drained(int fan)
{
	struct pollfd pfd = { .fd = fan, .events = POLLIN };
	char buf[8192];
	int seen = 0;

	while (poll(&pfd, 1, 300) > 0) {
		ssize_t len = read(fan, buf, sizeof(buf));
		if (len <= 0) break;
		for (char *p = buf; FAN_EVENT_OK((struct fanotify_event_metadata *)p, len);
		     p = (char *)FAN_EVENT_NEXT((struct fanotify_event_metadata *)p, len)) {
			struct fanotify_event_metadata *md = (void *)p;
			if (md->fd < 0) continue;
			seen++;
			// The rule the worker will actually run, exercised here
			// rather than described: nlink==0 says nothing can open
			// this by name, and the construction mark says it is ours
			// and not a placeholder someone unlinked mid-read.
			struct stat es;
			int nameless = fstat(md->fd, &es) == 0 && es.st_nlink == 0;
			int building = fgetxattr(md->fd, "user.hydration.building", NULL, 0) >= 0;
			fprintf(stderr, "    event: nlink=%lu building=%s -> %s\n",
				(unsigned long)(fstat(md->fd, &es) == 0 ? es.st_nlink : 99),
				building ? "yes" : "no",
				(nameless && building) ? "ALLOW (no reader possible)" : "would hydrate");
			struct fanotify_response r = { .fd = md->fd, .response = FAN_ALLOW };
			if (write(fan, &r, sizeof(r)) < 0)
				fprintf(stderr, "  (response failed: %s)\n", strerror(errno));
			close(md->fd);
		}
	}
	return seen;
}

int main(int argc, char **argv)
{
	const char *mnt = argv[1];
	setbuf(stdout, NULL);
	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]); return 1; }

	char target[512];
	snprintf(target, sizeof(target), "%s/tmpfile-placeholder.bin", mnt);
	unlink(target);

	int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("fanotify_init"); return 2; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, mnt) < 0) { perror("mark"); return 3; }
	printf("mount marked\n");

	// An anonymous inode on the mount's filesystem.
	int fd = open(mnt, O_TMPFILE | O_WRONLY, 0644);
	if (fd < 0) {
		printf("O_TMPFILE unsupported here: %s\n", strerror(errno));
		return 4;
	}
	printf("O_TMPFILE inode created\n");
	printf("  events after create: %d\n", drained(fan));

	// The question. In a child, so a block shows up as a timeout rather than
	// wedging the probe — the failure mode being measured is precisely "this
	// call never returns".
	pid_t c = fork();
	if (c == 0) {
		// Order is load-bearing. The mark has to be on the inode before
		// the event fires, or the handler sees an unmarked file and does
		// what it does to unmarked files — which in the real worker means
		// leaving a permanent ignore mark that then follows the inode
		// through linkat into the sync directory. That is this project's
		// recurring trap in yet another disguise.
		if (fsetxattr(fd, "user.hydration.building", "1", 1, 0) < 0)
			fprintf(stderr, "  fsetxattr building: %s\n", strerror(errno));
		if (fsetxattr(fd, "user.hydration.dehydrated", "1", 1, 0) < 0)
			fprintf(stderr, "  fsetxattr: %s\n", strerror(errno));
		if (fsetxattr(fd, "user.hydration.id", "obj-1", 5, 0) < 0)
			fprintf(stderr, "  fsetxattr id: %s\n", strerror(errno));
		if (ftruncate(fd, 4096) < 0) { fprintf(stderr, "  ftruncate: %s\n", strerror(errno)); _exit(1); }
		if (fremovexattr(fd, "user.hydration.building") < 0)
			fprintf(stderr, "  fremovexattr: %s\n", strerror(errno));
		_exit(0);
	}
	// Answering while we wait, so a block is distinguished from a hang: if an
	// event is generated we both see it and release the child, which then also
	// lets the linkat question be asked. Inferring "an event fired" from a hang
	// alone has been wrong before in this project.
	int st, done = 0, during = 0;
	for (int i = 0; i < 20; i++) {
		if (waitpid(c, &st, WNOHANG) == c) { done = 1; break; }
		during += drained(fan);
	}
	printf("  events observed while sizing: %d\n", during);
	if (!done) {
		kill(c, 9); waitpid(c, &st, 0);
		printf("RESULT: ftruncate on an anonymous inode did not complete even with\n"
		       "        events being answered — unexpected; investigate.\n");
		return 0;
	}
	printf("  ftruncate + xattrs completed\n");

	// Give it a name, already complete.
	char procpath[64];
	snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", fd);
	if (linkat(AT_FDCWD, procpath, AT_FDCWD, target, AT_SYMLINK_FOLLOW) < 0) {
		printf("linkat failed: %s\n", strerror(errno));
		return 5;
	}
	printf("linked into place\n");
	printf("  events during linkat: %d\n", drained(fan));
	close(fd);

	struct stat sb;
	if (stat(target, &sb) == 0)
		printf("  result: size=%lld blocks=%lld\n",
		       (long long)sb.st_size, (long long)sb.st_blocks);
	char v[8] = {0};
	printf("  dehydrated mark present: %s\n",
	       getxattr(target, "user.hydration.dehydrated", v, sizeof(v)) > 0 ? "yes" : "NO");
	printf("  construction mark cleared: %s\n",
	       getxattr(target, "user.hydration.building", v, sizeof(v)) < 0 ? "yes" : "NO — leaked");

	printf("\nRESULT: an unprivileged process built a complete placeholder with no\n"
	       "        name and linked it in. The privileged side is not involved in\n"
	       "        creation, so there is no destination for it to accept.\n");
	unlink(target);
	return 0;
}

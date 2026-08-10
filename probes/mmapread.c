// Probe: does reading a placeholder through mmap hydrate it?
//
// The last thing in §9 that could produce silent zeros. Every hydration path in
// this framework hangs off FAN_PRE_ACCESS, and the kernel has a separate hook
// for mapped access (`fsnotify_mmap_perm`). If that hook does not fire for our
// group, then any program that maps a file instead of read()ing it — and that
// is most language runtimes loading a library, most databases, grep on a large
// file, every ELF loader — sees the hole rather than the content, with no error.
//
// Two questions:
//   1. Does mmap() itself fire a pre-content event?
//   2. Does *touching the mapped page* fire one?
// The second matters more: a lazy mapping that faults later is the normal case.
#define _GNU_SOURCE
#include <sys/fanotify.h>

// Numbers the running kernel knows that its headers may not — see the header.
#include "fanotify_compat.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#define LEN 8192

static int answer(int fan, int ms, int fill)
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
			if (fill) {
				// What the worker does: fill through the event fd.
				char content[LEN];
				memset(content, 'H', sizeof(content));
				if (pwrite(md->fd, content, sizeof(content), 0) != sizeof(content))
					fprintf(stderr, "    fill failed: %s\n", strerror(errno));
				fsync(md->fd);
			}
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

	char path[512], path2[512];
	snprintf(path, sizeof(path), "%s/mmap-probe.bin", mnt);
	snprintf(path2, sizeof(path2), "%s/trunc-probe.bin", mnt);
	unlink(path); unlink(path2);

	// A placeholder, made before the mark: sized, empty, occupying nothing.
	int fd = open(path, O_CREAT | O_RDWR, 0644);
	if (fd < 0 || ftruncate(fd, LEN) < 0) { perror("placeholder"); return 2; }
	close(fd);
	// The second placeholder is made here too, before the mark. Creating it
	// afterwards means opening a file inside the marked mount from the process
	// that answers events — which is the trap in §6a-ter, and it wedged the first
	// version of this probe exactly as it has wedged everything else.
	int fd2 = open(path2, O_CREAT | O_RDWR, 0644);
	if (fd2 < 0 || ftruncate(fd2, LEN) < 0) { perror("second placeholder"); return 2; }
	close(fd2);

	struct stat sb;
	stat(path, &sb);
	printf("placeholder: size=%lld blocks=%lld\n",
	       (long long)sb.st_size, (long long)sb.st_blocks);

	int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("fanotify_init"); return 3; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, mnt) < 0) { perror("mark"); return 4; }
	answer(fan, 200, 0);

	// A reader that maps rather than reads, in a child so a block is a timeout.
	pid_t c = fork();
	if (c == 0) {
		int d = open(path, O_RDONLY);
		if (d < 0) { perror("  open"); _exit(2); }
		char *m = mmap(NULL, LEN, PROT_READ, MAP_PRIVATE, d, 0);
		if (m == MAP_FAILED) { perror("  mmap"); _exit(2); }
		// The fault happens here, not above.
		volatile char first = m[0];
		volatile char later = m[4096];
		fprintf(stderr, "    mapped bytes: [0]=%d [4096]=%d\n", first, later);
		_exit((first == 'H' && later == 'H') ? 0 : 7);
	}
	int st, events = 0, done = 0;
	for (int i = 0; i < 25; i++) {
		events += answer(fan, 200, 1);
		if (waitpid(c, &st, WNOHANG) == c) { done = 1; break; }
	}
	if (!done) { kill(c, 9); waitpid(c, &st, 0); }

	printf("  events fired for a mapped read: %d\n", events);
	printf("  reader %s\n", !done ? "BLOCKED" :
	       WEXITSTATUS(st) == 0 ? "got hydrated content" :
	       WEXITSTATUS(st) == 7 ? "GOT ZEROS" : "failed to map");
	printf("\nRESULT: %s\n", (done && WEXITSTATUS(st) == 0)
	       ? "mmap is intercepted; a mapped placeholder hydrates like a read one."
	       : "mmap is NOT covered — a mapped placeholder reads as zeros with no error.");

	// The other unmeasured hook: `fsnotify_truncate_perm`. Shortening a
	// placeholder is not a read, but it decides what survives — uncovered, the
	// file keeps the first N *zeros* instead of the first N real bytes, which is
	// worse than zeros because it looks like a deliberate edit and gets uploaded.
	unlink(path);
	answer(fan, 200, 0);

	pid_t t = fork();
	if (t == 0) {
		int d = open(path2, O_WRONLY);
		if (d < 0) { perror("  open"); _exit(2); }
		if (ftruncate(d, 4096) < 0) { perror("  truncate"); _exit(2); }
		close(d);
		_exit(0);
	}
	int tst, tev = 0, tdone = 0;
	for (int i = 0; i < 25; i++) {
		tev += answer(fan, 200, 1);
		if (waitpid(t, &tst, WNOHANG) == t) { tdone = 1; break; }
	}
	if (!tdone) { kill(t, 9); waitpid(t, &tst, 0); }

	char probe[8] = {0};
	pid_t r = fork();
	if (r == 0) {
		char b[8] = {0};
		int d = open(path2, O_RDONLY);
		if (d >= 0) { if (read(d, b, sizeof(b)) < 0) perror("  readback"); close(d); }
		_exit(b[0] == 'H' ? 0 : 1);
	}
	int rst, rdone = 0;
	for (int i = 0; i < 25; i++) {
		answer(fan, 200, 1);
		if (waitpid(r, &rst, WNOHANG) == r) { rdone = 1; break; }
	}
	if (!rdone) { kill(r, 9); waitpid(r, &rst, 0); }
	probe[0] = (rdone && WEXITSTATUS(rst) == 0) ? 'H' : 0;
	int rd = -1;
	(void)rd;
	printf("\ntruncate to half:\n");
	printf("  events fired: %d\n", tev);
	printf("  surviving first byte: %d (%s)\n", probe[0],
	       probe[0] == 'H' ? "real content" : "a zero from the hole");
	printf("RESULT: %s\n", probe[0] == 'H'
	       ? "truncate is intercepted; what survives is the real content."
	       : "truncate is NOT covered — shortening a placeholder keeps zeros, and\n"
	         "        the result looks like a deliberate edit and would be uploaded.");
	unlink(path2);
	return 0;
}

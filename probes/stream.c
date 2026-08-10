// Probe: is it safe to fill a placeholder incrementally?
//
// Streaming hydration means the worker writes bytes into the event fd as they
// arrive instead of buffering the whole object first. That is the only way a
// file larger than the per-event deadline can ever be served — but it creates a
// state that does not exist today: a placeholder that is *partly* filled, still
// marked, with its reader parked inside the pre-content event.
//
// Three questions decide whether that state is safe:
//   1. Can a *second* process observe the partial content while the first is
//      still blocked? If it can, streaming would let a reader see a half file
//      and believe it — which is the one outcome this framework exists to
//      prevent.
//   2. Does writing into the event fd from the answering process fire further
//      events? (The trap in §6a-ter, in its ninth possible disguise.)
//   3. If the transfer fails halfway, does punching the hole restore the
//      placeholder exactly — size kept, blocks back to zero?
#define _GNU_SOURCE
#include <sys/fanotify.h>

// Numbers the running kernel knows that its headers may not — see the header.
#include "fanotify_compat.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#define LEN (1 << 20)   /* 1 MiB, big enough that partial is unambiguous */

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]); return 1; }
	const char *mnt = argv[1];
	setbuf(stdout, NULL);

	char path[512];
	snprintf(path, sizeof(path), "%s/stream-probe.bin", mnt);
	unlink(path);
	int fd = open(path, O_CREAT | O_RDWR, 0644);
	if (fd < 0 || ftruncate(fd, LEN) < 0) { perror("placeholder"); return 2; }
	close(fd);

	int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("fanotify_init"); return 3; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, mnt) < 0) { perror("mark"); return 4; }

	// The reader whose event we will answer slowly.
	pid_t reader = fork();
	if (reader == 0) {
		char b[16] = {0};
		int d = open(path, O_RDONLY);
		if (d < 0) _exit(3);
		if (read(d, b, sizeof(b)) < 0) _exit(3);
		_exit(b[0] == 'H' ? 0 : 7);
	}

	// Wait for its event.
	struct pollfd pfd = { .fd = fan, .events = POLLIN };
	char buf[4096];
	struct fanotify_event_metadata *md = NULL;
	for (int i = 0; i < 30 && !md; i++) {
		if (poll(&pfd, 1, 200) <= 0) continue;
		ssize_t len = read(fan, buf, sizeof(buf));
		if (len <= 0) continue;
		md = (void *)buf;
	}
	if (!md || md->fd < 0) { printf("no event arrived\n"); return 5; }
	printf("event held for a 1 MiB placeholder\n");

	// Fill it in chunks, the way a streaming worker would.
	char chunk[65536];
	memset(chunk, 'H', sizeof(chunk));
	off_t off = 0;
	for (int i = 0; i < 4; i++) {
		if (pwrite(md->fd, chunk, sizeof(chunk), off) != sizeof(chunk)) {
			perror("  chunk"); break;
		}
		off += sizeof(chunk);
	}
	printf("  wrote %lld of %d bytes so far\n", (long long)off, LEN);

	// Q2: did those writes generate events of their own?
	int extra = 0;
	while (poll(&pfd, 1, 200) > 0) {
		ssize_t len = read(fan, buf + 2048, 2048);
		if (len <= 0) break;
		extra++;
	}
	printf("  events fired by our own partial writes: %d\n", extra);

	// Q1: can a bystander see the half-written file right now?
	pid_t peek = fork();
	if (peek == 0) {
		char b[8] = {0};
		int d = open(path, O_RDONLY);
		if (d < 0) _exit(2);
		ssize_t n = read(d, b, sizeof(b));
		_exit(n > 0 ? (b[0] == 'H' ? 1 : 2) : 3);
	}
	int pst, pdone = 0;
	for (int i = 0; i < 10; i++) {
		if (waitpid(peek, &pst, WNOHANG) == peek) { pdone = 1; break; }
		usleep(200000);
	}
	if (!pdone) {
		kill(peek, 9); waitpid(peek, &pst, 0);
		printf("  a second reader: BLOCKED (its own event is queued behind ours)\n");
	} else {
		printf("  a second reader: saw %s — partial content is OBSERVABLE\n",
		       WEXITSTATUS(pst) == 1 ? "our half-written bytes" : "something else");
	}

	// Q3: abandon the transfer and roll back.
	if (fallocate(md->fd, 0x02 | 0x01 /* PUNCH_HOLE|KEEP_SIZE */, 0, LEN) < 0)
		perror("  rollback punch");
	struct stat sb;
	if (fstat(md->fd, &sb) == 0)
		printf("  after rollback: size=%lld blocks=%lld\n",
		       (long long)sb.st_size, (long long)sb.st_blocks);

	// Let the reader go with a denial, which is what an abandoned transfer owes it.
	struct fanotify_response r = { .fd = md->fd, .response = FAN_DENY };
	if (write(fan, &r, sizeof(r)) < 0) perror("respond");
	close(md->fd);
	int rst; waitpid(reader, &rst, 0);
	printf("  the reader got %s\n", WEXITSTATUS(rst) == 7 ? "zeros (BAD)" :
	       WEXITSTATUS(rst) == 3 ? "an error, as it should" : "content");

	unlink(path);
	return 0;
}

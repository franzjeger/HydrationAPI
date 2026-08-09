// Probe: is the event's `count` a hint or a demand?
//
// The design has assumed it is a hint — that `count` is the readahead window
// rather than what the application asked for, so a worker fills the whole file
// and answers. Streaming makes a more attractive assumption available: fill the
// first chunk, allow, and let the reader start while the rest arrives.
//
// If `count` is a *demand*, that is silent data corruption: the reader gets
// whatever is there, no second event fires, and nothing reports a problem. It
// would be the seventh disguise of §6a-ter and the most tempting one yet,
// because it looks like an optimisation rather than a shortcut.
//
// Also measures what a mapped read demands, because that decides whether
// streaming can decompose an mmap at all.
#define _GNU_SOURCE
#include <sys/fanotify.h>
#include <linux/fanotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#define LEN (4 << 20)

struct outcome { int events; long long first_off, first_count; int reader; };

// fill: 0 = none, 1 = exactly what was asked, 2 = half of what was asked
static struct outcome trial(const char *mnt, const char *path, int mapped, int fill)
{
	struct outcome o = { 0, -1, -1, -1 };
	unlink(path);
	int fd = open(path, O_CREAT | O_RDWR, 0644);
	if (fd < 0 || ftruncate(fd, LEN) < 0) { perror("placeholder"); return o; }
	close(fd);

	// FAN_REPORT_FID is not needed, but the range record only arrives when the
	// group asks for it — without this every event reports the whole file and the
	// probe would answer its own question wrongly.
	int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_REPORT_FD_ERROR | FAN_CLOEXEC,
				O_RDWR | O_LARGEFILE);
	if (fan < 0) fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) { perror("init"); return o; }
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, mnt) < 0) { perror("mark"); close(fan); return o; }

	pid_t c = fork();
	if (c == 0) {
		int d = open(path, O_RDONLY);
		if (d < 0) _exit(9);
		int bad = 0;
		if (mapped) {
			char *m = mmap(NULL, LEN, PROT_READ, MAP_PRIVATE, d, 0);
			if (m == MAP_FAILED) _exit(9);
			// Touch a page beyond the half-way point.
			if (m[LEN / 2 + 4096] != 'H') bad = 1;
		} else {
			char b[16] = {0};
			// Read past the half-way point of the first demand.
			if (pread(d, b, sizeof(b), 40000) < 0) _exit(9);
			if (b[0] != 'H') bad = 1;
		}
		_exit(bad ? 7 : 0);
	}

	char buf[8192], chunk[1 << 20];
	memset(chunk, 'H', sizeof(chunk));
	struct pollfd pfd = { .fd = fan, .events = POLLIN };
	int st, done = 0;
	for (int i = 0; i < 40 && !done; i++) {
		if (poll(&pfd, 1, 200) > 0) {
			ssize_t len = read(fan, buf, sizeof(buf));
			for (char *p = buf; len > 0 && FAN_EVENT_OK((struct fanotify_event_metadata *)p, len);
			     p = (char *)FAN_EVENT_NEXT((struct fanotify_event_metadata *)p, len)) {
				struct fanotify_event_metadata *md = (void *)p;
				if (md->fd < 0) continue;
				struct fanotify_event_info_range *rng = NULL;
				char *info = (char *)md + md->metadata_len;
				// The range record follows the metadata when reported.
				struct fanotify_event_info_header *h = (void *)info;
				if ((char *)h < (char *)md + md->event_len && h->info_type == 6 /* FAN_EVENT_INFO_TYPE_RANGE */)
					rng = (void *)h;
				long long off = rng ? (long long)rng->offset : 0;
				long long cnt = rng ? (long long)rng->count : LEN;
				if (o.events == 0) { o.first_off = off; o.first_count = cnt; }
				o.events++;
				if (fill) {
					long long want = fill == 1 ? cnt : cnt / 2;
					long long w = 0;
					while (w < want) {
						long long n = want - w;
						if (n > (long long)sizeof(chunk)) n = sizeof(chunk);
						if (pwrite(md->fd, chunk, n, off + w) != n) break;
						w += n;
					}
				}
				struct fanotify_response r = { .fd = md->fd, .response = FAN_ALLOW };
				if (write(fan, &r, sizeof(r)) < 0) perror("respond");
				close(md->fd);
			}
		}
		if (waitpid(c, &st, WNOHANG) == c) done = 1;
	}
	if (!done) { kill(c, 9); waitpid(c, &st, 0); o.reader = -1; }
	else o.reader = WEXITSTATUS(st);
	close(fan);
	unlink(path);
	return o;
}

int main(int argc, char **argv)
{
	if (argc < 2) { fprintf(stderr, "usage: %s <mountpoint>\n", argv[0]); return 1; }
	setbuf(stdout, NULL);
	char p[512]; snprintf(p, sizeof(p), "%s/demand-probe.bin", argv[1]);

	struct { const char *name; int mapped, fill; } cases[] = {
		{ "read(), fill exactly what was asked", 0, 1 },
		{ "read(), fill HALF of what was asked", 0, 2 },
		{ "mmap(), fill exactly what was asked", 1, 1 },
		{ "mmap(), fill HALF of what was asked", 1, 2 },
	};
	printf("%-38s %8s %12s %10s  %s\n", "case", "events", "first off", "first cnt", "reader");
	for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
		struct outcome o = trial(argv[1], p, cases[i].mapped, cases[i].fill);
		printf("%-38s %8d %12lld %10lld  %s\n", cases[i].name, o.events,
		       o.first_off, o.first_count,
		       o.reader == 0 ? "real content" :
		       o.reader == 7 ? "ZEROS" : o.reader < 0 ? "blocked" : "error");
	}
	return 0;
}

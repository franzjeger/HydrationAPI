// Probe: what does a *large* placeholder demand, and is filling only that
// enough?
//
// `probes/demand.c` settled that `count` is a demand and not a hint, on a 4 MiB
// file. That measurement is quoted in §8d, and §8d draws two conclusions from
// it that only hold if the numbers do not change with the object's size:
//
//   * a `read()` demands only its own pages, so a large file is many small
//     bounded demands rather than one big one;
//   * an `mmap()` demands the whole object in one event, which no streaming can
//     decompose.
//
// The second one is the ceiling. It was measured on a 4 MiB file, where "the
// whole object" and "the mapped length" are the same number and the measurement
// cannot tell them apart. On a 2.77 GiB file they are not the same number, and
// which of the two the kernel actually reports decides whether a mapped read of
// a multi-gigabyte object is a 2.77 GiB demand or a 4 KiB one.
//
// So: the same questions, on a file big enough that the answers can differ.
//
//   1. a small read of a large file — what is `count`?
//   2. a large read — does `count` follow the request, or a readahead window?
//   3. sequential reads — do the demands tile, or overlap, or grow?
//   4. two distant reads — does the *second* one fire its own event after the
//      first was answered `FAN_ALLOW` with only its own range filled? This is
//      the question range-based hydration lives or dies on: if the file stops
//      generating events once it has been allowed once, a partially filled file
//      serves holes forever.
//   5. re-reading a range already filled — event or not?
//   6. mmap of the whole file, of a small window, and of a segment — is the
//      demand the object, or the mapping?
//
// Filling is capped (see FILL_CAP): a demand larger than the cap is reported and
// then *denied*, never allowed, because allowing it after filling less would be
// the silent-zeros case this probe exists to keep marked.
#define _GNU_SOURCE
#include <sys/fanotify.h>

// Numbers the running kernel knows that its headers may not — see the header.
#include "fanotify_compat.h"
#include <linux/fanotify.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

// Default object size: the file from the live account that started this, near
// enough. Overridable, because the interesting boundaries (2 GiB, 4 GiB) are
// where a 32-bit count or offset would fold.
#define DEFAULT_SIZE ((long long)2972712960LL) /* 2.77 GiB */

// Two offsets far enough apart to be unmistakably different pages, and far
// enough into the file that nothing about them is near a boundary.
#define OFF1 ((long long)1073741824LL) /* 1 GiB */
#define OFF2 ((long long)2147483648LL) /* 2 GiB */

// The most this probe will write to satisfy one demand. A demand above this is
// reported and denied rather than half-filled: the point of the measurement is
// lost if it produces the very corruption it is measuring.
#define FILL_CAP ((long long)(64 << 20))

#define MAX_EVENTS 64

enum mode {
	READ_SMALL,	// one 4 KiB read
	READ_BIG,	// one 8 MiB read
	READ_SEQ,	// eight sequential 128 KiB reads
	READ_TWO,	// two distant reads, then a re-read of the first
	MMAP_WHOLE,	// map the entire object, touch one page
	MMAP_WINDOW,	// map 4 KiB at OFF1, touch it
	MMAP_SEGMENT,	// map 64 MiB at OFF1, touch one page in it
};

struct outcome {
	int events;
	long long off[MAX_EVENTS], cnt[MAX_EVENTS];
	long long demanded;	// sum of every count seen
	long long filled;	// what we actually wrote
	int refused;		// demands too large to fill, so denied
	int reader;		// 0 ok, 7 zeros, 9 access error, -1 blocked
	int signal;		// non-zero if the reader died on a signal
};

static int reader_child(const char *path, enum mode m, long long size)
{
	int d = open(path, O_RDONLY);
	if (d < 0)
		_exit(9);

	// Big enough for the largest single read below. Heap, not stack.
	long long blen = 8 << 20;
	char *b = malloc(blen);
	if (!b)
		_exit(9);

	switch (m) {
	case READ_SMALL:
		if (pread(d, b, 4096, OFF1) != 4096)
			_exit(9);
		if (b[0] != 'H' || b[4095] != 'H')
			_exit(7);
		break;
	case READ_BIG:
		if (pread(d, b, blen, OFF1) != blen)
			_exit(9);
		if (b[0] != 'H' || b[blen - 1] != 'H')
			_exit(7);
		break;
	case READ_SEQ:
		for (int i = 0; i < 8; i++) {
			long long n = 128 << 10;
			if (pread(d, b, n, OFF1 + i * n) != n)
				_exit(9);
			if (b[0] != 'H' || b[n - 1] != 'H')
				_exit(7);
		}
		break;
	case READ_TWO:
		if (pread(d, b, 4096, OFF1) != 4096)
			_exit(9);
		if (b[0] != 'H')
			_exit(7);
		if (pread(d, b, 4096, OFF2) != 4096)
			_exit(9);
		if (b[0] != 'H')
			_exit(7);
		// Third access, back to the first range. Already filled, already
		// allowed once — the question is whether it costs another event.
		if (pread(d, b, 4096, OFF1) != 4096)
			_exit(9);
		if (b[0] != 'H')
			_exit(7);
		break;
	case MMAP_WHOLE: {
		char *p = mmap(NULL, size, PROT_READ, MAP_PRIVATE, d, 0);
		if (p == MAP_FAILED)
			_exit(9);
		if (p[OFF1] != 'H')
			_exit(7);
		break;
	}
	case MMAP_WINDOW: {
		char *p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, d, OFF1);
		if (p == MAP_FAILED)
			_exit(9);
		if (p[0] != 'H')
			_exit(7);
		break;
	}
	case MMAP_SEGMENT: {
		long long len = 64 << 20;
		char *p = mmap(NULL, len, PROT_READ, MAP_PRIVATE, d, OFF1);
		if (p == MAP_FAILED)
			_exit(9);
		if (p[0] != 'H' || p[len - 1] != 'H')
			_exit(7);
		break;
	}
	}
	_exit(0);
}

static struct outcome trial(const char *mnt, const char *path, enum mode m, long long size)
{
	struct outcome o;
	memset(&o, 0, sizeof(o));
	o.reader = -1;

	unlink(path);
	int fd = open(path, O_CREAT | O_RDWR, 0644);
	// Sparse: ftruncate only, no data. This is what a placeholder is.
	if (fd < 0 || ftruncate(fd, size) < 0) {
		perror("placeholder");
		return o;
	}
	close(fd);

	// The range record only arrives when the group asks for it; without this
	// every event reports the whole file and the probe answers its own
	// question wrongly. Same note as demand.c, and it is still the trap.
	int fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_REPORT_FD_ERROR | FAN_CLOEXEC,
				O_RDWR | O_LARGEFILE);
	if (fan < 0)
		fan = fanotify_init(FAN_CLASS_PRE_CONTENT | FAN_CLOEXEC, O_RDWR | O_LARGEFILE);
	if (fan < 0) {
		perror("init");
		return o;
	}
	if (fanotify_mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_PRE_ACCESS,
			  AT_FDCWD, mnt) < 0) {
		perror("mark");
		close(fan);
		return o;
	}

	pid_t c = fork();
	if (c == 0) {
		close(fan);
		reader_child(path, m, size);
	}

	long long chunklen = 4 << 20;
	char *chunk = malloc(chunklen);
	if (!chunk) {
		perror("chunk");
		kill(c, 9);
		close(fan);
		return o;
	}
	memset(chunk, 'H', chunklen);

	char buf[8192];
	struct pollfd pfd = { .fd = fan, .events = POLLIN };
	int st, done = 0;
	// Long enough for a 64 MiB fill on a slow filesystem, short enough that a
	// wedged trial does not stall the run.
	for (int i = 0; i < 600 && !done; i++) {
		if (poll(&pfd, 1, 100) > 0) {
			ssize_t len = read(fan, buf, sizeof(buf));
			for (char *p = buf;
			     len > 0 && FAN_EVENT_OK((struct fanotify_event_metadata *)p, len);
			     p = (char *)FAN_EVENT_NEXT((struct fanotify_event_metadata *)p, len)) {
				struct fanotify_event_metadata *md = (void *)p;
				if (md->fd < 0)
					continue;

				struct fanotify_event_info_header *h =
					(void *)((char *)md + md->metadata_len);
				struct fanotify_event_info_range *rng = NULL;
				if ((char *)h < (char *)md + md->event_len &&
				    h->info_type == FAN_EVENT_INFO_TYPE_RANGE)
					rng = (void *)h;
				long long off = rng ? (long long)rng->offset : 0;
				long long cnt = rng ? (long long)rng->count : size;

				if (o.events < MAX_EVENTS) {
					o.off[o.events] = off;
					o.cnt[o.events] = cnt;
				}
				o.events++;
				o.demanded += cnt;

				// Fill exactly what was asked, or refuse. Never
				// less than asked followed by an allow — that is
				// the silent-zeros case (§8d).
				int allow = 1;
				if (cnt > FILL_CAP) {
					o.refused++;
					allow = 0;
				} else {
					long long w = 0;
					while (w < cnt) {
						long long n = cnt - w;
						if (n > chunklen)
							n = chunklen;
						ssize_t got = pwrite(md->fd, chunk, n, off + w);
						if (got != n) {
							perror("pwrite");
							allow = 0;
							break;
						}
						w += got;
					}
					o.filled += w;
				}

				struct fanotify_response r = {
					.fd = md->fd,
					.response = allow ? FAN_ALLOW : FAN_DENY,
				};
				if (write(fan, &r, sizeof(r)) < 0)
					perror("respond");
				close(md->fd);
			}
		}
		if (waitpid(c, &st, WNOHANG) == c)
			done = 1;
	}
	if (!done) {
		kill(c, 9);
		waitpid(c, &st, 0);
		o.reader = -1;
	} else if (WIFSIGNALED(st)) {
		o.signal = WTERMSIG(st);
		o.reader = 9;
	} else {
		o.reader = WEXITSTATUS(st);
	}

	free(chunk);
	close(fan);
	unlink(path);
	return o;
}

static const char *verdict(const struct outcome *o)
{
	if (o->signal)
		return "killed by signal";
	switch (o->reader) {
	case 0: return "real content";
	case 7: return "ZEROS";
	case 9: return "error";
	default: return "blocked";
	}
}

static void human(long long n, char *out, size_t len)
{
	if (n >= (1 << 30))
		snprintf(out, len, "%.2f GiB", (double)n / (1 << 30));
	else if (n >= (1 << 20))
		snprintf(out, len, "%.2f MiB", (double)n / (1 << 20));
	else if (n >= (1 << 10))
		snprintf(out, len, "%.1f KiB", (double)n / (1 << 10));
	else
		snprintf(out, len, "%lld B", n);
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <mountpoint> [size-in-bytes]\n", argv[0]);
		return 1;
	}
	setbuf(stdout, NULL);
	long long size = argc > 2 ? atoll(argv[2]) : DEFAULT_SIZE;
	char p[512];
	snprintf(p, sizeof(p), "%s/bigdemand-probe.bin", argv[1]);

	char sz[32];
	human(size, sz, sizeof(sz));
	printf("object: %s (%lld bytes), sparse, on %s\n", sz, size, argv[1]);
	printf("reads at %lld and %lld; fill cap %lld bytes\n\n", OFF1, OFF2, FILL_CAP);

	struct { const char *name; enum mode m; } cases[] = {
		{ "read() 4 KiB at 1 GiB",		READ_SMALL },
		{ "read() 8 MiB at 1 GiB",		READ_BIG },
		{ "read() 8 x 128 KiB sequential",	READ_SEQ },
		{ "read() 4 KiB at 1 GiB, at 2 GiB, again at 1 GiB", READ_TWO },
		{ "mmap() whole object, touch 1 page",	MMAP_WHOLE },
		{ "mmap() 4 KiB window at 1 GiB",	MMAP_WINDOW },
		{ "mmap() 64 MiB segment at 1 GiB",	MMAP_SEGMENT },
	};

	for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct outcome o = trial(argv[1], p, cases[i].m, size);
		char dem[32], fil[32];
		human(o.demanded, dem, sizeof(dem));
		human(o.filled, fil, sizeof(fil));
		printf("%s\n", cases[i].name);
		printf("  events %d   demanded %s   filled %s   reader: %s%s\n",
		       o.events, dem, fil, verdict(&o),
		       o.refused ? "  (a demand exceeded the fill cap; denied)" : "");
		int show = o.events < MAX_EVENTS ? o.events : MAX_EVENTS;
		for (int e = 0; e < show; e++) {
			char c[32];
			human(o.cnt[e], c, sizeof(c));
			printf("    #%-2d off %12lld  count %12lld  (%s)\n",
			       e + 1, o.off[e], o.cnt[e], c);
		}
		printf("\n");
	}
	return 0;
}

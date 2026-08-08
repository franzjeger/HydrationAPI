// Feasibility probe only -- not implementation code.
// Question: can an UNPRIVILEGED FUSE daemon register a backing file and get
// real passthrough I/O on this kernel? The read handler deliberately refuses
// to serve data, so if `cat` through the mount returns the backing content,
// the kernel served it without entering userspace.
#define FUSE_USE_VERSION 318
#include <fuse3/fuse_lowlevel.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

static char backing_path[4096];
static const char *NAME = "hydrated";
static int read_handler_calls = 0;

static void probe_init(void *ud, struct fuse_conn_info *conn)
{
	(void)ud;
	fprintf(stderr, "[probe] kernel proto = %u.%u\n", conn->proto_major, conn->proto_minor);
	fprintf(stderr, "[probe] PASSTHROUGH capable = %s\n",
		(conn->capable_ext & FUSE_CAP_PASSTHROUGH) ? "YES" : "NO");
	if (conn->capable_ext & FUSE_CAP_PASSTHROUGH) {
		bool ok = fuse_set_feature_flag(conn, FUSE_CAP_PASSTHROUGH);
		fprintf(stderr, "[probe] PASSTHROUGH enabled = %s\n", ok ? "YES" : "NO");
	}
	fprintf(stderr, "[probe] max_backing_stack_depth = %u\n", conn->max_backing_stack_depth);
}

static int fill_attr(fuse_ino_t ino, struct stat *st)
{
	memset(st, 0, sizeof(*st));
	st->st_ino = ino;
	if (ino == FUSE_ROOT_ID) {
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2;
		return 0;
	}
	if (ino == 2) {
		struct stat bs;
		if (stat(backing_path, &bs) != 0)
			return -1;
		st->st_mode = S_IFREG | 0644;
		st->st_nlink = 1;
		st->st_size = bs.st_size;   // truth comes from the local copy
		return 0;
	}
	return -1;
}

static void probe_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fuse_entry_param e;
	if (parent != FUSE_ROOT_ID || strcmp(name, NAME) != 0) {
		fuse_reply_err(req, ENOENT);
		return;
	}
	memset(&e, 0, sizeof(e));
	e.ino = 2;
	e.attr_timeout = 0;
	e.entry_timeout = 0;
	fill_attr(2, &e.attr);
	fuse_reply_entry(req, &e);
}

static void probe_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct stat st;
	(void)fi;
	if (fill_attr(ino, &st) != 0) {
		fuse_reply_err(req, ENOENT);
		return;
	}
	fuse_reply_attr(req, &st, 0);
}

static void probe_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	int fd, id;
	if (ino != 2) {
		fuse_reply_err(req, EISDIR);
		return;
	}
	// This is the "hydrate on first access" moment: the daemon would fetch
	// the bytes here, then hand the kernel the local file.
	fd = open(backing_path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "[probe] open(backing) failed: %s\n", strerror(errno));
		fuse_reply_err(req, errno);
		return;
	}
	if (getenv("PROBE_NO_PASSTHROUGH")) {
		// Baseline mode: serve reads from userspace like a classic FUSE fs.
		fi->fh = (uint64_t)fd;
		fi->keep_cache = 0;
		fi->direct_io = 1;
		fprintf(stderr, "[probe] baseline mode: daemon-served I/O\n");
		fuse_reply_open(req, fi);
		return;
	}
	errno = 0;
	id = fuse_passthrough_open(req, fd);
	fprintf(stderr, "[probe] fuse_passthrough_open() -> %d (%s)\n",
		id, id > 0 ? "SUCCESS" : strerror(errno));
	close(fd);   // kernel holds its own reference

	if (id > 0) {
		// Only FOPEN_PASSTHROUGH|DIRECT_IO|PARALLEL_DIRECT_WRITES|NOFLUSH
		// may accompany passthrough; anything else (e.g. keep_cache) makes
		// open() fail EIO with no diagnostic.
		fi->backing_id = id;
	} else {
		fprintf(stderr, "[probe] NO PASSTHROUGH - falling back to daemon I/O\n");
	}
	fi->fh = 0;
	fuse_reply_open(req, fi);
}

// Deliberately refuses. If data still reads back, the kernel never came here.
static void probe_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
		       struct fuse_file_info *fi)
{
	(void)ino;
	read_handler_calls++;
	if (getenv("PROBE_NO_PASSTHROUGH")) {
		char *buf = malloc(size);
		ssize_t n;
		if (!buf) { fuse_reply_err(req, ENOMEM); return; }
		n = pread((int)fi->fh, buf, size, off);
		if (n < 0) fuse_reply_err(req, errno);
		else fuse_reply_buf(req, buf, n);
		free(buf);
		return;
	}
	fprintf(stderr, "[probe] *** DAEMON READ HANDLER CALLED (#%d) - NOT passthrough ***\n",
		read_handler_calls);
	fuse_reply_err(req, EIO);
}

static void probe_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size,
			off_t off, struct fuse_file_info *fi)
{
	(void)ino; (void)buf; (void)size; (void)off; (void)fi;
	fprintf(stderr, "[probe] *** DAEMON WRITE HANDLER CALLED - NOT passthrough ***\n");
	fuse_reply_err(req, EIO);
}

static void probe_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
			  struct fuse_file_info *fi)
{
	char *buf;
	size_t used = 0;
	struct stat st;
	(void)fi;
	if (ino != FUSE_ROOT_ID) { fuse_reply_err(req, ENOTDIR); return; }
	if (off > 0) { fuse_reply_buf(req, NULL, 0); return; }
	buf = calloc(1, size);
	if (!buf) { fuse_reply_err(req, ENOMEM); return; }
	memset(&st, 0, sizeof(st)); st.st_ino = 2; st.st_mode = S_IFREG | 0644;
	used += fuse_add_direntry(req, buf + used, size - used, NAME, &st, used + 1);
	fuse_reply_buf(req, buf, used);
	free(buf);
}

static const struct fuse_lowlevel_ops ops = {
	.init    = probe_init,
	.lookup  = probe_lookup,
	.getattr = probe_getattr,
	.open    = probe_open,
	.read    = probe_read,
	.write   = probe_write,
	.readdir = probe_readdir,
};

int main(int argc, char **argv)
{
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	struct fuse_session *se;
	const char *mp;
	int ret = 1;

	if (argc < 3) {
		fprintf(stderr, "usage: %s <mountpoint> <backingfile> [fuse opts]\n", argv[0]);
		return 1;
	}
	mp = argv[1];
	snprintf(backing_path, sizeof(backing_path), "%s", argv[2]);
	// strip our two positional args before handing the rest to libfuse
	args.argc = 1;

	se = fuse_session_new(&args, &ops, sizeof(ops), NULL);
	if (!se) { fprintf(stderr, "[probe] session_new failed\n"); goto out; }
	if (fuse_set_signal_handlers(se) != 0) goto out_destroy;
	if (fuse_session_mount(se, mp) != 0) {
		fprintf(stderr, "[probe] mount failed\n");
		goto out_signals;
	}
	fprintf(stderr, "[probe] mounted at %s, backing=%s\n", mp, backing_path);
	ret = fuse_session_loop(se);
	fuse_session_unmount(se);
out_signals:
	fuse_remove_signal_handlers(se);
out_destroy:
	fuse_session_destroy(se);
out:
	fuse_opt_free_args(&args);
	fprintf(stderr, "[probe] exit, read handler was called %d time(s)\n", read_handler_calls);
	return ret;
}

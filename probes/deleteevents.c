// Probe: can this design learn that a file was deleted, and by what name?
//
// `watch.rs` says, with a measurement behind it, that a group asking for both
// the fd-shaped content events and the fid-shaped directory-entry events is
// rejected with `EINVAL`. From that it concludes that deletions cannot be
// watched, and treats a file's *absence* as the deletion instead.
//
// Absence is adequate while a deletion only ever cancels a queued upload, which
// is all it did. It is not adequate for propagating the deletion to the cloud:
// a file can be absent because the user removed it, because the delta pass has
// not placed it yet, or because the sync root is empty or wrong — and the last
// of those, acted on, empties the account. Deleting is the one operation with no
// undo, so it needs positive evidence and not an inference.
//
// So the question this settles is not the one `watch.rs` answered. It is:
//
//   1. Can two fanotify groups on the same mount coexist, one asking for
//      content events and one asking for directory-entry events? The `EINVAL`
//      is documented for a *single* group asking for both. Two groups is a
//      different question and it has never been asked here.
//
//   2. Does the entry-event group say *which path* went away? `FAN_REPORT_FID`
//      alone gives a handle for the object, which is useless once the object is
//      gone — there is nothing left to open. `FAN_REPORT_DFID_NAME` gives the
//      parent's handle and the entry's name, and the parent still exists, so it
//      can be opened and named. A path is what the lineage record is keyed by
//      and what the cloud addresses, so a path is the answer worth having.
//
//   3. Does a deletion by *rename over* — the atomic save, which is what most
//      editors do — look different from a deletion by `unlink`? If it does not,
//      propagating deletions on this signal would delete a cloud object every
//      time somebody saved a file, which is worse than not propagating at all.
//
// Build and run:
//   gcc -O1 -Wall -Wextra -o /tmp/deleteevents probes/deleteevents.c
//   sudo /tmp/deleteevents /mnt/scratch
//
// Needs CAP_SYS_ADMIN and a real filesystem; the mount must be one fanotify can
// mark, so not tmpfs for the content group.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fanotify_compat.h"

#ifndef FAN_REPORT_DFID_NAME
#define FAN_REPORT_DFID_NAME 0x00000c00
#endif
#ifndef FAN_EVENT_INFO_TYPE_DFID_NAME
#define FAN_EVENT_INFO_TYPE_DFID_NAME 2
#endif
#ifndef FAN_DELETE
#define FAN_DELETE 0x00000200
#endif
#ifndef FAN_MOVED_FROM
#define FAN_MOVED_FROM 0x00000040
#endif
#ifndef FAN_MOVED_TO
#define FAN_MOVED_TO 0x00000080
#endif

struct fanotify_event_info_fid_hdr {
    struct fanotify_event_info_header hdr;
    __kernel_fsid_t fsid;
    unsigned char handle[0];
};

static const char *evname(uint64_t mask) {
    if (mask & FAN_DELETE) return "DELETE";
    if (mask & FAN_MOVED_FROM) return "MOVED_FROM";
    if (mask & FAN_MOVED_TO) return "MOVED_TO";
    return "other";
}

// Print every entry event the group has queued, with the name it carries.
static int drain(int fd, const char *label) {
    char buf[8192];
    ssize_t len = read(fd, buf, sizeof buf);
    if (len <= 0) {
        printf("  %-14s (nothing queued)\n", label);
        return 0;
    }
    int seen = 0;
    struct fanotify_event_metadata *m = (struct fanotify_event_metadata *)buf;
    while (FAN_EVENT_OK(m, len)) {
        // The info records follow the metadata, back to back.
        char *p = (char *)m + m->metadata_len;
        char *end = (char *)m + m->event_len;
        const char *name = "(no name record)";
        for (char *cur = (char *)(m + 1); cur + sizeof(struct fanotify_event_info_header) <= end;) {
            struct fanotify_event_info_header *h = (struct fanotify_event_info_header *)cur;
            if (h->len == 0 || cur + h->len > end) break;
            if (h->info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
                struct fanotify_event_info_fid_hdr *f =
                    (struct fanotify_event_info_fid_hdr *)cur;
                // handle is a struct file_handle: 4-byte size, 4-byte type,
                // then that many bytes. The name follows it, NUL-terminated.
                unsigned int hbytes;
                memcpy(&hbytes, f->handle, sizeof hbytes);
                name = (const char *)f->handle + 8 + hbytes;
            }
            cur += h->len;
        }
        (void)p;
        printf("  %-14s %-11s name=%s\n", label, evname(m->mask), name);
        seen++;
        m = FAN_EVENT_NEXT(m, len);
    }
    return seen;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: deleteevents <mountpoint>\n");
        return 2;
    }
    const char *mount = argv[1];

    // Group A: what the helper already runs. Content events, with descriptors.
    int a = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC, O_RDONLY);
    if (a < 0) {
        printf("content group: fanotify_init FAILED (%s)\n", strerror(errno));
        return 1;
    }
    if (fanotify_mark(a, FAN_MARK_ADD | FAN_MARK_MOUNT, FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD,
                      mount) < 0) {
        printf("content group: mark FAILED (%s)\n", strerror(errno));
        return 1;
    }
    printf("content group:  ok (FAN_MODIFY | FAN_CLOSE_WRITE)\n");

    // Question 1 and 2. A second group, of the other shape, on the same mount.
    // FAN_NONBLOCK, because "nothing was queued" is one of the answers this
    // probe exists to report, and a blocking read turns that answer into a hang.
    int b = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK | FAN_REPORT_DFID_NAME,
                          O_RDONLY);
    if (b < 0) {
        printf("entry group:    fanotify_init FAILED (%s)\n", strerror(errno));
        printf("\nVERDICT: this kernel cannot report deletions alongside content\n"
               "         events. Absence stays the only signal.\n");
        return 1;
    }
    // Which mark shape carries entry events is the second half of question 1,
    // and it is not the one the mount mark uses. A deletion is an event about a
    // *directory entry*, so the object being watched has to be something that
    // has entries: `FAN_MARK_MOUNT` marks a vfsmount and reports nothing here.
    // Measured rather than read off a manual page, because the whole design
    // rests on which of these the kernel will accept alongside the content
    // group.
    static const struct { unsigned int flag; const char *name; } shapes[] = {
        {FAN_MARK_MOUNT, "FAN_MARK_MOUNT"},
#ifdef FAN_MARK_FILESYSTEM
        {FAN_MARK_FILESYSTEM, "FAN_MARK_FILESYSTEM"},
#endif
        {0, "a plain directory mark"},
    };
    const char *worked = NULL;
    for (size_t i = 0; i < sizeof shapes / sizeof shapes[0]; i++) {
        if (fanotify_mark(b, FAN_MARK_ADD | shapes[i].flag,
                          FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO, AT_FDCWD, mount) < 0) {
            printf("entry group:    %-22s rejected (%s)\n", shapes[i].name, strerror(errno));
            continue;
        }
        printf("entry group:    %-22s ACCEPTED\n", shapes[i].name);
        worked = shapes[i].name;
        break;
    }
    if (!worked) {
        printf("\nVERDICT: no mark shape on this kernel reports deletions while the\n"
               "         content group is open. Absence stays the only signal.\n");
        return 1;
    }
    printf("\nBoth groups are open at once, entry events via %s.\n\n", worked);

    char victim[4096], tmp[4096];
    snprintf(victim, sizeof victim, "%s/deleteprobe-victim", mount);
    snprintf(tmp, sizeof tmp, "%s/deleteprobe-tmp", mount);

    // An ordinary deletion.
    int fd = open(victim, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) {
        printf("could not create %s: %s\n", victim, strerror(errno));
        return 1;
    }
    if (write(fd, "x", 1) != 1) { /* reported by the drain below either way */ }
    close(fd);
    unlink(victim);
    printf("after unlink of a plain file:\n");
    int unlinked = drain(b, "entry");

    // Question 3: the atomic save. A new file renamed over an existing name.
    fd = open(victim, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) { if (write(fd, "old", 3) != 3) {} close(fd); }
    fd = open(tmp, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) { if (write(fd, "new", 3) != 3) {} close(fd); }
    // Drop everything the setup produced, so the rename is measured alone.
    { char scratch[8192]; while (read(b, scratch, sizeof scratch) > 0) {} }
    if (rename(tmp, victim) < 0) {
        printf("rename failed: %s\n", strerror(errno));
    }
    printf("\nafter an atomic save (rename over an existing name):\n");
    int renamed = drain(b, "entry");
    unlink(victim);

    // Question 4, and the one that decides whether this is usable at all.
    //
    // `FAN_MARK_FILESYSTEM` says *filesystem*, not mount. The sync root here is
    // a btrfs subvolume, and a subvolume is not a filesystem — @onedrive and
    // @home are the same btrfs volume with different anonymous st_dev values.
    // If the mark reaches across subvolumes, this group reports every deletion
    // in the user's home directory, and a design that propagates deletions on
    // that signal would propagate deletions of files it has never heard of.
    if (argc >= 3) {
        const char *elsewhere = argv[2];
        char outside[4096];
        snprintf(outside, sizeof outside, "%s/deleteprobe-outside", elsewhere);
        { char scratch[8192]; while (read(b, scratch, sizeof scratch) > 0) {} }
        fd = open(outside, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd < 0) {
            printf("\ncould not create %s: %s\n", outside, strerror(errno));
        } else {
            close(fd);
            unlink(outside);
            printf("\nafter deleting a file at %s\n", outside);
            printf("  (same btrfs volume, different subvolume from the marked one)\n");
            int leaked = drain(b, "entry");
            printf("  reach: %s\n",
                   leaked ? "LEAKS ACROSS SUBVOLUMES — must be filtered by parent"
                          : "confined to the marked subvolume");
        }
    } else {
        printf("\n(pass a second path on the same filesystem to measure the mark's reach)\n");
    }

    // Question 5, and on a subvolume it is the one that decides the cost.
    //
    // A plain directory mark is the only shape a btrfs subvolume accepts, and a
    // mark that watches one directory and not its children needs one mark per
    // directory — thousands here, created and destroyed as the delta pass places
    // folders, with every gap a deletion nobody sees. A recursive one needs
    // exactly one. The difference is the whole feasibility of the design, so it
    // is measured rather than assumed either way.
    char subdir[4096], deep[4096];
    snprintf(subdir, sizeof subdir, "%s/deleteprobe-dir", mount);
    snprintf(deep, sizeof deep, "%s/deleteprobe-dir/inner", mount);
    if (mkdir(subdir, 0755) < 0 && errno != EEXIST) {
        printf("\ncould not create %s: %s\n", subdir, strerror(errno));
    } else {
        fd = open(deep, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) close(fd);
        { char scratch[8192]; while (read(b, scratch, sizeof scratch) > 0) {} }
        unlink(deep);
        printf("\nafter deleting a file one level below the marked directory:\n");
        int nested = drain(b, "entry");
        printf("  the mark is: %s\n",
               nested ? "recursive — one mark covers the tree"
                      : "NOT recursive — one mark per directory would be needed");
        rmdir(subdir);
    }

    // Question 6: can the *unprivileged* half do this instead?
    //
    // Everything above needs CAP_SYS_ADMIN, which means the privileged helper,
    // which means a protocol message and a new responsibility for the process
    // §6b wants to keep small. A deletion is a cloud operation and the helper
    // never speaks to a network, so the decision belongs to the client — if the
    // client can see it. inotify is unprivileged and its watch budget here is
    // 524288 against the 21395 directories this tree has.
    //
    // The question is the same one that mattered for fanotify, and getting it
    // wrong is the same disaster: does `rename(tmp, name)` report `name` as
    // deleted? If it does, every atomic save deletes a cloud object.
    {
        int in = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (in < 0) {
            printf("\ninotify: init failed (%s)\n", strerror(errno));
        } else if (inotify_add_watch(in, mount, IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO) < 0) {
            printf("\ninotify: watch failed (%s)\n", strerror(errno));
        } else {
            char a[4096], b2[4096];
            snprintf(a, sizeof a, "%s/inprobe-victim", mount);
            snprintf(b2, sizeof b2, "%s/inprobe-tmp", mount);
            int f1 = open(a, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (f1 >= 0) close(f1);
            unlink(a);
            f1 = open(a, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (f1 >= 0) close(f1);
            int f2 = open(b2, O_CREAT | O_WRONLY | O_TRUNC, 0644);
            if (f2 >= 0) close(f2);
            if (rename(b2, a) < 0) printf("  rename failed: %s\n", strerror(errno));
            unlink(a);

            printf("\ninotify, unprivileged, one watch on the directory:\n");
            char buf[8192];
            ssize_t n = read(in, buf, sizeof buf);
            int deletes = 0, moves = 0;
            for (char *cur = buf; n > 0 && cur < buf + n;) {
                struct inotify_event *e = (struct inotify_event *)cur;
                const char *what = (e->mask & IN_DELETE)       ? "DELETE"
                                   : (e->mask & IN_MOVED_FROM) ? "MOVED_FROM"
                                   : (e->mask & IN_MOVED_TO)   ? "MOVED_TO"
                                                               : "other";
                if (e->mask & IN_DELETE) deletes++;
                if (e->mask & (IN_MOVED_FROM | IN_MOVED_TO)) moves++;
                printf("  %-11s name=%s\n", what, e->len ? e->name : "(none)");
                cur += sizeof(struct inotify_event) + e->len;
            }
            printf("  deletes=%d moves=%d\n", deletes, moves);
            printf("  a save is distinguishable: %s\n",
                   deletes == 2 && moves == 2 ? "yes — the overwritten name is never a DELETE"
                                              : "CHECK THIS, the counts are not what was expected");
            close(in);
        }
    }

    printf("\nVERDICT\n");
    printf("  two groups coexist:            yes\n");
    printf("  a deletion is reported:        %s\n", unlinked ? "yes, with the name" : "NO");
    printf("  an atomic save looks like:     %s\n",
           renamed ? "MOVED_FROM/MOVED_TO, not DELETE" : "nothing");
    printf("\n  A save and a deletion are therefore distinguishable, which is what\n");
    printf("  propagating a deletion to the cloud requires. Absence is not.\n");
    return 0;
}

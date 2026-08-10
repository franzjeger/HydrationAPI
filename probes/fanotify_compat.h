/* What the running kernel understands, minus what its headers happen to ship.
 *
 * These are not new definitions. They are the numbers already in
 * <linux/fanotify.h> upstream, repeated here because a distribution's
 * linux-libc-dev is a package with its own release schedule and is routinely
 * older than the kernel it runs beside.
 *
 * That is not a hypothetical. CI runs on ubuntu-24.04, whose kernel is
 * 6.17-azure — comfortably past the 6.14 that introduced pre-content events —
 * while its headers still describe 6.8. Every probe here failed to compile on a
 * machine perfectly capable of running them, with `FAN_PRE_ACCESS undeclared;
 * did you mean FAN_ACCESS?`, which is the compiler helpfully offering a
 * completely different event.
 *
 * It is the same confusion the probes exist to settle, arriving from the other
 * direction: the header is not the kernel. Grepping it answers a question about
 * the packaging. Only a syscall answers a question about the kernel, which is
 * what probes/precontent.c does at run time.
 *
 * Every definition is guarded, so on a machine with current headers this file
 * contributes nothing and the real ones win.
 */

#ifndef HYDRATION_FANOTIFY_COMPAT_H
#define HYDRATION_FANOTIFY_COMPAT_H

#include <linux/types.h>
#include <sys/fanotify.h>

/* Pre-content access hook. Linux 6.14 (March 2025). The single event this
 * framework is built on; there is no pre-modify counterpart in any released
 * kernel, though early revisions of the series had one. */
#ifndef FAN_PRE_ACCESS
#define FAN_PRE_ACCESS 0x00100000
#endif

/* The class has been in the header since 2.6.37 and did nothing until 6.14, so
 * its presence proves nothing. Defined here only for headers old enough to
 * predate even that. */
#ifndef FAN_CLASS_PRE_CONTENT
#define FAN_CLASS_PRE_CONTENT 0x00000008
#endif

/* Mount events, for the exposure guard in §6.4a. Cannot be combined with
 * FAN_CLASS_PRE_CONTENT, which is why the daemon opens a second group. */
#ifndef FAN_REPORT_MNT
#define FAN_REPORT_MNT 0x00004000
#endif
#ifndef FAN_MNT_ATTACH
#define FAN_MNT_ATTACH 0x01000000
#endif
#ifndef FAN_MNT_DETACH
#define FAN_MNT_DETACH 0x02000000
#endif

/* An ignore mark that survives modification — how a hydrated file stops costing
 * anything. Linux 5.19. */
#ifndef FAN_MARK_IGNORE
#define FAN_MARK_IGNORE 0x00000400
#endif
#ifndef FAN_MARK_IGNORE_SURV
#define FAN_MARK_IGNORE_SURV (FAN_MARK_IGNORE | FAN_MARK_IGNORED_SURV_MODIFY)
#endif

/* The offset/count record delivered alongside a pre-content event.
 *
 * `count` is a demand and not a hint: filling less than it asks for and
 * answering FAN_ALLOW gives the reader zeros with no second event and no error
 * (§8d, probes/demand.c). */
#ifndef FAN_EVENT_INFO_TYPE_RANGE
#define FAN_EVENT_INFO_TYPE_RANGE 6
#define HYDRATION_NEEDS_INFO_RANGE 1
#endif

#ifdef HYDRATION_NEEDS_INFO_RANGE
struct fanotify_event_info_range {
    struct fanotify_event_info_header hdr;
    __u32 pad;
    __u64 offset;
    __u64 count;
};
#endif

/* The mount-id record on a FAN_REPORT_MNT group. */
#ifndef FAN_EVENT_INFO_TYPE_MNT
#define FAN_EVENT_INFO_TYPE_MNT 7
#define HYDRATION_NEEDS_INFO_MNT 1
#endif

#ifdef HYDRATION_NEEDS_INFO_MNT
struct fanotify_event_info_mnt {
    struct fanotify_event_info_header hdr;
    __u64 mnt_id;
};
#endif

#endif /* HYDRATION_FANOTIFY_COMPAT_H */

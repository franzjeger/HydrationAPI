//! Deciding whether a reader gets to hydrate.
//!
//! A backup sweep reads every file. Without a policy, one `restic` run pulls the
//! whole drive down, which defeats on-demand entirely. Windows and macOS solve
//! this with a hint in the API — the application says "do not hydrate" — and
//! Linux has no such thing, so the decision has to be made from outside, about a
//! process that did not ask to be judged. See DESIGN.md §6c.
//!
//! Two measurements shape this module:
//!
//! * **`stat` does not hydrate.** Only content access fires a pre-content event,
//!   so `ls`, `du`, `find` and the metadata pass of most indexers are free. The
//!   policy only ever sees processes that actually read bytes, which is a much
//!   smaller set than it first appears.
//! * **cgroup is the only key that works.** Two readers were measured that were
//!   identical in `comm` (`cat`) and in `exe` (`/usr/bin/cat`) and had to be
//!   treated differently: one was the user's shell, one was a backup unit. An
//!   exe-based rule cannot tell them apart, so it would either let the backup
//!   through or deny the user their own file.

use std::fs;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::Path;

/// What to do with a reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Fetch the content.
    Hydrate,
    /// Refuse, and say so out loud. The reader gets an error rather than a
    /// silently short or zero-filled file.
    Deny { rule: String },
}

/// Which readers are not allowed to pull content down.
///
/// Matched against the cgroup path as a substring, so `restic.service` catches
/// `/system.slice/restic.service` and the timer-spawned scope alike.
#[derive(Debug, Clone)]
pub struct Policy {
    denied: Vec<String>,
}

impl Default for Policy {
    /// The tools that read every byte of a home directory on a schedule.
    ///
    /// A default list is a guess about someone else's machine, so it is
    /// deliberately short and every entry is a program whose whole job is to
    /// walk everything. Anything less obvious belongs in the user's config, not
    /// here.
    fn default() -> Self {
        Self {
            denied: [
                "restic",
                "borg",
                "borgmatic",
                "duplicity",
                "rclone",
                "baloo_file",
                "tracker-extract",
                "tracker-miner",
                "clamd",
                "freshclam",
                "updatedb",
                "mlocate",
                "plocate",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
}

impl Policy {
    pub fn new(denied: Vec<String>) -> Self {
        Self { denied }
    }

    /// Allow everything. For tests, and for a user who would rather pay the
    /// bandwidth than think about it.
    pub fn permissive() -> Self {
        Self { denied: Vec::new() }
    }

    pub fn decide(&self, cgroup: Option<&str>) -> Decision {
        let Some(cgroup) = cgroup else {
            // Not knowing who is asking is not grounds for refusing them. A
            // denial has a visible cost -- a failed backup, a broken open -- and
            // spending it on a process we merely failed to identify would make
            // the policy untrustworthy in exactly the cases it matters.
            return Decision::Hydrate;
        };
        for rule in &self.denied {
            if cgroup.contains(rule.as_str()) {
                return Decision::Deny { rule: rule.clone() };
            }
        }
        Decision::Hydrate
    }
}

/// The cgroup of the process behind an event, via its pidfd.
///
/// The pidfd matters: `event->pid` is a number that can be recycled, and by the
/// time this runs the process may be gone and its pid reused by something else.
/// A pidfd pins the pid for as long as it is open, so the `/proc` lookup below
/// cannot land on a different process than the one that generated the event.
///
/// Takes a borrow rather than a number: the caller keeps the descriptor, and the
/// lookup has no business closing it. The number-taking version invited the
/// caller to dispose of the pidfd here, and the disposal then only happened on
/// the paths that reached this call — a leak on every other path out of the
/// decision.
pub fn cgroup_of(pidfd: BorrowedFd<'_>) -> io::Result<String> {
    let pid = pid_from_pidfd(pidfd)?;
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    // cgroup v2: a single "0::/path" line.
    let path = raw
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .unwrap_or_else(|| raw.trim())
        .trim()
        .to_string();
    Ok(path)
}

fn pid_from_pidfd(pidfd: BorrowedFd<'_>) -> io::Result<i32> {
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))?;
    info.lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Pid in fdinfo"))
}

/// A record of every refusal, so a denial is never silent.
///
/// §6c is explicit that the list is a product, not a setting: a user whose
/// backup started complaining has to be able to find out why in one place. A
/// policy that quietly refuses is a worse failure than no policy at all.
#[derive(Debug, Default)]
pub struct DenialLog {
    entries: Vec<Denial>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    pub cgroup: String,
    pub rule: String,
    pub path: Option<String>,
}

impl DenialLog {
    pub fn record(&mut self, cgroup: &str, rule: &str, path: Option<&Path>) {
        self.entries.push(Denial {
            cgroup: cgroup.to_string(),
            rule: rule.to_string(),
            path: path.map(|p| p.display().to_string()),
        });
    }

    pub fn entries(&self) -> &[Denial] {
        &self.entries
    }

    /// What the user is shown. Grouped by rule, because "restic was refused
    /// 412 times" is the sentence they need, not 412 lines.
    pub fn summary(&self) -> Vec<(String, usize)> {
        let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
        for e in &self.entries {
            *counts.entry(e.rule.clone()).or_default() += 1;
        }
        counts.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_unit_is_refused_and_the_users_shell_is_not() {
        // The measured case: both readers were `cat` at `/usr/bin/cat`, and
        // only the cgroup told them apart.
        let p = Policy::default();
        assert_eq!(
            p.decide(Some("/system.slice/restic.service")),
            Decision::Deny {
                rule: "restic".into()
            }
        );
        assert_eq!(
            p.decide(Some(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-konsole.scope"
            )),
            Decision::Hydrate
        );
    }

    #[test]
    fn an_unidentified_reader_is_allowed() {
        // Denying on missing information would spend a visible failure on a
        // process we merely could not name.
        assert_eq!(Policy::default().decide(None), Decision::Hydrate);
    }

    #[test]
    fn the_denial_log_counts_rather_than_lists() {
        let mut log = DenialLog::default();
        for _ in 0..412 {
            log.record("/system.slice/restic.service", "restic", None);
        }
        log.record("/system.slice/clamd.service", "clamd", None);
        assert_eq!(
            log.summary(),
            vec![("clamd".to_string(), 1), ("restic".to_string(), 412)]
        );
    }

    #[test]
    fn our_own_cgroup_is_readable() {
        // Proves the lookup path works on this machine, not just that it
        // compiles. Uses the current process rather than a pidfd, which the
        // integration test covers with a real event.
        let raw = std::fs::read_to_string("/proc/self/cgroup").expect("read cgroup");
        assert!(raw.contains("0::"), "unexpected cgroup format: {raw}");
    }
}

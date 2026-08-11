//! The privileged half of the hydration framework.
//!
//! It holds `CAP_SYS_ADMIN` and does exactly three things: watch a mount for
//! pre-content events, fill placeholders with content someone else fetched, and
//! fail closed when it cannot. It never opens a socket to the network, never
//! sees a token, and never accepts a path from the unprivileged side.
//!
//! Everything here is shaped by a measurement rather than a guess; see the
//! module docs and `probes/` for which one.

pub mod daemon;
pub mod evict;
pub mod exposure;
pub mod fanotify;
pub mod placeholder;
pub mod policy;
pub mod remote;
pub mod report;
pub mod selfcheck;
pub mod supervisor;
pub mod watch;

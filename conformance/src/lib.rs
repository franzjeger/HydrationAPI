//! Executable specification for a Linux cloud-file hydration framework.
//!
//! This crate is the product. It is deliberately ignorant of how hydration is
//! implemented — FUSE, fanotify pre-content hooks, or a kernel filesystem that
//! does not exist yet. It states what a cloud client must answer and what the
//! framework guarantees, as tests that either pass or do not.
//!
//! That independence is the point. Every invariant here was a real data-loss bug
//! in a shipped FUSE client, and every one of them is a property of the POSIX
//! contract rather than of any particular implementation of it. Swap the
//! architecture and these tests still say the same thing.
//!
//! # How to use it
//!
//! Implement [`Harness`] for the thing under test, then call the invariants in
//! [`invariants`]. An implementation conforms when all of them pass.
//!
//! # Why the harness has the shape it does
//!
//! Most of these bugs are races that only reproduce when an upload is in flight
//! at the moment something else happens. Testing them by sleeping is how they
//! stayed hidden. The harness therefore requires the implementation to expose
//! *deterministic* control over the upload window — [`Harness::hold_uploads`]
//! and [`Harness::wait_for_upload_start`] — so the race is arranged rather than
//! hoped for.

use std::path::Path;
use std::time::Duration;

pub mod invariants;

/// What the cloud side holds for one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudObject {
    /// The id the cloud assigned. Never a locally invented one.
    pub id: String,
    /// The name the object currently has in the cloud.
    pub name: String,
    pub content: Vec<u8>,
    pub etag: String,
}

/// A request the implementation made to the cloud, as observed by the fake.
///
/// Tests assert on these because "the delete reached the server" is not
/// observable from the filesystem alone — the bug being prevented is precisely
/// one where the local state looked right and the remote did not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloudOp {
    Get { id: String },
    Put { name: String, content: Vec<u8> },
    Delete { id: String },
    Rename { id: String, to: String },
}

/// What a hydration attempt should return, so §5.7 can be provoked.
#[derive(Debug, Clone)]
pub enum FetchBehaviour {
    /// Serve the object as declared. The normal case.
    Honest,
    /// Serve fewer bytes than the placeholder's size promises.
    Short { bytes: usize },
    /// Serve content whose etag no longer matches the placeholder's.
    Stale { etag: String },
}

/// The control surface an implementation must expose to be tested.
///
/// Everything here exists because some invariant cannot be checked without it.
/// Nothing here is a convenience.
pub trait Harness {
    // ---- the filesystem under test -------------------------------------

    /// The directory a user would see. Tests do ordinary POSIX operations here
    /// and nothing else — no back doors, because a back door would test the
    /// implementation rather than the contract.
    fn sync_dir(&self) -> &Path;

    // ---- seeding the cloud ---------------------------------------------

    /// Place an object in the cloud and let a sync pass bring it down as a
    /// placeholder. Returns the cloud id.
    fn seed_remote(&mut self, name: &str, content: &[u8], etag: &str) -> String;

    /// What the cloud holds now, by name. `None` means it is not there —
    /// which is the assertion for "the delete stuck".
    fn remote(&self, name: &str) -> Option<CloudObject>;

    /// Every request the implementation has made. Ordered.
    fn ops_observed(&self) -> Vec<CloudOp>;

    // ---- making races deterministic ------------------------------------

    /// Hold uploads open once they start, so a rename or unlink can be made to
    /// land strictly inside the upload window.
    fn hold_uploads(&mut self);

    /// Let held uploads complete.
    fn release_uploads(&mut self);

    /// Block until an upload has actually begun, or the timeout expires.
    /// Returns false on timeout.
    ///
    /// Needed because a debounce means "closed the file" and "started
    /// uploading" are far apart; a test that assumes otherwise passes for the
    /// wrong reason.
    fn wait_for_upload_start(&self, timeout: Duration) -> bool;

    /// Force any debounce window to expire and drain the upload queue.
    fn settle(&mut self);

    // ---- provoking hydration failures ----------------------------------

    /// How the next hydration should behave. Drives §5.7.
    fn set_fetch_behaviour(&mut self, name: &str, behaviour: FetchBehaviour);

    /// Evict local content, leaving metadata. The file must keep its size and
    /// mode and lose its blocks. Needed to prove mode survives a
    /// dehydrate/rehydrate round trip, which is where a cloud that does not
    /// store the exec bit loses it.
    fn dehydrate(&mut self, name: &str);

    // ---- status the user is meant to trust ------------------------------

    /// Changes not yet in the cloud, including ones still waiting out a
    /// debounce. A count that omits waiting edits shows "everything synced"
    /// over work that has not left the machine.
    fn pending_uploads(&self) -> usize;

    /// Files present as metadata with no local content. §6d requires this to
    /// be visible to the user, so it must be visible here.
    fn dehydrated_count(&self) -> usize;

    // ---- lifecycle -------------------------------------------------------

    /// Kill the component that services hydration, without a clean shutdown.
    /// Used to prove the system fails closed (§6a) rather than serving zeros.
    fn kill_hydration_worker(&mut self);

    /// True if this implementation has a separable hydration worker at all.
    /// A plain FUSE client does not, and should report false so the
    /// fail-closed invariant reports "not applicable" rather than a false pass.
    fn has_separable_worker(&self) -> bool {
        false
    }
}

/// Outcome of one invariant, so a runner can report "not applicable"
/// distinctly from "passed". A skip that reads as a pass is how the reference
/// client shipped an untested created-file path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    NotApplicable(String),
}

impl Outcome {
    pub fn is_pass(&self) -> bool {
        matches!(self, Outcome::Pass)
    }
}

//! The eight invariants, against this framework.
//!
//! Needs root and a real mount, because there is no way to exercise a
//! pre-content event without them:
//!
//! ```text
//! sudo -E HYDRATION_TEST_MOUNT=/mnt/scratch cargo test -p adapter-framework
//! ```
//!
//! A skip is reported as "did not run", never as a pass. `HYDRATION_REQUIRE=1`
//! turns a skip into a failure.

use adapter_framework::Framework;
use hydration_conformance::{invariants, Outcome};
use std::panic::{catch_unwind, AssertUnwindSafe};

type Invariant = fn(&mut Framework) -> Outcome;

fn suite() -> Vec<(&'static str, Invariant)> {
    vec![
        ("5.1 identity is stable", invariants::identity_is_stable),
        ("5.2 size is local truth", invariants::size_is_local_truth),
        (
            "5.3 mode survives dehydration",
            invariants::mode_survives_dehydration,
        ),
        (
            "5.4 atomic save keeps its name",
            invariants::atomic_save_keeps_its_name,
        ),
        (
            "5.5 delete beats in-flight upload",
            invariants::delete_beats_inflight_upload,
        ),
        ("5.6 fsync does not lie", invariants::fsync_does_not_lie),
        (
            "5.7 hydration mismatch fails closed",
            invariants::hydration_mismatch_fails_closed,
        ),
        (
            "5.8 placeholder consumes no disk",
            invariants::placeholder_consumes_no_disk,
        ),
        (
            "6a worker death fails closed",
            invariants::worker_death_fails_closed,
        ),
    ]
}

#[test]
fn framework_conformance() {
    if Framework::start().is_none() {
        let msg = "needs root and HYDRATION_TEST_MOUNT on a real filesystem";
        if std::env::var_os("HYDRATION_REQUIRE").is_some() {
            panic!("HYDRATION_REQUIRE is set but the run did not happen: {msg}");
        }
        eprintln!("SKIPPED: {msg}");
        return;
    }

    println!("\n  HydrationAPI framework — conformance\n");
    println!("  invariant                              result   detail");
    println!("  ------------------------------------------------------------");

    let mut passed = 0;
    let mut failed = Vec::new();

    for (name, run) in suite() {
        // A fresh mount, worker and cloud per invariant. They are a
        // specification, not a sequence.
        let Some(mut fw) = Framework::start() else {
            println!("  {name:<38} SKIP     could not start");
            continue;
        };
        let outcome = catch_unwind(AssertUnwindSafe(|| run(&mut fw)));
        drop(fw);

        match outcome {
            Ok(Outcome::Pass) => {
                passed += 1;
                println!("  {name:<38} PASS");
            }
            Ok(Outcome::NotApplicable(why)) => println!("  {name:<38} N/A      {why}"),
            Err(e) => {
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panic".into());
                let first = msg.lines().next().unwrap_or("").trim();
                let short: String = first.chars().take(110).collect();
                println!("  {name:<38} FAIL     {short}");
                failed.push((name, short));
            }
        }
    }

    println!("\n  {passed} passed, {} failed\n", failed.len());
    for (name, why) in &failed {
        println!("  {name}\n      {why}\n");
    }

    // The framework satisfies its own contract, and this asserts it.
    //
    // It did not until the three causes below were found, and the suite ran at
    // 5-7 of 9 with different invariants failing each time. None of them was the
    // kernel: `probes/eventtrace.c` gets a pre-content event on a well-formed
    // placeholder eight times out of eight.
    //
    //  * `seed_remote` created placeholders inside the marked mount. Giving a
    //    file its size is `ftruncate`, which fires a pre-content event, and at
    //    that instant the file existed but was not yet marked — so the worker
    //    concluded the content was present and added an ignore mark. The
    //    finished placeholder was then invisible to hydration for good, and read
    //    as zeros with no event and no error. Fixed by building it under an
    //    ignore mark (`placeholder::create_under`).
    //  * The daemon's index was scanned once at startup and never again, so a
    //    placeholder created afterwards was refused with EIO. Whether that
    //    happened depended on thread scheduling. Fixed by looking again before
    //    refusing.
    //  * A rename over a placeholder legitimately leaves two cloud objects with
    //    the same name, and the harness picked between them by `HashMap`
    //    iteration order. Fixed by picking the newest — which makes the harness
    //    deterministic and leaves the design question in §5.4 open.
    assert!(
        failed.is_empty(),
        "the framework no longer satisfies its own contract: {:?}",
        failed.iter().map(|(n, _)| *n).collect::<Vec<_>>()
    );
    let _ = passed;
}

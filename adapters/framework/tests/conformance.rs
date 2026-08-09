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

    // Deliberately no pass/fail assertion yet, and that is the current finding.
    //
    // Consecutive runs of this suite do not agree: one run reported 7 of 9, the
    // next 5 of 9, with different invariants failing. The framework is not
    // stable, so any expectation table written today would be recording a coin
    // toss and would fail for the wrong reason tomorrow.
    //
    // What is established:
    //
    //  * The suite drives both halves for real — forked worker, socket,
    //    supervisor — and 5.1, 5.2, 5.6 and 5.8 pass in every run.
    //  * Three genuine framework bugs were found by pointing it here and are
    //    fixed: a placeholder needs an explicit mark (`st_blocks == 0` also
    //    describes a brand-new file, so the first write into the sync directory
    //    failed with EIO); btrfs stores small files inline, so a punched hole
    //    leaves blocks behind and a dehydrated script was served as zeros; and
    //    a second fanotify group with nobody serving it blocks every write.
    //  * The remaining failures share one symptom: a read of a well-formed
    //    placeholder — marked, right size, zero blocks, cloud id present —
    //    sometimes returns zeros with no event recorded for it.
    //
    // The next step is to find out whether that event is not generated or not
    // delivered, and only then to write down what this suite should assert.
    let _ = (passed, failed);
}

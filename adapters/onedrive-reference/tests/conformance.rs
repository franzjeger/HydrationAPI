//! The conformance suite, against the real FUSE client.
//!
//! Each invariant gets a fresh mount: they are a specification, not a sequence,
//! and one must not be able to pass because another ran first.
//!
//! A skip here is not a pass. Where FUSE is unavailable the run reports that it
//! did not happen; set `HYDRATION_REQUIRE_FUSE` to turn a skip into a failure,
//! which is what CI should do.

use adapter_onedrive_reference::ReferenceClient;
use hydration_conformance::{invariants, Outcome};
use std::panic::{catch_unwind, AssertUnwindSafe};

type Invariant = fn(&mut ReferenceClient) -> Outcome;

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
fn reference_client_conformance() {
    if ReferenceClient::start().is_none() {
        let msg = "FUSE unavailable: the conformance run did not happen";
        if std::env::var_os("HYDRATION_REQUIRE_FUSE").is_some() {
            panic!("{msg}");
        }
        eprintln!("SKIPPED: {msg}");
        return;
    }

    println!("\n  OneDriveForLinux @ f1f090c — conformance\n");
    println!("  invariant                              result   detail");
    println!("  ------------------------------------------------------------");

    let mut passed = 0;
    let mut failed = Vec::new();

    for (name, run) in suite() {
        let Some(mut client) = ReferenceClient::start() else {
            println!("  {name:<38} SKIP     could not mount");
            continue;
        };

        let outcome = catch_unwind(AssertUnwindSafe(|| run(&mut client)));
        drop(client);

        match outcome {
            Ok(Outcome::Pass) => {
                passed += 1;
                println!("  {name:<38} PASS");
            }
            Ok(Outcome::NotApplicable(why)) => {
                println!("  {name:<38} N/A      {why}");
            }
            Err(e) => {
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                    .unwrap_or_else(|| "panic".into());
                let first = msg.lines().next().unwrap_or("").trim();
                let short: String = first.chars().take(120).collect();
                println!("  {name:<38} FAIL     {short}");
                failed.push((name, short));
            }
        }
    }

    println!("\n  {passed} passed, {} failed\n", failed.len());
    for (name, why) in &failed {
        println!("  {name}\n      {why}\n");
    }

    // Deliberately no assertion that everything passes. This suite exists to
    // measure a client that predates it; the report is the product. Encoding a
    // pass/fail expectation here would turn a measurement into a regression
    // test against bugs nobody has fixed yet.
}

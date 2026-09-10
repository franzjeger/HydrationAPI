use hydration_client::desktop::Desktop;
use hydration_client::upload::{Outcome, Queue, TestClock};
use hydration_protocol::FileId;
use serde_json::Value;
use std::path::Path;
use std::time::Duration;

#[test]
fn queue_errors_survive_retry_and_history_survives_restart() {
    let dir = test_scratch::scratch(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../target"),
        "desktop-history",
    );
    let file = dir.join("history.json");
    let _ = std::fs::remove_file(&file);
    let desktop = Desktop::load(Some(file.clone()));
    let mut queue = Queue::new(Duration::from_secs(10), TestClock::default());
    let id = FileId { fsid: 1, ino: 2 };
    queue.touch(id);
    queue.begin(id);
    queue.finish(id);
    queue.failed(id);
    desktop.record(
        id,
        Some("Documents/a.txt"),
        &Outcome::Failed("Remote version changed".into()),
    );
    let parse = |d: &Desktop, q: &Queue<TestClock>| -> Value {
        serde_json::from_str(&d.snapshot(Path::new("/sync"), q)).unwrap()
    };
    let state = parse(&desktop, &queue);
    assert_eq!(state["queue"][0]["status"], "retry");
    assert_eq!(state["queue"][0]["detail"], "Remote version changed");
    assert!(state["queue"][0]["retry_after"].as_u64().unwrap() > 0);
    queue.touch(id);
    let edited = parse(&desktop, &queue);
    assert_eq!(edited["queue"][0]["status"], "waiting");
    assert!(
        edited["queue"][0]["detail"].is_null(),
        "old error must not describe newly edited content"
    );
    desktop.pause(7200);
    assert!(desktop.paused());
    assert_eq!(queue.pending(), 1, "pausing must retain queued work");
    desktop.pause(0);
    assert!(!desktop.paused());
    queue.flush_now();
    assert_eq!(queue.due(), vec![id]);
    queue.begin(id);
    assert_eq!(parse(&desktop, &queue)["queue"][0]["status"], "uploading");
    queue.finish(id);
    queue.sent(id);
    desktop.record(
        id,
        Some("Documents/a.txt"),
        &Outcome::Sent {
            cloud_id: "cloud-id".into(),
        },
    );
    let restarted = Desktop::load(Some(file));
    let state = parse(&restarted, &queue);
    assert_eq!(state["queue"].as_array().unwrap().len(), 0);
    assert_eq!(state["history"][0]["status"], "uploaded");
    assert_eq!(state["history"][1]["status"], "error");
    assert!(
        !restarted.paused(),
        "pause does not silently persist across restart"
    );
}

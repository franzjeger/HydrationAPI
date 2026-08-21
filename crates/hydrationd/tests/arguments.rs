use std::process::Command;

fn hydrationd(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_hydrationd"))
        .args(arguments)
        .output()
        .expect("could not run hydrationd")
}

#[test]
fn an_invalid_peer_uid_fails_before_the_helper_can_start() {
    let output = hydrationd(&[
        "--mount",
        "/tmp",
        "--socket",
        "/tmp/hydrationd-arguments.sock",
        "--peer-uid",
        "root",
    ]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--peer-uid must be an unsigned 32-bit integer"));
}

#[test]
fn a_peer_uid_without_a_value_fails_before_the_helper_can_start() {
    let output = hydrationd(&[
        "--mount",
        "/tmp",
        "--socket",
        "/tmp/hydrationd-arguments.sock",
        "--peer-uid",
    ]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--peer-uid requires a value"));
}

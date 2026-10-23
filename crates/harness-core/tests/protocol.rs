use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

fn invoke(input: &[u8]) -> (bool, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_harness-core"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}
#[test]
fn protocol_version_and_unknown_fields_are_rejected() {
    for input in [
        json!({"protocol_version":2,"operation":"schemas"}),
        json!({"protocol_version":1,"operation":"schemas","unexpected":true}),
        json!({"protocol_version":1,"operation":"unknown"}),
    ] {
        let (success, response) = invoke(&serde_json::to_vec(&input).unwrap());
        assert!(!success);
        assert_eq!(response["ok"], false);
    }
}
#[test]
fn schemas_and_digest_protocol_work() {
    let (success, response) = invoke(br#"{"protocol_version":1,"operation":"schemas"}"#);
    assert!(success, "{response}");
    assert!(response["data"]["task"].is_object());
    let input = json!({"protocol_version":1,"operation":"verify_digest","sha256":harness_core::digest("hello"),"content":"hello"});
    let (success, response) = invoke(&serde_json::to_vec(&input).unwrap());
    assert!(success, "{response}");
}
#[test]
fn malformed_input_produces_structured_failure() {
    for bytes in [b"{".as_slice(), b"{} {}".as_slice()] {
        let (success, response) = invoke(bytes);
        assert!(!success);
        assert_eq!(response["protocol_version"], 1);
    }
}

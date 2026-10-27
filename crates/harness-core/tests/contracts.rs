use harness_core::{Evidence, TaskSpec, bind_evidence, validate_document};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn example(name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(root().join("examples").join(name)).unwrap()).unwrap()
}
#[test]
fn all_examples_validate() {
    for name in ["task.source.json", "task.web.json", "task.hybrid.json"] {
        validate_document("task", example(name)).unwrap();
    }
    validate_document("attempt", example("attempt.json")).unwrap();
    validate_document("evidence", example("evidence.http.json")).unwrap();
}
#[test]
fn task_rejects_malformed_or_unsafe_contracts() {
    let cases = [
        ("/schema_version", json!(2)),
        ("/question", json!("   ")),
        ("/budget/max_wall_seconds", json!(0)),
        ("/budget/max_requests", json!(0)),
        ("/budget/max_model_tokens", json!(-1)),
        ("/task_id", json!("../task")),
        ("/deadline", json!("2020-01-01T00:00:00Z")),
        ("/created_at", json!("2026-10-23T00:00:00")),
        ("/target/web/origin", json!("file:///etc/passwd")),
        (
            "/target/web/origin",
            json!("https://user:secret@example.test"),
        ),
        ("/target/web/origin", json!("http://127.0.0.1:8081/path")),
        ("/target/web/seed_urls", json!([])),
        (
            "/target/web/seed_urls",
            json!(["http://127.0.0.1:8081.evil.test/"]),
        ),
        ("/target/web/seed_urls", json!(["http://127.0.0.1:8082/"])),
        ("/dependencies", json!(["task-lab-web"])),
        ("/dependencies", json!(["other", "other"])),
    ];
    for (path, value) in cases {
        let mut task = example("task.web.json");
        *task.pointer_mut(path).unwrap() = value;
        assert!(validate_document("task", task).is_err(), "accepted {path}");
    }
}
#[test]
fn source_requires_immutable_commit() {
    let mut task = example("task.source.json");
    task["target"]["source"]["commit"] = json!("main");
    assert!(validate_document("task", task).is_err());
}
#[test]
fn reject_unknown_fields_and_mixed_target_modes() {
    let mut task = example("task.web.json");
    task["approved"] = json!(true);
    assert!(validate_document("task", task).is_err());
    let mut task = example("task.web.json");
    task["target"]["source"] = example("task.source.json")["target"]["source"].clone();
    assert!(validate_document("task", task).is_err());
    let mut evidence = example("evidence.http.json");
    evidence["confirmed"] = json!(true);
    assert!(validate_document("evidence", evidence).is_err());
}
#[test]
fn attempt_completion_requires_consistent_terminal_fields() {
    let mut attempt = example("attempt.json");
    attempt["finished_at"] = Value::Null;
    assert!(validate_document("attempt", attempt).is_err());
    let mut attempt = example("attempt.json");
    attempt["status"] = json!("running");
    assert!(validate_document("attempt", attempt).is_err());
    let mut attempt = example("attempt.json");
    attempt["lease_generation"] = json!(0);
    assert!(validate_document("attempt", attempt).is_err());
}
#[test]
fn evidence_requires_valid_digest_and_nonempty_artifact() {
    for (path, value) in [
        ("/artifact/sha256", json!("fake")),
        ("/artifact/byte_length", json!(0)),
        ("/expected_property", json!("")),
    ] {
        let mut evidence = example("evidence.http.json");
        *evidence.pointer_mut(path).unwrap() = value;
        assert!(validate_document("evidence", evidence).is_err());
    }
}
#[test]
fn binding_rejects_wrong_run_version_and_budget() {
    let task: TaskSpec = serde_json::from_value(example("task.web.json")).unwrap();
    let good: Evidence = serde_json::from_value(example("evidence.http.json")).unwrap();
    bind_evidence(&task, &good).unwrap();
    for (path, value) in [
        ("/project_id", json!("other")),
        ("/task_id", json!("other")),
        ("/run_id", json!("other")),
        ("/policy_ref", json!("other")),
        ("/payload/observation_id", json!("other")),
        ("/payload/deployment_id", json!("other")),
        ("/artifact/byte_length", json!(1000000)),
        ("/observed_at", json!("2020-01-01T00:00:00Z")),
    ] {
        let mut e = example("evidence.http.json");
        *e.pointer_mut(path).unwrap() = value;
        let e: Evidence = serde_json::from_value(e).unwrap();
        assert!(bind_evidence(&task, &e).is_err(), "bound {path}");
    }
}
#[test]
fn source_evidence_cannot_bind_to_a_web_only_task() {
    let task: TaskSpec = serde_json::from_value(example("task.web.json")).unwrap();
    let mut e = example("evidence.http.json");
    e["payload"] = json!({"kind":"source_trace","snapshot_sha256":"b".repeat(64),"anchors":[{"path":"src/main.go","line_start":1,"line_end":2}]});
    let evidence: Evidence = serde_json::from_value(e.clone()).unwrap();
    evidence.validate().unwrap();
    assert!(bind_evidence(&task, &evidence).is_err());
    e["payload"]["anchors"][0]["path"] = json!("../outside");
    assert!(validate_document("evidence", e).is_err());
}
#[test]
fn digest_checks_actual_artifact() {
    let evidence = example("evidence.http.json");
    let content = fs::read_to_string(root().join("examples/http-sequence.json")).unwrap();
    assert_eq!(
        harness_core::digest(&content),
        evidence["artifact"]["sha256"].as_str().unwrap()
    );
    assert_eq!(
        content.len() as u64,
        evidence["artifact"]["byte_length"].as_u64().unwrap()
    );
    assert_ne!(
        harness_core::digest(&(content + "tampered")),
        evidence["artifact"]["sha256"].as_str().unwrap()
    );
}
#[test]
fn published_schemas_match_rust_contracts() {
    let schemas = harness_core::schemas();
    for kind in ["task", "attempt", "evidence"] {
        let published: Value = serde_json::from_str(
            &fs::read_to_string(root().join(format!("schemas/{kind}.schema.json"))).unwrap(),
        )
        .unwrap();
        assert_eq!(
            published, schemas[kind],
            "regenerate schema after intentional contract changes"
        );
    }
}

#[test]
fn anonymous_browser_observation_defaults_to_no_identities() {
    let payload: harness_core::EvidencePayload = serde_json::from_value(serde_json::json!({
        "kind": "browser_observation",
        "deployment_id": "deployment",
        "observation_id": "observation",
        "browser_version": "test-browser"
    }))
    .unwrap();
    match payload {
        harness_core::EvidencePayload::BrowserObservation { identity_refs, .. } => {
            assert!(identity_refs.is_empty());
        }
        _ => panic!("wrong evidence kind"),
    }
}

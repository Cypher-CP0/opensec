use harness_core::validate_document;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};
#[test]
fn tenant_check_contract_requires_explicit_safe_inputs() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/task.web.json");
    let mut task: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    task["check"] = json!({"kind":"tenant_isolation","identity_a_ref":"tenant-a-reader","identity_b_ref":"tenant-b-reader","tenant_a":"tenant-a","tenant_b":"tenant-b","export_a":"export-a","export_b":"export-b"});
    validate_document("task", task.clone()).unwrap();
    for (path, value) in [
        ("/check/identity_b_ref", json!("tenant-a-reader")),
        ("/check/tenant_b", json!("tenant-a")),
        ("/check/export_b", json!("export-a")),
        ("/check/export_a", json!("../secret")),
        ("/stage", json!("prepare")),
        ("/retry_class", json!("resettable")),
        ("/budget/max_requests", json!(2)),
        ("/budget/max_artifact_bytes", json!(100)),
    ] {
        let mut bad = task.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(validate_document("task", bad).is_err(), "accepted {path}");
    }
    task["check"]["token"] = json!("secret");
    assert!(validate_document("task", task).is_err());
}

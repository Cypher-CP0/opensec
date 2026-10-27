use harness_core::validate_document;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

#[test]
fn preflight_is_read_only_object_controls_with_two_requests() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut task: Value =
        serde_json::from_str(&fs::read_to_string(root.join("examples/task.web.json")).unwrap())
            .unwrap();
    task["check"] = json!({"kind":"object_authorization","identity_a_ref":"a","identity_b_ref":"b",
        "object":{"path_template":"/objects/{id}","resource_a":"a","resource_b":"b","response":{"resource_id":"/id","protected_value":"/private"}}});
    task["stage"] = json!("prepare");
    task["budget"]["max_requests"] = json!(2);
    validate_document("task", task.clone()).unwrap();
    for (path, value) in [
        ("/stage", json!("hunt")),
        ("/stage", json!("validate")),
        ("/stage", json!("recon")),
        ("/budget/max_requests", json!(1)),
        ("/retry_class", json!("resettable")),
    ] {
        let mut bad = task.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(validate_document("task", bad).is_err(), "accepted {path}");
    }
    task["budget"]["max_requests"] = json!(3);
    task["check"] = json!({"kind":"tenant_isolation","identity_a_ref":"a","identity_b_ref":"b",
        "tenant_a":"a","tenant_b":"b","export_a":"a","export_b":"b"});
    assert!(validate_document("task", task).is_err());
}

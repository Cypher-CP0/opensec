use harness_core::{policy::Policy, validate_document};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};
fn policy() -> Policy {
    serde_json::from_value(json!({
        "policy_ref":"local-lab-v1","project_id":"lab-project","allowed_origins":["http://127.0.0.1:8081"],
        "allowed_cidrs":["127.0.0.1/32"],"allow_private":true,"repository_ids":[],"max_input_bytes":1048576,
        "allowed_endpoints":[{"method":"GET","path_template":"/exports/{id}"},{"method":"GET","path_template":"/healthz"}],
        "traffic":{"min_interval_ms":100,"max_concurrent":1,"backoff_seconds":1}
    })).unwrap()
}
#[test]
fn endpoint_scope_is_checked_before_network() {
    let p = policy();
    p.validate().unwrap();
    for path in ["/exports/export-a", "/exports/export-b", "/healthz"] {
        p.authorize_request(&format!("http://127.0.0.1:8081{path}"), "GET")
            .unwrap();
    }
    for path in [
        "/admin",
        "/exports/a/private",
        "/exports/../exports/a",
        "/exports/%61",
        "/exports/a?extra=1",
        "//exports/a",
        "/exports/..",
    ] {
        assert!(
            p.authorize_request(&format!("http://127.0.0.1:8081{path}"), "GET")
                .is_err(),
            "accepted {path}"
        );
    }
    assert!(
        p.authorize_request("http://127.0.0.1:8081/exports/a", "POST")
            .is_err()
    );
}
#[test]
fn tasks_cannot_hide_unapproved_probe_endpoints() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut t: Value =
        serde_json::from_str(&fs::read_to_string(root.join("examples/task.web.json")).unwrap())
            .unwrap();
    t["target"]["web"]["seed_urls"] = json!(["http://127.0.0.1:8081/healthz"]);
    t["check"] = json!({"kind":"tenant_isolation","identity_a_ref":"reader-a","identity_b_ref":"reader-b","tenant_a":"a","tenant_b":"b","export_a":"a","export_b":"b"});
    validate_document("task", t.clone()).unwrap();
    let task = serde_json::from_value(t).unwrap();
    policy().authorize_task(&task).unwrap();
    let mut denied = policy();
    denied
        .allowed_endpoints
        .as_mut()
        .unwrap()
        .retain(|e| e.path_template == "/healthz");
    assert!(denied.authorize_task(&task).is_err());
}
#[test]
fn invalid_rules_and_traffic_limits_fail_closed() {
    let p = policy();
    let base = serde_json::to_value(p).unwrap();
    for (path, value) in [
        ("/traffic/max_concurrent", json!(0)),
        ("/traffic/min_interval_ms", json!(0)),
        ("/traffic/backoff_seconds", json!(301)),
        ("/allowed_endpoints/0/method", json!("TRACE")),
        (
            "/allowed_endpoints/0/path_template",
            json!("/exports/%2f/{id}"),
        ),
        ("/allowed_endpoints", json!([])),
    ] {
        let mut bad = base.clone();
        *bad.pointer_mut(path).unwrap() = value;
        let p: Policy = serde_json::from_value(bad).unwrap();
        assert!(p.validate().is_err(), "accepted {path}");
    }
}

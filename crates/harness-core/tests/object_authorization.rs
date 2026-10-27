use harness_core::validate_document;
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

fn task() -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut t: Value =
        serde_json::from_str(&fs::read_to_string(root.join("examples/task.web.json")).unwrap())
            .unwrap();
    t["check"] = json!({"kind":"object_authorization","identity_a_ref":"reader-a","identity_b_ref":"reader-b",
        "object":{"path_template":"/api/invoices/{id}","resource_a":"invoice-a","resource_b":"invoice-b","owner_a":"account-a","owner_b":"account-b",
            "response":{"resource_id":"/data/id","owner_id":"/data/owner","protected_value":"/data/private"}}});
    t
}
#[test]
fn generic_object_check_is_strict_and_web_only_capable() {
    let t = task();
    validate_document("task", t.clone()).unwrap();
    for (path, value) in [
        ("/check/identity_b_ref", json!("reader-a")),
        ("/check/object/resource_b", json!("invoice-a")),
        ("/check/object/owner_b", json!("account-a")),
        ("/check/object/path_template", json!("//other.test/{id}")),
        ("/check/object/path_template", json!("/api/../{id}")),
        ("/check/object/path_template", json!("/api/%2e/{id}")),
        ("/check/object/path_template", json!("/api/{id}?next=other")),
        ("/check/object/path_template", json!("/api/prefix-{id}")),
        ("/check/object/response/resource_id", json!("/bad~2")),
        ("/check/object/response/protected_value", json!("/data/id")),
        ("/budget/max_requests", json!(2)),
    ] {
        let mut bad = t.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(validate_document("task", bad).is_err(), "accepted {path}");
    }
    let mut mixed = t.clone();
    mixed["check"]["tenant_a"] = json!("unexpected");
    assert!(validate_document("task", mixed).is_err());
    let mut auth = t.clone();
    auth["check"]["object"]["token"] = json!("secret");
    assert!(validate_document("task", auth).is_err());
}
#[test]
fn ownership_selector_is_optional_but_consistent() {
    let mut t = task();
    t["check"]["object"]
        .as_object_mut()
        .unwrap()
        .remove("owner_a");
    assert!(validate_document("task", t.clone()).is_err());
    t["check"]["object"]
        .as_object_mut()
        .unwrap()
        .remove("owner_b");
    t["check"]["object"]["response"]
        .as_object_mut()
        .unwrap()
        .remove("owner_id");
    validate_document("task", t).unwrap();
}

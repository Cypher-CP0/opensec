use harness_core::TaskSpec;
use serde_json::{Value, json};

fn task() -> Value {
    let mut v: Value =
        serde_json::from_str(include_str!("../../../examples/task.hybrid.json")).unwrap();
    v["stage"] = json!("hunt");
    v["retry_class"] = json!("read_only");
    v["budget"]["max_artifact_bytes"] = json!(262144);
    v["budget"]["max_model_tokens"] = json!(10000);
    v["investigator"] =
        json!({"profile_ref":"local-cli","max_steps":6,"paths":["internal/lab/lab.go"]});
    v
}
fn valid(v: Value) -> bool {
    serde_json::from_value::<TaskSpec>(v).is_ok_and(|t| t.validate().is_ok())
}
#[test]
fn investigator_requires_bounded_source_authority() {
    assert!(valid(task()));
    for (field, value) in [
        ("max_steps", json!(0)),
        ("max_steps", json!(13)),
        ("paths", json!([])),
        ("paths", json!(["../secret"])),
        ("paths", json!(["a", "a"])),
        ("paths", json!(["C:/secret"])),
    ] {
        let mut t = task();
        t["investigator"][field] = value;
        assert!(!valid(t));
    }
    let mut t = task();
    t["investigator"]["command"] = json!("shell");
    assert!(!valid(t));
    let mut t = task();
    t["budget"]["max_model_tokens"] = json!(0);
    assert!(!valid(t));
    let mut t = task();
    t["stage"] = json!("validate");
    assert!(!valid(t));
    let mut t = task();
    t["target"]["mode"] = json!("web");
    t["target"].as_object_mut().unwrap().remove("source");
    t["target"].as_object_mut().unwrap().remove("mapping_ref");
    assert!(!valid(t));
}

use harness_core::policy::Policy;
use serde_json::json;

#[test]
fn mutations_require_exact_method_path_query_and_origin() {
    let p: Policy = serde_json::from_value(json!({
        "policy_ref":"lab-policy","project_id":"lab-project",
        "allowed_origins":["http://127.0.0.1:8081"],
        "allowed_cidrs":["127.0.0.1/32"],"allow_private":true,
        "repository_ids":[],"max_input_bytes":1048576,
        "allowed_endpoints":[
            {"method":"GET","path_template":"/objects/{id}"},
            {"method":"POST","path_template":"/objects/{id}","allow_query":true}
        ],
        "traffic":{"min_interval_ms":100,"max_concurrent":1,"backoff_seconds":1}
    }))
    .unwrap();
    p.validate().unwrap();
    p.authorize_request("http://127.0.0.1:8081/objects/one?mode=check", "POST")
        .unwrap();
    for (url, method) in [
        ("http://127.0.0.1:8081/objects/one?mode=check", "GET"),
        ("http://127.0.0.1:8081/objects/one", "DELETE"),
        ("http://127.0.0.1:8081/objects/one/child", "POST"),
        ("http://127.0.0.1:8081/objects/%2e%2e", "POST"),
        ("http://127.0.0.1:8082/objects/one", "POST"),
    ] {
        assert!(p.authorize_request(url, method).is_err(), "{method} {url}");
    }
}

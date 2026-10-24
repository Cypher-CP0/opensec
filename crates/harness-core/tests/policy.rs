use harness_core::policy::Policy;
use serde_json::json;
fn policy(private: bool) -> Policy {
    serde_json::from_value(json!({
        "policy_ref":"local-lab-v1","project_id":"lab-project",
        "allowed_origins":["http://127.0.0.1:8081","https://example.com"],
        "allowed_cidrs":["0.0.0.0/0","::/0"],"allow_private":private,
        "repository_ids":["repo-example"],"max_input_bytes":1048576
    }))
    .unwrap()
}
#[test]
fn origins_and_resolved_ips_are_both_required() {
    let p = policy(false);
    assert!(
        p.authorize_network("https://example.com/a", &["93.184.216.34".into()])
            .is_ok()
    );
    for u in [
        "https://evil.example/a",
        "http://example.com/a",
        "https://example.com:444/a",
        "https://u@example.com/a",
        "https://example.com/#f",
        "https://example.com./a",
        "https://example.com\\@evil.example",
    ] {
        assert!(
            p.authorize_network(u, &["93.184.216.34".into()]).is_err(),
            "{u}"
        );
    }
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "100.100.100.200",
        "::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "64:ff9b::a00:1",
        "2002:7f00:1::1",
    ] {
        assert!(
            p.authorize_network("https://example.com", &[ip.into()])
                .is_err(),
            "{ip}"
        );
    }
    assert!(
        p.authorize_network(
            "https://example.com",
            &["93.184.216.34".into(), "127.0.0.1".into()]
        )
        .is_err()
    );
}
#[test]
fn private_lab_is_explicit_and_metadata_stays_denied() {
    let mut p = policy(true);
    p.allowed_cidrs = vec!["127.0.0.1/32".into()];
    assert!(
        p.authorize_network("http://127.0.0.1:8081/healthz", &["127.0.0.1".into()])
            .is_ok()
    );
    assert!(
        p.authorize_network("http://127.0.0.1:8081", &["127.0.0.2".into()])
            .is_err()
    );
    p.allowed_cidrs = vec!["0.0.0.0/0".into(), "::/0".into()];
    for ip in ["fd00:ec2::254", "168.63.129.16"] {
        assert!(
            p.authorize_network("http://127.0.0.1:8081", &[ip.into()])
                .is_err()
        );
    }
    assert!(
        p.authorize_network("http://127.0.0.1:8081", &["169.254.169.254".into()])
            .is_err()
    );
}
#[test]
fn task_authorization_binds_project_policy_and_repository() {
    let raw = include_str!("../../../examples/task.web.json");
    let mut task: harness_core::TaskSpec = serde_json::from_str(raw).unwrap();
    assert!(policy(true).authorize_task(&task).is_ok());
    task.project_id.0 = "other-project".into();
    assert!(policy(true).authorize_task(&task).is_err());
    let source: harness_core::TaskSpec =
        serde_json::from_str(include_str!("../../../examples/task.source.json")).unwrap();
    let mut p = policy(true);
    p.repository_ids.clear();
    assert!(p.authorize_task(&source).is_err());
}

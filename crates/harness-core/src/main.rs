use harness_core::{Evidence, TaskSpec};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{self, Read};

const MAX_INPUT: u64 = 4 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    ValidatePolicy {
        protocol_version: u8,
        policy: harness_core::policy::Policy,
    },
    AuthorizeTask {
        protocol_version: u8,
        policy: harness_core::policy::Policy,
        task: Box<TaskSpec>,
    },
    AuthorizeNetwork {
        protocol_version: u8,
        policy: harness_core::policy::Policy,
        url: String,
        addresses: Vec<String>,
    },
    Schemas {
        protocol_version: u8,
    },
    Validate {
        protocol_version: u8,
        kind: String,
        document: Value,
    },
    BindEvidence {
        protocol_version: u8,
        task: Box<TaskSpec>,
        evidence: Box<Evidence>,
    },
    VerifyDigest {
        protocol_version: u8,
        sha256: String,
        content: String,
    },
}
fn execute(request: Request) -> Result<Value, String> {
    let version = match &request {
        Request::ValidatePolicy {
            protocol_version, ..
        }
        | Request::AuthorizeTask {
            protocol_version, ..
        }
        | Request::AuthorizeNetwork {
            protocol_version, ..
        }
        | Request::Schemas { protocol_version }
        | Request::Validate {
            protocol_version, ..
        }
        | Request::BindEvidence {
            protocol_version, ..
        }
        | Request::VerifyDigest {
            protocol_version, ..
        } => *protocol_version,
    };
    if version != 1 {
        return Err("unsupported protocol version".into());
    }
    match request {
        Request::ValidatePolicy { policy, .. } => {
            policy.validate()?;
            Ok(json!({"valid":true}))
        }
        Request::AuthorizeTask { policy, task, .. } => {
            policy.authorize_task(&task)?;
            Ok(json!({"allowed":true}))
        }
        Request::AuthorizeNetwork {
            policy,
            url,
            addresses,
            ..
        } => {
            policy.authorize_network(&url, &addresses)?;
            Ok(json!({"allowed":true}))
        }
        Request::Schemas { .. } => Ok(harness_core::schemas()),
        Request::Validate { kind, document, .. } => {
            harness_core::validate_document(&kind, document)?;
            Ok(json!({"kind":kind,"valid":true}))
        }
        Request::BindEvidence { task, evidence, .. } => {
            harness_core::bind_evidence(&task, &evidence)?;
            Ok(json!({"bound":true}))
        }
        Request::VerifyDigest {
            sha256, content, ..
        } => {
            if harness_core::digest(&content) != sha256 {
                return Err("artifact digest mismatch".into());
            }
            Ok(json!({"verified":true,"byte_length":content.len()}))
        }
    }
}
fn main() {
    let mut input = Vec::new();
    let result = io::stdin()
        .take(MAX_INPUT + 1)
        .read_to_end(&mut input)
        .map_err(|e| e.to_string())
        .and_then(|_| {
            if input.len() as u64 > MAX_INPUT {
                Err("request exceeds 4 MiB".into())
            } else {
                Ok(())
            }
        })
        .and_then(|_| serde_json::from_slice::<Request>(&input).map_err(|e| e.to_string()))
        .and_then(execute);
    match result {
        Ok(data) => println!("{}", json!({"protocol_version":1,"ok":true,"data":data})),
        Err(error) => {
            println!("{}", json!({"protocol_version":1,"ok":false,"error":error}));
            std::process::exit(2)
        }
    }
}

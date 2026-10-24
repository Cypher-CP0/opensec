use chrono::{DateTime, Utc};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Id(#[schemars(regex(pattern = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"))] pub String);
impl Id {
    fn validate(&self) -> Result<(), String> {
        let s = self.0.as_bytes();
        if s.is_empty()
            || s.len() > 128
            || !s[0].is_ascii_alphanumeric()
            || !s
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(b))
        {
            return Err("invalid identifier".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct Hash(#[schemars(regex(pattern = "^[0-9a-f]{64}$"))] pub String);
impl Hash {
    fn validate(&self) -> Result<(), String> {
        if self.0.len() != 64
            || !self
                .0
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("digest must contain 64 lowercase hexadecimal characters".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceTarget {
    pub repository_id: Id,
    #[schemars(regex(pattern = "^[0-9a-f]{40}([0-9a-f]{24})?$"))]
    pub commit: String,
    pub snapshot_sha256: Hash,
}
impl SourceTarget {
    fn validate(&self) -> Result<(), String> {
        self.repository_id.validate()?;
        self.snapshot_sha256.validate()?;
        if ![40, 64].contains(&self.commit.len())
            || !self
                .commit
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("source target requires a full immutable Git commit".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebTarget {
    pub deployment_id: Id,
    pub observation_id: Id,
    pub origin: String,
    #[schemars(length(min = 1))]
    pub seed_urls: Vec<String>,
}
fn http_url(s: &str) -> Result<Url, String> {
    let u = Url::parse(s).map_err(|_| "invalid URL")?;
    if !["http", "https"].contains(&u.scheme())
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.fragment().is_some()
    {
        return Err("URL must be HTTP(S), without credentials or a fragment".into());
    }
    Ok(u)
}
impl WebTarget {
    fn validate(&self) -> Result<(), String> {
        self.deployment_id.validate()?;
        self.observation_id.validate()?;
        let origin = http_url(&self.origin)?;
        if origin.path() != "/" || origin.query().is_some() || self.seed_urls.is_empty() {
            return Err("origin must have no path/query and seeds must be nonempty".into());
        }
        for seed in &self.seed_urls {
            if http_url(seed)?.origin() != origin.origin() {
                return Err("seed URL is outside the declared origin".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Source {
        source: SourceTarget,
    },
    Web {
        web: WebTarget,
    },
    Hybrid {
        source: SourceTarget,
        web: WebTarget,
        mapping_ref: Id,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Prepare,
    Recon,
    Hunt,
    Validate,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    ReadOnly,
    Resettable,
    RequiresReconciliation,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    #[schemars(range(min = 1))]
    pub max_wall_seconds: u32,
    pub max_model_tokens: u32,
    pub max_requests: u32,
    #[schemars(range(min = 1))]
    pub max_artifact_bytes: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskSpec {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u8,
    pub task_id: Id,
    pub project_id: Id,
    pub run_id: Id,
    pub investigation_id: Id,
    pub stage: Stage,
    pub target: Target,
    pub policy_ref: Id,
    #[schemars(length(min = 1, max = 4096))]
    pub question: String,
    pub created_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    pub retry_class: RetryClass,
    pub budget: Budget,
    pub dependencies: Vec<Id>,
}
impl TaskSpec {
    pub fn validate(&self) -> Result<(), String> {
        version(self.schema_version)?;
        for id in [
            &self.task_id,
            &self.project_id,
            &self.run_id,
            &self.investigation_id,
            &self.policy_ref,
        ] {
            id.validate()?;
        }
        text(&self.question, 4096)?;
        if self.deadline <= self.created_at {
            return Err("deadline must follow creation".into());
        }
        if self.budget.max_wall_seconds == 0 || self.budget.max_artifact_bytes == 0 {
            return Err("wall-time and artifact limits must be positive".into());
        }
        let mut seen = std::collections::HashSet::new();
        for dependency in &self.dependencies {
            dependency.validate()?;
            if dependency.0 == self.task_id.0 || !seen.insert(&dependency.0) {
                return Err("dependencies cannot repeat or reference the task itself".into());
            }
        }
        match &self.target {
            Target::Source { source } => source.validate()?,
            Target::Web { web } => web.validate()?,
            Target::Hybrid {
                source,
                web,
                mapping_ref,
            } => {
                source.validate()?;
                web.validate()?;
                mapping_ref.validate()?;
            }
        }
        if !matches!(self.target, Target::Source { .. }) && self.budget.max_requests == 0 {
            return Err("web-capable tasks need a request allowance".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    Running,
    Succeeded,
    RetryableFailure,
    BlockedEnvironment,
    NeedsReconciliation,
    Failed,
    Cancelled,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TaskAttempt {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u8,
    pub attempt_id: Id,
    pub task_id: Id,
    #[schemars(range(min = 1))]
    pub lease_generation: u64,
    pub status: AttemptStatus,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub terminal_reason: Option<String>,
}
impl TaskAttempt {
    pub fn validate(&self) -> Result<(), String> {
        version(self.schema_version)?;
        self.attempt_id.validate()?;
        self.task_id.validate()?;
        if self.lease_generation == 0 {
            return Err("lease generation must be positive".into());
        }
        let running = matches!(self.status, AttemptStatus::Running);
        if running {
            if self.finished_at.is_some() || self.terminal_reason.is_some() {
                return Err("running attempt cannot have terminal fields".into());
            }
        } else {
            let finished = self
                .finished_at
                .ok_or("terminal attempt needs finished_at")?;
            if finished < self.started_at {
                return Err("attempt cannot finish before it starts".into());
            }
            text(
                self.terminal_reason
                    .as_deref()
                    .ok_or("terminal attempt needs a reason")?,
                4096,
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub sha256: Hash,
    #[schemars(range(min = 1))]
    pub byte_length: u64,
    pub media_type: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceAnchor {
    pub path: String,
    #[schemars(range(min = 1))]
    pub line_start: u32,
    #[schemars(range(min = 1))]
    pub line_end: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidencePayload {
    SourceTrace {
        snapshot_sha256: Hash,
        anchors: Vec<SourceAnchor>,
    },
    TestExecution {
        snapshot_sha256: Hash,
        test_name: String,
        test_sha256: Hash,
        environment_sha256: Hash,
        exit_code: i32,
    },
    HttpSequence {
        deployment_id: Id,
        observation_id: Id,
        identity_refs: Vec<Id>,
    },
    BrowserObservation {
        deployment_id: Id,
        observation_id: Id,
        identity_refs: Vec<Id>,
        browser_version: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    #[schemars(range(min = 1, max = 1))]
    pub schema_version: u8,
    pub evidence_id: Id,
    pub candidate_id: Id,
    pub project_id: Id,
    pub run_id: Id,
    pub task_id: Id,
    pub task_attempt_id: Id,
    pub policy_ref: Id,
    pub observed_at: DateTime<Utc>,
    pub expected_property: String,
    pub observed_result: String,
    pub redaction_version: Id,
    pub limitations: Vec<String>,
    pub artifact: ArtifactRef,
    pub payload: EvidencePayload,
}
impl Evidence {
    pub fn validate(&self) -> Result<(), String> {
        version(self.schema_version)?;
        for id in [
            &self.evidence_id,
            &self.candidate_id,
            &self.project_id,
            &self.run_id,
            &self.task_id,
            &self.task_attempt_id,
            &self.policy_ref,
            &self.redaction_version,
        ] {
            id.validate()?;
        }
        text(&self.expected_property, 4096)?;
        text(&self.observed_result, 4096)?;
        self.artifact.sha256.validate()?;
        text(&self.artifact.media_type, 128)?;
        if self.artifact.byte_length == 0 {
            return Err("artifact cannot be empty".into());
        }
        match &self.payload {
            EvidencePayload::SourceTrace {
                snapshot_sha256,
                anchors,
            } => {
                snapshot_sha256.validate()?;
                if anchors.is_empty() {
                    return Err("source trace needs anchors".into());
                }
                for a in anchors {
                    if a.path.is_empty()
                        || a.path.contains('\\')
                        || a.path.contains(':')
                        || a.path
                            .split('/')
                            .any(|p| p.is_empty() || p == "." || p == "..")
                        || a.line_start == 0
                        || a.line_end < a.line_start
                    {
                        return Err("invalid relative source anchor".into());
                    }
                }
            }
            EvidencePayload::TestExecution {
                snapshot_sha256,
                test_name,
                test_sha256,
                environment_sha256,
                ..
            } => {
                snapshot_sha256.validate()?;
                test_sha256.validate()?;
                environment_sha256.validate()?;
                text(test_name, 1024)?;
            }
            EvidencePayload::HttpSequence {
                deployment_id,
                observation_id,
                identity_refs,
            }
            | EvidencePayload::BrowserObservation {
                deployment_id,
                observation_id,
                identity_refs,
                ..
            } => {
                deployment_id.validate()?;
                observation_id.validate()?;
                let mut seen = std::collections::HashSet::new();
                for id in identity_refs {
                    id.validate()?;
                    if !seen.insert(&id.0) {
                        return Err("duplicate identity reference".into());
                    }
                }
            }
        }
        if let EvidencePayload::BrowserObservation {
            browser_version, ..
        } = &self.payload
        {
            text(browser_version, 128)?;
        }
        for limitation in &self.limitations {
            text(limitation, 4096)?;
        }
        Ok(())
    }
}

/// Structural/semantic binding only; this does not establish exploitability.
pub fn bind_evidence(task: &TaskSpec, evidence: &Evidence) -> Result<(), String> {
    task.validate()?;
    evidence.validate()?;
    if task.task_id.0 != evidence.task_id.0
        || task.project_id.0 != evidence.project_id.0
        || task.run_id.0 != evidence.run_id.0
        || task.policy_ref.0 != evidence.policy_ref.0
    {
        return Err("evidence does not belong to this task/project/run/policy".into());
    }
    if evidence.observed_at < task.created_at
        || evidence.observed_at > task.deadline
        || evidence.artifact.byte_length > task.budget.max_artifact_bytes
    {
        return Err("evidence exceeds task time or artifact bounds".into());
    }
    let source = match &task.target {
        Target::Source { source } | Target::Hybrid { source, .. } => Some(source),
        _ => None,
    };
    let web = match &task.target {
        Target::Web { web } | Target::Hybrid { web, .. } => Some(web),
        _ => None,
    };
    match &evidence.payload {
        EvidencePayload::SourceTrace {
            snapshot_sha256, ..
        }
        | EvidencePayload::TestExecution {
            snapshot_sha256, ..
        } => {
            if source.is_none_or(|s| s.snapshot_sha256.0 != snapshot_sha256.0) {
                return Err("source snapshot mismatch".into());
            }
        }
        EvidencePayload::HttpSequence {
            deployment_id,
            observation_id,
            ..
        }
        | EvidencePayload::BrowserObservation {
            deployment_id,
            observation_id,
            ..
        } => {
            if web.is_none_or(|w| {
                w.deployment_id.0 != deployment_id.0 || w.observation_id.0 != observation_id.0
            }) {
                return Err("deployment observation mismatch".into());
            }
        }
    }
    Ok(())
}
fn version(v: u8) -> Result<(), String> {
    if v == 1 {
        Ok(())
    } else {
        Err("unsupported schema version".into())
    }
}
fn text(s: &str, max: usize) -> Result<(), String> {
    if s.trim().is_empty() || s.chars().count() > max {
        Err("text must be nonblank and within its length limit".into())
    } else {
        Ok(())
    }
}
pub fn digest(content: &str) -> String {
    format!("{:x}", Sha256::digest(content.as_bytes()))
}

pub fn schemas() -> Value {
    json!({"task":schema_for!(TaskSpec),"attempt":schema_for!(TaskAttempt),"evidence":schema_for!(Evidence)})
}
pub fn validate_document(kind: &str, document: Value) -> Result<(), String> {
    match kind {
        "task" => serde_json::from_value::<TaskSpec>(document)
            .map_err(|e| e.to_string())?
            .validate(),
        "attempt" => serde_json::from_value::<TaskAttempt>(document)
            .map_err(|e| e.to_string())?
            .validate(),
        "evidence" => serde_json::from_value::<Evidence>(document)
            .map_err(|e| e.to_string())?
            .validate(),
        _ => Err("unknown contract kind".into()),
    }
}

pub mod policy;

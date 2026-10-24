CREATE TABLE evidence_records (
 project_id text NOT NULL, run_id text NOT NULL, evidence_id text NOT NULL,
 task_id text NOT NULL, attempt_id text NOT NULL, candidate_id text NOT NULL,
 digest text NOT NULL, byte_length bigint NOT NULL CHECK(byte_length BETWEEN 1 AND 65536),
 record jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(project_id,run_id,evidence_id),
 UNIQUE(project_id,run_id,attempt_id),
 FOREIGN KEY(project_id,run_id,attempt_id) REFERENCES queue_attempts(project_id,run_id,attempt_id),
 FOREIGN KEY(project_id,run_id,task_id) REFERENCES queue_tasks(project_id,run_id,task_id)
);
CREATE TABLE findings (
 project_id text NOT NULL, run_id text NOT NULL, finding_id text NOT NULL,
 status text NOT NULL CHECK(status IN ('pending_validation','confirmed','not_reproduced','inconclusive','unvalidated')),
 origin text NOT NULL, deployment_id text NOT NULL, check_plan jsonb NOT NULL,
 discovery_task_id text NOT NULL, discovery_evidence_id text NOT NULL,
 validation_task_id text, validation_evidence_id text,
 reason text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(project_id,run_id,finding_id),
 FOREIGN KEY(project_id,run_id,discovery_task_id) REFERENCES queue_tasks(project_id,run_id,task_id),
 FOREIGN KEY(project_id,run_id,discovery_evidence_id) REFERENCES evidence_records(project_id,run_id,evidence_id),
 FOREIGN KEY(project_id,run_id,validation_task_id) REFERENCES queue_tasks(project_id,run_id,task_id),
 FOREIGN KEY(project_id,run_id,validation_evidence_id) REFERENCES evidence_records(project_id,run_id,evidence_id),
 UNIQUE(project_id,run_id,validation_task_id)
);
CREATE INDEX findings_status ON findings(project_id,run_id,status,finding_id);

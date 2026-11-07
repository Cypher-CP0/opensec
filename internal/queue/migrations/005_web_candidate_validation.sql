CREATE TABLE web_candidate_validations (
 project_id text NOT NULL, run_id text NOT NULL, candidate_evidence_id text NOT NULL,
 preflight_task_id text NOT NULL, discovery_task_id text NOT NULL,
 finding_id text NOT NULL, request_hash text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(project_id,run_id,candidate_evidence_id),
 UNIQUE(project_id,run_id,preflight_task_id),
 UNIQUE(project_id,run_id,discovery_task_id),
 UNIQUE(project_id,run_id,finding_id),
 FOREIGN KEY(project_id,run_id,candidate_evidence_id) REFERENCES evidence_records(project_id,run_id,evidence_id),
 FOREIGN KEY(project_id,run_id,preflight_task_id) REFERENCES queue_tasks(project_id,run_id,task_id),
 FOREIGN KEY(project_id,run_id,discovery_task_id) REFERENCES queue_tasks(project_id,run_id,task_id)
);
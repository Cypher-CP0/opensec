-- CLI token usage is reported after a call; preserve overage rather than hiding it.
-- Existing charged/reserved counters retain their original constraints.
ALTER TABLE queue_runs ADD COLUMN model_token_overage bigint NOT NULL DEFAULT 0 CHECK(model_token_overage>=0);
CREATE TABLE source_investigations (
 project_id text NOT NULL, run_id text NOT NULL, task_id text NOT NULL, attempt_id text NOT NULL,
 source jsonb NOT NULL, mapping_ref text NOT NULL,
 report jsonb NOT NULL, source_evidence_id text, probe_task_id text, finding_id text,
 schedule_reason text NOT NULL,
 PRIMARY KEY(project_id,run_id,attempt_id),
 UNIQUE(project_id,run_id,probe_task_id),
 FOREIGN KEY(project_id,run_id,attempt_id) REFERENCES queue_attempts(project_id,run_id,attempt_id),
 FOREIGN KEY(project_id,run_id,task_id) REFERENCES queue_tasks(project_id,run_id,task_id),
 FOREIGN KEY(project_id,run_id,probe_task_id) REFERENCES queue_tasks(project_id,run_id,task_id),
 FOREIGN KEY(project_id,run_id,source_evidence_id) REFERENCES evidence_records(project_id,run_id,evidence_id),
 FOREIGN KEY(project_id,run_id,finding_id) REFERENCES findings(project_id,run_id,finding_id)
);
CREATE INDEX source_investigation_findings ON source_investigations(project_id,run_id,finding_id);

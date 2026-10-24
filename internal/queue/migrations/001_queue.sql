CREATE TABLE queue_runs (
 project_id text NOT NULL, run_id text NOT NULL, status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','cancelled','completed','partial')),
 max_tasks bigint NOT NULL CHECK(max_tasks>0), max_attempts bigint NOT NULL CHECK(max_attempts>0),
 limit_bytes bigint NOT NULL CHECK(limit_bytes>=0),
 limit_tokens bigint NOT NULL CHECK(limit_tokens>=0), limit_requests bigint NOT NULL CHECK(limit_requests>=0),
 limit_seconds bigint NOT NULL CHECK(limit_seconds>=0), limit_cost bigint NOT NULL CHECK(limit_cost>=0),
 reserved_bytes bigint NOT NULL DEFAULT 0, charged_bytes bigint NOT NULL DEFAULT 0,
 task_count bigint NOT NULL DEFAULT 0, attempt_count bigint NOT NULL DEFAULT 0,
 reserved_tokens bigint NOT NULL DEFAULT 0, reserved_requests bigint NOT NULL DEFAULT 0,
 reserved_seconds bigint NOT NULL DEFAULT 0, reserved_cost bigint NOT NULL DEFAULT 0,
 charged_tokens bigint NOT NULL DEFAULT 0, charged_requests bigint NOT NULL DEFAULT 0,
 charged_seconds bigint NOT NULL DEFAULT 0, charged_cost bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(project_id,run_id),
 CHECK(reserved_bytes>=0 AND charged_bytes>=0 AND reserved_bytes+charged_bytes<=limit_bytes),
 CHECK(task_count BETWEEN 0 AND max_tasks), CHECK(attempt_count BETWEEN 0 AND max_attempts),
 CHECK(reserved_tokens>=0 AND charged_tokens>=0 AND reserved_tokens+charged_tokens<=limit_tokens),
 CHECK(reserved_requests>=0 AND charged_requests>=0 AND reserved_requests+charged_requests<=limit_requests),
 CHECK(reserved_seconds>=0 AND charged_seconds>=0 AND reserved_seconds+charged_seconds<=limit_seconds),
 CHECK(reserved_cost>=0 AND charged_cost>=0 AND reserved_cost+charged_cost<=limit_cost)
);
CREATE TABLE queue_tasks (
 project_id text NOT NULL, run_id text NOT NULL, task_id text NOT NULL, spec jsonb NOT NULL, fingerprint text NOT NULL,
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed','cancelled','blocked_environment','needs_reconciliation')),
 retry_class text NOT NULL CHECK(retry_class IN ('read_only','resettable','requires_reconciliation')),
 max_attempts integer NOT NULL CHECK(max_attempts BETWEEN 1 AND 100), generation bigint NOT NULL DEFAULT 0,
 reserve_bytes bigint NOT NULL CHECK(reserve_bytes>=0),
 reserve_tokens bigint NOT NULL CHECK(reserve_tokens>=0), reserve_requests bigint NOT NULL CHECK(reserve_requests>=0),
 reserve_seconds bigint NOT NULL CHECK(reserve_seconds>0), reserve_cost bigint NOT NULL CHECK(reserve_cost>=0),
 deadline timestamptz NOT NULL, available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), last_reason text NOT NULL DEFAULT '',
 PRIMARY KEY(project_id,run_id,task_id),
 FOREIGN KEY(project_id,run_id) REFERENCES queue_runs(project_id,run_id),
 CHECK(generation BETWEEN 0 AND max_attempts)
);
CREATE TABLE queue_dependencies (
 project_id text NOT NULL, run_id text NOT NULL, task_id text NOT NULL, depends_on text NOT NULL,
 PRIMARY KEY(project_id,run_id,task_id,depends_on),
 FOREIGN KEY(project_id,run_id,task_id) REFERENCES queue_tasks(project_id,run_id,task_id),
 FOREIGN KEY(project_id,run_id,depends_on) REFERENCES queue_tasks(project_id,run_id,task_id),
 CHECK(task_id<>depends_on)
);
CREATE TABLE queue_attempts (
 project_id text NOT NULL, run_id text NOT NULL, task_id text NOT NULL, attempt_id text NOT NULL,
 generation bigint NOT NULL, worker_id text NOT NULL, token_hash text NOT NULL,
 status text NOT NULL DEFAULT 'running', started_at timestamptz NOT NULL,
 lease_until timestamptz NOT NULL, hard_until timestamptz NOT NULL, finished_at timestamptz,
 reserve_bytes bigint NOT NULL CHECK(reserve_bytes>=0),
 reserve_tokens bigint NOT NULL, reserve_requests bigint NOT NULL, reserve_seconds bigint NOT NULL, reserve_cost bigint NOT NULL,
 used_bytes bigint,
 used_tokens bigint, used_requests bigint, used_seconds bigint, used_cost bigint, usage_uncertain boolean NOT NULL DEFAULT false,
 completion_hash text, next_status text, result jsonb, reason text NOT NULL DEFAULT '',
 PRIMARY KEY(project_id,run_id,attempt_id), UNIQUE(project_id,run_id,task_id,generation),
 FOREIGN KEY(project_id,run_id,task_id) REFERENCES queue_tasks(project_id,run_id,task_id),
 CHECK(lease_until<=hard_until),
 CHECK((status='running' AND finished_at IS NULL) OR (status<>'running' AND finished_at IS NOT NULL))
);
CREATE TABLE queue_events (
 event_id bigserial PRIMARY KEY, project_id text NOT NULL, run_id text NOT NULL, task_id text,
 kind text NOT NULL, details jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(project_id,run_id) REFERENCES queue_runs(project_id,run_id)
);
CREATE INDEX queue_ready ON queue_tasks(project_id,run_id,available_at,created_at) WHERE status='queued';
CREATE INDEX queue_expired ON queue_attempts(project_id,run_id,lease_until) WHERE status='running';


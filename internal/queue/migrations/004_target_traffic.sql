-- Shared target admission spans runs and workers within a project.
CREATE TABLE target_traffic (
 project_id text NOT NULL, origin text NOT NULL,
 min_interval_ms bigint NOT NULL CHECK(min_interval_ms BETWEEN 1 AND 60000),
 max_concurrent bigint NOT NULL CHECK(max_concurrent BETWEEN 1 AND 16),
 backoff_seconds bigint NOT NULL CHECK(backoff_seconds BETWEEN 1 AND 300),
 next_at timestamptz NOT NULL DEFAULT 'epoch',
 cooldown_until timestamptz NOT NULL DEFAULT 'epoch',
 PRIMARY KEY(project_id,origin)
);
CREATE TABLE traffic_permits (
 project_id text NOT NULL, run_id text NOT NULL, attempt_id text NOT NULL, request_id text NOT NULL,
 origin text NOT NULL, url_hash text NOT NULL,
 acquired_at timestamptz NOT NULL, expires_at timestamptz NOT NULL,
 released_at timestamptz, response_status integer,
 PRIMARY KEY(project_id,run_id,attempt_id,request_id),
 FOREIGN KEY(project_id,run_id,attempt_id) REFERENCES queue_attempts(project_id,run_id,attempt_id),
 FOREIGN KEY(project_id,origin) REFERENCES target_traffic(project_id,origin),
 CHECK(expires_at>acquired_at),
 CHECK(response_status IS NULL OR response_status=0 OR response_status BETWEEN 100 AND 599),
 CHECK((released_at IS NULL)=(response_status IS NULL))
);
CREATE INDEX traffic_active ON traffic_permits(project_id,origin,expires_at) WHERE released_at IS NULL;

//go:build integration

package queue

import (
	"bytes"
	"encoding/json"
	"testing"

	"example.com/unified-harness/internal/testdb"
)

func TestEvidenceMigrationUpgradesExistingQueue(t *testing.T) {
	ctx := t.Context()
	s, err := Open(ctx, testdb.New(t), CoreValidator{Binary: testdb.Core()}, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.pool.Exec(ctx, "CREATE TABLE harness_migrations(version integer PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())"); err != nil {
		t.Fatal(err)
	}
	// Simulate the already-pushed milestone, then upgrade without rewriting 001/002.
	for i, name := range []string{"migrations/001_queue.sql", "migrations/002_evidence.sql"} {
		raw, err := migrations.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.pool.Exec(ctx, string(raw)); err != nil {
			t.Fatal(err)
		}
		normalized := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
		if _, err = s.pool.Exec(ctx, "INSERT INTO harness_migrations(version,checksum) VALUES($1,$2)", i+1, hash(normalized)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.pool.Exec(ctx, `INSERT INTO queue_runs(project_id,run_id,max_tasks,max_attempts,limit_bytes,limit_tokens,limit_requests,limit_seconds,limit_cost) VALUES($1,$2,10,30,1000000,10000,100,3600,0)`, project, runID); err != nil {
		t.Fatal(err)
	}
	raw := testdb.Task(t, "web", "existing-task", "read_only")
	var spec specProjection
	if err = json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, `INSERT INTO queue_tasks(project_id,run_id,task_id,spec,fingerprint,retry_class,max_attempts,reserve_bytes,reserve_tokens,reserve_requests,reserve_seconds,reserve_cost,deadline) VALUES($1,$2,$3,$4,'old-fingerprint','read_only',3,65536,100,10,60,0,$5)`, project, runID, spec.TaskID, raw, spec.Deadline); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err = s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	task, err := s.GetTask(ctx, project, runID, "existing-task")
	if err != nil || task.Status != "queued" {
		t.Fatal(task, err)
	}
	run, err := s.GetRun(ctx, project, runID)
	if err != nil || run.ModelTokenOverage != 0 {
		t.Fatal(run, err)
	}
	var count int
	if err = s.pool.QueryRow(ctx, "SELECT count(*) FROM harness_migrations").Scan(&count); err != nil || count != 3 {
		t.Fatal(count, err)
	}
}

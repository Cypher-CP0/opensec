//go:build integration

package queue

import (
	"bytes"
	"example.com/unified-harness/internal/testdb"
	"testing"
)

func TestEvidenceMigrationUpgradesExistingQueue(t *testing.T) {
	ctx := t.Context()
	s, err := Open(ctx, testdb.New(t), CoreValidator{Binary: testdb.Core()}, DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw, err := migrations.ReadFile("migrations/001_queue.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, string(raw)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.pool.Exec(ctx, "CREATE TABLE harness_migrations(version integer PRIMARY KEY,checksum text NOT NULL,applied_at timestamptz NOT NULL DEFAULT clock_timestamp())"); err != nil {
		t.Fatal(err)
	}
	// Embedded migrations may use CRLF on Windows; the ledger uses normalized bytes.
	normalized := []byte(string(raw))
	normalized = bytes.ReplaceAll(normalized, []byte("\r\n"), []byte("\n"))
	if _, err = s.pool.Exec(ctx, "INSERT INTO harness_migrations(version,checksum) VALUES(1,$1)", hash(normalized)); err != nil {
		t.Fatal(err)
	}
	if err = s.CreateRun(ctx, config()); err != nil {
		t.Fatal(err)
	}
	if err = s.Enqueue(ctx, testdb.Task(t, "web", "existing-task", "read_only"), EnqueueOptions{MaxAttempts: 3}); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	task, err := s.GetTask(ctx, project, runID, "existing-task")
	if err != nil || task.Status != "queued" {
		t.Fatal(task, err)
	}
	var count int
	if err = s.pool.QueryRow(ctx, "SELECT count(*) FROM harness_migrations").Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
}

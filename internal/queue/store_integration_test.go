//go:build integration

package queue

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"example.com/unified-harness/internal/testdb"
)

const project = "lab-project"
const runID = "run-test"

func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func expect(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
func config() RunConfig {
	return RunConfig{ProjectID: project, RunID: runID, MaxTasks: 100, MaxAttempts: 100, Limits: Units{Tokens: 100000, Requests: 10000, WallSeconds: 100000, CostMicrousd: 100000, ArtifactBytes: 10000000}}
}
func setup(t *testing.T, c RunConfig) (*Store, string) {
	t.Helper()
	dsn := testdb.New(t)
	s, err := Open(t.Context(), dsn, CoreValidator{testdb.Core()}, Settings{30 * time.Second, 10 * time.Second, 30 * time.Second})
	check(t, err)
	t.Cleanup(s.Close)
	check(t, s.Migrate(t.Context()))
	check(t, s.CreateRun(t.Context(), c))
	return s, dsn
}
func enqueue(t *testing.T, s *Store, id, retry string, maxAttempts int, deps ...string) json.RawMessage {
	t.Helper()
	raw := testdb.Task(t, "web", id, retry, deps...)
	check(t, s.Enqueue(t.Context(), raw, EnqueueOptions{MaxAttempts: maxAttempts, CostMicrousd: 50}))
	return raw
}
func claim(t *testing.T, s *Store) Lease {
	t.Helper()
	l, err := s.Claim(t.Context(), project, runID, "worker-one")
	check(t, err)
	return l
}
func finish(t *testing.T, s *Store, l Lease, outcome string, usage *Units) string {
	t.Helper()
	status, err := s.Finish(t.Context(), l, Completion{Outcome: outcome, Reason: "test observation", Usage: usage})
	check(t, err)
	return status
}
func task(t *testing.T, s *Store, id string) Task {
	t.Helper()
	value, err := s.GetTask(t.Context(), project, runID, id)
	check(t, err)
	return value
}
func budget(t *testing.T, s *Store) Run {
	t.Helper()
	r, err := s.GetRun(t.Context(), project, runID)
	check(t, err)
	return r
}
func sql(t *testing.T, s *Store, query string, args ...any) {
	t.Helper()
	_, err := s.pool.Exec(t.Context(), query, args...)
	check(t, err)
}
func makeReady(t *testing.T, s *Store, id string) {
	t.Helper()
	sql(t, s, "UPDATE queue_tasks SET available_at=clock_timestamp() WHERE project_id=$1 AND run_id=$2 AND task_id=$3", project, runID, id)
}
func expire(t *testing.T, s *Store, l Lease) {
	t.Helper()
	sql(t, s, "UPDATE queue_attempts SET lease_until=clock_timestamp()-interval '1 second' WHERE attempt_id=$1", l.AttemptID)
}
func capUnits() Units {
	return Units{Tokens: 100, Requests: 10, WallSeconds: 60, CostMicrousd: 50, ArtifactBytes: 65536}
}
func assertLedger(t *testing.T, s *Store) {
	t.Helper()
	r := budget(t, s)
	var running, charged Units
	check(t, s.pool.QueryRow(t.Context(), "SELECT COALESCE(sum(reserve_tokens) FILTER(WHERE status='running'),0),COALESCE(sum(reserve_requests) FILTER(WHERE status='running'),0),COALESCE(sum(reserve_seconds) FILTER(WHERE status='running'),0),COALESCE(sum(reserve_cost) FILTER(WHERE status='running'),0),COALESCE(sum(reserve_bytes) FILTER(WHERE status='running'),0),COALESCE(sum(used_tokens),0),COALESCE(sum(used_requests),0),COALESCE(sum(used_seconds),0),COALESCE(sum(used_cost),0),COALESCE(sum(used_bytes),0) FROM queue_attempts WHERE project_id=$1 AND run_id=$2", project, runID).Scan(&running.Tokens, &running.Requests, &running.WallSeconds, &running.CostMicrousd, &running.ArtifactBytes, &charged.Tokens, &charged.Requests, &charged.WallSeconds, &charged.CostMicrousd, &charged.ArtifactBytes))
	if running != r.Reserved || charged != r.Charged {
		t.Fatalf("ledger mismatch: run=%+v running=%+v charged=%+v", r, running, charged)
	}
}

func TestMigrationsAdmissionAndIdempotency(t *testing.T) {
	c := config()
	c.MaxTasks = 2
	s, _ := setup(t, c)
	ctx := t.Context()
	check(t, s.Migrate(ctx))
	check(t, s.CreateRun(ctx, c))
	changed := c
	changed.MaxTasks++
	expect(t, s.CreateRun(ctx, changed), ErrConflict)
	raw := enqueue(t, s, "one", "read_only", 3)
	check(t, s.Enqueue(ctx, raw, EnqueueOptions{3, 50}))
	expect(t, s.Enqueue(ctx, raw, EnqueueOptions{2, 50}), ErrConflict)
	altered := testdb.Change(t, raw, "question", "different question")
	expect(t, s.Enqueue(ctx, altered, EnqueueOptions{3, 50}), ErrConflict)
	invalid := testdb.Change(t, raw, "unknown_field", true)
	if err := s.Enqueue(ctx, invalid, EnqueueOptions{3, 50}); err == nil {
		t.Fatal("Rust core did not reject unknown task field")
	}
	bad := testdb.Task(t, "web", "missing-dep", "read_only", "not-present")
	if err := s.Enqueue(ctx, bad, EnqueueOptions{3, 50}); err == nil {
		t.Fatal("missing prerequisite accepted")
	}
	enqueue(t, s, "two", "read_only", 1, "one")
	expect(t, s.Enqueue(ctx, testdb.Task(t, "web", "three", "read_only"), EnqueueOptions{1, 0}), ErrBudget)
	if budget(t, s).TaskCount != 2 {
		t.Fatal("idempotent admission consumed quota")
	}
	if err := s.CloseRun(ctx, project, runID); err == nil {
		t.Fatal("closed with pending tasks")
	}
	l := claim(t, s)
	if l.TaskID != "one" {
		t.Fatal("dependent task claimed first")
	}
	_, err := s.Claim(ctx, project, runID, "other")
	expect(t, err, ErrNoWork)
	finish(t, s, l, "succeeded", &Units{})
	l = claim(t, s)
	if l.TaskID != "two" {
		t.Fatal("dependent task not unblocked")
	}
	finish(t, s, l, "succeeded", &Units{})
	check(t, s.CloseRun(ctx, project, runID))
	check(t, s.CloseRun(ctx, project, runID))
	if budget(t, s).Status != "completed" {
		t.Fatal("run not completed")
	}
	check(t, s.Enqueue(ctx, raw, EnqueueOptions{3, 50})) // Exact replay still works after close.
	_, err = s.Claim(ctx, project, runID, "other")
	expect(t, err, ErrRunClosed)
	sql(t, s, "UPDATE harness_migrations SET checksum='tampered' WHERE version=1")
	if err = s.Migrate(ctx); err == nil {
		t.Fatal("migration drift accepted")
	}
	assertLedger(t, s)
}

func TestAllTargetModesPersist(t *testing.T) {
	s, _ := setup(t, config())
	for _, mode := range []string{"source", "web", "hybrid"} {
		raw := testdb.Task(t, mode, mode, "read_only")
		check(t, s.Enqueue(t.Context(), raw, EnqueueOptions{2, 50}))
		l := claim(t, s)
		original, err := canonical(raw)
		check(t, err)
		persisted, err := canonical(l.Spec)
		check(t, err)
		if string(original) != string(persisted) {
			t.Fatal("task target or other contract fields changed")
		}
		finish(t, s, l, "succeeded", &Units{})
	}
	assertLedger(t, s)
}
func TestConcurrentClaimsAndBudgetLimits(t *testing.T) {
	for _, dimension := range []string{"tokens", "requests", "wall", "cost", "artifacts"} {
		t.Run(dimension, func(t *testing.T) {
			c := config()
			switch dimension {
			case "tokens":
				c.Limits.Tokens = 200
			case "requests":
				c.Limits.Requests = 20
			case "wall":
				c.Limits.WallSeconds = 120
			case "cost":
				c.Limits.CostMicrousd = 100
			case "artifacts":
				c.Limits.ArtifactBytes = 131072
			}
			s, _ := setup(t, c)
			for i := 0; i < 10; i++ {
				enqueue(t, s, fmt.Sprintf("task-%02d", i), "read_only", 2)
			}
			results := make(chan Lease, 20)
			failures := make(chan error, 20)
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					l, err := s.Claim(t.Context(), project, runID, fmt.Sprintf("worker-%d", i))
					if err == nil {
						results <- l
					} else if !errors.Is(err, ErrBudget) {
						failures <- err
					}
				}(i)
			}
			wg.Wait()
			close(results)
			close(failures)
			for err := range failures {
				t.Error(err)
			}
			var leases []Lease
			seen := map[string]bool{}
			for l := range results {
				if seen[l.TaskID] {
					t.Fatal("two workers own the same task")
				}
				seen[l.TaskID] = true
				leases = append(leases, l)
			}
			if len(leases) != 2 {
				t.Fatalf("claimed %d tasks, want 2", len(leases))
			}
			r := budget(t, s)
			if r.AttemptCount != 2 {
				t.Fatalf("attempt count = %d", r.AttemptCount)
			}
			assertLedger(t, s)
			tooMuch := capUnits()
			tooMuch.ArtifactBytes++
			_, err := s.Finish(t.Context(), leases[0], Completion{Outcome: "succeeded", Reason: "invalid usage", Usage: &tooMuch})
			if err == nil {
				t.Fatal("usage exceeding reservation accepted")
			}
			if budget(t, s) != r {
				t.Fatal("rejected completion mutated accounting")
			}
			finish(t, s, leases[0], "succeeded", &Units{})
			claim(t, s) // Unused reservation can be reused by another task.
			_, err = s.Claim(t.Context(), project, runID, "cannot-fit")
			expect(t, err, ErrBudget)
			assertLedger(t, s)
		})
	}
}
func TestOneTaskHasOneOwnerAndProjectIsolation(t *testing.T) {
	s, _ := setup(t, config())
	enqueue(t, s, "single", "read_only", 3)
	var wg sync.WaitGroup
	results := make(chan error, 24)
	leases := make(chan Lease, 24)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, err := s.Claim(t.Context(), project, runID, "worker")
			results <- err
			if err == nil {
				leases <- l
			}
		}()
	}
	wg.Wait()
	close(results)
	close(leases)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			expect(t, err, ErrNoWork)
		}
	}
	if successes != 1 {
		t.Fatalf("%d successful claims", successes)
	}
	l := <-leases
	c := config()
	c.ProjectID = "other-project"
	check(t, s.CreateRun(t.Context(), c))
	_, err := s.GetTask(t.Context(), c.ProjectID, runID, l.TaskID)
	expect(t, err, ErrNotFound)
	forged := l
	forged.ProjectID = c.ProjectID
	_, err = s.Heartbeat(t.Context(), forged)
	expect(t, err, ErrLease)
	forged = l
	forged.Token = "wrong"
	_, err = s.Heartbeat(t.Context(), forged)
	expect(t, err, ErrLease)
	forged = l
	forged.WorkerID = "impostor"
	_, err = s.Finish(t.Context(), forged, Completion{Outcome: "succeeded", Reason: "forged"})
	expect(t, err, ErrLease)
	if budget(t, s).AttemptCount != 1 {
		t.Fatal("claim contention spent attempts")
	}
	assertLedger(t, s)
}
func TestAttemptLimit(t *testing.T) {
	c := config()
	c.MaxAttempts = 1
	s, _ := setup(t, c)
	enqueue(t, s, "one", "read_only", 3)
	l := claim(t, s)
	if finish(t, s, l, "retryable_failure", &Units{}) != "queued" {
		t.Fatal("not queued")
	}
	makeReady(t, s, "one")
	_, err := s.Claim(t.Context(), project, runID, "worker")
	expect(t, err, ErrBudget)
	assertLedger(t, s)
}

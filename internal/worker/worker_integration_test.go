//go:build integration

package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

func fixture(t *testing.T) (*queue.Store, string) {
	t.Helper()
	dsn := testdb.New(t)
	s, err := queue.Open(t.Context(), dsn, queue.CoreValidator{Binary: testdb.Core()}, queue.Settings{LeaseDuration: 400 * time.Millisecond, RetryBase: time.Second, RetryMax: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err = s.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = s.CreateRun(t.Context(), queue.RunConfig{ProjectID: "lab-project", RunID: "run-test", MaxTasks: 10, MaxAttempts: 10, Limits: queue.Units{Tokens: 1000, Requests: 100, WallSeconds: 1000, CostMicrousd: 1000, ArtifactBytes: 1000000}}); err != nil {
		t.Fatal(err)
	}
	if err = s.Enqueue(t.Context(), testdb.Task(t, "web", "work", "read_only"), queue.EnqueueOptions{MaxAttempts: 3}); err != nil {
		t.Fatal(err)
	}
	return s, dsn
}
func instance(s *queue.Store) Worker {
	return Worker{Store: s, ProjectID: "lab-project", RunID: "run-test", WorkerID: "test-worker", HeartbeatEvery: 40 * time.Millisecond}
}

func TestWorkerRenewsDuringLongHandler(t *testing.T) {
	s, _ := fixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	status, err := instance(s).RunOnce(ctx, func(ctx context.Context, l queue.Lease) queue.Completion {
		select {
		case <-ctx.Done():
			t.Error("handler lost lease despite heartbeats", ctx.Err())
		case <-time.After(time.Second):
		}
		return queue.Completion{Outcome: "succeeded", Reason: "handler finished", Usage: &queue.Units{Requests: 2, WallSeconds: 1}}
	})
	if err != nil {
		t.Fatal(err)
	}
	if status != "succeeded" {
		t.Fatal(status)
	}
	r, err := s.GetRun(ctx, "lab-project", "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Reserved != (queue.Units{}) || r.Charged.Requests != 2 {
		t.Fatal("handler result not settled")
	}
}

func TestWorkerStopsWhenCancelled(t *testing.T) {
	s, _ := fixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err := instance(s).RunOnce(ctx, func(ctx context.Context, l queue.Lease) queue.Completion {
		if err := s.Cancel(ctx, l.ProjectID, l.RunID, l.TaskID, "stop worker test"); err != nil {
			t.Error(err)
		}
		<-ctx.Done()
		return queue.Completion{Outcome: "succeeded", Reason: "must not publish"}
	})
	if !errors.Is(err, queue.ErrLease) {
		t.Fatalf("expected revoked lease, got %v", err)
	}
	state, err := s.GetTask(ctx, "lab-project", "run-test", "work")
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "cancelled" {
		t.Fatal("cancelled result overwritten")
	}
}

func TestWorkerStopsIfRenewalIsBlocked(t *testing.T) {
	s, dsn := fixture(t)
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = instance(s).RunOnce(ctx, func(execution context.Context, l queue.Lease) queue.Completion {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if _, err = tx.Exec(ctx, "SELECT run_id FROM queue_runs WHERE project_id=$1 AND run_id=$2 FOR UPDATE", l.ProjectID, l.RunID); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		<-execution.Done()
		if time.Since(start) > 2*time.Second {
			t.Error("blocked renewal waited beyond lease expiry")
		}
		return queue.Completion{Outcome: "succeeded", Reason: "must not publish"}
	})
	if err == nil {
		t.Fatal("published despite unconfirmed lease renewal")
	}
	state, err := s.GetTask(ctx, "lab-project", "run-test", "work")
	if err != nil {
		t.Fatal(err)
	}
	if state.Status != "running" {
		t.Fatal("worker published stale result")
	}
	if _, err = s.Reap(ctx, "lab-project", "run-test"); err != nil {
		t.Fatal(err)
	}
	r, err := s.GetRun(ctx, "lab-project", "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Reserved != (queue.Units{}) || r.Charged.Requests != 10 {
		t.Fatal("lost worker budget not settled")
	}
}

func TestWorkerPollingStopsOnClosedRun(t *testing.T) {
	s, _ := fixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	calls := 0
	err := instance(s).Run(ctx, 10*time.Millisecond, func(execution context.Context, l queue.Lease) queue.Completion {
		calls++
		if err := s.Cancel(execution, l.ProjectID, l.RunID, "", "stop poller"); err != nil {
			t.Error(err)
		}
		<-execution.Done()
		return queue.Completion{Outcome: "failed", Reason: "cancelled"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("handler called %d times", calls)
	}
}

//go:build integration

package queue

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"example.com/unified-harness/internal/testdb"
)

func TestLeaseExpiryRecoveryAndCoordinatorRestart(t *testing.T) {
	s, dsn := setup(t, config())
	ctx := t.Context()
	enqueue(t, s, "recover", "read_only", 3)
	original := claim(t, s)
	renewed, err := s.Heartbeat(ctx, original)
	check(t, err)
	if renewed.Before(original.ExpiresAt) || renewed.After(original.HardDeadline) {
		t.Fatal("invalid renewal bounds")
	}
	s.Close() // Reconnect through a separate pool: no scheduling state lives in Go.
	s, err = Open(ctx, dsn, CoreValidator{testdb.Core()}, Settings{2 * time.Second, 10 * time.Second, 30 * time.Second})
	check(t, err)
	t.Cleanup(s.Close)
	if task(t, s, "recover").Status != "running" {
		t.Fatal("task did not survive restart")
	}
	expire(t, s, original)
	_, err = s.Heartbeat(ctx, original)
	expect(t, err, ErrLease)
	_, err = s.Finish(ctx, original, Completion{Outcome: "succeeded", Reason: "late result", Usage: &Units{}})
	expect(t, err, ErrLease)
	n, err := s.Reap(ctx, project, runID)
	check(t, err)
	if n != 1 {
		t.Fatalf("reaped %d", n)
	}
	if budget(t, s).Charged != capUnits() || budget(t, s).Reserved != (Units{}) {
		t.Fatal("unknown spend was not conservatively settled")
	}
	var uncertain bool
	check(t, s.pool.QueryRow(ctx, "SELECT usage_uncertain FROM queue_attempts WHERE attempt_id=$1", original.AttemptID).Scan(&uncertain))
	if !uncertain {
		t.Fatal("unknown spend was reported as measured")
	}
	n, err = s.Reap(ctx, project, runID)
	check(t, err)
	if n != 0 {
		t.Fatal("expired attempt was settled twice")
	}
	_, err = s.Claim(ctx, project, runID, "too-early")
	expect(t, err, ErrNoWork)
	makeReady(t, s, "recover")
	fresh := claim(t, s)
	if fresh.Generation != 2 || fresh.AttemptID == original.AttemptID || fresh.Token == original.Token {
		t.Fatal("replacement did not fence old lease")
	}
	_, err = s.Heartbeat(ctx, original)
	expect(t, err, ErrLease)
	_, err = s.Finish(ctx, original, Completion{Outcome: "failed", Reason: "stale owner"})
	expect(t, err, ErrLease)
	finish(t, s, fresh, "succeeded", &Units{Requests: 2, WallSeconds: 1, ArtifactBytes: 123})
	assertLedger(t, s)
}

func TestCompletionReplayAndRetryBackoff(t *testing.T) {
	s, _ := setup(t, config())
	ctx := t.Context()
	enqueue(t, s, "retries", "read_only", 3)
	completion := Completion{Outcome: "retryable_failure", Reason: "transient failure", Usage: &Units{Requests: 1}, Result: json.RawMessage(`{"b":2,"a":1}`)}
	first := claim(t, s)
	status, err := s.Finish(ctx, first, completion)
	check(t, err)
	if status != "queued" {
		t.Fatal(status)
	}
	after := budget(t, s)
	replay := completion
	replay.Result = json.RawMessage(`{ "a": 1, "b": 2 }`)
	_, err = s.Finish(ctx, first, replay)
	check(t, err)
	if budget(t, s) != after {
		t.Fatal("duplicate acknowledgement charged usage twice")
	}
	altered := completion
	altered.Reason = "different failure"
	_, err = s.Finish(ctx, first, altered)
	expect(t, err, ErrConflict)
	queued := task(t, s, "retries")
	if queued.AvailableAt.Before(time.Now().Add(8 * time.Second)) {
		t.Fatal("missing initial backoff")
	}
	makeReady(t, s, "retries")
	second := claim(t, s)
	// An acknowledgement may be retried after the replacement has started.
	receipt, err := s.Finish(ctx, first, replay)
	check(t, err)
	if receipt != "queued" {
		t.Fatal(receipt)
	}
	if task(t, s, "retries").Status != "running" || task(t, s, "retries").Generation != 2 {
		t.Fatal("old acknowledgement modified new attempt")
	}
	finish(t, s, second, "retryable_failure", &Units{})
	if task(t, s, "retries").AvailableAt.Before(time.Now().Add(18 * time.Second)) {
		t.Fatal("backoff did not increase")
	}
	makeReady(t, s, "retries")
	third := claim(t, s)
	if finish(t, s, third, "retryable_failure", &Units{}) != "failed" {
		t.Fatal("attempt cap did not terminate retries")
	}
	_, err = s.Claim(ctx, project, runID, "worker")
	expect(t, err, ErrNoWork)
	check(t, s.CloseRun(ctx, project, runID))
	if budget(t, s).Status != "partial" {
		t.Fatal("failed work incorrectly marked completed")
	}
	assertLedger(t, s)
}

func TestUnsafeRetriesAndBlockedTasksRequireOperator(t *testing.T) {
	for _, retry := range []string{"resettable", "requires_reconciliation"} {
		t.Run(retry, func(t *testing.T) {
			s, _ := setup(t, config())
			ctx := t.Context()
			enqueue(t, s, "mutating", retry, 3)
			l := claim(t, s)
			expire(t, s, l)
			_, err := s.Reap(ctx, project, runID)
			check(t, err)
			if task(t, s, "mutating").Status != "needs_reconciliation" {
				t.Fatal("unsafe attempt was retried automatically")
			}
			_, err = s.Claim(ctx, project, runID, "worker")
			expect(t, err, ErrNoWork)
			if err = s.Resume(ctx, project, runID, "mutating", "operator looked", false); err == nil {
				t.Fatal("missing reconciliation assertion accepted")
			}
			check(t, s.Resume(ctx, project, runID, "mutating", "fixture reset verified", true))
			l = claim(t, s)
			if finish(t, s, l, "blocked_environment", &Units{}) != "blocked_environment" {
				t.Fatal("lost environment failure classification")
			}
			if err = s.Resume(ctx, project, runID, "mutating", "environment fixed", false); err == nil {
				t.Fatal("unsafe blocked attempt resumed without reconciliation")
			}
			check(t, s.Resume(ctx, project, runID, "mutating", "state and environment fixed", true))
			l = claim(t, s)
			finish(t, s, l, "blocked_environment", &Units{})
			if err = s.Resume(ctx, project, runID, "mutating", "fixed again", true); err == nil {
				t.Fatal("operator bypassed attempt limit")
			}
			assertLedger(t, s)
		})
	}
	t.Run("read-only-environment", func(t *testing.T) {
		s, _ := setup(t, config())
		enqueue(t, s, "blocked", "read_only", 2)
		finish(t, s, claim(t, s), "blocked_environment", &Units{})
		check(t, s.Resume(t.Context(), project, runID, "blocked", "credentials repaired", false))
		finish(t, s, claim(t, s), "succeeded", &Units{})
	})
}

func TestCancellationRevokesLeasesAndSettlesOnce(t *testing.T) {
	for _, wholeRun := range []bool{false, true} {
		t.Run(map[bool]string{false: "task", true: "run"}[wholeRun], func(t *testing.T) {
			s, _ := setup(t, config())
			ctx := t.Context()
			enqueue(t, s, "active", "read_only", 3)
			enqueue(t, s, "waiting", "read_only", 3, "active")
			l := claim(t, s)
			target := "active"
			if wholeRun {
				target = ""
			}
			check(t, s.Cancel(ctx, project, runID, target, "operator stopped execution"))
			after := budget(t, s)
			check(t, s.Cancel(ctx, project, runID, target, "same cancellation retried"))
			if budget(t, s) != after {
				t.Fatal("cancellation double charged")
			}
			if after.Reserved != (Units{}) || after.Charged != capUnits() {
				t.Fatal("cancellation accounting incorrect")
			}
			if task(t, s, "active").Status != "cancelled" {
				t.Fatal("active task was not cancelled")
			}
			_, err := s.Heartbeat(ctx, l)
			expect(t, err, ErrLease)
			_, err = s.Finish(ctx, l, Completion{Outcome: "succeeded", Reason: "post-cancel"})
			expect(t, err, ErrLease)
			if wholeRun {
				if after.Status != "cancelled" || task(t, s, "waiting").Status != "cancelled" {
					t.Fatal("run cancellation left pending task")
				}
				_, err = s.Claim(ctx, project, runID, "worker")
				expect(t, err, ErrRunClosed)
				expect(t, s.Enqueue(ctx, testdb.Task(t, "web", "new", "read_only"), EnqueueOptions{1, 0}), ErrRunClosed)
			} else {
				if after.Status != "active" {
					t.Fatal("task cancellation closed run")
				}
				_, err = s.Reap(ctx, project, runID)
				check(t, err)
				if task(t, s, "waiting").Status != "failed" {
					t.Fatal("cancelled prerequisite did not propagate")
				}
				check(t, s.CloseRun(ctx, project, runID))
				if budget(t, s).Status != "partial" {
					t.Fatal("cancelled work marked successful")
				}
			}
			assertLedger(t, s)
		})
	}
}

func TestCancelFinishRaceIsAtomic(t *testing.T) {
	s, _ := setup(t, config())
	ctx := t.Context()
	for i := 0; i < 10; i++ {
		id := randomID()
		enqueue(t, s, id, "read_only", 1)
		l := claim(t, s)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		errs := make(chan error, 2)
		go func() { defer wg.Done(); <-start; errs <- s.Cancel(ctx, project, runID, id, "race") }()
		go func() {
			defer wg.Done()
			<-start
			_, err := s.Finish(ctx, l, Completion{Outcome: "succeeded", Reason: "race", Usage: &Units{Requests: 1}})
			errs <- err
		}()
		close(start)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil && !errors.Is(err, ErrLease) {
				t.Fatal(err)
			}
		}
		status := task(t, s, id).Status
		if status != "succeeded" && status != "cancelled" {
			t.Fatalf("nonterminal state after race: %s", status)
		}
		assertLedger(t, s)
	}
}
func TestDeadlinesAndDependencyFailure(t *testing.T) {
	s, _ := setup(t, config())
	ctx := t.Context()
	expired := testdb.Change(t, testdb.Task(t, "web", "expired", "read_only"), "deadline", time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano))
	if err := s.Enqueue(ctx, expired, EnqueueOptions{1, 0}); err == nil {
		t.Fatal("expired admission accepted")
	}
	future := testdb.Change(t, testdb.Task(t, "web", "future", "read_only"), "created_at", time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano))
	if err := s.Enqueue(ctx, future, EnqueueOptions{1, 0}); err == nil {
		t.Fatal("future creation accepted")
	}
	enqueue(t, s, "parent", "read_only", 2)
	enqueue(t, s, "child", "read_only", 2, "parent")
	enqueue(t, s, "grandchild", "read_only", 2, "child")
	l := claim(t, s)
	// Move both deadlines to the database's past without sleeps.
	sql(t, s, "UPDATE queue_tasks SET deadline=clock_timestamp()-interval '1 second' WHERE task_id='parent'")
	expire(t, s, l)
	_, err := s.Finish(ctx, l, Completion{Outcome: "succeeded", Reason: "too late"})
	expect(t, err, ErrLease)
	_, err = s.Reap(ctx, project, runID)
	check(t, err)
	_, err = s.Reap(ctx, project, runID)
	check(t, err) // Descendants converge across sweeps.
	for _, id := range []string{"parent", "child", "grandchild"} {
		if task(t, s, id).Status != "failed" {
			t.Fatal("deadline/prerequisite failure not propagated", id)
		}
	}
	raw := testdb.Task(t, "web", "short", "read_only")
	raw = testdb.Change(t, raw, "budget", map[string]any{"max_wall_seconds": 1, "max_model_tokens": 0, "max_requests": 1, "max_artifact_bytes": 1})
	check(t, s.Enqueue(ctx, raw, EnqueueOptions{1, 0}))
	short := claim(t, s)
	if !short.ExpiresAt.Equal(short.HardDeadline) {
		t.Fatal("lease exceeded wall-time budget")
	}
	until, err := s.Heartbeat(ctx, short)
	check(t, err)
	if until.After(short.HardDeadline) {
		t.Fatal("heartbeat extended fixed hard deadline")
	}
	sql(t, s, "UPDATE queue_tasks SET deadline=clock_timestamp()-interval '1 second' WHERE task_id='short'")
	expire(t, s, short)
	_, err = s.Reap(ctx, project, runID)
	check(t, err)
	enqueue(t, s, "queued-expiry", "read_only", 1)
	sql(t, s, "UPDATE queue_tasks SET deadline=clock_timestamp()-interval '1 second' WHERE task_id='queued-expiry'")
	_, err = s.Reap(ctx, project, runID)
	check(t, err)
	if task(t, s, "queued-expiry").Status != "failed" {
		t.Fatal("queued deadline not enforced")
	}
	assertLedger(t, s)
}

// Package worker runs trusted handlers while maintaining their queue lease.
package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"example.com/unified-harness/internal/queue"
)

// Handler must honor context cancellation and enforce the task's per-attempt
// limits at each external call. A database lease cannot terminate a subprocess.
type Handler func(context.Context, queue.Lease) queue.Completion

type Worker struct {
	Store                      *queue.Store
	ProjectID, RunID, WorkerID string
	HeartbeatEvery             time.Duration
}

// RunOnce claims one task. A lost lease cancels the handler and forbids publishing
// its result. After a crash, Reap settles the reservation and schedules recovery.
func (w Worker) RunOnce(ctx context.Context, handler Handler) (string, error) {
	if w.Store == nil || handler == nil {
		return "", errors.New("store and handler are required")
	}
	if w.HeartbeatEvery <= 0 || w.HeartbeatEvery >= w.Store.LeaseDuration() {
		return "", errors.New("heartbeat interval must be shorter than the lease")
	}
	lease, err := w.Store.Claim(ctx, w.ProjectID, w.RunID, w.WorkerID)
	if err != nil {
		return "", err
	}
	execution, cancel := context.WithDeadline(ctx, lease.HardDeadline)
	defer cancel()
	stop := make(chan struct{})
	heartbeats := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(w.HeartbeatEvery)
		defer ticker.Stop()
		expiresAt := lease.ExpiresAt
		for {
			select {
			case <-execution.Done():
				heartbeats <- execution.Err()
				return
			case <-stop:
				heartbeats <- nil
				return
			case <-ticker.C:
				// A renewal must complete before the last confirmed lease expiry.
				renewal, done := context.WithDeadline(execution, expiresAt)
				expires, err := w.Store.Heartbeat(renewal, lease)
				done()
				if err != nil {
					cancel()
					heartbeats <- err
					return
				}
				expiresAt = expires
			}
		}
	}()
	completion := func() queue.Completion {
		defer close(stop)
		return handler(execution, lease)
	}()
	if err := <-heartbeats; err != nil {
		return "", fmt.Errorf("worker lost execution authority: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return w.Store.Finish(ctx, lease, completion)
}

// Run maintains recovery sweeps while polling a single run. Idle or budget-
// constrained work waits for the next poll. Database errors return to the
// process supervisor; restarting is safe because state lives in PostgreSQL.
func (w Worker) Run(ctx context.Context, pollEvery time.Duration, handler Handler) error {
	if w.Store == nil || handler == nil || pollEvery <= 0 || pollEvery > time.Minute {
		return errors.New("store, handler, and poll interval up to one minute are required")
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := w.Store.Reap(ctx, w.ProjectID, w.RunID); err != nil {
			if errors.Is(err, queue.ErrRunClosed) {
				return nil
			}
			return err
		}
		_, err := w.RunOnce(ctx, handler)
		if errors.Is(err, queue.ErrRunClosed) {
			return nil
		}
		if err != nil && !errors.Is(err, queue.ErrNoWork) && !errors.Is(err, queue.ErrBudget) && !errors.Is(err, queue.ErrLease) {
			return err
		}
		timer := time.NewTimer(pollEvery)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

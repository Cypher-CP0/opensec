package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const readyWhere = `t.project_id=$1 AND t.run_id=$2 AND t.status='queued' AND t.available_at<=clock_timestamp() AND t.deadline>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM queue_dependencies d JOIN queue_tasks p ON p.project_id=d.project_id AND p.run_id=d.run_id AND p.task_id=d.depends_on
 WHERE d.project_id=t.project_id AND d.run_id=t.run_id AND d.task_id=t.task_id AND p.status<>'succeeded')`

func (s *Store) Claim(ctx context.Context, project, run, worker string) (Lease, error) {
	if !identifier.MatchString(worker) {
		return Lease{}, fmt.Errorf("%w: invalid worker identity", ErrInvalid)
	}
	tx, r, err := s.locked(ctx, project, run)
	if err != nil {
		return Lease{}, err
	}
	defer tx.Rollback(ctx)
	if r.Status != "active" {
		return Lease{}, ErrRunClosed
	}
	if r.AttemptCount >= r.MaxAttempts {
		return Lease{}, ErrBudget
	}
	var l Lease
	var cap Units
	var deadline time.Time
	err = tx.QueryRow(ctx, `SELECT t.task_id,t.generation,t.spec,t.reserve_tokens,t.reserve_requests,t.reserve_seconds,t.reserve_cost,t.deadline,t.reserve_bytes
 FROM queue_tasks t WHERE `+readyWhere+`
 AND t.reserve_tokens<=$3 AND t.reserve_requests<=$4 AND t.reserve_seconds<=$5 AND t.reserve_cost<=$6 AND t.reserve_bytes<=$7
 ORDER BY t.created_at,t.task_id FOR UPDATE OF t SKIP LOCKED LIMIT 1`,
		project, run, r.Limits.Tokens-r.Reserved.Tokens-r.Charged.Tokens-r.ModelTokenOverage, r.Limits.Requests-r.Reserved.Requests-r.Charged.Requests, r.Limits.WallSeconds-r.Reserved.WallSeconds-r.Charged.WallSeconds, r.Limits.CostMicrousd-r.Reserved.CostMicrousd-r.Charged.CostMicrousd, r.Limits.ArtifactBytes-r.Reserved.ArtifactBytes-r.Charged.ArtifactBytes).
		Scan(&l.TaskID, &l.Generation, &l.Spec, &cap.Tokens, &cap.Requests, &cap.WallSeconds, &cap.CostMicrousd, &deadline, &cap.ArtifactBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		var ready bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM queue_tasks t WHERE "+readyWhere+")", project, run).Scan(&ready); err != nil {
			return Lease{}, err
		}
		if ready {
			return Lease{}, ErrBudget
		}
		return Lease{}, ErrNoWork
	}
	if err != nil {
		return Lease{}, err
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return Lease{}, err
	}
	l.Reserved = cap
	l.ProjectID = project
	l.RunID = run
	l.WorkerID = worker
	l.Generation++
	l.AttemptID = randomID()
	l.Token = randomID()
	l.HardDeadline = minTime(deadline, now.Add(time.Duration(cap.WallSeconds)*time.Second))
	if !l.HardDeadline.After(now) {
		return Lease{}, ErrNoWork
	}
	l.ExpiresAt = minTime(l.HardDeadline, now.Add(s.settings.LeaseDuration))
	_, err = tx.Exec(ctx, `INSERT INTO queue_attempts(project_id,run_id,task_id,attempt_id,generation,worker_id,token_hash,started_at,lease_until,hard_until,reserve_tokens,reserve_requests,reserve_seconds,reserve_cost,reserve_bytes)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, project, run, l.TaskID, l.AttemptID, l.Generation, worker, hash([]byte(l.Token)), now, l.ExpiresAt, l.HardDeadline, cap.Tokens, cap.Requests, cap.WallSeconds, cap.CostMicrousd, cap.ArtifactBytes)
	if err != nil {
		return Lease{}, err
	}
	if _, err = tx.Exec(ctx, "UPDATE queue_tasks SET status='running',generation=$4,last_reason='' WHERE project_id=$1 AND run_id=$2 AND task_id=$3", project, run, l.TaskID, l.Generation); err != nil {
		return Lease{}, err
	}
	_, err = tx.Exec(ctx, `UPDATE queue_runs SET attempt_count=attempt_count+1,reserved_tokens=reserved_tokens+$3,reserved_requests=reserved_requests+$4,reserved_seconds=reserved_seconds+$5,reserved_cost=reserved_cost+$6,reserved_bytes=reserved_bytes+$7 WHERE project_id=$1 AND run_id=$2`, project, run, cap.Tokens, cap.Requests, cap.WallSeconds, cap.CostMicrousd, cap.ArtifactBytes)
	if err != nil {
		return Lease{}, err
	}
	if err = event(ctx, tx, project, run, l.TaskID, "claimed", map[string]any{"attempt_id": l.AttemptID, "generation": l.Generation, "worker_id": worker, "reserved": cap}); err != nil {
		return Lease{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Lease{}, err
	}
	return l, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

type attempt struct {
	TaskID, ID, Worker, TokenHash, Status, RetryClass, NextStatus, CompletionHash string
	Generation, CurrentGeneration                                                 int64
	MaxAttempts                                                                   int
	LeaseUntil, HardUntil, Deadline                                               time.Time
	Reserved                                                                      Units
}

func readAttempt(ctx context.Context, tx pgx.Tx, project, run, id string) (attempt, error) {
	var a attempt
	err := tx.QueryRow(ctx, `SELECT a.task_id,a.attempt_id,a.worker_id,a.token_hash,a.status,a.generation,a.lease_until,a.hard_until,
 a.reserve_tokens,a.reserve_requests,a.reserve_seconds,a.reserve_cost,COALESCE(a.next_status,''),COALESCE(a.completion_hash,''),
 t.retry_class,t.max_attempts,t.generation,t.deadline,a.reserve_bytes
 FROM queue_attempts a JOIN queue_tasks t USING(project_id,run_id,task_id)
 WHERE a.project_id=$1 AND a.run_id=$2 AND a.attempt_id=$3 FOR UPDATE OF t,a`, project, run, id).
		Scan(&a.TaskID, &a.ID, &a.Worker, &a.TokenHash, &a.Status, &a.Generation, &a.LeaseUntil, &a.HardUntil, &a.Reserved.Tokens, &a.Reserved.Requests, &a.Reserved.WallSeconds, &a.Reserved.CostMicrousd, &a.NextStatus, &a.CompletionHash, &a.RetryClass, &a.MaxAttempts, &a.CurrentGeneration, &a.Deadline, &a.Reserved.ArtifactBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrLease
	}
	return a, err
}
func (a attempt) owned(l Lease) bool {
	return a.TaskID == l.TaskID && a.ID == l.AttemptID && a.Worker == l.WorkerID && a.Generation == l.Generation && a.TokenHash == hash([]byte(l.Token))
}
func (a attempt) live(now time.Time) bool {
	return a.Status == "running" && a.Generation == a.CurrentGeneration && now.Before(a.LeaseUntil) && now.Before(a.HardUntil) && now.Before(a.Deadline)
}
func (s *Store) Heartbeat(ctx context.Context, l Lease) (time.Time, error) {
	tx, r, err := s.locked(ctx, l.ProjectID, l.RunID)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	if r.Status != "active" {
		return time.Time{}, ErrLease
	}
	a, err := readAttempt(ctx, tx, l.ProjectID, l.RunID, l.AttemptID)
	if err != nil {
		return time.Time{}, err
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return time.Time{}, err
	}
	if !a.owned(l) || !a.live(now) {
		return time.Time{}, ErrLease
	}
	until := minTime(a.HardUntil, now.Add(s.settings.LeaseDuration))
	if _, err = tx.Exec(ctx, "UPDATE queue_attempts SET lease_until=$4 WHERE project_id=$1 AND run_id=$2 AND attempt_id=$3", l.ProjectID, l.RunID, l.AttemptID, until); err != nil {
		return time.Time{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return time.Time{}, err
	}
	return until, nil
}
func validateCompletion(c Completion) error {
	switch c.Outcome {
	case "succeeded", "failed", "retryable_failure", "blocked_environment", "needs_reconciliation":
	default:
		return fmt.Errorf("%w: invalid completion outcome", ErrInvalid)
	}
	if len(c.Reason) == 0 || len(c.Reason) > 4096 {
		return fmt.Errorf("%w: completion needs a bounded reason", ErrInvalid)
	}
	if c.Usage != nil && !c.Usage.valid() {
		return fmt.Errorf("%w: invalid usage", ErrInvalid)
	}
	if len(c.Result) > 1024*1024 || !json.Valid(c.Result) {
		return fmt.Errorf("%w: result must be JSON of at most 1 MiB", ErrInvalid)
	}
	return nil
}
func (s *Store) Finish(ctx context.Context, l Lease, c Completion) (string, error) {
	if len(c.Result) == 0 {
		c.Result = json.RawMessage("null")
	}
	if err := validateCompletion(c); err != nil {
		return "", err
	}
	normalized, err := canonical(c.Result)
	if err != nil {
		return "", err
	}
	c.Result = normalized
	payload, _ := json.Marshal(c)
	fingerprint := hash(payload)
	tx, r, err := s.locked(ctx, l.ProjectID, l.RunID)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	a, err := readAttempt(ctx, tx, l.ProjectID, l.RunID, l.AttemptID)
	if err != nil {
		return "", err
	}
	if !a.owned(l) {
		return "", ErrLease
	}
	if a.Status != "running" {
		if a.CompletionHash == fingerprint {
			return a.NextStatus, tx.Commit(ctx)
		}
		if a.CompletionHash != "" {
			return "", ErrConflict
		}
		return "", ErrLease
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return "", err
	}
	if r.Status != "active" || !a.live(now) {
		return "", ErrLease
	}
	if err = s.evidenceTx(ctx, tx, l, a, c, now, r); err != nil {
		return "", err
	}
	// Artifact writes/validation may take time. Recheck the authoritative lease
	// immediately before committing any evidence or queue state.
	now, err = dbNow(ctx, tx)
	if err != nil {
		return "", err
	}
	if !a.live(now) {
		return "", ErrLease
	}
	status, err := s.finishTx(ctx, tx, l.ProjectID, l.RunID, a, c, fingerprint, now, false)
	if err != nil {
		return "", err
	}
	if err = tx.Commit(ctx); err != nil {
		return "", err
	}
	return status, nil
}
func (s *Store) finishTx(ctx context.Context, tx pgx.Tx, project, run string, a attempt, c Completion, fingerprint string, now time.Time, cancelled bool) (string, error) {
	used := a.Reserved
	uncertain := c.Usage == nil || (c.Investigation != nil && !c.Investigation.UsageKnown)
	if c.Usage != nil {
		used = *c.Usage
		if !used.within(a.Reserved) {
			return "", fmt.Errorf("%w: reported usage exceeds reservation", ErrInvalid)
		}
	}
	next := c.Outcome
	available := now
	if cancelled {
		next = "cancelled"
	} else if c.Outcome == "retryable_failure" {
		switch {
		case a.RetryClass != "read_only":
			next = "needs_reconciliation"
		case a.Generation >= int64(a.MaxAttempts):
			next = "failed"
		default:
			delay := s.settings.RetryBase
			for i := int64(1); i < a.Generation && delay < s.settings.RetryMax; i++ {
				delay = min(delay*2, s.settings.RetryMax)
			}
			available = now.Add(delay)
			next = "queued"
			if !available.Before(a.Deadline) {
				next = "failed"
			}
		}
	}
	if !now.Before(a.Deadline) && !cancelled {
		next = "failed"
	}
	_, err := tx.Exec(ctx, `UPDATE queue_runs SET reserved_tokens=reserved_tokens-$3,reserved_requests=reserved_requests-$4,reserved_seconds=reserved_seconds-$5,reserved_cost=reserved_cost-$6,
 charged_tokens=charged_tokens+$7,charged_requests=charged_requests+$8,charged_seconds=charged_seconds+$9,charged_cost=charged_cost+$10,reserved_bytes=reserved_bytes-$11,charged_bytes=charged_bytes+$12 WHERE project_id=$1 AND run_id=$2`,
		project, run, a.Reserved.Tokens, a.Reserved.Requests, a.Reserved.WallSeconds, a.Reserved.CostMicrousd, used.Tokens, used.Requests, used.WallSeconds, used.CostMicrousd, a.Reserved.ArtifactBytes, used.ArtifactBytes)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec(ctx, `UPDATE queue_attempts SET status=$4,finished_at=$5,used_tokens=$6,used_requests=$7,used_seconds=$8,used_cost=$9,usage_uncertain=$10,completion_hash=NULLIF($11,''),next_status=$12,result=$13,reason=$14,used_bytes=$15 WHERE project_id=$1 AND run_id=$2 AND attempt_id=$3`,
		project, run, a.ID, c.Outcome, now, used.Tokens, used.Requests, used.WallSeconds, used.CostMicrousd, uncertain, fingerprint, next, c.Result, c.Reason, used.ArtifactBytes)
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, "UPDATE queue_tasks SET status=$4,available_at=$5,last_reason=$6 WHERE project_id=$1 AND run_id=$2 AND task_id=$3", project, run, a.TaskID, next, available, c.Reason); err != nil {
		return "", err
	}
	err = event(ctx, tx, project, run, a.TaskID, "attempt_finished", map[string]any{"attempt_id": a.ID, "outcome": c.Outcome, "next_status": next, "charged": used, "usage_uncertain": uncertain, "reason": c.Reason})
	return next, err
}
func attemptIDs(ctx context.Context, tx pgx.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
func (s *Store) Reap(ctx context.Context, project, run string) (int, error) {
	tx, r, err := s.locked(ctx, project, run)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	if r.Status != "active" {
		return 0, ErrRunClosed
	}
	ids, err := attemptIDs(ctx, tx, "SELECT attempt_id FROM queue_attempts WHERE project_id=$1 AND run_id=$2 AND status='running' AND lease_until<=clock_timestamp() ORDER BY lease_until LIMIT 100", project, run)
	if err != nil {
		return 0, err
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return 0, err
	}
	for _, id := range ids {
		a, err := readAttempt(ctx, tx, project, run, id)
		if err != nil {
			return 0, err
		}
		_, err = s.finishTx(ctx, tx, project, run, a, Completion{Outcome: "retryable_failure", Reason: "worker lease expired; usage conservatively charged", Result: json.RawMessage("null")}, "", now, false)
		if err != nil {
			return 0, err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE queue_tasks t SET status='failed',last_reason='deadline expired or prerequisite failed'
 WHERE t.project_id=$1 AND t.run_id=$2 AND t.status IN ('queued','blocked_environment','needs_reconciliation') AND
 (t.deadline<=clock_timestamp() OR EXISTS(SELECT 1 FROM queue_dependencies d JOIN queue_tasks p ON p.project_id=d.project_id AND p.run_id=d.run_id AND p.task_id=d.depends_on
 WHERE d.project_id=t.project_id AND d.run_id=t.run_id AND d.task_id=t.task_id AND p.status IN ('failed','cancelled')))`, project, run)
	if err != nil {
		return 0, err
	}
	count := len(ids) + int(tag.RowsAffected())
	if count > 0 {
		if err = event(ctx, tx, project, run, "", "reaped", map[string]int{"tasks": count}); err != nil {
			return 0, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, err
	}
	return count, nil
}
func (s *Store) Cancel(ctx context.Context, project, run, task, reason string) error {
	if reason == "" || len(reason) > 4096 {
		return fmt.Errorf("%w: cancellation needs a bounded reason", ErrInvalid)
	}
	tx, r, err := s.locked(ctx, project, run)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if r.Status == "cancelled" {
		return tx.Commit(ctx)
	}
	if r.Status != "active" {
		return ErrRunClosed
	}
	if task != "" {
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM queue_tasks WHERE project_id=$1 AND run_id=$2 AND task_id=$3)", project, run, task).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
	}
	ids, err := attemptIDs(ctx, tx, "SELECT attempt_id FROM queue_attempts WHERE project_id=$1 AND run_id=$2 AND status='running' AND ($3='' OR task_id=$3)", project, run, task)
	if err != nil {
		return err
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	for _, id := range ids {
		a, err := readAttempt(ctx, tx, project, run, id)
		if err != nil {
			return err
		}
		if _, err = s.finishTx(ctx, tx, project, run, a, Completion{Outcome: "cancelled", Reason: reason, Result: json.RawMessage("null")}, "", now, true); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, "UPDATE queue_tasks SET status='cancelled',last_reason=$4 WHERE project_id=$1 AND run_id=$2 AND ($3='' OR task_id=$3) AND status IN ('queued','blocked_environment','needs_reconciliation')", project, run, task, reason); err != nil {
		return err
	}
	if task == "" {
		if _, err = tx.Exec(ctx, "UPDATE queue_runs SET status='cancelled' WHERE project_id=$1 AND run_id=$2", project, run); err != nil {
			return err
		}
	}
	if err = event(ctx, tx, project, run, task, "cancelled", map[string]string{"reason": reason}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) Resume(ctx context.Context, project, run, task, reason string, stateReconciled bool) error {
	if reason == "" || len(reason) > 4096 {
		return fmt.Errorf("%w: resume needs a bounded reason", ErrInvalid)
	}
	tx, r, err := s.locked(ctx, project, run)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if r.Status != "active" {
		return ErrRunClosed
	}
	var status, retry string
	var generation int64
	var maxAttempts int
	var deadline time.Time
	err = tx.QueryRow(ctx, "SELECT status,retry_class,generation,max_attempts,deadline FROM queue_tasks WHERE project_id=$1 AND run_id=$2 AND task_id=$3 FOR UPDATE", project, run, task).Scan(&status, &retry, &generation, &maxAttempts, &deadline)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if status != "blocked_environment" && status != "needs_reconciliation" {
		return fmt.Errorf("%w: only blocked or reconciliation tasks can resume", ErrInvalid)
	}
	if (status == "needs_reconciliation" || retry != "read_only") && !stateReconciled {
		return fmt.Errorf("%w: operator must explicitly confirm state reconciliation or fixture reset", ErrInvalid)
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	if generation >= int64(maxAttempts) || !now.Before(deadline) {
		return fmt.Errorf("%w: task exhausted attempts or deadline", ErrInvalid)
	}
	if _, err = tx.Exec(ctx, "UPDATE queue_tasks SET status='queued',available_at=$4,last_reason=$5 WHERE project_id=$1 AND run_id=$2 AND task_id=$3", project, run, task, now, reason); err != nil {
		return err
	}
	if err = event(ctx, tx, project, run, task, "resumed", map[string]any{"reason": reason, "state_reconciled": stateReconciled}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) CloseRun(ctx context.Context, project, run string) error {
	tx, r, err := s.locked(ctx, project, run)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if r.Status == "completed" || r.Status == "partial" {
		return tx.Commit(ctx)
	}
	if r.Status != "active" {
		return ErrRunClosed
	}
	var pending, bad int
	err = tx.QueryRow(ctx, "SELECT count(*) FILTER(WHERE status IN ('queued','running','blocked_environment','needs_reconciliation')),count(*) FILTER(WHERE status IN ('failed','cancelled')) FROM queue_tasks WHERE project_id=$1 AND run_id=$2", project, run).Scan(&pending, &bad)
	if err != nil {
		return err
	}
	if pending > 0 {
		return fmt.Errorf("%w: %d tasks are still pending", ErrInvalid, pending)
	}
	var unresolved int
	if err = tx.QueryRow(ctx, "SELECT count(*) FROM findings WHERE project_id=$1 AND run_id=$2 AND status IN ('unvalidated','inconclusive')", project, run).Scan(&unresolved); err != nil {
		return err
	}
	var unscheduled int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM source_investigations i JOIN queue_tasks t USING(project_id,run_id,task_id) WHERE i.project_id=$1 AND i.run_id=$2 AND i.report->>'status'='hypothesis' AND i.probe_task_id IS NULL AND t.spec->'investigator'->'probe' IS NOT NULL`, project, run).Scan(&unscheduled); err != nil {
		return err
	}
	status := "completed"
	if bad > 0 || unresolved > 0 || unscheduled > 0 {
		status = "partial"
	}
	if _, err = tx.Exec(ctx, "UPDATE queue_runs SET status=$3 WHERE project_id=$1 AND run_id=$2", project, run, status); err != nil {
		return err
	}
	if err = event(ctx, tx, project, run, "", "closed", map[string]string{"status": status}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

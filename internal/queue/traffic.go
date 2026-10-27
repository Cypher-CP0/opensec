package queue

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/policy"
	"github.com/jackc/pgx/v5"
)

// ConfigureTraffic binds the operator policy registry at startup.
func (s *Store) ConfigureTraffic(registry *policy.Registry) error {
	if registry == nil {
		return errors.New("traffic policy registry is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var ready bool
	if err := s.pool.QueryRow(ctx, "SELECT to_regclass('traffic_permits') IS NOT NULL AND to_regclass('target_traffic') IS NOT NULL").Scan(&ready); err != nil {
		return err
	}
	if !ready {
		return errors.New("migration 004_target_traffic.sql is required; run harness queue migrate")
	}
	s.traffic = registry
	return nil
}
func (s *Store) AcquireTraffic(ctx context.Context, l Lease, raw, requestID string) (policy.TrafficGrant, error) {
	return s.AcquireTrafficMethod(ctx, l, raw, "GET", requestID)
}
func (s *Store) AcquireTrafficMethod(ctx context.Context, l Lease, raw, method, requestID string) (policy.TrafficGrant, error) {
	deny := policy.TrafficGrant{}
	if s.traffic == nil || !identifier.MatchString(requestID) {
		return deny, ErrInvalid
	}
	tx, r, err := s.locked(ctx, l.ProjectID, l.RunID)
	if err != nil {
		return deny, err
	}
	defer tx.Rollback(ctx)
	a, err := readAttempt(ctx, tx, l.ProjectID, l.RunID, l.AttemptID)
	if err != nil {
		return deny, err
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return deny, err
	}
	if r.Status != "active" || !a.owned(l) || !a.live(now) {
		return deny, ErrLease
	}
	// Never trust the spec, reservation or policy copied into a caller's lease.
	var spec json.RawMessage
	if err = tx.QueryRow(ctx, "SELECT spec FROM queue_tasks WHERE project_id=$1 AND run_id=$2 AND task_id=$3", l.ProjectID, l.RunID, l.TaskID).Scan(&spec); err != nil {
		return deny, err
	}
	p, err := s.traffic.AuthorizeTask(ctx, spec)
	if err != nil {
		return deny, ErrInvalid
	}
	if p.Traffic == nil {
		return deny, ErrInvalid
	}
	origin, err := s.traffic.MethodOrigin(ctx, p, raw, method)
	if err != nil {
		return deny, ErrInvalid
	}
	check, err := checks.Parse(spec)
	if err != nil {
		return deny, ErrInvalid
	}
	var target struct {
		WebInvestigator *struct {
			AllowMutations bool `json:"allow_mutations"`
		} `json:"web_investigator"`
		Target struct {
			Web *struct {
				Seeds []string `json:"seed_urls"`
			} `json:"web"`
		} `json:"target"`
	}
	if json.Unmarshal(spec, &target) != nil {
		return deny, ErrInvalid
	}
	permitted := []string{}
	if check.Check != nil {
		permitted = check.URLs()
	} else if target.Target.Web != nil {
		permitted = target.Target.Web.Seeds
	}
	// Web investigators may discover any endpoint authorized by this policy,
	// but never expand the stored task's canonical origin or mutation authority.
	found := false
	if target.WebInvestigator != nil && target.Target.Web != nil {
		if len(target.Target.Web.Seeds) == 0 {
			return deny, ErrInvalid
		}
		taskOrigin, e := s.traffic.RequestOrigin(ctx, p, target.Target.Web.Seeds[0])
		found = e == nil && origin == taskOrigin && (method == "GET" || method == "HEAD" || target.WebInvestigator.AllowMutations)
	} else if method != "GET" {
		return deny, ErrInvalid
	}
	for _, u := range permitted {
		if target.WebInvestigator == nil && raw == u {
			found = true
			break
		}
	}
	if !found {
		return deny, ErrInvalid
	}
	t := p.Traffic
	_, err = tx.Exec(ctx, `INSERT INTO target_traffic(project_id,origin,min_interval_ms,max_concurrent,backoff_seconds) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, l.ProjectID, origin, t.MinIntervalMS, t.MaxConcurrent, t.BackoffSeconds)
	if err != nil {
		return deny, err
	}
	var interval, concurrent, backoff int64
	var next, cooldown time.Time
	if err = tx.QueryRow(ctx, `SELECT min_interval_ms,max_concurrent,backoff_seconds,next_at,cooldown_until FROM target_traffic WHERE project_id=$1 AND origin=$2 FOR UPDATE`, l.ProjectID, origin).Scan(&interval, &concurrent, &backoff, &next, &cooldown); err != nil {
		return deny, err
	}
	// Mismatched coordinator configurations fail closed instead of relaxing a target.
	if interval != t.MinIntervalMS || concurrent != t.MaxConcurrent || backoff != t.BackoffSeconds {
		return deny, ErrConflict
	}
	now, err = dbNow(ctx, tx)
	if err != nil {
		return deny, err
	}
	if !a.live(now) {
		return deny, ErrLease
	}
	var expires time.Time
	var released *time.Time
	var priorHash string
	err = tx.QueryRow(ctx, `SELECT url_hash,expires_at,released_at FROM traffic_permits WHERE project_id=$1 AND run_id=$2 AND attempt_id=$3 AND request_id=$4`, l.ProjectID, l.RunID, l.AttemptID, requestID).Scan(&priorHash, &expires, &released)
	if err == nil {
		if priorHash != hash([]byte(method+"\n"+raw)) || released != nil || !expires.After(now) {
			return deny, ErrConflict
		}
		return policy.TrafficGrant{Granted: true, ValidForMS: expires.Sub(now).Milliseconds()}, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return deny, err
	}
	var admitted, active int64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM traffic_permits WHERE project_id=$1 AND run_id=$2 AND attempt_id=$3`, l.ProjectID, l.RunID, l.AttemptID).Scan(&admitted); err != nil {
		return deny, err
	}
	if admitted >= a.Reserved.Requests {
		return deny, ErrBudget
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM traffic_permits WHERE project_id=$1 AND origin=$2 AND released_at IS NULL AND expires_at>$3`, l.ProjectID, origin, now).Scan(&active); err != nil {
		return deny, err
	}
	wait := next.Sub(now)
	if d := cooldown.Sub(now); d > wait {
		wait = d
	}
	if active >= concurrent && wait < 100*time.Millisecond {
		wait = 100 * time.Millisecond
	}
	if wait > 0 {
		return policy.TrafficGrant{RetryAfterMS: max(int64(1), wait.Milliseconds()+1)}, tx.Commit(ctx)
	}
	expires = minTime(now.Add(15*time.Second), minTime(a.LeaseUntil, a.HardUntil))
	if expires.Sub(now) < 500*time.Millisecond {
		return deny, ErrLease
	}
	_, err = tx.Exec(ctx, `INSERT INTO traffic_permits(project_id,run_id,attempt_id,request_id,origin,url_hash,acquired_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, l.ProjectID, l.RunID, l.AttemptID, requestID, origin, hash([]byte(method+"\n"+raw)), now, expires)
	if err != nil {
		return deny, err
	}
	if _, err = tx.Exec(ctx, "UPDATE target_traffic SET next_at=$3 WHERE project_id=$1 AND origin=$2", l.ProjectID, origin, now.Add(time.Duration(interval)*time.Millisecond)); err != nil {
		return deny, err
	}
	return policy.TrafficGrant{Granted: true, ValidForMS: expires.Sub(now).Milliseconds()}, tx.Commit(ctx)
}
func (s *Store) ReleaseTraffic(ctx context.Context, l Lease, requestID string, status int) error {
	if !identifier.MatchString(requestID) || (status != 0 && (status < 100 || status > 599)) {
		return ErrInvalid
	}
	tx, _, err := s.locked(ctx, l.ProjectID, l.RunID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	a, err := readAttempt(ctx, tx, l.ProjectID, l.RunID, l.AttemptID)
	if err != nil {
		return err
	}
	// Permit cleanup is allowed after cancellation/expiry, but ownership is still required.
	if !a.owned(l) {
		return ErrLease
	}
	var origin string
	var prior *int
	err = tx.QueryRow(ctx, `SELECT origin,response_status FROM traffic_permits WHERE project_id=$1 AND run_id=$2 AND attempt_id=$3 AND request_id=$4`, l.ProjectID, l.RunID, l.AttemptID, requestID).Scan(&origin, &prior)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var backoff int64
	if err = tx.QueryRow(ctx, "SELECT backoff_seconds FROM target_traffic WHERE project_id=$1 AND origin=$2 FOR UPDATE", l.ProjectID, origin).Scan(&backoff); err != nil {
		return err
	}
	if prior != nil {
		if *prior != status {
			return ErrConflict
		}
		return tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `UPDATE traffic_permits SET released_at=clock_timestamp(),response_status=$5 WHERE project_id=$1 AND run_id=$2 AND attempt_id=$3 AND request_id=$4`, l.ProjectID, l.RunID, l.AttemptID, requestID, status); err != nil {
		return err
	}
	if status == 429 || status == 503 {
		if _, err = tx.Exec(ctx, `UPDATE target_traffic SET cooldown_until=GREATEST(cooldown_until,clock_timestamp()+$3::bigint*interval '1 second') WHERE project_id=$1 AND origin=$2`, l.ProjectID, origin, backoff); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

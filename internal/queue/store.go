package queue

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"example.com/unified-harness/internal/coreclient"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrations embed.FS
var identifier = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

type CoreValidator struct{ Binary string }

func (v CoreValidator) ValidateTask(ctx context.Context, raw json.RawMessage) error {
	_, err := coreclient.Call(ctx, v.Binary, map[string]any{"operation": "validate", "kind": "task", "document": raw})
	return err
}

type Store struct {
	pool      *pgxpool.Pool
	validator Validator
	settings  Settings
}

func Open(ctx context.Context, dsn string, validator Validator, settings Settings) (*Store, error) {
	if validator == nil {
		return nil, errors.New("a contract validator is required")
	}
	if settings.LeaseDuration <= 0 || settings.LeaseDuration > 5*time.Minute || settings.RetryBase <= 0 || settings.RetryMax < settings.RetryBase || settings.RetryMax > time.Hour {
		return nil, errors.New("invalid queue timing settings")
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("invalid database configuration")
	}
	config.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, errors.New("cannot initialize database pool")
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database connection failed: %w", err)
	}
	return &Store{pool, validator, settings}, nil
}
func (s *Store) Close() { s.pool.Close() }
func (s *Store) Migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(716032845)"); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS harness_migrations(version integer PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp())"); err != nil {
		return err
	}
	raw, err := migrations.ReadFile("migrations/001_queue.sql")
	if err != nil {
		return err
	}
	checksum := hash(bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n")))
	var existing string
	err = tx.QueryRow(ctx, "SELECT checksum FROM harness_migrations WHERE version=1").Scan(&existing)
	if err == nil {
		if existing != checksum {
			return errors.New("migration checksum mismatch")
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if _, err = tx.Exec(ctx, string(raw)); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO harness_migrations(version,checksum) VALUES(1,$1)", checksum); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func hash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func randomID() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}
func canonical(raw []byte) ([]byte, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if !json.Valid(raw) {
		return nil, errors.New("invalid JSON")
	}
	return json.Marshal(value)
}

const runColumns = "project_id,run_id,status,max_tasks,max_attempts,limit_tokens,limit_requests,limit_seconds,limit_cost,task_count,attempt_count,reserved_tokens,reserved_requests,reserved_seconds,reserved_cost,charged_tokens,charged_requests,charged_seconds,charged_cost,limit_bytes,reserved_bytes,charged_bytes"

func scanRun(row pgx.Row) (Run, error) {
	var r Run
	err := row.Scan(&r.ProjectID, &r.RunID, &r.Status, &r.MaxTasks, &r.MaxAttempts, &r.Limits.Tokens, &r.Limits.Requests, &r.Limits.WallSeconds, &r.Limits.CostMicrousd, &r.TaskCount, &r.AttemptCount, &r.Reserved.Tokens, &r.Reserved.Requests, &r.Reserved.WallSeconds, &r.Reserved.CostMicrousd, &r.Charged.Tokens, &r.Charged.Requests, &r.Charged.WallSeconds, &r.Charged.CostMicrousd, &r.Limits.ArtifactBytes, &r.Reserved.ArtifactBytes, &r.Charged.ArtifactBytes)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return r, err
}
func (s *Store) GetRun(ctx context.Context, project, run string) (Run, error) {
	return scanRun(s.pool.QueryRow(ctx, "SELECT "+runColumns+" FROM queue_runs WHERE project_id=$1 AND run_id=$2", project, run))
}
func (s *Store) CreateRun(ctx context.Context, c RunConfig) error {
	if !identifier.MatchString(c.ProjectID) || !identifier.MatchString(c.RunID) || c.MaxTasks < 1 || c.MaxTasks > 1e9 || c.MaxAttempts < 1 || c.MaxAttempts > 1e9 || !c.Limits.valid() {
		return fmt.Errorf("%w: invalid run limits or identity", ErrInvalid)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO queue_runs(project_id,run_id,max_tasks,max_attempts,limit_tokens,limit_requests,limit_seconds,limit_cost,limit_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`, c.ProjectID, c.RunID, c.MaxTasks, c.MaxAttempts, c.Limits.Tokens, c.Limits.Requests, c.Limits.WallSeconds, c.Limits.CostMicrousd, c.Limits.ArtifactBytes)
	if err != nil {
		return err
	}
	existing, err := s.GetRun(ctx, c.ProjectID, c.RunID)
	if err != nil {
		return err
	}
	if existing.RunConfig != c {
		return ErrConflict
	}
	return nil
}
func (s *Store) locked(ctx context.Context, project, run string) (pgx.Tx, Run, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, Run{}, err
	}
	r, err := scanRun(tx.QueryRow(ctx, "SELECT "+runColumns+" FROM queue_runs WHERE project_id=$1 AND run_id=$2 FOR UPDATE", project, run))
	if err != nil {
		tx.Rollback(ctx)
		return nil, Run{}, err
	}
	return tx, r, nil
}
func dbNow(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var now time.Time
	err := tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now)
	return now, err
}
func event(ctx context.Context, tx pgx.Tx, project, run, task, kind string, details any) error {
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "INSERT INTO queue_events(project_id,run_id,task_id,kind,details) VALUES($1,$2,NULLIF($3,''),$4,$5)", project, run, task, kind, raw)
	return err
}

type specProjection struct {
	ProjectID    string    `json:"project_id"`
	RunID        string    `json:"run_id"`
	TaskID       string    `json:"task_id"`
	RetryClass   string    `json:"retry_class"`
	CreatedAt    time.Time `json:"created_at"`
	Deadline     time.Time `json:"deadline"`
	Dependencies []string  `json:"dependencies"`
	Budget       struct {
		ArtifactBytes int64 `json:"max_artifact_bytes"`
		Tokens        int64 `json:"max_model_tokens"`
		Requests      int64 `json:"max_requests"`
		Seconds       int64 `json:"max_wall_seconds"`
	} `json:"budget"`
}

func (s *Store) Enqueue(ctx context.Context, raw json.RawMessage, options EnqueueOptions) error {
	if options.MaxAttempts < 1 || options.MaxAttempts > 100 || options.CostMicrousd < 0 || options.CostMicrousd > 1e12 {
		return fmt.Errorf("%w: invalid task scheduling options", ErrInvalid)
	}
	if err := s.validator.ValidateTask(ctx, raw); err != nil {
		return err
	}
	normalized, err := canonical(raw)
	if err != nil {
		return err
	}
	var spec specProjection
	if err = json.Unmarshal(normalized, &spec); err != nil {
		return err
	}
	if spec.Budget.ArtifactBytes < 1 || spec.Budget.ArtifactBytes > 1e12 {
		return fmt.Errorf("%w: artifact budget exceeds supported accounting range", ErrInvalid)
	}
	optionJSON, _ := json.Marshal(options)
	fingerprint := hash(append(normalized, optionJSON...))
	tx, r, err := s.locked(ctx, spec.ProjectID, spec.RunID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var old string
	err = tx.QueryRow(ctx, "SELECT fingerprint FROM queue_tasks WHERE project_id=$1 AND run_id=$2 AND task_id=$3", spec.ProjectID, spec.RunID, spec.TaskID).Scan(&old)
	if err == nil {
		if old != fingerprint {
			return ErrConflict
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if r.Status != "active" {
		return ErrRunClosed
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return err
	}
	if !spec.Deadline.After(now) || spec.CreatedAt.After(now) {
		return fmt.Errorf("%w: task must have a current creation time and future deadline", ErrInvalid)
	}
	if r.TaskCount >= r.MaxTasks {
		return ErrBudget
	}
	for _, dependency := range spec.Dependencies {
		var exists bool
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM queue_tasks WHERE project_id=$1 AND run_id=$2 AND task_id=$3)", spec.ProjectID, spec.RunID, dependency).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("%w: dependency %q must already exist in the same run", ErrInvalid, dependency)
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO queue_tasks(project_id,run_id,task_id,spec,fingerprint,retry_class,max_attempts,reserve_tokens,reserve_requests,reserve_seconds,reserve_cost,deadline,reserve_bytes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, spec.ProjectID, spec.RunID, spec.TaskID, normalized, fingerprint, spec.RetryClass, options.MaxAttempts, spec.Budget.Tokens, spec.Budget.Requests, spec.Budget.Seconds, options.CostMicrousd, spec.Deadline, spec.Budget.ArtifactBytes)
	if err != nil {
		return err
	}
	for _, d := range spec.Dependencies {
		if _, err = tx.Exec(ctx, "INSERT INTO queue_dependencies VALUES($1,$2,$3,$4)", spec.ProjectID, spec.RunID, spec.TaskID, d); err != nil {
			return err
		}
	}
	if _, err = tx.Exec(ctx, "UPDATE queue_runs SET task_count=task_count+1 WHERE project_id=$1 AND run_id=$2", spec.ProjectID, spec.RunID); err != nil {
		return err
	}
	if err = event(ctx, tx, spec.ProjectID, spec.RunID, spec.TaskID, "enqueued", options); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) GetTask(ctx context.Context, project, run, task string) (Task, error) {
	var t Task
	err := s.pool.QueryRow(ctx, "SELECT task_id,status,generation,available_at,last_reason,(SELECT result FROM queue_attempts a WHERE a.project_id=t.project_id AND a.run_id=t.run_id AND a.task_id=t.task_id AND a.generation=t.generation) FROM queue_tasks t WHERE project_id=$1 AND run_id=$2 AND task_id=$3", project, run, task).Scan(&t.TaskID, &t.Status, &t.Generation, &t.AvailableAt, &t.LastReason, &t.Result)
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrNotFound
	}
	return t, err
}

func (s *Store) LeaseDuration() time.Duration { return s.settings.LeaseDuration }

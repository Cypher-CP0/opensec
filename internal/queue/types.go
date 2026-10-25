// Package queue implements transactional scheduling for trusted coordinator processes.
package queue

import (
	"context"
	"encoding/json"
	"errors"
	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/investigator"
	"time"
)

var (
	ErrInvalid   = errors.New("invalid queue request")
	ErrConflict  = errors.New("idempotency conflict")
	ErrBudget    = errors.New("run budget exhausted or insufficient")
	ErrNoWork    = errors.New("no eligible task")
	ErrLease     = errors.New("stale, expired, or invalid lease")
	ErrRunClosed = errors.New("run is not active")
	ErrNotFound  = errors.New("record not found")
)

type Units struct {
	ArtifactBytes int64 `json:"artifact_bytes"`
	Tokens        int64 `json:"tokens"`
	Requests      int64 `json:"requests"`
	WallSeconds   int64 `json:"wall_seconds"`
	CostMicrousd  int64 `json:"cost_microusd"`
}

func (u Units) valid() bool {
	return u.ArtifactBytes >= 0 && u.ArtifactBytes <= 1e12 && u.Tokens >= 0 && u.Requests >= 0 && u.WallSeconds >= 0 && u.CostMicrousd >= 0 && u.Tokens <= 1e12 && u.Requests <= 1e12 && u.WallSeconds <= 1e12 && u.CostMicrousd <= 1e12
}
func (u Units) within(b Units) bool {
	return u.valid() && u.ArtifactBytes <= b.ArtifactBytes && u.Tokens <= b.Tokens && u.Requests <= b.Requests && u.WallSeconds <= b.WallSeconds && u.CostMicrousd <= b.CostMicrousd
}

type RunConfig struct {
	ProjectID   string `json:"project_id"`
	RunID       string `json:"run_id"`
	MaxTasks    int64  `json:"max_tasks"`
	MaxAttempts int64  `json:"max_attempts"`
	Limits      Units  `json:"limits"`
}
type Run struct {
	ModelTokenOverage int64 `json:"model_token_overage"`
	RunConfig
	Status       string `json:"status"`
	TaskCount    int64  `json:"task_count"`
	AttemptCount int64  `json:"attempt_count"`
	Reserved     Units  `json:"reserved"`
	Charged      Units  `json:"charged"`
}
type EnqueueOptions struct {
	MaxAttempts  int   `json:"max_attempts"`
	CostMicrousd int64 `json:"cost_microusd"`
}
type Lease struct {
	Reserved     Units           `json:"reserved"`
	ProjectID    string          `json:"project_id"`
	RunID        string          `json:"run_id"`
	TaskID       string          `json:"task_id"`
	AttemptID    string          `json:"attempt_id"`
	WorkerID     string          `json:"worker_id"`
	Generation   int64           `json:"generation"`
	Token        string          `json:"token"`
	ExpiresAt    time.Time       `json:"expires_at"`
	HardDeadline time.Time       `json:"hard_deadline"`
	Spec         json.RawMessage `json:"spec"`
}
type Completion struct {
	Investigation *investigator.Report `json:"investigation,omitempty"`
	Evidence      *checks.Submission   `json:"evidence,omitempty"`
	Outcome       string               `json:"outcome"`
	Reason        string               `json:"reason"`
	Usage         *Units               `json:"usage"`
	Result        json.RawMessage      `json:"result"`
}
type Task struct {
	Result      json.RawMessage `json:"result,omitempty"`
	TaskID      string          `json:"task_id"`
	Status      string          `json:"status"`
	Generation  int64           `json:"generation"`
	AvailableAt time.Time       `json:"available_at"`
	LastReason  string          `json:"last_reason"`
}
type Validator interface {
	ValidateTask(context.Context, json.RawMessage) error
}
type Settings struct{ LeaseDuration, RetryBase, RetryMax time.Duration }

func DefaultSettings() Settings { return Settings{30 * time.Second, time.Second, time.Minute} }

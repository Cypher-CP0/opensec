package policy

import (
	"context"
	"errors"
)

var ErrTrafficUnavailable = errors.New("shared target traffic admission unavailable")
var ErrTargetBackoff = errors.New("target backoff requested")

type Endpoint struct {
	AllowQuery   bool   `json:"allow_query,omitempty"`
	Method       string `json:"method"`
	PathTemplate string `json:"path_template"`
}
type TrafficLimits struct {
	MinIntervalMS  int64 `json:"min_interval_ms"`
	MaxConcurrent  int64 `json:"max_concurrent"`
	BackoffSeconds int64 `json:"backoff_seconds"`
}

func DefaultTraffic() *TrafficLimits {
	return &TrafficLimits{MinIntervalMS: 500, MaxConcurrent: 1, BackoffSeconds: 30}
}

type TrafficGrant struct {
	Granted      bool  `json:"granted"`
	ValidForMS   int64 `json:"valid_for_ms"`
	RetryAfterMS int64 `json:"retry_after_ms"`
}
type MethodTrafficGate interface {
	AcquireMethod(context.Context, string, string, string) (TrafficGrant, error)
}
type TrafficGate interface {
	Acquire(context.Context, string, string) (TrafficGrant, error)
	Release(context.Context, string, int) error
}

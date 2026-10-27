package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"example.com/unified-harness/internal/configfile"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
)

type Server struct {
	store    *queue.Store
	auth     *Auth
	policies *policy.Registry
	slots    chan struct{}
}

func New(store *queue.Store, auth *Auth, policies *policy.Registry) (*Server, error) {
	if store == nil || auth == nil || policies == nil {
		return nil, errors.New("store, authentication, and policies are required")
	}
	if err := store.ConfigureTraffic(policies); err != nil {
		return nil, err
	}
	return &Server{store, auth, policies, make(chan struct{}, 64)}, nil
}

type Scope struct {
	ProjectID       string `json:"project_id"`
	RunID           string `json:"run_id"`
	TaskID          string `json:"task_id,omitempty"`
	Reason          string `json:"reason,omitempty"`
	StateReconciled bool   `json:"state_reconciled,omitempty"`
	EvidenceID      string `json:"evidence_id,omitempty"`
	FindingID       string `json:"finding_id,omitempty"`
	After           string `json:"after,omitempty"`
}
type EnqueueRequest struct {
	Task    json.RawMessage      `json:"task"`
	Options queue.EnqueueOptions `json:"options"`
}
type LeaseRequest struct {
	Lease      queue.Lease       `json:"lease"`
	Completion *queue.Completion `json:"completion,omitempty"`
}
type Info struct {
	TrafficAdmission  bool   `json:"traffic_admission"`
	Subject           string `json:"subject"`
	Role              string `json:"role"`
	LeaseMilliseconds int64  `json:"lease_milliseconds"`
}
type ErrorResponse struct {
	Error string `json:"error"`
}

func jsonBytes(v any) ([]byte, error) { return json.Marshal(v) }
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if status != http.StatusNoContent {
		_ = json.NewEncoder(w).Encode(v)
	}
}
func fail(w http.ResponseWriter, status int, code string) { respond(w, status, ErrorResponse{code}) }
func queueError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, queue.ErrNoWork):
		respond(w, 204, nil)
	case errors.Is(err, queue.ErrBudget):
		fail(w, 409, "budget_exhausted")
	case errors.Is(err, queue.ErrLease):
		fail(w, 409, "invalid_lease")
	case errors.Is(err, queue.ErrConflict):
		fail(w, 409, "conflict")
	case errors.Is(err, queue.ErrRunClosed):
		fail(w, 409, "run_closed")
	case errors.Is(err, queue.ErrNotFound):
		fail(w, 404, "not_found")
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		fail(w, 503, "unavailable")
	case errors.Is(err, queue.ErrInvalid):
		fail(w, 400, "invalid_request")
	default:
		fail(w, 500, "internal_error") // Never expose SQL, credentials, or subprocess diagnostics.
	}
}
func decode(w http.ResponseWriter, r *http.Request, out any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		fail(w, 415, "json_required")
		return false
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, configfile.MaxBytes))
	if err != nil {
		fail(w, 413, "body_too_large")
		return false
	}
	if err = configfile.Decode(raw, out); err != nil {
		fail(w, 400, "invalid_json")
		return false
	}
	return true
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	principal, ok := s.auth.authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		fail(w, 401, "unauthorized")
		return
	}
	if r.URL.RawQuery != "" {
		fail(w, 400, "query_not_supported")
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/info" {
		respond(w, 200, Info{Subject: principal.Subject, Role: principal.Role, LeaseMilliseconds: s.store.LeaseDuration().Milliseconds(), TrafficAdmission: true})
		return
	}
	if r.Method != http.MethodPost {
		fail(w, 405, "post_required")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail(w, 503, "busy")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	operation := strings.TrimPrefix(r.URL.Path, "/v1/queue/")
	if r.URL.Path != "/v1/queue/"+operation {
		fail(w, 404, "not_found")
		return
	}
	workerOp := operation == "claim" || operation == "heartbeat" || operation == "finish" || operation == "traffic-acquire" || operation == "traffic-release"
	controlOp := operation == "create-run" || operation == "enqueue" || operation == "cancel" || operation == "resume" || operation == "close"
	if (workerOp && principal.Role != "worker") || (controlOp && principal.Role != "operator") {
		fail(w, 403, "forbidden")
		return
	}
	scopeOK := func(project, run string) bool {
		if !principal.allows(project, run) {
			fail(w, 403, "forbidden")
			return false
		}
		return true
	}
	var value any = map[string]bool{"ok": true}
	var err error
	switch operation {
	case "create-run":
		var c queue.RunConfig
		if !decode(w, r, &c) || !scopeOK(c.ProjectID, c.RunID) {
			return
		}
		err = s.store.CreateRun(ctx, c)
	case "enqueue":
		var input EnqueueRequest
		if !decode(w, r, &input) {
			return
		}
		var scope Scope
		// Read identity only; the authoritative core checks the complete task next.
		if json.Unmarshal(input.Task, &scope) != nil {
			fail(w, 400, "invalid_task")
			return
		}
		if !scopeOK(scope.ProjectID, scope.RunID) {
			return
		}
		if _, err = s.policies.AuthorizeTask(ctx, input.Task); err != nil {
			fail(w, 403, "target_policy_denied")
			return
		}
		err = s.store.Enqueue(ctx, input.Task, input.Options)
	case "traffic-acquire", "traffic-release":
		var input TrafficRequest
		if !decode(w, r, &input) || !scopeOK(input.Lease.ProjectID, input.Lease.RunID) {
			return
		}
		if input.Lease.WorkerID != principal.Subject {
			fail(w, 403, "worker_mismatch")
			return
		}
		if operation == "traffic-acquire" {
			if input.Status != 0 {
				fail(w, 400, "unexpected_status")
				return
			}
			if input.Method == "" {
				input.Method = "GET"
			}
			value, err = s.store.AcquireTrafficMethod(ctx, input.Lease, input.URL, input.Method, input.RequestID)
		} else {
			if input.URL != "" || input.Method != "" {
				fail(w, 400, "unexpected_url")
				return
			}
			err = s.store.ReleaseTraffic(ctx, input.Lease, input.RequestID, input.Status)
		}
	case "heartbeat", "finish":
		var input LeaseRequest
		if !decode(w, r, &input) {
			return
		}
		l := input.Lease
		if !scopeOK(l.ProjectID, l.RunID) {
			return
		}
		if l.WorkerID != principal.Subject {
			fail(w, 403, "worker_mismatch")
			return
		}
		if operation == "heartbeat" {
			if input.Completion != nil {
				fail(w, 400, "unexpected_completion")
				return
			}
			var expires time.Time
			expires, err = s.store.Heartbeat(ctx, l)
			value = map[string]any{"expires_at": expires}
		} else {
			if input.Completion == nil {
				fail(w, 400, "completion_required")
				return
			}
			var status string
			status, err = s.store.Finish(ctx, l, *input.Completion)
			value = map[string]string{"task_status": status}
		}
	case "run", "task", "claim", "cancel", "reap", "resume", "close", "evidence", "finding", "findings", "investigation", "report":
		var scope Scope
		if !decode(w, r, &scope) || !scopeOK(scope.ProjectID, scope.RunID) {
			return
		}
		if (operation == "task" || operation == "resume" || operation == "investigation") && scope.TaskID == "" {
			fail(w, 400, "task_required")
			return
		}
		switch operation {
		case "investigation":
			value, err = s.store.GetInvestigation(ctx, scope.ProjectID, scope.RunID, scope.TaskID)
		case "evidence":
			if scope.EvidenceID == "" {
				fail(w, 400, "evidence_required")
				return
			}
			value, err = s.store.GetEvidence(ctx, scope.ProjectID, scope.RunID, scope.EvidenceID)
		case "finding", "findings":
			if operation == "finding" && scope.FindingID == "" {
				fail(w, 400, "finding_required")
				return
			}
			if (operation == "finding" && scope.After != "") || (operation == "findings" && scope.FindingID != "") {
				fail(w, 400, "invalid_cursor")
				return
			}
			value, err = s.store.Findings(ctx, scope.ProjectID, scope.RunID, scope.FindingID, scope.After)
		case "report":
			if scope.TaskID != "" || scope.EvidenceID != "" || scope.FindingID != "" || scope.After != "" || scope.Reason != "" || scope.StateReconciled {
				fail(w, 400, "run_scope_required")
				return
			}
			value, err = s.store.Report(ctx, scope.ProjectID, scope.RunID)
		case "run":
			value, err = s.store.GetRun(ctx, scope.ProjectID, scope.RunID)
		case "task":
			value, err = s.store.GetTask(ctx, scope.ProjectID, scope.RunID, scope.TaskID)
		case "claim":
			value, err = s.store.Claim(ctx, scope.ProjectID, scope.RunID, principal.Subject)
		case "cancel":
			err = s.store.Cancel(ctx, scope.ProjectID, scope.RunID, scope.TaskID, scope.Reason)
		case "reap":
			var n int
			n, err = s.store.Reap(ctx, scope.ProjectID, scope.RunID)
			value = map[string]int{"reaped": n}
		case "resume":
			err = s.store.Resume(ctx, scope.ProjectID, scope.RunID, scope.TaskID, scope.Reason, scope.StateReconciled)
		case "close":
			err = s.store.CloseRun(ctx, scope.ProjectID, scope.RunID)
		}
	default:
		fail(w, 404, "not_found")
		return
	}
	if err != nil {
		queueError(w, err)
		return
	}
	respond(w, 200, value)
}

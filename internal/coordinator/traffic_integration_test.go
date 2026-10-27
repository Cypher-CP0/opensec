//go:build integration

package coordinator

import (
	"encoding/json"
	"errors"
	"testing"

	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/runner"
	"example.com/unified-harness/internal/testdb"
	"strings"
)

func TestTrafficAPIRequiresOwnedLiveLeaseAndStoredTask(t *testing.T) {
	p := policy.Policy{Ref: "local-lab-v1", ProjectID: "lab-project", Origins: []string{"http://127.0.0.1:8081"}, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true,
		Repositories: []string{}, MaxInputBytes: 1 << 20, Endpoints: []policy.Endpoint{{Method: "GET", PathTemplate: "/healthz"}},
		Traffic: &policy.TrafficLimits{MinIntervalMS: 1, MaxConcurrent: 1, BackoffSeconds: 1}}
	registry, err := policy.New(t.Context(), []policy.Policy{p}, testdb.Core())
	if err != nil {
		t.Fatal(err)
	}
	_, api, op, wr := setupAPIUsing(t, registry)
	create(t, op)
	var task map[string]any
	_ = json.Unmarshal(testdb.Task(t, "web", "traffic-api", "read_only"), &task)
	task["target"].(map[string]any)["web"].(map[string]any)["seed_urls"] = []string{"http://127.0.0.1:8081/healthz"}
	raw, _ := json.Marshal(task)
	envelope, _ := json.Marshal(EnqueueRequest{Task: raw, Options: queue.EnqueueOptions{MaxAttempts: 1}})
	if _, err = op.Call(t.Context(), "enqueue", envelope); err != nil {
		t.Fatal(err)
	}
	lease, err := wr.Claim(t.Context(), "lab-project", "run-test", "ignored")
	if err != nil {
		t.Fatal(err)
	}
	if lease.Traffic == nil || *lease.Traffic != *p.Traffic {
		t.Fatal("claim omitted authoritative traffic settings")
	}
	info, err := wr.Info(t.Context())
	if err != nil || !info.TrafficAdmission {
		t.Fatal(info, err)
	}
	legacyPolicy := p
	legacyPolicy.Traffic = nil
	legacyPolicy.Endpoints = nil
	legacyRegistry, err := policy.New(t.Context(), []policy.Policy{legacyPolicy}, testdb.Core())
	if err != nil {
		t.Fatal(err)
	}
	mismatched := runner.Handler{Policies: legacyRegistry, Executor: inspectionExecutor{}}
	completion := mismatched.Run(t.Context(), lease)
	if completion.Outcome != "blocked_environment" || completion.Usage == nil || completion.Usage.Requests != 0 || !strings.Contains(completion.Reason, "traffic policy mismatch") {
		t.Fatal("worker could omit coordinator traffic controls", completion)
	}
	request := TrafficRequest{Lease: lease, URL: "http://127.0.0.1:8081/healthz", RequestID: "request-one"}
	for _, token := range []string{opToken, otherToken} {
		code, _ := apiRequest(t, api, token, "traffic-acquire", request)
		if code != 403 {
			t.Fatal("role or worker ownership bypass", code)
		}
	}
	forged := lease
	forged.Token = "forged"
	if _, err = wr.AcquireTraffic(t.Context(), forged, request.URL, "forged"); !errors.Is(err, queue.ErrLease) {
		t.Fatal(err)
	}
	forged = lease
	forged.Spec = json.RawMessage(`{"target":{"mode":"web","web":{"seed_urls":["http://127.0.0.1:8081/admin"]}}}`)
	forged.Reserved.Requests = 100000
	if _, err = wr.AcquireTraffic(t.Context(), forged, "http://127.0.0.1:8081/admin", "wrong-path"); err == nil {
		t.Fatal("caller spec changed target scope")
	}
	grant, err := wr.AcquireTraffic(t.Context(), forged, request.URL, request.RequestID)
	if err != nil || !grant.Granted {
		t.Fatal(grant, err)
	}
	if err = wr.ReleaseTraffic(t.Context(), lease, request.RequestID, 200); err != nil {
		t.Fatal(err)
	}
	scope, _ := json.Marshal(Scope{ProjectID: "lab-project", RunID: "run-test", TaskID: lease.TaskID, Reason: "stop"})
	if _, err = op.Call(t.Context(), "cancel", scope); err != nil {
		t.Fatal(err)
	}
	if _, err = wr.AcquireTraffic(t.Context(), lease, request.URL, "after-cancel"); !errors.Is(err, queue.ErrLease) {
		t.Fatal(err)
	}
	if err = wr.ReleaseTraffic(t.Context(), lease, request.RequestID, 200); err != nil {
		t.Fatal("idempotent cleanup after cancellation", err)
	}
}

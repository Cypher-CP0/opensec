//go:build integration

package coordinator

import (
	"encoding/json"
	"errors"
	"testing"

	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/testdb"
)

func TestMutationTrafficPermitBindsMethodAndSingleAttempt(t *testing.T) {
	origin := "http://127.0.0.1:8081"
	p := policy.Policy{Ref: "local-lab-v1", ProjectID: "lab-project", Origins: []string{origin}, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{}, MaxInputBytes: 1 << 20,
		Endpoints: []policy.Endpoint{{Method: "GET", PathTemplate: "/healthz"}, {Method: "GET", PathTemplate: "/objects/{id}", AllowQuery: true}, {Method: "POST", PathTemplate: "/objects/{id}", AllowQuery: true}},
		Traffic:   &policy.TrafficLimits{MinIntervalMS: 1, MaxConcurrent: 1, BackoffSeconds: 1}}
	registry, err := policy.New(t.Context(), []policy.Policy{p}, testdb.Core())
	if err != nil {
		t.Fatal(err)
	}
	store, _, op, wr := setupAPIUsing(t, registry)
	create(t, op)
	var doc map[string]any
	_ = json.Unmarshal(testdb.Task(t, "web", "mutation-task", "requires_reconciliation"), &doc)
	doc["web_investigator"] = map[string]any{"profile_ref": "web-cli", "max_steps": 2, "identity_refs": []string{}, "allow_mutations": true}
	web := doc["target"].(map[string]any)["web"].(map[string]any)
	web["seed_urls"] = []string{origin + "/healthz"}
	budget := doc["budget"].(map[string]any)
	budget["max_model_tokens"] = 100
	budget["max_requests"] = 3
	budget["max_artifact_bytes"] = 262144
	raw, _ := json.Marshal(doc)
	if err = store.Enqueue(t.Context(), raw, queue.EnqueueOptions{MaxAttempts: 2}); !errors.Is(err, queue.ErrInvalid) {
		t.Fatal("mutation retry accepted", err)
	}
	if err = store.Enqueue(t.Context(), raw, queue.EnqueueOptions{MaxAttempts: 1}); err != nil {
		t.Fatal(err)
	}
	lease, err := wr.Claim(t.Context(), "lab-project", "run-test", "worker-one")
	if err != nil {
		t.Fatal(err)
	}
	url := origin + "/objects/a?mode=check"
	permit, err := wr.AcquireTrafficMethod(t.Context(), lease, url, "POST", "mutation-one")
	if err != nil || !permit.Granted {
		t.Fatal(permit, err)
	}
	if _, err = wr.AcquireTrafficMethod(t.Context(), lease, url, "GET", "mutation-one"); !errors.Is(err, queue.ErrConflict) {
		t.Fatal("permit changed method", err)
	}
	if err = wr.ReleaseTraffic(t.Context(), lease, "mutation-one", 201); err != nil {
		t.Fatal(err)
	}
	if _, err = wr.AcquireTrafficMethod(t.Context(), lease, origin+"/objects/a", "DELETE", "mutation-two"); !errors.Is(err, queue.ErrInvalid) {
		t.Fatal("undeclared write admitted", err)
	}
}

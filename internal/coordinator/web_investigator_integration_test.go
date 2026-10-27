//go:build integration

package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/testdb"
	"example.com/unified-harness/internal/webinvestigator"
	"example.com/unified-harness/internal/worker"
)

type webScriptModel struct {
	calls  int
	origin string
}

func (m *webScriptModel) Call(_ context.Context, _ []byte) (webinvestigator.Action, int64, error) {
	m.calls++
	if m.calls == 1 {
		return webinvestigator.Action{Kind: "request", URL: m.origin + "/healthz"}, 10, nil
	}
	return webinvestigator.Action{Kind: "propose", Rationale: "Response needs independent confirmation", ObservationIDs: []int{0}}, 10, nil
}

type webScriptTool struct{ origin string }

func (t webScriptTool) Execute(_ context.Context, _ webinvestigator.Action) (webinvestigator.ToolResult, error) {
	return webinvestigator.ToolResult{BrowserVersion: "scripted-browser", Admissions: 1, Events: []webinvestigator.NetworkEvent{{URL: t.origin + "/healthz", Method: "GET", Status: 200, BodyBytes: 2}}, Text: "ok"}, nil
}
func TestWebCandidateIsStoredButNotPromotedToFinding(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer target.Close()
	p := policy.Policy{Ref: "local-lab-v1", ProjectID: "lab-project", Origins: []string{target.URL}, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{}, MaxInputBytes: 1 << 20,
		Endpoints: []policy.Endpoint{{Method: "GET", PathTemplate: "/healthz"}}, Traffic: &policy.TrafficLimits{MinIntervalMS: 1, MaxConcurrent: 1, BackoffSeconds: 1}}
	registry, err := policy.New(t.Context(), []policy.Policy{p}, testdb.Core())
	if err != nil {
		t.Fatal(err)
	}
	store, _, op, wr := setupAPIUsing(t, registry)
	evidenceStore(t, store)
	create(t, op)
	var doc map[string]any
	_ = json.Unmarshal(testdb.Task(t, "web", "web-candidate", "read_only"), &doc)
	web := doc["target"].(map[string]any)["web"].(map[string]any)
	web["origin"] = target.URL
	web["seed_urls"] = []string{target.URL + "/healthz"}
	doc["web_investigator"] = map[string]any{"profile_ref": "test-web", "max_steps": 3, "identity_refs": []string{}, "allow_mutations": false}
	budget := doc["budget"].(map[string]any)
	budget["max_model_tokens"] = 100
	budget["max_requests"] = 3
	budget["max_artifact_bytes"] = 262144
	raw, _ := json.Marshal(doc)
	envelope, _ := json.Marshal(EnqueueRequest{Task: raw, Options: queue.EnqueueOptions{MaxAttempts: 1}})
	if _, err = op.Call(t.Context(), "enqueue", envelope); err != nil {
		t.Fatal(err)
	}
	h := tenantHandler(t, target.URL, true)
	h.Policies = registry
	h.Broker.Policies = registry
	h.TrafficStore = wr
	h.WebProfiles = []webinvestigator.Profile{{ID: "test-web", ProjectID: "lab-project", PolicyRef: "local-lab-v1", Origin: target.URL, MaxCalls: 3, MaxPromptBytes: 65536, AllowTargetDisclosure: true}}
	h.WebModelAdapter = func(webinvestigator.Profile) webinvestigator.Model { return &webScriptModel{origin: target.URL} }
	h.WebToolFactory = func(context.Context, queue.Lease, policy.Policy, webinvestigator.Spec) (webinvestigator.Tool, func() error, error) {
		return webScriptTool{origin: target.URL}, func() error { return nil }, nil
	}
	w := worker.Worker{Store: wr, ProjectID: "lab-project", RunID: "run-test", WorkerID: "worker-one", HeartbeatEvery: time.Second}
	status, err := w.RunOnce(t.Context(), h.Run)
	if err != nil || status != "succeeded" {
		t.Fatal(status, err)
	}
	task, err := store.GetTask(t.Context(), "lab-project", "run-test", "web-candidate")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Web        webinvestigator.Report `json:"web_investigation"`
		EvidenceID string                 `json:"web_evidence_id"`
	}
	if json.Unmarshal(task.Result, &result) != nil || result.Web.Status != "candidate" || result.EvidenceID == "" {
		t.Fatalf("%s", task.Result)
	}
	evidence, err := store.GetEvidence(t.Context(), "lab-project", "run-test", result.EvidenceID)
	if err != nil || evidence.Record.Payload.Kind != "browser_observation" {
		t.Fatal(evidence.Record, err)
	}
	if page, err := store.Findings(t.Context(), "lab-project", "run-test", "", ""); err != nil || len(page.Findings) != 0 {
		t.Fatal(page, err)
	}
	runReport, err := store.Report(t.Context(), "lab-project", "run-test")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, item := range runReport.Tasks {
		if item.ID == "web-candidate" {
			found = true
			if item.CandidateStatus != "needs_validation" || item.EvidenceID != result.EvidenceID {
				t.Fatalf("candidate report did not bind evidence: %+v", item)
			}
		}
	}
	if !found {
		t.Fatal("candidate missing from run report")
	}
}

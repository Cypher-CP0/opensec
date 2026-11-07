//go:build integration

package coordinator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/lab"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/testdb"
	"example.com/unified-harness/internal/webinvestigator"
	"example.com/unified-harness/internal/worker"
)

type candidateModel struct {
	calls int
	url   string
}

func (m *candidateModel) Call(context.Context, []byte) (webinvestigator.Action, int64, error) {
	m.calls++
	if m.calls == 1 {
		return webinvestigator.Action{Kind: "request", URL: m.url, IdentityRef: "tenant-a-reader"}, 10, nil
	}
	return webinvestigator.Action{Kind: "propose", Rationale: "Account A appeared to read B's export; check it independently", ObservationIDs: []int{0}}, 10, nil
}

type candidateTool struct{ url string }

func (t candidateTool) Execute(context.Context, webinvestigator.Action) (webinvestigator.ToolResult, error) {
	return webinvestigator.ToolResult{Admissions: 1, BrowserVersion: "scripted-browser",
		Events: []webinvestigator.NetworkEvent{{URL: t.url, Method: "GET", IdentityRef: "tenant-a-reader", Status: 200, BodyBytes: 2}},
		Text:   "untrusted candidate response"}, nil
}

func TestWebCandidateIndependentValidation(t *testing.T) {
	for _, scenario := range []string{"vulnerable", "patched-before-replay"} {
		t.Run(scenario, func(t *testing.T) {
			vulnerable, _ := lab.New("vulnerable")
			patched, _ := lab.New("patched")
			var repaired atomic.Bool
			var targetCalls atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetCalls.Add(1)
				if repaired.Load() {
					patched.ServeHTTP(w, r)
				} else {
					vulnerable.ServeHTTP(w, r)
				}
			}))
			defer target.Close()
			registry, err := policy.New(t.Context(), []policy.Policy{{
				Ref: "local-lab-v1", ProjectID: "lab-project", Origins: []string{target.URL},
				CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{}, MaxInputBytes: 1 << 20,
				Endpoints: []policy.Endpoint{{Method: "GET", PathTemplate: "/exports/{id}"}},
				Traffic:   &policy.TrafficLimits{MinIntervalMS: 1, MaxConcurrent: 1, BackoffSeconds: 1},
			}}, testdb.Core())
			if err != nil {
				t.Fatal(err)
			}
			store, api, op, wr := setupAPIUsing(t, registry)
			evidenceStore(t, store)
			create(t, op)
			var doc map[string]any
			_ = json.Unmarshal(testdb.Task(t, "web", "web-candidate", "read_only"), &doc)
			web := doc["target"].(map[string]any)["web"].(map[string]any)
			web["origin"] = target.URL
			web["seed_urls"] = []string{target.URL + "/exports/export-b"}
			doc["web_investigator"] = map[string]any{"profile_ref": "test-web", "max_steps": 3,
				"identity_refs": []string{"tenant-a-reader", "tenant-b-reader"}, "allow_mutations": false}
			budget := doc["budget"].(map[string]any)
			budget["max_model_tokens"] = 100
			budget["max_requests"] = 3
			budget["max_artifact_bytes"] = 262144
			sourceRaw, _ := json.Marshal(doc)
			envelope, _ := json.Marshal(EnqueueRequest{Task: sourceRaw, Options: queue.EnqueueOptions{MaxAttempts: 1}})
			if _, err = op.Call(t.Context(), "enqueue", envelope); err != nil {
				t.Fatal(err)
			}
			handler := tenantHandler(t, target.URL, true)
			handler.Policies = registry
			handler.Broker.Policies = registry
			handler.TrafficStore = wr
			handler.WebProfiles = []webinvestigator.Profile{{ID: "test-web", ProjectID: "lab-project", PolicyRef: "local-lab-v1",
				Origin: target.URL, MaxCalls: 3, MaxPromptBytes: 65536, AllowTargetDisclosure: true}}
			crossURL := target.URL + "/exports/export-b"
			handler.WebModelAdapter = func(webinvestigator.Profile) webinvestigator.Model { return &candidateModel{url: crossURL} }
			handler.WebToolFactory = func(context.Context, queue.Lease, policy.Policy, webinvestigator.Spec) (webinvestigator.Tool, func() error, error) {
				return candidateTool{url: crossURL}, func() error { return nil }, nil
			}
			w := worker.Worker{Store: wr, ProjectID: "lab-project", RunID: "run-test", WorkerID: "worker-one", HeartbeatEvery: time.Second}
			if status, err := w.RunOnce(t.Context(), handler.Run); err != nil || status != "succeeded" {
				t.Fatal(status, err)
			}
			if targetCalls.Load() != 0 || len(findings(t, op).Findings) != 0 {
				t.Fatal("candidate was treated as a validated finding")
			}
			sourceTask, err := store.GetTask(t.Context(), "lab-project", "run-test", "web-candidate")
			if err != nil {
				t.Fatal(err)
			}
			var sourceResult struct {
				EvidenceID string `json:"web_evidence_id"`
			}
			if json.Unmarshal(sourceTask.Result, &sourceResult) != nil || sourceResult.EvidenceID == "" {
				t.Fatal("candidate evidence missing")
			}
			plan := checks.Plan{Kind: "object_authorization", IdentityA: "tenant-a-reader", IdentityB: "tenant-b-reader",
				Object: &checks.ObjectCheck{PathTemplate: "/exports/{id}", ResourceA: "export-a", ResourceB: "export-b",
					OwnerA: "tenant-a", OwnerB: "tenant-b",
					Response: checks.ObjectResponse{ResourceID: "/export_id", OwnerID: "/tenant_id", ProtectedValue: "/content"}}}
			input := queue.CandidateValidationRequest{ProjectID: "lab-project", RunID: "run-test", CandidateEvidenceID: sourceResult.EvidenceID,
				Plan: plan, MaxAttempts: 1, DeadlineSeconds: 300, MaxWallSeconds: 60, MaxArtifactBytes: 65536}
			if code, _ := apiRequest(t, api, workerToken, "validate-candidate", input); code != 403 {
				t.Fatal("worker scheduled candidate validation", code)
			}
			wrong := input
			wrong.Plan.Object = &checks.ObjectCheck{PathTemplate: "/other/{id}", ResourceA: "export-a", ResourceB: "export-b",
				OwnerA: "tenant-a", OwnerB: "tenant-b", Response: plan.Object.Response}
			if code, _ := apiRequest(t, api, opToken, "validate-candidate", wrong); code != 400 {
				t.Fatal("unrelated plan was accepted", code)
			}
			request, _ := json.Marshal(input)
			raw, err := op.Call(t.Context(), "validate-candidate", request)
			if err != nil {
				t.Fatal(err)
			}
			var scheduled queue.CandidateValidation
			if err = json.Unmarshal(raw, &scheduled); err != nil {
				t.Fatal(err)
			}
			repeated, err := op.Call(t.Context(), "validate-candidate", request)
			if err != nil || string(repeated) != string(raw) {
				t.Fatal("candidate scheduling was not idempotent", err)
			}
			run, err := store.GetRun(t.Context(), "lab-project", "run-test")
			if err != nil || run.TaskCount != 3 {
				t.Fatal(run, err)
			}
			if status, err := w.RunOnce(t.Context(), handler.Run); err != nil || status != "succeeded" {
				t.Fatal("positive controls", status, err)
			}
			if targetCalls.Load() != 2 || len(findings(t, op).Findings) != 0 {
				t.Fatal("positive controls created a finding")
			}
			if status, err := w.RunOnce(t.Context(), handler.Run); err != nil || status != "succeeded" {
				t.Fatal("fresh discovery", status, err)
			}
			page := findings(t, op)
			if len(page.Findings) != 1 || page.Findings[0].Status != "pending_validation" ||
				page.Findings[0].CandidateEvidenceID != sourceResult.EvidenceID ||
				page.Findings[0].DiscoveryTaskID != scheduled.DiscoveryTaskID {
				t.Fatal(page)
			}
			if scenario == "patched-before-replay" {
				repaired.Store(true)
			}
			if status, err := w.RunOnce(t.Context(), handler.Run); err != nil || status != "succeeded" {
				t.Fatal("independent replay", status, err)
			}
			page = findings(t, op)
			want := "confirmed"
			if scenario == "patched-before-replay" {
				want = "not_reproduced"
			}
			if len(page.Findings) != 1 || page.Findings[0].Status != want ||
				page.Findings[0].CandidateEvidenceID != sourceResult.EvidenceID ||
				page.Findings[0].ValidationEvidenceID == nil ||
				*page.Findings[0].ValidationEvidenceID == page.Findings[0].DiscoveryEvidenceID ||
				targetCalls.Load() != 8 {
				t.Fatal(page, targetCalls.Load())
			}
			report := runReport(t, op)
			linkedTasks := 0
			for _, task := range report.Tasks {
				if task.CandidateEvidenceID == sourceResult.EvidenceID {
					linkedTasks++
				}
			}
			if linkedTasks != 2 {
				t.Fatal("run report lost validation task links", report.Tasks)
			}
			if len(report.Findings) != 1 || report.Findings[0].CandidateEvidenceID != sourceResult.EvidenceID {
				t.Fatal("run report lost candidate link", report.Findings)
			}
		})
	}
}

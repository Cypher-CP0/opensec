package webinvestigator

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

type scriptedModel struct {
	actions []Action
	next    int
}

func (m *scriptedModel) Call(_ context.Context, _ []byte) (Action, int64, error) {
	a := m.actions[m.next]
	m.next++
	return a, 10, nil
}

type scriptedTool struct {
	calls  int
	result ToolResult
}

func (t *scriptedTool) Execute(_ context.Context, _ Action) (ToolResult, error) {
	t.calls++
	return t.result, nil
}

func webSpec(t *testing.T, mutation bool) Spec {
	t.Helper()
	now := time.Now().UTC()
	retry := "read_only"
	if mutation {
		retry = "requires_reconciliation"
	}
	raw, _ := json.Marshal(map[string]any{
		"schema_version": 1, "project_id": "project", "run_id": "run", "task_id": "task", "policy_ref": "policy",
		"created_at": now, "deadline": now.Add(time.Hour), "retry_class": retry,
		"web_investigator": Config{ProfileRef: "profile", MaxSteps: 3, IdentityRefs: []string{"reader"}, AllowMutations: mutation},
		"budget":           map[string]any{"max_model_tokens": 1000, "max_requests": 3, "max_artifact_bytes": 262144, "max_wall_seconds": 120},
		"target":           map[string]any{"mode": "web", "web": map[string]any{"origin": "http://127.0.0.1:8081", "deployment_id": "deployment", "observation_id": "observation", "seed_urls": []string{"http://127.0.0.1:8081/healthz"}}},
	})
	s, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func TestCandidateRequiresObservedRequestAndPreservesEvidenceBinding(t *testing.T) {
	s := webSpec(t, false)
	model := &scriptedModel{actions: []Action{
		{Kind: "request", URL: "http://127.0.0.1:8081/healthz", IdentityRef: "reader"},
		{Kind: "propose", Rationale: "Observed a response worth independent checking", ObservationIDs: []int{0}},
	}}
	tool := &scriptedTool{result: ToolResult{BrowserVersion: "123.0", Admissions: 1, Events: []NetworkEvent{{URL: "http://127.0.0.1:8081/healthz", Method: "GET", IdentityRef: "reader", Status: 200, BodyBytes: 2}}, Text: "ok"}}
	report := Run(context.Background(), s, model, tool, 65536)
	if report.Status != "candidate" || report.Requests != 1 || report.Validate(s) != nil {
		t.Fatalf("%+v", report)
	}
	evidence := NewEvidence(s, "attempt", report, time.Now().UTC())
	if evidence.Record.Payload.Kind != "browser_observation" || evidence.Record.Payload.BrowserVersion != "123.0" || evidence.Record.Artifact.Bytes != int64(len(evidence.Artifact)) {
		t.Fatalf("%+v", evidence.Record)
	}
	summary := Summary(report, "attempt")
	if !json.Valid(summary) || tool.calls != 1 {
		t.Fatal("invalid summary or tool execution")
	}
}
func TestMutationNeedsTaskAuthority(t *testing.T) {
	s := webSpec(t, false)
	model := &scriptedModel{actions: []Action{{Kind: "request", URL: "http://127.0.0.1:8081/objects/a", Method: "POST", Body: "x"}}}
	tool := &scriptedTool{}
	report := Run(context.Background(), s, model, tool, 65536)
	if report.Status != "invalid_action" || tool.calls != 0 {
		t.Fatalf("%+v", report)
	}
	if err := (Action{Kind: "click", Selector: "#save", AllowMutation: true}).ValidFor(s); err == nil {
		t.Fatal("click mutation allowed without task authority")
	}
	s = webSpec(t, true)
	if err := (Action{Kind: "request", URL: "http://127.0.0.1:8081/objects/a", Method: "POST", Body: "x"}).ValidFor(s); err != nil {
		t.Fatal(err)
	}
}
func TestAdmissionsCountEvenWithoutResponseAndOriginMustMatch(t *testing.T) {
	s := webSpec(t, false)
	model := &scriptedModel{actions: []Action{{Kind: "request", URL: "http://127.0.0.1:8081/healthz"}, {Kind: "stop"}}}
	tool := &scriptedTool{result: ToolResult{BrowserVersion: "123", Admissions: 1, Text: "request failed"}}
	report := Run(context.Background(), s, model, tool, 65536)
	if report.Status != "no_candidate" || report.Requests != 1 {
		t.Fatalf("%+v", report)
	}
	report.Observations = []NetworkEvent{{ID: 0, URL: "http://127.0.0.1:8081.evil/healthz", Method: "GET", Status: 200}}
	if report.Validate(s) == nil {
		t.Fatal("origin prefix bypass accepted")
	}
}
func TestActionDecoderRejectsUnsupportedMethodAndExtraFields(t *testing.T) {
	for _, raw := range []string{
		`{"kind":"request","url":"http://127.0.0.1:8081/","method":"TRACE"}`,
		`{"kind":"request","url":"http://127.0.0.1:8081/","method":"GET","body":"x"}`,
		`{"kind":"stop","unknown":true}`,
	} {
		if _, err := DecodeAction([]byte(raw)); err == nil {
			t.Fatal(raw)
		}
	}
}

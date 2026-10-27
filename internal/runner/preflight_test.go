package runner

import (
	"testing"

	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/policy"
)

func TestInspectorPreflightAcceptsOnlyTwoPositiveControls(t *testing.T) {
	p := checks.Plan{Kind: "object_authorization", IdentityA: "reader-a", IdentityB: "reader-b", Object: &checks.ObjectCheck{
		PathTemplate: "/objects/{id}", ResourceA: "a", ResourceB: "b", Response: checks.ObjectResponse{ResourceID: "/id", ProtectedValue: "/private"},
	}}
	input := Input{Preflight: true, Check: &p, Observations: []policy.Observation{
		{Status: 200, Body: []byte(`{"id":"a","private":"secret-a"}`)},
		{Status: 200, Body: []byte(`{"id":"b","private":"secret-b"}`)},
	}}
	r, err := Inspect(input)
	if err != nil || r.Check == nil || r.Check.Verdict != "ready" || r.SecurityJudgment != "preflight_only" {
		t.Fatal(r, err)
	}
	input.Observations = append(input.Observations, input.Observations[1])
	if _, err = Inspect(input); err == nil {
		t.Fatal("preflight accepted third response")
	}
	if _, err = Inspect(Input{Preflight: true}); err == nil {
		t.Fatal("preflight accepted missing plan")
	}
}

package checks

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTenantVerdictsRequireControlsOwnershipAndContent(t *testing.T) {
	a := Summarize(200, []byte(`{"export_id":"export-a","tenant_id":"tenant-a","content":"a","unknown":"secret"}`), "export-a", "tenant-a")
	b := Summarize(200, []byte(`{"export_id":"export-b","tenant_id":"tenant-b","content":"secret"}`), "export-b", "tenant-b")
	base := Transcript{Version: Version, Observations: []Observation{a, b, b}}
	if r := Evaluate(base); r.Verdict != "vulnerable" {
		t.Fatal(r)
	}
	raw, _ := json.Marshal(base)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "unknown") {
		t.Fatal("response content leaked", string(raw))
	}
	for _, tc := range []struct {
		name   string
		index  int
		change func(*Observation)
		want   string
	}{
		{"missing control", 0, func(o *Observation) { o.Status = 401 }, "inconclusive"},
		{"wrong owner", 2, func(o *Observation) { o.TenantMatches = false }, "inconclusive"},
		{"wrong content", 2, func(o *Observation) { o.ContentSHA256 = a.ContentSHA256 }, "inconclusive"},
		{"wrong export", 2, func(o *Observation) { o.ExportMatches = false }, "inconclusive"},
		{"denied", 2, func(o *Observation) { o.Status = 404 }, "not_vulnerable"},
		{"unauthenticated", 2, func(o *Observation) { o.Status = 401 }, "inconclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := base
			v.Observations = append([]Observation{}, base.Observations...)
			tc.change(&v.Observations[tc.index])
			if r := Evaluate(v); r.Verdict != tc.want {
				t.Fatal(r)
			}
		})
	}
}

func TestDuplicateResponseKeysAreInconclusive(t *testing.T) {
	o := Summarize(200, []byte(`{"export_id":"a","export_id":"b","tenant_id":"b","content":"secret"}`), "b", "b")
	if o.ExportMatches || o.TenantMatches || o.ContentSHA256 != "" {
		t.Fatal("ambiguous ownership accepted", o)
	}
}

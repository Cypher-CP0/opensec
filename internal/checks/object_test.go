package checks

import (
	"encoding/json"
	"strings"
	"testing"
)

func objectPlan() Plan {
	return Plan{Kind: "object_authorization", IdentityA: "reader-a", IdentityB: "reader-b", Object: &ObjectCheck{
		PathTemplate: "/api/invoices/{id}/detail", ResourceA: "invoice-a", ResourceB: "invoice-b", OwnerA: "account-a", OwnerB: "account-b",
		Response: ObjectResponse{ResourceID: "/data/id", OwnerID: "/data/owner", ProtectedValue: "/data/private"},
	}}
}
func objectBody(id, owner, private string) []byte {
	raw, _ := json.Marshal(map[string]any{"timestamp": "dynamic", "data": map[string]any{"id": id, "owner": owner, "private": map[string]string{"text": private}}})
	return raw
}
func TestObjectAuthorizationRequiresProtectedControls(t *testing.T) {
	p := objectPlan()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	a := SummarizePlan(p, 200, objectBody("invoice-a", "account-a", "PRIVATE-A"), 0)
	b := SummarizePlan(p, 200, objectBody("invoice-b", "account-b", "PRIVATE-B"), 1)
	base := Transcript{Version: ObjectVersion, Observations: []Observation{a, b, b}}
	if r := Evaluate(base); r.Verdict != "vulnerable" || r.Kind != ObjectVersion {
		t.Fatal(r)
	}
	artifact, _ := json.Marshal(base)
	if strings.Contains(string(artifact), "PRIVATE-") || strings.Contains(string(artifact), "account-b") {
		t.Fatal("protected content leaked")
	}
	for _, tc := range []struct {
		name   string
		change func(*Transcript)
		want   string
	}{
		{"denied", func(t *Transcript) { t.Observations[2].Status = 403 }, "not_vulnerable"},
		{"not-found", func(t *Transcript) { t.Observations[2].Status = 404 }, "not_vulnerable"},
		{"expired-auth", func(t *Transcript) { t.Observations[0].Status = 401 }, "inconclusive"},
		{"wrong-object", func(t *Transcript) { t.Observations[2].ExportMatches = false }, "inconclusive"},
		{"wrong-owner", func(t *Transcript) { t.Observations[2].TenantMatches = false }, "inconclusive"},
		{"changed-data", func(t *Transcript) { t.Observations[2].ContentSHA256 = a.ContentSHA256 }, "inconclusive"},
		{"same-control-data", func(t *Transcript) { t.Observations[0] = b }, "inconclusive"},
		{"missing-response", func(t *Transcript) { t.Observations = t.Observations[:2] }, "inconclusive"},
		{"rate-limit", func(t *Transcript) { t.Observations[2].Status = 429 }, "inconclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := base
			v.Observations = append([]Observation{}, base.Observations...)
			tc.change(&v)
			if r := Evaluate(v); r.Verdict != tc.want {
				t.Fatal(r)
			}
		})
	}
}
func TestObjectSelectorsRejectAmbiguousOrMissingData(t *testing.T) {
	p := objectPlan()
	for _, body := range []string{
		`{"data":{"id":"invoice-b","id":"invoice-a","owner":"account-b","private":{"x":"secret"}}}`,
		`{"data":{"id":"invoice-b","owner":"account-b","private":{"x":"a","x":"b"}}}`,
		`{"data":{"id":"invoice-b","owner":"account-b","private":null}}`,
		`{"data":{"id":"invoice-b","owner":"account-b","private":true}}`,
		`{"data":{"id":"invoice-b","owner":"account-b","private":123}}`,
		`{"data":{"id":"invoice-b","owner":"account-b","private":[]}}`,
		`{"data":{"id":"invoice-b","owner":"account-b"}}`,
		`{"data":{"id":"invoice-b","owner":"account-b","private":"secret"}} {}`,
	} {
		o := SummarizePlan(p, 200, []byte(body), 1)
		if o.ContentSHA256 != "" {
			t.Fatal("accepted ambiguous control", body, o)
		}
	}
	p.Object.Response = ObjectResponse{ResourceID: "/rows/0/id", ProtectedValue: "/rows/0/a~1b~0c"}
	p.Object.OwnerA, p.Object.OwnerB = "", ""
	o := SummarizePlan(p, 200, []byte(`{"rows":[{"id":"invoice-b","a/b~c":"secret"}]}`), 1)
	if !o.ExportMatches || !o.TenantMatches || o.ContentSHA256 == "" {
		t.Fatal(o)
	}
	p.Object.ResourceB = "123"
	o = SummarizePlan(p, 200, []byte(`{"rows":[{"id":123,"a/b~c":"secret"}]}`), 1)
	if !o.ExportMatches {
		t.Fatal(o)
	}
}
func TestObjectPlansRejectScopeAndSelectorAmbiguity(t *testing.T) {
	for _, change := range []func(*Plan){
		func(p *Plan) { p.IdentityB = p.IdentityA },
		func(p *Plan) { p.TenantA = "mixed" },
		func(p *Plan) { p.Object.ResourceB = p.Object.ResourceA },
		func(p *Plan) { p.Object.PathTemplate = "https://other.test/{id}" },
		func(p *Plan) { p.Object.PathTemplate = "//other.test/{id}" },
		func(p *Plan) { p.Object.PathTemplate = "/api/../{id}" },
		func(p *Plan) { p.Object.PathTemplate = "/api/%2e/{id}" },
		func(p *Plan) { p.Object.PathTemplate = "/api/{id}?next=other" },
		func(p *Plan) { p.Object.PathTemplate = "/api/prefix-{id}" },
		func(p *Plan) { p.Object.PathTemplate = "/api/{id}/{id}" },
		func(p *Plan) { p.Object.Response.ResourceID = "/bad~2" },
		func(p *Plan) { p.Object.Response.ProtectedValue = p.Object.Response.ResourceID },
		func(p *Plan) { p.Object.Response.OwnerID = "" },
		func(p *Plan) { p.Object.OwnerB = p.Object.OwnerA },
	} {
		p := objectPlan()
		change(&p)
		if p.Validate() == nil {
			t.Fatal("accepted", p)
		}
	}
}

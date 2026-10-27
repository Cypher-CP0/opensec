package policy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestBrokerEnforcesExplicitMutationMethodPathAndQuery(t *testing.T) {
	var writes atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writes.Add(1)
		if r.Method != "POST" || r.URL.Path != "/objects/a" || r.URL.RawQuery != "mode=check" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL)
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte("created"))
	}))
	defer target.Close()
	p := Policy{Ref: "policy", ProjectID: "project", Origins: []string{target.URL}, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{}, MaxInputBytes: 1 << 20,
		Endpoints: []Endpoint{{Method: "GET", PathTemplate: "/healthz"}, {Method: "POST", PathTemplate: "/objects/{id}", AllowQuery: true}}}
	registry, err := New(t.Context(), []Policy{p}, testCore(t))
	if err != nil {
		t.Fatal(err)
	}
	broker := Broker{Policies: registry}
	probe := Probe{URL: target.URL + "/objects/a?mode=check", Method: "POST", Body: []byte("{}"), Headers: map[string]string{"Content-Type": "application/json"}}
	obs, n, _, err := broker.FetchProbes(context.Background(), p, []Probe{probe}, 1, 1024)
	if err != nil || n != 1 || len(obs) != 1 || obs[0].Status != 201 || writes.Load() != 1 {
		t.Fatalf("%+v %d %v", obs, n, err)
	}
	for _, denied := range []Probe{
		{URL: target.URL + "/objects/a", Method: "DELETE"},
		{URL: target.URL + "/objects/a/extra", Method: "POST"},
		{URL: target.URL + "/healthz", Method: "GET", Body: []byte("mutation")},
	} {
		if _, _, _, err = broker.FetchProbes(context.Background(), p, []Probe{denied}, 1, 1024); err == nil {
			t.Fatal("unauthorized request admitted", denied)
		}
	}
	if writes.Load() != 1 {
		t.Fatal("denied probes reached target")
	}
}

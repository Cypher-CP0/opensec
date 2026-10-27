package policy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type fakeGate struct {
	acquire            func(context.Context, string, string) (TrafficGrant, error)
	release            func(context.Context, string, int) error
	acquired, released int
	status             int
}

func (g *fakeGate) Acquire(ctx context.Context, u, id string) (TrafficGrant, error) {
	g.acquired++
	if g.acquire != nil {
		return g.acquire(ctx, u, id)
	}
	return TrafficGrant{Granted: true, ValidForMS: 10000}, nil
}
func (g *fakeGate) Release(ctx context.Context, id string, status int) error {
	g.released++
	g.status = status
	if g.release != nil {
		return g.release(ctx, id, status)
	}
	return nil
}
func trafficRegistry(t *testing.T, origin string) (*Registry, Policy) {
	t.Helper()
	p := Policy{Ref: "test-policy", ProjectID: "project", Origins: []string{origin}, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{}, MaxInputBytes: 1 << 20,
		Endpoints: []Endpoint{{Method: "GET", PathTemplate: "/objects/{id}"}}, Traffic: &TrafficLimits{MinIntervalMS: 1, MaxConcurrent: 1, BackoffSeconds: 1}}
	r, err := New(t.Context(), []Policy{p}, testCore(t))
	if err != nil {
		t.Fatal(err)
	}
	return r, p
}
func TestTrafficBrokerStopsOnBackoffAndDiscardsErrorBody(t *testing.T) {
	for _, status := range []int{429, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var sent atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sent.Add(1)
				w.Header().Set("Retry-After", "9999999")
				w.WriteHeader(status)
				_, _ = w.Write([]byte("private-error-body"))
			}))
			defer server.Close()
			registry, p := trafficRegistry(t, server.URL)
			gate := &fakeGate{}
			b := Broker{Policies: registry, Gate: gate}
			got, n, size, err := b.Fetch(t.Context(), p, []string{server.URL + "/objects/a", server.URL + "/objects/b"}, 2, 1024)
			if !errors.Is(err, ErrTargetBackoff) || n != 1 || size != 0 || sent.Load() != 1 || len(got) != 1 || len(got[0].Body) != 0 ||
				gate.acquired != 1 || gate.released != 1 || gate.status != status {
				t.Fatal(got, n, size, err, gate)
			}
		})
	}
}
func TestTrafficBrokerPrevalidatesScopeAndRequiresGate(t *testing.T) {
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
	defer server.Close()
	registry, p := trafficRegistry(t, server.URL)
	gate := &fakeGate{}
	b := Broker{Policies: registry, Gate: gate}
	_, n, _, err := b.Fetch(t.Context(), p, []string{server.URL + "/objects/a", server.URL + "/admin"}, 2, 1024)
	if err == nil || n != 0 || sent.Load() != 0 || gate.acquired != 0 {
		t.Fatal("partial out-of-scope batch executed", n, err)
	}
	b.Gate = nil
	_, n, _, err = b.Fetch(t.Context(), p, []string{server.URL + "/objects/a"}, 1, 1024)
	if !errors.Is(err, ErrTrafficUnavailable) || n != 0 || sent.Load() != 0 {
		t.Fatal("traffic policy bypassed", n, err)
	}
}
func TestTrafficBrokerCancellationAndUncertainAdmission(t *testing.T) {
	var sent atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { sent.Add(1) }))
	defer server.Close()
	registry, p := trafficRegistry(t, server.URL)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gate := &fakeGate{acquire: func(context.Context, string, string) (TrafficGrant, error) {
		cancel()
		return TrafficGrant{RetryAfterMS: 1000}, nil
	}}
	b := Broker{Policies: registry, Gate: gate}
	_, n, _, err := b.Fetch(ctx, p, []string{server.URL + "/objects/a"}, 1, 1024)
	if !errors.Is(err, context.Canceled) || n != 0 || sent.Load() != 0 {
		t.Fatal(n, err)
	}
	gate = &fakeGate{acquire: func(context.Context, string, string) (TrafficGrant, error) {
		return TrafficGrant{}, errors.New("transport uncertainty")
	}}
	b.Gate = gate
	_, n, _, err = b.Fetch(t.Context(), p, []string{server.URL + "/objects/a"}, 1, 1024)
	if !errors.Is(err, ErrTrafficUnavailable) || n != 0 || sent.Load() != 0 {
		t.Fatal(n, err)
	}
	gate = &fakeGate{acquire: func(context.Context, string, string) (TrafficGrant, error) {
		return TrafficGrant{Granted: true, ValidForMS: 1}, nil
	}}
	b.Gate = gate
	_, n, _, err = b.Fetch(t.Context(), p, []string{server.URL + "/objects/a"}, 1, 1024)
	if !errors.Is(err, ErrTrafficUnavailable) || n != 1 || gate.released != 1 || sent.Load() != 0 {
		t.Fatal(n, err)
	}
	gate = &fakeGate{release: func(context.Context, string, int) error { return errors.New("transport uncertainty") }}
	b.Gate = gate
	_, n, _, err = b.Fetch(t.Context(), p, []string{server.URL + "/objects/a"}, 1, 1024)
	if !errors.Is(err, ErrTrafficUnavailable) || n != 1 || gate.released != 1 || sent.Load() != 1 {
		t.Fatal(n, err)
	}
}
func TestTrafficPoliciesCannotDisagreeForSameOrigin(t *testing.T) {
	registry, p := trafficRegistry(t, "https://api.example.test")
	other := p
	other.Ref = "other"
	changed := *p.Traffic
	changed.MaxConcurrent = 2
	other.Traffic = &changed
	if _, err := New(t.Context(), []Policy{p, other}, testCore(t)); err == nil {
		t.Fatal("conflicting shared target limits accepted")
	}
	empty := p
	empty.Endpoints = []Endpoint{}
	empty.Traffic = nil
	if _, err := New(t.Context(), []Policy{empty}, testCore(t)); err == nil {
		t.Fatal("empty endpoint rules became unrestricted")
	}
	other.Traffic = nil
	if _, err := New(t.Context(), []Policy{p, other}, testCore(t)); err == nil {
		t.Fatal("uncontrolled alias accepted")
	}
	for _, u := range []string{"https://API.example.test:443/objects/a", "https://api.example.test/objects/a"} {
		origin, err := registry.RequestOrigin(t.Context(), p, u)
		if err != nil || origin != "https://api.example.test" {
			t.Fatal(origin, err)
		}
	}
}

func TestTrafficCanonicalOriginsUseRustSemantics(t *testing.T) {
	registry, p := trafficRegistry(t, "http://127.0.0.1:8081")
	for _, u := range []string{"http://127.1:8081/objects/a", "http://2130706433:8081/objects/a", "http://127.0.0.1:08081/objects/a"} {
		origin, err := registry.RequestOrigin(t.Context(), p, u)
		if err != nil || origin != "http://127.0.0.1:8081" {
			t.Fatal(origin, err)
		}
	}
	alias := p
	alias.Ref = "alias"
	alias.Origins = []string{"http://127.1:8081"}
	different := *p.Traffic
	different.MaxConcurrent = 2
	alias.Traffic = &different
	if _, err := New(t.Context(), []Policy{p, alias}, testCore(t)); err == nil {
		t.Fatal("IPv4 alias bypassed shared limits")
	}
}

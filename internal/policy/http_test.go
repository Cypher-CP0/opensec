package policy

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

func testCore(t *testing.T) string {
	t.Helper()
	name := "harness-core"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p, err := filepath.Abs(filepath.Join("..", "..", "target", "debug", name))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func registry(t *testing.T, origins ...string) (*Registry, Policy) {
	t.Helper()
	p := Policy{Ref: "test-policy", ProjectID: "project", Origins: origins, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{}, MaxInputBytes: 1 << 20}
	r, err := New(t.Context(), []Policy{p}, testCore(t))
	if err != nil {
		t.Fatal(err)
	}
	return r, p
}

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (f resolverFunc) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return f(ctx, network, host)
}

func TestBrokerPinsDNSAndIgnoresProxy(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Error("credential forwarded")
		}
		_, _ = w.Write([]byte("controlled response"))
	}))
	defer target.Close()
	_, port, _ := net.SplitHostPort(target.Listener.Addr().String())
	origin := "http://lab.test:" + port
	policies, p := registry(t, origin)
	var lookups atomic.Int32
	resolver := resolverFunc(func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		lookups.Add(1)
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	})
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	broker := Broker{Policies: policies, Resolver: resolver}
	got, n, b, err := broker.Fetch(t.Context(), p, []string{origin + "/a"}, 1, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || b != int64(len("controlled response")) || len(got) != 1 || requests.Load() != 1 || lookups.Load() != 1 {
		t.Fatal("fetch was not bounded and pinned")
	}
}
func TestBrokerRejectsMixedDNSBeforeConnection(t *testing.T) {
	var requests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer target.Close()
	_, port, _ := net.SplitHostPort(target.Listener.Addr().String())
	origin := "http://lab.test:" + port
	policies, p := registry(t, origin)
	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")}, nil
	})
	_, n, _, err := (Broker{policies, resolver}).Fetch(t.Context(), p, []string{origin}, 1, 100)
	if err == nil || n != 0 || requests.Load() != 0 {
		t.Fatal("mixed DNS answers bypassed policy")
	}
}
func TestBrokerRedirectAndByteLimits(t *testing.T) {
	var redirected atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer destination.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, destination.URL, 302)
			return
		}
		_, _ = w.Write(make([]byte, 2048))
	}))
	defer target.Close()
	policies, p := registry(t, target.URL, destination.URL)
	broker := Broker{Policies: policies}
	_, n, _, err := broker.Fetch(t.Context(), p, []string{target.URL + "/redirect"}, 1, 4096)
	if err == nil || n != 1 || redirected.Load() != 0 {
		t.Fatal("redirect was followed")
	}
	_, n, b, err := broker.Fetch(t.Context(), p, []string{target.URL}, 1, 512)
	if err != ErrLimit || n != 1 || b != 512 {
		t.Fatalf("unbounded response: %d %d %v", n, b, err)
	}
	_, n, _, err = broker.Fetch(t.Context(), p, []string{target.URL, target.URL}, 1, 512)
	if err != ErrLimit || n != 0 {
		t.Fatal("request allowance was exceeded")
	}
}
func TestBrokerDeniesOriginAndMissingDNS(t *testing.T) {
	policies, p := registry(t, "http://allowed.test")
	broker := Broker{Policies: policies, Resolver: resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil })}
	if _, _, _, err := broker.Fetch(t.Context(), p, []string{"http://allowed.test"}, 1, 100); err == nil {
		t.Fatal("empty DNS set accepted")
	}
	if _, _, _, err := broker.Fetch(t.Context(), p, []string{"http://127.0.0.1:1"}, 1, 100); err == nil {
		t.Fatal("unlisted origin accepted")
	}
}

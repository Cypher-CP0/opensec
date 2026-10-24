package policy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestProbeCredentialsAreScopedAndNeverRedirected(t *testing.T) {
	var sent, redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer other.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent.Add(1)
		if r.Header.Get("Authorization") != "Bearer fixture-secret-token" {
			t.Error("expected scoped authentication")
		}
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer target.Close()
	policies, p := registry(t, target.URL, other.URL)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.token"), []byte("fixture-secret-token"), 0600); err != nil {
		t.Fatal(err)
	}
	records := []Credential{{ProjectID: p.ProjectID, PolicyRef: p.Ref, Origin: target.URL, IdentityRef: "reader", TokenFile: "secret.token"}}
	raw, _ := json.Marshal(records)
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	creds, err := LoadCredentials(path)
	if err != nil {
		t.Fatal(err)
	}
	broker := Broker{Policies: policies, Credentials: creds}
	if _, _, _, err = broker.FetchProbes(t.Context(), p, []Probe{{URL: target.URL, IdentityRef: "reader"}}, 1, 1000); err == nil {
		t.Fatal("redirect followed")
	}
	if sent.Load() != 1 || redirected.Load() != 0 {
		t.Fatal("credential could follow redirect")
	}
	for _, tc := range []struct {
		p     Policy
		probe Probe
	}{
		{p, Probe{URL: other.URL, IdentityRef: "reader"}},
		{p, Probe{URL: target.URL, IdentityRef: "unknown"}},
		{Policy{ProjectID: "other", Ref: p.Ref}, Probe{URL: target.URL, IdentityRef: "reader"}},
	} {
		if _, _, _, err = broker.FetchProbes(t.Context(), tc.p, []Probe{tc.probe}, 1, 1000); err == nil {
			t.Fatal("credential scope bypass")
		}
	}
	if sent.Load() != 1 || redirected.Load() != 0 {
		t.Fatal("scope denial still sent a request")
	}
	// Insecure public credential scopes must fail at configuration time.
	records[0].Origin = "http://public.example"
	raw, _ = json.Marshal(records)
	_ = os.WriteFile(path, raw, 0600)
	if _, err = LoadCredentials(path); err == nil {
		t.Fatal("insecure credential origin accepted")
	}
}

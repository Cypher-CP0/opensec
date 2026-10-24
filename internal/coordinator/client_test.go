package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClientRequiresTLSAndRefusesRedirects(t *testing.T) {
	token := strings.Repeat("a", 64)
	for _, url := range []string{"http://example.com", "http://localhost:8090", "https://u:p@example.com", "https://example.com/path", "https://example.com?token=x"} {
		if _, err := NewClient(url, token, ""); err == nil {
			t.Fatal("unsafe API origin accepted", url)
		}
	}
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer destination.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 307) }))
	defer redirect.Close()
	client, err := NewClient(redirect.URL, token, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err = client.Info(context.Background()); err == nil {
		t.Fatal("redirect accepted")
	}
	if leaked.Load() != 0 {
		t.Fatal("API credential sent to redirect target")
	}
}
func TestAuthConfigurationAndHeaderAmbiguity(t *testing.T) {
	token := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(token))
	c := Credential{Subject: "worker", Role: "worker", TokenSHA256: hex.EncodeToString(sum[:]), Scopes: map[string][]string{"p": {"r"}}}
	if _, err := NewAuth([]Credential{c, c}); err == nil {
		t.Fatal("duplicate credential accepted")
	}
	auth, err := NewAuth([]Credential{c})
	if err != nil {
		t.Fatal(err)
	}
	c.Scopes["p"][0] = "*" // Constructor must copy the caller's mutable map.
	request := httptest.NewRequest("POST", "/v1/queue/claim", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	principal, ok := auth.authenticate(request)
	if !ok || principal.allows("p", "other") {
		t.Fatal("authorization scope mutated")
	}
	request.Header.Add("Authorization", "Bearer "+token)
	if _, ok = auth.authenticate(request); ok {
		t.Fatal("ambiguous auth headers accepted")
	}
}

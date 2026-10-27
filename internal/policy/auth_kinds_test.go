package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthKindsStayWorkerLocalAndScoped(t *testing.T) {
	for _, tc := range []struct{ kind, name, secret, header, value string }{
		{"", "", "bearer-secret", "Authorization", "Bearer bearer-secret"},
		{"bearer", "", "bearer-secret", "Authorization", "Bearer bearer-secret"},
		{"cookie", "", "session=private; tenant=a", "Cookie", "session=private; tenant=a"},
		{"api_key", "X-API-Key", "key-secret", "X-API-Key", "key-secret"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "secret.token"), []byte(tc.secret), 0600); err != nil {
				t.Fatal(err)
			}
			record := Credential{ProjectID: "p", PolicyRef: "scope", Origin: "https://api.example.test", IdentityRef: "reader", TokenFile: "secret.token", AuthKind: tc.kind, HeaderName: tc.name}
			raw, _ := json.Marshal([]Credential{record})
			file := filepath.Join(dir, "credentials.json")
			if err := os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			c, err := LoadCredentials(file)
			if err != nil {
				t.Fatal(err)
			}
			h, err := c.header(Policy{ProjectID: "p", Ref: "scope"}, "https://api.example.test/item", "reader")
			if err != nil || h.name != tc.header || h.value != tc.value {
				t.Fatal("wrong scoped auth kind")
			}
			if _, err = c.header(Policy{ProjectID: "other", Ref: "scope"}, "https://api.example.test/item", "reader"); err == nil {
				t.Fatal("scope bypass")
			}
			b, _ := json.Marshal(c)
			if strings.Contains(string(b), tc.secret) {
				t.Fatal("credential serialized")
			}
		})
	}
}
func TestAuthConfigurationRejectsRoutingAndInjection(t *testing.T) {
	base := Credential{ProjectID: "p", PolicyRef: "scope", Origin: "https://api.example.test", IdentityRef: "reader", TokenFile: "secret.token", AuthKind: "api_key"}
	for _, name := range []string{"Host", "Authorization", "Cookie", "Content-Length", "X-Forwarded-Host", "X-Original-URL", "X-HTTP-Method-Override", "X-Key\r\nHost"} {
		c := base
		c.HeaderName = name
		if ValidateCredential(c) == nil {
			t.Fatal("accepted credential header", name)
		}
	}
	base.AuthKind = "browser"
	if ValidateCredential(base) == nil {
		t.Fatal("accepted unsupported auth")
	}
}

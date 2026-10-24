package main

import (
	"bytes"
	"context"
	"example.com/unified-harness/internal/coordinator"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthInitAndInsecureListenerRejection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth")
	var out bytes.Buffer
	if err := run(context.Background(), []string{"auth-init", "--out", path}, &out); err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(filepath.Join(path, "operator.token"))
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 64 || bytes.Contains(out.Bytes(), token) {
		t.Fatal("invalid or leaked generated token")
	}
	if _, err = coordinator.LoadAuth(filepath.Join(path, "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if err = run(context.Background(), []string{"auth-init", "--out", path}, &out); err == nil {
		t.Fatal("existing credentials overwritten")
	}
	if err = run(context.Background(), []string{"serve", "--listen", "0.0.0.0:8090", "--auth", "missing", "--policies", "missing"}, &out); err == nil || err.Error() != "non-loopback API listeners require TLS" {
		t.Fatal("plaintext external listener allowed", err)
	}
}

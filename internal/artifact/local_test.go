package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScopedImmutableArtifactsAndIntegrity(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	raw := []byte(`{"safe":true}`)
	digest := Digest(raw)
	scope := Scope("project", "run")
	if err = s.Put(t.Context(), scope, digest, raw); err != nil {
		t.Fatal(err)
	}
	if err = s.Put(t.Context(), scope, digest, raw); err != nil {
		t.Fatal("idempotency", err)
	}
	if _, err = s.Get(t.Context(), Scope("other", "run"), digest); !os.IsNotExist(err) {
		t.Fatal("cross-project blob leak", err)
	}
	if err = s.Put(t.Context(), scope, digest, []byte("tampered")); err == nil {
		t.Fatal("digest tampering accepted")
	}
	if _, err = s.Get(t.Context(), "../", digest); err == nil {
		t.Fatal("traversal accepted")
	}
	name, _ := key(scope, digest)
	if err = os.WriteFile(filepath.Join(dir, name), []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Get(t.Context(), scope, digest); err == nil {
		t.Fatal("corruption not detected")
	}
	if err = s.Put(t.Context(), scope, digest, raw); err == nil {
		t.Fatal("silently replaced corrupt artifact")
	}
}

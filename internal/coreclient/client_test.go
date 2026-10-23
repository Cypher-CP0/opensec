package coreclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"example.com/unified-harness/internal/lab"
)

func binary(t *testing.T) string {
	t.Helper()
	if override := os.Getenv("HARNESS_CORE_BIN"); override != "" {
		return override
	}
	name := "harness-core"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join("..", "..", "target", "debug", name)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("build the Rust core first: cargo build --locked: %v", err)
	}
	return path
}
func example(t *testing.T, name string) map[string]any {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "examples", name))
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err = json.Unmarshal(content, &value); err != nil {
		t.Fatal(err)
	}
	return value
}
func TestCoreSchemaAndValidationProtocol(t *testing.T) {
	ctx := context.Background()
	bin := binary(t)
	data, err := Call(ctx, bin, map[string]any{"operation": "schemas"})
	if err != nil {
		t.Fatal(err)
	}
	var schemas map[string]any
	if err = json.Unmarshal(data, &schemas); err != nil {
		t.Fatal(err)
	}
	if len(schemas) != 3 {
		t.Fatalf("unexpected schema count: %d", len(schemas))
	}
	for _, mode := range []string{"source", "web", "hybrid"} {
		task := example(t, "task."+mode+".json")
		if _, err = Call(ctx, bin, map[string]any{"operation": "validate", "kind": "task", "document": task}); err != nil {
			t.Fatal(err)
		}
	}
	task := example(t, "task.web.json")
	task["schema_version"] = 2
	if _, err = Call(ctx, bin, map[string]any{"operation": "validate", "kind": "task", "document": task}); err == nil {
		t.Fatal("accepted future schema")
	}
	if _, err = Call(ctx, bin, map[string]any{"operation": "schemas", "unexpected": true}); err == nil {
		t.Fatal("accepted unknown protocol field")
	}
}
func TestLabEvidenceAcrossCompiledBoundary(t *testing.T) {
	for _, variant := range []string{"vulnerable", "patched"} {
		t.Run(variant, func(t *testing.T) {
			handler, err := lab.New(variant)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			client := server.Client()
			client.Timeout = 3 * time.Second
			observe := func(path string) (int, []byte) {
				req, err := http.NewRequest("GET", server.URL+path, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer lab-only-token-a")
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				return response.StatusCode, body
			}
			ownStatus, ownBody := observe("/exports/export-a")
			if ownStatus != 200 {
				t.Fatal("normal control failed")
			}
			var own lab.Export
			if err = json.Unmarshal(ownBody, &own); err != nil || own.Tenant != "tenant-a" {
				t.Fatalf("control: %s", ownBody)
			}
			crossStatus, crossBody := observe("/exports/export-b")
			want := 404
			if variant == "vulnerable" {
				want = 200
			}
			if crossStatus != want {
				t.Fatalf("unexpected runtime result: %d", crossStatus)
			}
			if variant == "vulnerable" {
				var item lab.Export
				if err = json.Unmarshal(crossBody, &item); err != nil || item.Tenant != "tenant-b" || item.ID != "export-b" {
					t.Fatalf("wrong resource: %s", crossBody)
				}
			}
			// Capture only synthetic bodies and an identity reference, never an Authorization header.
			artifact, err := json.Marshal(map[string]any{"control_status": ownStatus, "control_body": string(ownBody), "cross_status": crossStatus, "cross_body": string(crossBody), "identity_ref": "tenant-a-reader"})
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(artifact)
			digest := hex.EncodeToString(hash[:])
			task := example(t, "task.web.json")
			start := time.Now().UTC()
			task["created_at"] = start.Add(-time.Minute).Format(time.RFC3339Nano)
			task["deadline"] = start.Add(time.Minute).Format(time.RFC3339Nano)
			web := task["target"].(map[string]any)["web"].(map[string]any)
			web["origin"] = server.URL
			web["seed_urls"] = []string{server.URL + "/exports"}
			web["deployment_id"] = "lab-" + variant
			evidence := example(t, "evidence.http.json")
			evidence["observed_at"] = start.Format(time.RFC3339Nano)
			evidence["observed_result"] = string(crossBody)
			evidence["limitations"] = []string{"Controlled lab observation; no independent vulnerability verdict."}
			evidence["artifact"] = map[string]any{"sha256": digest, "byte_length": len(artifact), "media_type": "application/json"}
			evidence["payload"].(map[string]any)["deployment_id"] = "lab-" + variant
			bin := binary(t)
			if _, err = Call(context.Background(), bin, map[string]any{"operation": "verify_digest", "sha256": digest, "content": string(artifact)}); err != nil {
				t.Fatal(err)
			}
			if _, err = Call(context.Background(), bin, map[string]any{"operation": "bind_evidence", "task": task, "evidence": evidence}); err != nil {
				t.Fatal(err)
			}
			if _, err = Call(context.Background(), bin, map[string]any{"operation": "verify_digest", "sha256": digest, "content": string(artifact) + "tampered"}); err == nil {
				t.Fatal("accepted tampered artifact")
			}
			evidence["payload"].(map[string]any)["observation_id"] = "different-deployment-version"
			if _, err = Call(context.Background(), bin, map[string]any{"operation": "bind_evidence", "task": task, "evidence": evidence}); err == nil {
				t.Fatal("accepted version mismatch")
			}
		})
	}
}

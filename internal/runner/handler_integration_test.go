//go:build integration

package runner

import (
	"archive/tar"
	"encoding/json"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/testdb"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHandlerSourceWebAndHybrid(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("synthetic observation")) }))
	defer target.Close()
	p := policy.Policy{Ref: "local-lab-v1", ProjectID: "lab-project", Origins: []string{target.URL}, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{"lab-repository"}, MaxInputBytes: 1 << 20}
	policies, err := policy.New(t.Context(), []policy.Policy{p}, testdb.Core())
	if err != nil {
		t.Fatal(err)
	}
	source := archive(t, tar.Header{Name: "src/main.go", Typeflag: tar.TypeReg, Size: 4})
	path := filepath.Join(t.TempDir(), "source.tar")
	if err = os.WriteFile(path, source, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"source", "web", "hybrid"} {
		t.Run(mode, func(t *testing.T) {
			raw := testdb.Task(t, mode, "task", "read_only")
			var doc map[string]any
			_ = json.Unmarshal(raw, &doc)
			targetDoc := doc["target"].(map[string]any)
			if web, ok := targetDoc["web"].(map[string]any); ok {
				web["origin"] = target.URL
				web["seed_urls"] = []string{target.URL + "/healthz"}
			}
			var snapshots []Snapshot
			if src, ok := targetDoc["source"].(map[string]any); ok {
				src["snapshot_sha256"] = digest(source)
				snapshots = []Snapshot{{RepositoryID: src["repository_id"].(string), Commit: src["commit"].(string), SHA256: digest(source), Archive: path}}
			}
			raw, _ = json.Marshal(doc)
			command := &fakeCommand{}
			engine, err := NewDocker(t.Context(), testImage, DefaultLimits(), command)
			if err != nil {
				t.Fatal(err)
			}
			handler := Handler{Policies: policies, Broker: policy.Broker{Policies: policies}, Executor: engine, Snapshots: snapshots}
			lease := queue.Lease{Spec: raw, HardDeadline: time.Now().Add(time.Minute), Reserved: queue.Units{Tokens: 100, Requests: 10, WallSeconds: 60, ArtifactBytes: 65536}}
			completion := handler.Run(t.Context(), lease)
			if completion.Outcome != "succeeded" || completion.Usage == nil {
				t.Fatalf("mode %s failed: %+v", mode, completion)
			}
			if completion.Usage.ArtifactBytes > lease.Reserved.ArtifactBytes || completion.Usage.Tokens != 0 {
				t.Fatal("usage bounds violated")
			}
			var report Report
			if json.Unmarshal(completion.Result, &report) != nil {
				t.Fatal("invalid result")
			}
			if (mode != "web") != (len(report.Files) == 1) || (mode != "source") != (len(report.Responses) == 1) {
				t.Fatalf("mode inputs lost: %+v", report)
			}
			if mode != "source" && completion.Usage.Requests != 1 {
				t.Fatal("HTTP usage not tracked")
			}
			if mode != "web" {
				handler.Snapshots = nil
				if got := handler.Run(t.Context(), lease); got.Outcome != "blocked_environment" {
					t.Fatal("unregistered source was executed")
				}
			}
			command.fail = "start"
			handler.Snapshots = snapshots
			if got := handler.Run(t.Context(), lease); got.Usage != nil || got.Outcome != "blocked_environment" {
				t.Fatal("unknown container consumption refunded")
			}
		})
	}
}

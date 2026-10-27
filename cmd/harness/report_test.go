package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"example.com/unified-harness/internal/queue"
)

func TestReportCommandExportsPrivateSnapshotAndRefusesOverwrite(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/v1/queue/report" || r.Header.Get("Authorization") != "Bearer "+strings.Repeat("a", 64) {
			t.Error("wrong scoped request")
		}
		_ = json.NewEncoder(w).Encode(queue.RunReport{Version: "opensec-run-report-v1", Run: queue.Run{RunConfig: queue.RunConfig{ProjectID: "p", RunID: "r"}, Status: "active"}})
	}))
	defer server.Close()
	dir := t.TempDir()
	token, scope := filepath.Join(dir, "token"), filepath.Join(dir, "scope.json")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(scope, []byte(`{"project_id":"p","run_id":"r"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"markdown", "json"} {
		path := filepath.Join(dir, "report."+format)
		args := []string{"report", "--url", server.URL, "--token-file", token, "--file", scope, "--out", path, "--format", format}
		if err := run(t.Context(), args, new(bytes.Buffer)); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil || len(raw) == 0 || (format == "json" && !json.Valid(raw)) {
			t.Fatal(string(raw), err)
		}
		before := calls.Load()
		if err = run(t.Context(), args, new(bytes.Buffer)); err == nil || calls.Load() != before {
			t.Fatal("overwrite was not rejected before request", err)
		}
	}
	for _, args := range [][]string{{"report"}, {"report", "--format", "html"}, {"report", "unexpected"}} {
		if err := run(t.Context(), args, new(bytes.Buffer)); err == nil {
			t.Fatal(args)
		}
	}
}

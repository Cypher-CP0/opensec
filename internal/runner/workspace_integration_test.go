//go:build container

package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/webinvestigator"
)

func TestRealWorkspaceBrowserShellIsolationAndCleanup(t *testing.T) {
	image := os.Getenv("HARNESS_TEST_WORKSPACE_IMAGE")
	if image == "" {
		t.Fatal("set HARNESS_TEST_WORKSPACE_IMAGE; refusing to skip workspace test")
	}
	workspace, err := NewWorkspaceDocker(t.Context(), image, "../../runtime/workspace/seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	s := webinvestigator.Spec{Investigator: &webinvestigator.Config{MaxSteps: 3}}
	s.Deadline = time.Now().Add(90 * time.Second)
	s.Budget.Requests = 2
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	tool, err := workspace.Open(ctx, s.Deadline, policy.Broker{}, policy.Policy{}, s)
	if err != nil {
		t.Fatal(err)
	}
	name := tool.name
	out, err := tool.Execute(ctx, webinvestigator.Action{Kind: "command", Script: "python3 -c 'print(2+2)'"})
	if err != nil || !strings.Contains(out.Text, "4") {
		t.Fatalf("shell: %+v %v", out, err)
	}
	out, err = tool.Execute(ctx, webinvestigator.Action{Kind: "snapshot"})
	if err != nil || out.BrowserVersion == "" {
		t.Fatalf("browser: %+v %v", out, err)
	}
	out, err = tool.Execute(ctx, webinvestigator.Action{Kind: "command", Script: "python3 -c 'import socket; socket.create_connection((\"1.1.1.1\",443),timeout=1)'"})
	if err != nil || strings.Contains(out.Text, "exit=0") || !(strings.Contains(out.Text, "OSError") || strings.Contains(out.Text, "PermissionError") || strings.Contains(out.Text, "TimeoutError")) {
		t.Fatalf("network isolation: %+v %v", out, err)
	}
	if err = tool.Close(); err != nil {
		t.Fatal(err)
	}
	check, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	if err = boundedDocker(check, "docker", "inspect", name); err == nil {
		t.Fatal("workspace container was not removed")
	}
}

func TestRealWorkspaceRoutesBrowserShellAndScopedMutationThroughBroker(t *testing.T) {
	image := os.Getenv("HARNESS_TEST_WORKSPACE_IMAGE")
	if image == "" {
		t.Fatal("set HARNESS_TEST_WORKSPACE_IMAGE; refusing to skip workspace test")
	}
	var reads, writes atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/page":
			reads.Add(1)
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<link rel="stylesheet" href="http://127.0.0.1:9/blocked.css"><p>Scoped page</p>`))
		case r.Method == "GET" && r.URL.Path == "/healthz":
			reads.Add(1)
			_, _ = w.Write([]byte("healthy"))
		case r.Method == "POST" && r.URL.Path == "/objects/a":
			writes.Add(1)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("created"))
		default:
			t.Errorf("out of scope target request: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer target.Close()
	core, err := filepath.Abs("../../target/debug/harness-core")
	if err != nil {
		t.Fatal(err)
	}
	p := policy.Policy{Ref: "workspace-lab", ProjectID: "lab", Origins: []string{target.URL}, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{}, MaxInputBytes: 1 << 20,
		Endpoints: []policy.Endpoint{{Method: "GET", PathTemplate: "/page"}, {Method: "GET", PathTemplate: "/healthz"}, {Method: "POST", PathTemplate: "/objects/a"}}}
	registry, err := policy.New(t.Context(), []policy.Policy{p}, core)
	if err != nil {
		t.Fatal(err)
	}
	workspace, err := NewWorkspaceDocker(t.Context(), image, "../../runtime/workspace/seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	s := webinvestigator.Spec{Investigator: &webinvestigator.Config{AllowMutations: true, MaxSteps: 5}}
	s.Deadline = time.Now().Add(90 * time.Second)
	s.Budget.Requests = 6
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	tool, err := workspace.Open(ctx, s.Deadline, policy.Broker{Policies: registry}, p, s)
	if err != nil {
		t.Fatal(err)
	}
	defer tool.Close()
	out, err := tool.Execute(ctx, webinvestigator.Action{Kind: "navigate", URL: target.URL + "/page"})
	if err != nil || !strings.Contains(out.Text, "Scoped page") || len(out.Events) != 1 || out.Admissions != 1 {
		t.Fatalf("browser navigation with denied subresource: %+v %v", out, err)
	}
	out, err = tool.Execute(ctx, webinvestigator.Action{Kind: "command", Script: "curl -s '" + target.URL + "/healthz'"})
	if err != nil || !strings.Contains(out.Text, "healthy") || len(out.Events) != 1 || out.Admissions != 1 {
		t.Fatalf("brokered shell request: %+v %v", out, err)
	}
	out, err = tool.Execute(ctx, webinvestigator.Action{Kind: "request", URL: target.URL + "/objects/a", Method: "POST", Body: "{}"})
	if err != nil || !out.Mutating || len(out.Events) != 1 || out.Events[0].Status != http.StatusCreated || out.Admissions != 1 {
		t.Fatalf("scoped mutation: %+v %v", out, err)
	}
	if reads.Load() != 2 || writes.Load() != 1 {
		t.Fatalf("unexpected target traffic: reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

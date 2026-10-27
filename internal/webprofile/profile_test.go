package webprofile

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/webinvestigator"
)

func coreBinary() string {
	_, file, _, _ := runtime.Caller(0)
	name := "harness-core"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "target", "debug", name)
}
func TestPrepareMutationTaskIsScopedAndOffline(t *testing.T) {
	origin := "http://127.0.0.1:8081"
	p := Profile{
		SchemaVersion: 1, ProjectID: "lab-project", PolicyRef: "lab-policy", Origin: origin, DeploymentID: "local-lab",
		CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true,
		Endpoints:  []policy.Endpoint{{Method: "GET", PathTemplate: "/healthz"}, {Method: "POST", PathTemplate: "/objects/{id}", AllowQuery: true}},
		Seeds:      []string{origin + "/healthz"},
		Identities: []Identity{{Ref: "reader-a", TokenFile: "missing-token-file"}},
		Question:   "Investigate configured object behavior", MaxSteps: 3, AllowMutations: true,
		DeadlineSeconds: 600, WallSeconds: 120, ArtifactBytes: 262144, Tokens: 1000, Requests: 3,
		Model: webinvestigator.Profile{ID: "local-model", Provider: "claude_code", Executable: filepath.Join(t.TempDir(), "claude"), Model: "sonnet", ProjectID: "lab-project", PolicyRef: "lab-policy", Origin: origin, MaxCalls: 3, MaxPromptBytes: 32768, CallSeconds: 30, AllowTargetDisclosure: true},
	}
	b, err := Prepare(t.Context(), p, "run-one", t.TempDir(), coreBinary(), time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	var task webinvestigator.Spec
	if err = json.Unmarshal(b.Task, &task); err != nil {
		t.Fatal(err)
	}
	if task.Investigator == nil || !task.Investigator.AllowMutations || task.RetryClass != "requires_reconciliation" || b.Run.MaxAttempts != 1 || len(b.Credentials) != 1 {
		t.Fatalf("%+v", b)
	}
	var envelope struct {
		Options struct {
			MaxAttempts int `json:"max_attempts"`
		} `json:"options"`
	}
	if err = json.Unmarshal(b.Enqueue, &envelope); err != nil || envelope.Options.MaxAttempts != 1 {
		t.Fatal(string(b.Enqueue), err)
	}
}

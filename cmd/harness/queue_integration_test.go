//go:build integration

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/testdb"
)

func TestQueueCLIEndToEnd(t *testing.T) {
	t.Setenv("HARNESS_DATABASE_URL", testdb.New(t))
	t.Setenv("HARNESS_CORE_BIN", testdb.Core())
	dir := t.TempDir()
	save := func(name string, value any) string {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err = os.WriteFile(p, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	command := func(args ...string) []byte {
		t.Helper()
		var out bytes.Buffer
		if err := run(t.Context(), append([]string{"queue"}, args...), &out); err != nil {
			t.Fatalf("queue %s: %v", args[0], err)
		}
		return out.Bytes()
	}
	command("migrate")
	command("migrate")
	config := queue.RunConfig{ProjectID: "lab-project", RunID: "run-test", MaxTasks: 10, MaxAttempts: 10, Limits: queue.Units{Tokens: 1000, Requests: 100, WallSeconds: 1000, CostMicrousd: 1000, ArtifactBytes: 1000000}}
	command("create-run", "--file", save("run.json", config))
	command("enqueue", "--file", save("task.json", testdb.Task(t, "web", "cli-task", "read_only")))
	claim := command("claim", "--project", "lab-project", "--run", "run-test", "--worker", "cli-worker")
	var lease queue.Lease
	if err := json.Unmarshal(claim, &lease); err != nil {
		t.Fatal(err)
	}
	if lease.Reserved.ArtifactBytes != 65536 {
		t.Fatal("lease did not expose budget to worker")
	}
	leasePath := save("lease.json", lease)
	command("heartbeat", "--lease", leasePath)
	completionPath := save("completion.json", queue.Completion{Outcome: "succeeded", Reason: "CLI smoke", Usage: &queue.Units{Requests: 2, WallSeconds: 1, ArtifactBytes: 32}, Result: json.RawMessage(`{"smoke_test":true}`)})
	command("finish", "--lease", leasePath, "--file", completionPath)
	command("finish", "--lease", leasePath, "--file", completionPath)
	var task queue.Task
	if err := json.Unmarshal(command("task", "--project", "lab-project", "--run", "run-test", "--task", "cli-task"), &task); err != nil {
		t.Fatal(err)
	}
	if task.Status != "succeeded" {
		t.Fatal(task.Status)
	}
	command("close", "--project", "lab-project", "--run", "run-test")
	var got queue.Run
	if err := json.Unmarshal(command("run", "--project", "lab-project", "--run", "run-test"), &got); err != nil {
		t.Fatal(err)
	}
	if got.Status != "completed" || got.AttemptCount != 1 || got.Reserved != (queue.Units{}) || got.Charged.Requests != 2 {
		t.Fatalf("unexpected run receipt: %+v", got)
	}
}

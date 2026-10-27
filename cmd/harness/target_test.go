package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTargetPrepareWritesBoundedTasksWithoutSecrets(t *testing.T) {
	name := "harness-core"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	core, err := filepath.Abs(filepath.Join("../..", "target/debug", name))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := filepath.Abs("../../examples/target.web.json")
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(t.TempDir(), "prepared")
	args := []string{"target-prepare", "--file", profile, "--run", "prepared-run", "--out", outDir, "--core", core}
	var output bytes.Buffer
	if err = run(t.Context(), args, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"secrets_read":0`) || !strings.Contains(output.String(), `"target_requests":0`) {
		t.Fatal(output.String())
	}
	for _, file := range []string{"policies.json", "probe-credentials.json", "run.json", "scope.json", "enqueue-invoice-access.json", "task-invoice-access.json", "enqueue-preflight-invoice-access.json", "task-preflight-invoice-access.json"} {
		raw, err := os.ReadFile(filepath.Join(outDir, file))
		if err != nil || !json.Valid(raw) {
			t.Fatal(file, err)
		}
	}
	if err = run(t.Context(), args, new(bytes.Buffer)); err == nil {
		t.Fatal("overwrote preparation")
	}
	before, err := os.ReadFile(filepath.Join(outDir, "run.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte("prepared-run")) {
		t.Fatal("wrong run")
	}
}
func TestTargetPrepareRequiresExplicitInputs(t *testing.T) {
	for _, args := range [][]string{{"target-prepare"}, {"target-prepare", "--file", "missing"}, {"target-prepare", "unexpected"}} {
		if err := run(t.Context(), args, new(bytes.Buffer)); err == nil {
			t.Fatal(args)
		}
	}
}

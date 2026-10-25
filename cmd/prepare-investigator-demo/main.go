// prepare-investigator-demo creates local fixtures only; it never calls a model or enqueues work.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/investigator"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/runner"
)

func main() {
	if err := prepare(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func packSource(content []byte) ([]byte, error) {
	if len(content) > 512<<10 {
		return nil, fmt.Errorf("lab source exceeds selected-file limit")
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	if err := w.WriteHeader(&tar.Header{Name: "internal/lab/lab.go", Mode: 0600, Size: int64(len(content)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		return nil, err
	}
	if _, err := w.Write(content); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func prepare() error {
	run := flag.String("run", "investigator-demo", "fresh run ID and work directory")
	model := flag.String("model", "", "model name supported by your Claude Code account")
	cli := flag.String("claude", "claude", "Claude Code executable")
	flag.Parse()
	if flag.NArg() != 0 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`).MatchString(*run) || *model == "" {
		return fmt.Errorf("provide a run identifier and --model")
	}
	executable, err := exec.LookPath(*cli)
	if err != nil {
		return fmt.Errorf("install Claude Code in WSL and log in before preparing a live demo: %w", err)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return err
	}
	if err = exec.Command("git", "diff", "--quiet", "HEAD", "--", "internal/lab/lab.go").Run(); err != nil {
		return fmt.Errorf("lab.go must match HEAD before creating the committed source snapshot")
	}
	commitRaw, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	commit := strings.TrimSpace(string(commitRaw))
	content, err := exec.Command("git", "show", commit+":internal/lab/lab.go").Output()
	if err != nil {
		return err
	}
	packed, err := packSource(content)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(packed)
	digest := hex.EncodeToString(sum[:])
	dir := filepath.Join("work", *run)
	if err = os.MkdirAll("work", 0700); err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("demo directory must be new: %w", err)
	}
	write := func(name string, value any) error {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), 0600)
	}
	if err = os.WriteFile(filepath.Join(dir, "source.tar"), packed, 0600); err != nil {
		return err
	}
	if err = write("snapshots.json", []runner.Snapshot{{RepositoryID: "lab-repository", Commit: commit, SHA256: digest, Archive: filepath.ToSlash(filepath.Join(dir, "source.tar"))}}); err != nil {
		return err
	}
	profile := investigator.Profile{ID: "local-claude", Provider: "claude_code", Executable: executable, Model: *model, ProjectID: "lab-project", PolicyRef: "local-lab-v1", RepositoryID: "lab-repository", Paths: []string{"internal/lab/lab.go"}, MaxCalls: 8, MaxPromptBytes: 65536, CallSeconds: 60, AllowSourceDisclosure: true}
	if err = write("investigators.json", []investigator.Profile{profile}); err != nil {
		return err
	}
	if err = write("run.json", queue.RunConfig{ProjectID: "lab-project", RunID: *run, MaxTasks: 10, MaxAttempts: 20, Limits: queue.Units{Tokens: 200000, Requests: 100, WallSeconds: 3600, ArtifactBytes: 16 << 20}}); err != nil {
		return err
	}
	if err = write("scope.json", map[string]string{"project_id": "lab-project", "run_id": *run}); err != nil {
		return err
	}
	creds := []map[string]string{}
	now := time.Now().UTC()
	plan := checks.Plan{Kind: "tenant_isolation", IdentityA: "tenant-a-reader", IdentityB: "tenant-b-reader", TenantA: "tenant-a", TenantB: "tenant-b", ExportA: "export-a", ExportB: "export-b"}
	for i, variant := range []string{"vulnerable", "patched"} {
		origin := fmt.Sprintf("http://127.0.0.1:%d", 8081+i)
		for _, letter := range []string{"a", "b"} {
			creds = append(creds, map[string]string{"project_id": "lab-project", "policy_ref": "local-lab-v1", "origin": origin, "identity_ref": "tenant-" + letter + "-reader", "token_file": "tenant-" + letter + ".token"})
		}
		task := map[string]any{
			"schema_version": 1, "task_id": "investigate-" + variant, "project_id": "lab-project", "run_id": *run, "investigation_id": "source-tenant-demo", "stage": "hunt",
			"policy_ref": "local-lab-v1", "question": "Inspect the single-export route for a possible tenant ownership bypass. Use search/read to obtain exact source lines before proposing tenant_isolation. This file contains both lab variants; runtime probes must establish whether this deployment reproduces the issue.",
			"created_at": now, "deadline": now.Add(time.Hour), "retry_class": "read_only", "dependencies": []string{},
			"budget":       map[string]any{"max_wall_seconds": 300, "max_model_tokens": 100000, "max_requests": 3, "max_artifact_bytes": 1 << 20},
			"investigator": investigator.Config{ProfileRef: profile.ID, MaxSteps: 8, Paths: profile.Paths, Probe: &plan},
			"target": map[string]any{"mode": "hybrid", "source": investigator.Source{RepositoryID: "lab-repository", Commit: commit, SHA256: digest}, "mapping_ref": "operator-lab-" + variant,
				"web": map[string]any{"deployment_id": "lab-" + variant, "observation_id": "source-demo-" + variant, "origin": origin, "seed_urls": []string{origin + "/exports"}}},
		}
		if err = write(variant+".json", map[string]any{"task": task, "options": queue.EnqueueOptions{MaxAttempts: 1}}); err != nil {
			return err
		}
		if err = write(variant+"-task.json", map[string]string{"project_id": "lab-project", "run_id": *run, "task_id": "investigate-" + variant}); err != nil {
			return err
		}
	}
	if err = write("probe-credentials.json", creds); err != nil {
		return err
	}
	for _, letter := range []string{"a", "b"} {
		if err = os.WriteFile(filepath.Join(dir, "tenant-"+letter+".token"), []byte("lab-only-token-"+letter), 0600); err != nil {
			return err
		}
	}
	fmt.Printf("Prepared %s. No model calls or target requests were made. Review investigators.json before starting a worker.\n", filepath.ToSlash(dir))
	return nil
}

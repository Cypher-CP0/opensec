package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"example.com/unified-harness/internal/configfile"
	"example.com/unified-harness/internal/coreclient"
	"example.com/unified-harness/internal/targetprofile"
)

func targetPrepareCommand(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("target-prepare", flag.ContinueOnError)
	file := f.String("file", "", "non-secret web target profile")
	run := f.String("run", "", "new run identifier")
	dir := f.String("out", "", "new private output directory")
	core := f.String("core", coreclient.DefaultBinary(), "Rust validator")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *file == "" || *run == "" || *dir == "" {
		return errors.New("--file, --run and --out are required")
	}
	var profile targetprofile.Profile
	if err := configfile.Read(*file, &profile); err != nil {
		return err
	}
	bundle, err := targetprofile.Prepare(ctx, profile, *run, filepath.Dir(*file), *core, time.Now().UTC())
	if err != nil {
		return err
	}
	// No target requests, DNS lookups, model invocations or secret-file reads occur above.
	if err = os.Mkdir(*dir, 0700); err != nil {
		return fmt.Errorf("output directory must be new and its parent must exist: %w", err)
	}
	write := func(name string, value any) error {
		raw, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(*dir, name), append(raw, '\n'), 0600)
	}
	if err = write("policies.json", bundle.Policies); err != nil {
		return err
	}
	if err = write("probe-credentials.json", bundle.Credentials); err != nil {
		return err
	}
	if err = write("run.json", bundle.Run); err != nil {
		return err
	}
	scope := map[string]string{"project_id": profile.ProjectID, "run_id": *run}
	if err = write("scope.json", scope); err != nil {
		return err
	}
	for _, task := range bundle.Tasks {
		name := task.CheckID
		if task.Stage == "prepare" {
			name = "preflight-" + name
		}
		if err = write("enqueue-"+name+".json", task.Enqueue); err != nil {
			return err
		}
		if err = write("task-"+name+".json", map[string]string{"project_id": profile.ProjectID, "run_id": *run, "task_id": task.ID}); err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(map[string]any{"ok": true, "directory": *dir, "checks": len(profile.Checks), "model_calls": 0, "target_requests": 0, "secrets_read": 0})
}

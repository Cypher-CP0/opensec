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
	"example.com/unified-harness/internal/webprofile"
)

func webPrepareCommand(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("web-prepare", flag.ContinueOnError)
	file := f.String("file", "", "non-secret autonomous web profile")
	run := f.String("run", "", "new run identifier")
	dir := f.String("out", "", "new private output directory")
	core := f.String("core", coreclient.DefaultBinary(), "Rust validator")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *file == "" || *run == "" || *dir == "" {
		return errors.New("--file, --run and --out are required")
	}
	var profile webprofile.Profile
	if err := configfile.Read(*file, &profile); err != nil {
		return err
	}
	bundle, err := webprofile.Prepare(ctx, profile, *run, filepath.Dir(*file), *core, time.Now().UTC())
	if err != nil {
		return err
	}
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
	if err = write("policies.json", bundle.Policy); err != nil {
		return err
	}
	if err = write("probe-credentials.json", bundle.Credentials); err != nil {
		return err
	}
	if err = write("web-investigators.json", bundle.Profiles); err != nil {
		return err
	}
	if err = write("run.json", bundle.Run); err != nil {
		return err
	}
	if err = write("enqueue.json", bundle.Enqueue); err != nil {
		return err
	}
	if err = write("scope.json", map[string]string{"project_id": profile.ProjectID, "run_id": *run}); err != nil {
		return err
	}
	if err = write("task.json", map[string]string{"project_id": profile.ProjectID, "run_id": *run, "task_id": "investigate-web"}); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(map[string]any{"ok": true, "directory": *dir, "model_calls": 0, "target_requests": 0, "secrets_read": 0})
}

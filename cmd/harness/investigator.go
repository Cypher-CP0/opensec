package main

import (
	"context"
	"encoding/json"
	"errors"
	"example.com/unified-harness/internal/investigator"
	"flag"
	"fmt"
	"io"
)

func investigatorCheckCommand(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("investigator-check", flag.ContinueOnError)
	file := f.String("profiles", "", "worker investigator profile JSON")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *file == "" || f.NArg() != 0 {
		return errors.New("--profiles is required")
	}
	profiles, err := investigator.LoadProfiles(*file)
	if err != nil {
		return err
	}
	if len(profiles) == 0 {
		return errors.New("at least one profile is required")
	}
	ids := []string{}
	for _, p := range profiles {
		if _, err := investigator.NewCLI(ctx, p); err != nil {
			return fmt.Errorf("investigator profile %s: %w", p.ID, err)
		}
		ids = append(ids, p.ID)
	}
	return json.NewEncoder(out).Encode(map[string]any{"ok": true, "profiles": ids, "check": "local_cli_capabilities", "model_calls": 0})
}

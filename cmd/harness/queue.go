package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"example.com/unified-harness/internal/coreclient"
	"example.com/unified-harness/internal/queue"
)

func readJSONFile(path string) (json.RawMessage, error) {
	if path == "" {
		return nil, errors.New("--file or --lease path is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4*1024*1024+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > 4*1024*1024 || !json.Valid(raw) {
		return nil, errors.New("expected a JSON document no larger than 4 MiB")
	}
	return raw, nil
}
func readContract(path string, value any) error {
	raw, err := readJSONFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}
func queueCommand(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: harness queue <migrate|create-run|enqueue|claim|heartbeat|finish|run|task|cancel|reap|resume|close> [options]")
	}
	operation := args[0]
	switch operation {
	case "migrate", "create-run", "enqueue", "claim", "heartbeat", "finish", "run", "task", "cancel", "reap", "resume", "close":
	default:
		return fmt.Errorf("unknown queue command %q", operation)
	}
	flags := flag.NewFlagSet("queue "+operation, flag.ContinueOnError)
	project := flags.String("project", "", "project ID")
	runID := flags.String("run", "", "run ID")
	task := flags.String("task", "", "task ID; omit for whole-run cancellation")
	workerID := flags.String("worker", "", "worker identity")
	file := flags.String("file", "", "JSON task, run configuration, or completion")
	leaseFile := flags.String("lease", "", "private JSON lease file")
	maxAttempts := flags.Int("max-attempts", 3, "maximum attempts per task")
	cost := flags.Int64("cost-microusd", 0, "per-attempt cost reservation in millionths of a USD")
	reason := flags.String("reason", "", "operator reason")
	reconciled := flags.Bool("state-reconciled", false, "confirm external state was reconciled or reset")
	binary := flags.String("core", coreclient.DefaultBinary(), "Rust core binary")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected queue arguments")
	}
	switch operation {
	case "claim", "run", "task", "cancel", "reap", "resume", "close":
		if *project == "" || *runID == "" {
			return errors.New("--project and --run are required")
		}
	}
	if (operation == "task" || operation == "resume") && *task == "" {
		return errors.New("--task is required")
	}
	dsn := os.Getenv("HARNESS_DATABASE_URL")
	if dsn == "" {
		return errors.New("HARNESS_DATABASE_URL is required")
	}
	store, err := queue.Open(ctx, dsn, queue.CoreValidator{Binary: *binary}, queue.DefaultSettings())
	if err != nil {
		return err
	}
	defer store.Close()
	emit := func(value any) error {
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(value)
	}
	switch operation {
	case "migrate":
		if err = store.Migrate(ctx); err != nil {
			return err
		}
	case "create-run":
		var config queue.RunConfig
		if err = readContract(*file, &config); err != nil {
			return err
		}
		if err = store.CreateRun(ctx, config); err != nil {
			return err
		}
	case "enqueue":
		raw, err := readJSONFile(*file)
		if err != nil {
			return err
		}
		if err = store.Enqueue(ctx, raw, queue.EnqueueOptions{MaxAttempts: *maxAttempts, CostMicrousd: *cost}); err != nil {
			return err
		}
	case "claim":
		lease, err := store.Claim(ctx, *project, *runID, *workerID)
		if err != nil {
			return err
		}
		return emit(lease)
	case "heartbeat", "finish":
		var lease queue.Lease
		if err = readContract(*leaseFile, &lease); err != nil {
			return err
		}
		if operation == "heartbeat" {
			expires, err := store.Heartbeat(ctx, lease)
			if err != nil {
				return err
			}
			return emit(map[string]any{"expires_at": expires})
		}
		var completion queue.Completion
		if err = readContract(*file, &completion); err != nil {
			return err
		}
		status, err := store.Finish(ctx, lease, completion)
		if err != nil {
			return err
		}
		return emit(map[string]string{"task_status": status})
	case "run":
		value, err := store.GetRun(ctx, *project, *runID)
		if err != nil {
			return err
		}
		return emit(value)
	case "task":
		value, err := store.GetTask(ctx, *project, *runID, *task)
		if err != nil {
			return err
		}
		return emit(value)
	case "cancel":
		err = store.Cancel(ctx, *project, *runID, *task, *reason)
	case "reap":
		count, err := store.Reap(ctx, *project, *runID)
		if err != nil {
			return err
		}
		return emit(map[string]int{"reaped": count})
	case "resume":
		err = store.Resume(ctx, *project, *runID, *task, *reason, *reconciled)
	case "close":
		err = store.CloseRun(ctx, *project, *runID)
	}
	if err != nil {
		return err
	}
	return emit(map[string]bool{"ok": true})
}

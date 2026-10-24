package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"example.com/unified-harness/internal/coreclient"
	"example.com/unified-harness/internal/lab"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: harness <schema|validate|lab|queue|serve|api|auth-init|worker> [options]")
	}
	switch args[0] {
	case "serve":
		return serveCommand(ctx, args[1:], out)
	case "api":
		return apiCommand(ctx, args[1:], out)
	case "auth-init":
		return authInitCommand(args[1:], out)
	case "worker":
		return workerCommand(ctx, args[1:], out)
	case "queue":
		return queueCommand(ctx, args[1:], out)
	case "schema":
		flags := flag.NewFlagSet("schema", flag.ContinueOnError)
		dir := flags.String("out", "schemas", "output directory")
		binary := flags.String("core", coreclient.DefaultBinary(), "Rust core binary")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected schema arguments")
		}
		data, err := coreclient.Call(ctx, *binary, map[string]any{"operation": "schemas"})
		if err != nil {
			return err
		}
		var schemas map[string]json.RawMessage
		if err = json.Unmarshal(data, &schemas); err != nil {
			return err
		}
		if err = os.MkdirAll(*dir, 0755); err != nil {
			return err
		}
		for _, kind := range []string{"task", "attempt", "evidence"} {
			schema, ok := schemas[kind]
			if !ok {
				return fmt.Errorf("core omitted %s schema", kind)
			}
			var value any
			if err = json.Unmarshal(schema, &value); err != nil {
				return err
			}
			pretty, _ := json.MarshalIndent(value, "", "  ")
			if err = os.WriteFile(filepath.Join(*dir, kind+".schema.json"), append(pretty, '\n'), 0644); err != nil {
				return err
			}
		}
		fmt.Fprintln(out, "Exported task, attempt, and evidence JSON Schemas.")
		return nil
	case "validate":
		flags := flag.NewFlagSet("validate", flag.ContinueOnError)
		kind := flags.String("kind", "task", "task, attempt, or evidence")
		file := flags.String("file", "", "JSON contract file")
		binary := flags.String("core", coreclient.DefaultBinary(), "Rust core binary")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *file == "" || flags.NArg() != 0 {
			return errors.New("--file is required; unexpected arguments are rejected")
		}
		input, err := os.Open(*file)
		if err != nil {
			return err
		}
		defer input.Close()
		content, err := io.ReadAll(io.LimitReader(input, 4*1024*1024+1))
		if err != nil {
			return err
		}
		if len(content) > 4*1024*1024 {
			return errors.New("contract file exceeds 4 MiB")
		}
		if !json.Valid(content) {
			return errors.New("invalid JSON document")
		}
		data, err := coreclient.Call(ctx, *binary, map[string]any{"operation": "validate", "kind": *kind, "document": json.RawMessage(content)})
		if err != nil {
			return err
		}
		fmt.Fprintln(out, string(data))
		return nil
	case "lab":
		flags := flag.NewFlagSet("lab", flag.ContinueOnError)
		variant := flags.String("variant", "patched", "patched or vulnerable")
		address := flags.String("listen", "127.0.0.1:8081", "loopback listen address")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected lab arguments")
		}
		host, _, err := net.SplitHostPort(*address)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("lab requires a literal loopback address, for example 127.0.0.1:8081")
		}
		handler, err := lab.New(*variant)
		if err != nil {
			return err
		}
		listener, err := net.Listen("tcp", *address)
		if err != nil {
			return err
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-ctx.Done():
				shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				_ = server.Shutdown(shutdown)
			case <-done:
			}
		}()
		fmt.Fprintf(out, "Synthetic %s lab: http://%s\n", *variant, listener.Addr())
		if err = server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

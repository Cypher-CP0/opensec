package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"example.com/unified-harness/internal/configfile"
	"example.com/unified-harness/internal/coordinator"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/report"
)

func reportCommand(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("report", flag.ContinueOnError)
	base := f.String("url", "http://127.0.0.1:8090", "coordinator origin")
	tokenFile := f.String("token-file", "", "operator or worker token file")
	ca := f.String("ca", "", "optional trusted CA PEM")
	file := f.String("file", "", "run scope JSON")
	format := f.String("format", "markdown", "markdown or json")
	path := f.String("out", "", "new private report file")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *file == "" || *tokenFile == "" || *path == "" || (*format != "markdown" && *format != "json") {
		return errors.New("--token-file, --file and --out are required; --format must be markdown or json")
	}
	// Reject an existing destination before making any coordinator request.
	if _, err := os.Lstat(*path); err == nil {
		return errors.New("report output must be a new file")
	} else if !os.IsNotExist(err) {
		return err
	}
	var scope coordinator.Scope
	if err := configfile.Read(*file, &scope); err != nil {
		return err
	}
	if scope.ProjectID == "" || scope.RunID == "" || scope.TaskID != "" || scope.EvidenceID != "" || scope.FindingID != "" || scope.After != "" || scope.Reason != "" || scope.StateReconciled {
		return errors.New("report requires only project_id and run_id")
	}
	token, err := tokenFromFile(*tokenFile)
	if err != nil {
		return err
	}
	client, err := coordinator.NewClient(*base, token, *ca)
	if err != nil {
		return err
	}
	defer client.Close()
	input, _ := json.Marshal(scope)
	raw, err := client.Call(ctx, "report", input)
	if err != nil {
		return err
	}
	var snapshot queue.RunReport
	if err = configfile.Decode(raw, &snapshot); err != nil {
		return err
	}
	if snapshot.Version != "opensec-run-report-v1" || snapshot.Run.ProjectID != scope.ProjectID || snapshot.Run.RunID != scope.RunID {
		return errors.New("unsupported or incorrectly scoped report")
	}
	var body []byte
	if *format == "json" {
		body, err = json.MarshalIndent(snapshot, "", "  ")
		body = append(body, '\n')
	} else {
		body = report.Markdown(snapshot)
	}
	if err != nil {
		return err
	}
	output, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := output.Write(body)
	closeErr := output.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	fmt.Fprintf(out, "Saved %s report to %s\n", *format, *path)
	return nil
}

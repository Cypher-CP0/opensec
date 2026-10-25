package main

import (
	"example.com/unified-harness/internal/investigator"
	"example.com/unified-harness/internal/runner"
	"testing"
)

func TestCommittedSourcePackIsAcceptedByInspector(t *testing.T) {
	content := []byte("package lab\n// exact committed source\n")
	packed, err := packSource(content)
	if err != nil {
		t.Fatal(err)
	}
	report, err := runner.Inspect(runner.Input{SourceTar: packed, SourcePaths: []string{"internal/lab/lab.go"}, SourceQuery: &investigator.Query{Kind: "read", Path: "internal/lab/lab.go", Start: 1, End: 2}})
	if err != nil || report.Source == nil || report.Source.Excerpt == nil || report.Source.Excerpt.Text != string(content) {
		t.Fatal(report, err)
	}
}

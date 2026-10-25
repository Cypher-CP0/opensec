package runner

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"testing"

	"example.com/unified-harness/internal/configfile"
	"example.com/unified-harness/internal/investigator"
)

func TestInspectorSourceProblemsAndEOF(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, item := range []struct{ path, text string }{{"handler.go", "one\ntwo\n"}, {"private.key", "not selected"}} {
		if err := tw.WriteHeader(&tar.Header{Name: item.path, Mode: 0600, Size: int64(len(item.text))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(item.text)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	query := investigator.Query{Kind: "read", Path: "handler.go", Start: 3, End: 64}
	input := Input{SourceTar: b.Bytes(), SourcePaths: []string{"handler.go"}, SourceQuery: &query}
	raw, _ := json.Marshal(input)
	var output bytes.Buffer
	if err := InspectStream(bytes.NewReader(raw), &output); err != nil {
		t.Fatal(err)
	}
	var report Report
	if err := configfile.Decode(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Source == nil || report.Source.Problem == nil || report.Source.Problem.Code != "read_start_past_eof" ||
		report.Source.Problem.TotalLines != 2 || len(report.Files) != 0 || bytes.Contains(output.Bytes(), []byte("private.key")) {
		t.Fatal(report, string(output.Bytes()))
	}
	query.Start = 1
	report, err := Inspect(input)
	if err != nil || report.Source == nil || report.Source.Excerpt == nil || report.Source.Excerpt.End != 2 ||
		report.Source.Excerpt.Text != "one\ntwo\n" || report.Source.TotalLines != 2 {
		t.Fatal(report, err)
	}
	query.Path = "private.key"
	report, err = Inspect(input)
	if err != nil || report.Source.Problem == nil || report.Source.Problem.Code != "path_not_allowed" || report.Source.Excerpt != nil {
		t.Fatal(report, err)
	}
}

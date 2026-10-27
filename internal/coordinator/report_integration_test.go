//go:build integration

package coordinator

import (
	"encoding/json"
	"testing"

	"example.com/unified-harness/internal/queue"
)

func runReport(t *testing.T, c *Client) queue.RunReport {
	t.Helper()
	input, _ := json.Marshal(Scope{ProjectID: "lab-project", RunID: "run-test"})
	raw, err := c.Call(t.Context(), "report", input)
	if err != nil {
		t.Fatal(err)
	}
	var r queue.RunReport
	if err = json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReportScopesAndEmptyRun(t *testing.T) {
	_, server, op, wr := setupAPI(t)
	create(t, op)
	for _, client := range []*Client{op, wr} {
		r := runReport(t, client)
		if r.Version != "opensec-run-report-v1" || r.Run.TaskCount != 0 || len(r.Tasks) != 0 || len(r.Findings) != 0 || r.GeneratedAt.IsZero() {
			t.Fatal(r)
		}
	}
	for _, token := range []string{opToken, workerToken} {
		for _, scope := range []Scope{{ProjectID: "other-project", RunID: "run-test"}, {ProjectID: "lab-project", RunID: "other-run"}} {
			status, _ := apiRequest(t, server, token, "report", scope)
			if status != 403 {
				t.Fatal(status)
			}
		}
	}
	status, _ := apiRequest(t, server, "", "report", Scope{ProjectID: "lab-project", RunID: "run-test"})
	if status != 401 {
		t.Fatal(status)
	}
	status, _ = apiRequest(t, server, opToken, "report", Scope{ProjectID: "lab-project", RunID: "run-test", TaskID: "x"})
	if status != 400 {
		t.Fatal(status)
	}
}

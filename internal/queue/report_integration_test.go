//go:build integration

package queue

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestReportBoundsCountsAndResultProjection(t *testing.T) {
	c := config()
	c.MaxTasks = ReportTaskLimit + 10
	s, _ := setup(t, c)
	for i := 0; i < ReportTaskLimit+1; i++ {
		enqueue(t, s, fmt.Sprintf("report-%03d", i), "read_only", 1)
	}
	l := claim(t, s)
	result := json.RawMessage(`{"verdict":"vulnerable","evidence_id":"forged","source":{"secret":"DO-NOT-EXPORT"},"headers":{"Authorization":"DO-NOT-EXPORT"}}`)
	u := Units{}
	_, err := s.Finish(t.Context(), l, Completion{Outcome: "succeeded", Reason: "DO-NOT-EXPORT", Result: result, Usage: &u})
	check(t, err)
	r, err := s.Report(t.Context(), project, runID)
	check(t, err)
	if len(r.Tasks) != ReportTaskLimit || !r.TasksTruncated || r.FindingsTruncated || len(r.TaskCounts) != 2 || r.Run.TaskCount != ReportTaskLimit+1 {
		t.Fatal(r)
	}
	var total int64
	for _, c := range r.TaskCounts {
		total += c.Count
	}
	if total != ReportTaskLimit+1 {
		t.Fatal(total)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "DO-NOT-EXPORT") || strings.Contains(string(raw), "forged") || strings.Contains(string(raw), `"verdict":"vulnerable"`) {
		t.Fatal("report exposed raw results or unverified verdict")
	}
	_, err = s.Report(t.Context(), "other-project", runID)
	expect(t, err, ErrNotFound)
}

package report

import (
	"strings"
	"testing"

	"example.com/unified-harness/internal/queue"
)

func TestMarkdownEscapesUntrustedNamesAndExplainsIncompleteCoverage(t *testing.T) {
	v := queue.RunReport{Run: queue.Run{RunConfig: queue.RunConfig{ProjectID: "<script>|x\n# injected", RunID: "[click](javascript:alert(1))"}, Status: "active"}, TaskCounts: []queue.TaskCount{{Stage: "hunt", Status: "failed", Count: 1}, {Stage: "prepare", Status: "succeeded", Count: 1}},
		Tasks:         []queue.ReportTask{{ID: "x|y", Stage: "prepare", Status: "succeeded", Verdict: "ready"}, {ID: "hunt", Stage: "hunt", Status: "failed", FailedPrerequisites: 1}, {ID: "web-candidate", Stage: "hunt", Status: "succeeded", CandidateStatus: "needs_validation", EvidenceID: "web-evidence"}},
		FindingCounts: map[string]int64{}, TasksTruncated: true}
	md := string(Markdown(v))
	for _, bad := range []string{"<script>", "[click]", "x|y", "\n# injected"} {
		if strings.Contains(md, bad) {
			t.Fatal("unescaped content", bad, md)
		}
	}
	for _, want := range []string{"provisional", "preflight: ready", "not evaluated; prerequisite failed", "details are truncated", "does not establish that the target is secure", "Failed or cancelled tasks: 1", "web candidate: needs&#95;validation"} {
		if !strings.Contains(md, want) {
			t.Fatal(want, md)
		}
	}
}

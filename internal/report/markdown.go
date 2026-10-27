// Package report renders a bounded, redacted coordinator snapshot.
package report

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"example.com/unified-harness/internal/queue"
)

func cell(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029':
			b.WriteByte(' ')
		case strings.ContainsRune("&<>\"'\\`|[]*_#!", r):
			fmt.Fprintf(&b, "&#%d;", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func Markdown(v queue.RunReport) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# OpenSec run report\n\nProject: %s  \nRun: %s  \nSnapshot: %s  \nRun status: %s\n\n",
		cell(v.Run.ProjectID), cell(v.Run.RunID), v.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z"), cell(v.Run.Status))
	var unfinished, unsuccessful int64
	for _, c := range v.TaskCounts {
		switch c.Status {
		case "queued", "running", "blocked_environment", "needs_reconciliation":
			unfinished += c.Count
		case "failed", "cancelled":
			unsuccessful += c.Count
		}
	}
	fmt.Fprintf(&b, "Confirmed findings: %d. Unfinished tasks: %d. Failed or cancelled tasks: %d.\n\n", v.FindingCounts["confirmed"], unfinished, unsuccessful)
	b.WriteString("These are results for the configured checks at the snapshot time. Zero confirmed findings does not establish that the target is secure. Preflight readiness is separate from a security verdict.\n\n")
	if v.Run.Status == "active" {
		b.WriteString("The run remains active; this report is provisional.\n\n")
	}
	b.WriteString("## Budget\n\n| Unit | Limit | Charged | Reserved |\n| --- | ---: | ---: | ---: |\n")
	for _, u := range []struct {
		name                     string
		limit, charged, reserved int64
	}{
		{"Requests", v.Run.Limits.Requests, v.Run.Charged.Requests, v.Run.Reserved.Requests},
		{"Model tokens", v.Run.Limits.Tokens, v.Run.Charged.Tokens, v.Run.Reserved.Tokens},
		{"Artifact bytes", v.Run.Limits.ArtifactBytes, v.Run.Charged.ArtifactBytes, v.Run.Reserved.ArtifactBytes},
		{"Wall seconds", v.Run.Limits.WallSeconds, v.Run.Charged.WallSeconds, v.Run.Reserved.WallSeconds},
		{"Cost (microUSD)", v.Run.Limits.CostMicrousd, v.Run.Charged.CostMicrousd, v.Run.Reserved.CostMicrousd},
	} {
		fmt.Fprintf(&b, "| %s | %d | %d | %d |\n", u.name, u.limit, u.charged, u.reserved)
	}
	fmt.Fprintf(&b, "\nReported model token overage: %d.\n\n", v.Run.ModelTokenOverage)
	b.WriteString("## Task totals\n\n| Stage | Status | Count |\n| --- | --- | ---: |\n")
	for _, c := range v.TaskCounts {
		fmt.Fprintf(&b, "| %s | %s | %d |\n", cell(c.Stage), cell(c.Status), c.Count)
	}
	b.WriteString("\n## Task details\n\n| Task | Stage | Status | Attempts | Result | Evidence |\n| --- | --- | --- | ---: | --- | --- |\n")
	for _, t := range v.Tasks {
		result := t.Verdict
		if t.CandidateStatus != "" {
			result = "web candidate: " + t.CandidateStatus
		}
		if result == "" {
			result = "not evaluated"
		}
		if t.Stage == "prepare" && t.Verdict != "" {
			result = "preflight: " + t.Verdict
		}
		if t.ReasonCode != "" {
			result += " (" + t.ReasonCode + ")"
		}
		if t.FailedPrerequisites > 0 {
			result += "; prerequisite failed"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s | %s |\n", cell(t.ID), cell(t.Stage), cell(t.Status), t.Generation, cell(result), cell(t.EvidenceID))
	}
	if v.TasksTruncated {
		b.WriteString("\nTask details are truncated. Task totals above include all records.\n")
	}
	b.WriteString("\n## Findings\n\n")
	keys := make([]string, 0, len(v.FindingCounts))
	for k := range v.FindingCounts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "- %s: %d\n", cell(k), v.FindingCounts[k])
	}
	if len(keys) == 0 {
		b.WriteString("No finding records exist in this snapshot. Check task outcomes before interpreting this result.\n")
	}
	for _, f := range v.Findings {
		fmt.Fprintf(&b, "\n### %s\n\nStatus: %s  \nOrigin: %s  \nDeployment: %s  \nDiscovery: %s  \nDiscovery evidence: %s\n\n",
			cell(f.ID), cell(f.Status), cell(f.Origin), cell(f.DeploymentID), cell(f.DiscoveryTaskID), cell(f.DiscoveryEvidenceID))
		if f.ValidationTaskID != nil {
			fmt.Fprintf(&b, "Validation task: %s  \n", cell(*f.ValidationTaskID))
		}
		if f.ValidationEvidenceID != nil {
			fmt.Fprintf(&b, "Validation evidence: %s  \n", cell(*f.ValidationEvidenceID))
		}
		b.WriteString("\nReproduction procedure (uses operator-supplied identity references):\n\n")
		for i, step := range f.Steps {
			fmt.Fprintf(&b, "%d. %s\n", i+1, cell(step))
		}
		if len(f.SourceEvidenceIDs) > 0 {
			b.WriteString("\nSource evidence references (separate from runtime validation):\n\n")
			for _, id := range f.SourceEvidenceIDs {
				fmt.Fprintf(&b, "- %s\n", cell(id))
			}
		}
	}
	if v.FindingsTruncated {
		b.WriteString("\nFinding details or source references are truncated. Finding totals above include all records.\n")
	}
	b.WriteString("\n## Limitations\n\n")
	for _, l := range v.Limitations {
		fmt.Fprintf(&b, "- %s\n", cell(l))
	}
	return []byte(b.String())
}

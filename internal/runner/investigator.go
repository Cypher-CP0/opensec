package runner

import (
	"context"
	"time"

	"example.com/unified-harness/internal/configfile"
	"example.com/unified-harness/internal/investigator"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
)

func (h Handler) runInvestigator(ctx context.Context, l queue.Lease, p policy.Policy, s investigator.Spec) queue.Completion {
	start := time.Now()
	profile, err := investigator.Select(h.InvestigatorProfiles, s)
	if err != nil {
		return queue.Completion{Outcome: "blocked_environment", Reason: "investigator profile missing or source disclosure denied", Usage: &queue.Units{}}
	}
	var packed []byte
	for _, registered := range h.Snapshots {
		if source := s.Target.Source; registered.RepositoryID == source.RepositoryID && registered.Commit == source.Commit && registered.SHA256 == source.SHA256 {
			packed, err = readSnapshot(registered, min(p.MaxInputBytes/2, 16<<20))
			break
		}
	}
	if err != nil || len(packed) == 0 {
		return queue.Completion{Outcome: "blocked_environment", Reason: "immutable source snapshot unavailable or mismatched", Usage: &queue.Units{}}
	}
	var adapter investigator.Adapter
	if h.ModelAdapter != nil {
		adapter = h.ModelAdapter(profile)
	} else {
		adapter, err = investigator.NewCLI(ctx, profile)
		if err != nil {
			return queue.Completion{Outcome: "blocked_environment", Reason: "investigator preflight: " + investigator.ErrorCode(err), Usage: &queue.Units{}}
		}
	}
	used := int64(0)
	source := func(ctx context.Context, q investigator.Query) (investigator.SourceResult, error) {
		// Reports, evidence and final task result all share the artifact allowance.
		limit := min(int64(32<<10), l.Reserved.ArtifactBytes-used-2*investigator.MaxArtifact)
		if limit < 1024 {
			return investigator.SourceResult{}, &investigator.SourceProblem{Code: "source_allowance_exhausted"}
		}
		raw, err := h.Executor.Execute(ctx, l.HardDeadline, Input{SourceTar: packed, SourcePaths: s.Investigator.Paths, SourceQuery: &q}, limit)
		used += int64(len(raw))
		var report Report
		if err != nil {
			return investigator.SourceResult{}, &investigator.SourceProblem{Code: "runner_failed"}
		}
		if configfile.Decode(raw, &report) != nil || report.Source == nil {
			return investigator.SourceResult{}, &investigator.SourceProblem{Code: "runner_report_invalid"}
		}
		return *report.Source, nil
	}
	report := investigator.Run(ctx, *s.Investigator, s.Question, l.Reserved.Tokens, profile.MaxPromptBytes, adapter, source)
	if report.Validate(*s.Investigator) != nil {
		return queue.Completion{Outcome: "failed", Reason: "invalid investigator report; usage unknown"}
	}
	result := investigator.Summary(report, l.AttemptID)
	usage := queue.Units{Tokens: min(report.Tokens, l.Reserved.Tokens), ArtifactBytes: used + int64(len(result)), WallSeconds: min(l.Reserved.WallSeconds, int64(time.Since(start).Seconds())+1)}
	if !report.UsageKnown {
		usage.Tokens = l.Reserved.Tokens
	}
	c := queue.Completion{Outcome: "succeeded", Reason: "bounded source investigation: " + report.Status, Usage: &usage, Result: result, Investigation: &report}
	if report.Status != "hypothesis" && report.Status != "no_hypothesis" {
		c.Outcome = "failed"
	}
	if report.Status == "provider_error" {
		c.Outcome = "blocked_environment"
		if report.ProviderError != "" {
			c.Reason += ": " + report.ProviderError
		}
	}
	if report.Status == "tool_error" && len(report.ToolEvents) > 0 {
		c.Reason += ": " + report.ToolEvents[len(report.ToolEvents)-1].Code
	}
	if report.ActionError != "" {
		c.Reason += ": " + report.ActionError
	}
	if report.Hypothesis != nil {
		evidence := investigator.NewEvidence(s, l.AttemptID, report, time.Now().UTC())
		c.Evidence = &evidence
		usage.ArtifactBytes += int64(len(evidence.Artifact))
	}
	if usage.ArtifactBytes > l.Reserved.ArtifactBytes {
		return queue.Completion{Outcome: "failed", Reason: "investigation artifact allowance exhausted; usage unknown"}
	}
	return c
}

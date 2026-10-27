package runner

import (
	"context"
	"time"

	"example.com/unified-harness/internal/investigator"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/webinvestigator"
)

func (h Handler) runWebInvestigator(ctx context.Context, l queue.Lease, p policy.Policy, s webinvestigator.Spec) queue.Completion {
	start := time.Now()
	profile, err := webinvestigator.Select(h.WebProfiles, s)
	if err != nil {
		return queue.Completion{Outcome: "blocked_environment", Reason: "web investigator profile unavailable", Usage: &queue.Units{}}
	}
	var model webinvestigator.Model
	if h.WebModelAdapter != nil {
		model = h.WebModelAdapter(profile)
	} else {
		cli, e := investigator.NewCLI(ctx, webinvestigator.CLIProfile(profile))
		if e != nil {
			return queue.Completion{Outcome: "blocked_environment", Reason: "model CLI preflight: " + investigator.ErrorCode(e), Usage: &queue.Units{}}
		}
		model = webinvestigator.CLIModel{CLI: cli}
	}
	var tool webinvestigator.Tool
	var closeTool func() error
	if h.WebToolFactory != nil {
		tool, closeTool, err = h.WebToolFactory(ctx, l, p, s)
	} else if h.Workspace != nil {
		var opened *workspaceTool
		opened, err = h.Workspace.Open(ctx, l.HardDeadline, h.Broker, p, s)
		if err == nil {
			tool = opened
			closeTool = opened.Close
		}
	} else {
		err = policy.ErrTrafficUnavailable
	}
	if err != nil || tool == nil || closeTool == nil {
		return queue.Completion{Outcome: "blocked_environment", Reason: "isolated browser workspace unavailable", Usage: &queue.Units{}}
	}
	report := webinvestigator.Run(ctx, s, model, tool, profile.MaxPromptBytes)
	if closeTool() != nil {
		return queue.Completion{Outcome: "blocked_environment", Reason: "workspace cleanup could not be confirmed; usage unknown"}
	}
	if report.Validate(s) != nil {
		outcome := "failed"
		if report.MutationsAttempted {
			outcome = "needs_reconciliation"
		}
		return queue.Completion{Outcome: outcome, Reason: "invalid web investigation report; usage unknown"}
	}
	result := webinvestigator.Summary(report, l.AttemptID)
	usage := queue.Units{Tokens: min(report.Tokens, l.Reserved.Tokens), Requests: report.Requests, WallSeconds: min(l.Reserved.WallSeconds, int64(time.Since(start).Seconds())+1), ArtifactBytes: int64(len(result))}
	for _, event := range report.Observations {
		usage.ArtifactBytes += event.BodyBytes
	}
	completion := queue.Completion{Outcome: "succeeded", Reason: "bounded web investigation: " + report.Status, Result: result, WebInvestigation: &report, Usage: &usage}
	if report.Candidate != nil {
		evidence := webinvestigator.NewEvidence(s, l.AttemptID, report, time.Now().UTC())
		completion.Evidence = &evidence
		usage.ArtifactBytes += int64(len(evidence.Artifact))
	}
	if report.Status != "candidate" && report.Status != "no_candidate" {
		completion.Outcome = "failed"
	}
	if report.Status == "provider_error" {
		completion.Outcome = "blocked_environment"
	}
	if !report.UsageKnown {
		completion.Usage = nil
		completion.Outcome = "blocked_environment"
	}
	if report.MutationsAttempted && completion.Outcome != "succeeded" {
		completion.Outcome = "needs_reconciliation"
	}
	if report.Tokens > l.Reserved.Tokens && completion.Outcome == "succeeded" {
		completion.Outcome = "failed"
	}
	if usage.ArtifactBytes > l.Reserved.ArtifactBytes {
		outcome := "failed"
		if report.MutationsAttempted {
			outcome = "needs_reconciliation"
		}
		return queue.Completion{Outcome: outcome, Reason: "web artifact allowance exhausted; usage unknown"}
	}
	return completion
}

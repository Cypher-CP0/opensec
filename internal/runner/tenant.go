package runner

import (
	"context"
	"encoding/json"
	"errors"
	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"time"
)

func (h Handler) runCheck(ctx context.Context, l queue.Lease, p policy.Policy, s checks.Spec) queue.Completion {
	start := time.Now()
	urls := s.URLs()
	probes := []policy.Probe{{URL: urls[0], IdentityRef: s.Check.IdentityA}, {URL: urls[1], IdentityRef: s.Check.IdentityB}}
	if s.Stage != "prepare" {
		probes = append(probes, policy.Probe{URL: urls[2], IdentityRef: s.Check.IdentityA})
	}
	// Keep room for the report and redacted transcript. Partial/network/auth failures
	// are inconclusive, never evidence that a target is safe.
	capBytes := min(int64(checks.MaxArtifact), l.Reserved.ArtifactBytes/4, p.MaxInputBytes/4)
	observations, requests, bodyBytes, fetchErr := h.Broker.FetchProbes(ctx, p, probes, l.Reserved.Requests, capBytes)
	if errors.Is(fetchErr, policy.ErrTrafficUnavailable) {
		return queue.Completion{Outcome: "blocked_environment", Reason: "traffic admission failed; request usage unknown"}
	}
	input := Input{Preflight: s.Stage == "prepare", Check: s.Check, Observations: observations}
	prepared, _ := json.Marshal(input)
	if int64(len(prepared)) > p.MaxInputBytes {
		return queue.Completion{Outcome: "failed", Reason: "prepared check exceeds policy limit"}
	}
	raw, err := h.Executor.Execute(ctx, l.HardDeadline, input, min(int64(checks.MaxArtifact), l.Reserved.ArtifactBytes/4))
	if err != nil {
		return queue.Completion{Outcome: "blocked_environment", Reason: "isolated check runner failed; usage unknown"}
	}
	var report Report
	if json.Unmarshal(raw, &report) != nil || report.Check == nil {
		return queue.Completion{Outcome: "failed", Reason: "invalid check result; usage unknown"}
	}
	transcript := report.Check.Transcript
	if fetchErr != nil && !errors.Is(fetchErr, policy.ErrTargetBackoff) {
		transcript.Observations = []checks.Observation{}
	} // No partial sequence can confirm a finding.
	evidence := checks.NewEvidence(s, l.AttemptID, transcript, time.Now().UTC())
	result := checks.Evaluate(transcript)
	resultRaw, _ := json.Marshal(checks.Summary(result, evidence.Record.EvidenceID))
	usage := queue.Units{Requests: requests, WallSeconds: min(l.Reserved.WallSeconds, int64(time.Since(start).Seconds())+1), ArtifactBytes: bodyBytes + int64(len(raw)+len(evidence.Artifact)+len(resultRaw))}
	if usage.ArtifactBytes > l.Reserved.ArtifactBytes {
		return queue.Completion{Outcome: "failed", Reason: "check artifact allowance exhausted; usage unknown"}
	}
	reason := "deterministic authorization check: " + result.Verdict
	if errors.Is(fetchErr, policy.ErrTargetBackoff) {
		reason += ": target_backoff"
	}
	outcome := "succeeded"
	if s.Stage == "prepare" {
		reason = "object preflight: " + result.ReasonCode
		if result.Verdict != "ready" {
			outcome = "failed"
		}
	}
	return queue.Completion{Outcome: outcome, Reason: reason, Usage: &usage, Result: resultRaw, Evidence: &evidence}
}

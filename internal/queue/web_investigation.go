package queue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"example.com/unified-harness/internal/artifact"
	"example.com/unified-harness/internal/coreclient"
	"example.com/unified-harness/internal/webinvestigator"
	"github.com/jackc/pgx/v5"
)

func (s *Store) webInvestigationTx(ctx context.Context, tx pgx.Tx, l Lease, a attempt, c Completion, raw json.RawMessage, spec webinvestigator.Spec, started, now time.Time) error {
	if c.WebInvestigation == nil {
		if c.Outcome == "succeeded" || c.Evidence != nil {
			return invalidWebEvidence("completion_required")
		}
		return nil
	}
	report := *c.WebInvestigation
	if report.Validate(spec) != nil || s.traffic == nil {
		return invalidWebEvidence("report_bounds_or_registry")
	}
	boundPolicy, err := s.traffic.AuthorizeTask(ctx, raw)
	if err != nil {
		return invalidWebEvidence("task_policy")
	}
	for _, observed := range report.Observations {
		if _, err = s.traffic.MethodOrigin(ctx, boundPolicy, observed.URL, observed.Method); err != nil {
			return invalidWebEvidence("observed_endpoint")
		}
	}
	expected, _ := canonical(webinvestigator.Summary(report, l.AttemptID))
	if !bytes.Equal(expected, c.Result) {
		return invalidWebEvidence("summary_mismatch")
	}
	success := report.Status == "candidate" || report.Status == "no_candidate"
	if success != (c.Outcome == "succeeded") || (success && !report.UsageKnown) {
		return invalidWebEvidence("outcome_mismatch")
	}
	if report.MutationsAttempted && !success && c.Outcome != "needs_reconciliation" {
		return invalidWebEvidence("mutation_outcome")
	}
	if !report.MutationsAttempted && c.Outcome == "needs_reconciliation" {
		return invalidWebEvidence("unexpected_reconciliation")
	}
	if !report.UsageKnown {
		if c.Usage != nil || c.Evidence != nil {
			return invalidWebEvidence("unknown_usage")
		}
	} else {
		if c.Usage == nil || !c.Usage.within(a.Reserved) || c.Usage.Requests != report.Requests || c.Usage.Tokens != min(report.Tokens, a.Reserved.Tokens) || c.Usage.CostMicrousd != 0 || c.Usage.ArtifactBytes < int64(len(c.Result)) {
			return invalidWebEvidence("usage_mismatch")
		}
	}
	if report.Candidate != nil {
		if s.evidence == nil || c.Evidence == nil || c.Usage == nil || report.BrowserVersion == "" {
			return invalidWebEvidence("candidate_artifact_missing")
		}
		sub := c.Evidence
		want := webinvestigator.NewEvidence(spec, l.AttemptID, report, sub.Record.ObservedAt)
		wantRaw, _ := json.Marshal(want.Record)
		gotRaw, _ := json.Marshal(sub.Record)
		if !bytes.Equal(wantRaw, gotRaw) || !bytes.Equal(want.Artifact, sub.Artifact) || sub.Record.ObservedAt.Before(started.Add(-5*time.Second)) || sub.Record.ObservedAt.After(now.Add(5*time.Second)) || c.Usage.ArtifactBytes < int64(len(c.Result)+len(sub.Artifact)) {
			return invalidWebEvidence("artifact_mismatch")
		}
		if _, err := coreclient.Call(ctx, s.evidence.core, map[string]any{"operation": "bind_evidence", "task": raw, "evidence": sub.Record}); err != nil {
			return invalidWebEvidence("rust_binding")
		}
		if _, err := coreclient.Call(ctx, s.evidence.core, map[string]any{"operation": "verify_digest", "sha256": sub.Record.Artifact.SHA256, "content": string(sub.Artifact)}); err != nil {
			return invalidWebEvidence("digest")
		}
		if err := s.evidence.blobs.Put(ctx, artifact.Scope(l.ProjectID, l.RunID), sub.Record.Artifact.SHA256, sub.Artifact); err != nil {
			return errors.New("web artifact storage failed")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO evidence_records(project_id,run_id,evidence_id,task_id,attempt_id,candidate_id,digest,byte_length,record) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, l.ProjectID, l.RunID, sub.Record.EvidenceID, l.TaskID, l.AttemptID, sub.Record.CandidateID, sub.Record.Artifact.SHA256, sub.Record.Artifact.Bytes, gotRaw); err != nil {
			return err
		}
	} else if c.Evidence != nil {
		return invalidWebEvidence("unexpected_artifact")
	}
	if report.Tokens > a.Reserved.Tokens {
		if _, err := tx.Exec(ctx, "UPDATE queue_runs SET model_token_overage=model_token_overage+$3 WHERE project_id=$1 AND run_id=$2", l.ProjectID, l.RunID, report.Tokens-a.Reserved.Tokens); err != nil {
			return err
		}
	}
	return nil
}

func invalidWebEvidence(code string) error {
	return fmt.Errorf("%w: web evidence %s", ErrInvalid, code)
}

package queue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"example.com/unified-harness/internal/artifact"
	"example.com/unified-harness/internal/coreclient"
	"example.com/unified-harness/internal/investigator"
	"github.com/jackc/pgx/v5"
)

func (s *Store) investigationTx(ctx context.Context, tx pgx.Tx, l Lease, a attempt, c Completion, raw json.RawMessage, spec investigator.Spec, started, now time.Time, r Run) error {
	if c.Investigation == nil {
		if c.Outcome == "succeeded" || c.Evidence != nil {
			return invalidEvidence()
		}
		return nil
	}
	report := *c.Investigation
	if report.Validate(*spec.Investigator) != nil || c.Usage == nil || !c.Usage.within(a.Reserved) {
		return invalidEvidence()
	}
	expectedTokens := min(report.Tokens, a.Reserved.Tokens)
	if !report.UsageKnown {
		expectedTokens = a.Reserved.Tokens
	}
	if c.Usage.Tokens != expectedTokens || c.Usage.Requests != 0 || c.Usage.CostMicrousd != 0 {
		return invalidEvidence()
	}
	summary, _ := canonical(investigator.Summary(report, l.AttemptID))
	if !bytes.Equal(c.Result, summary) {
		return invalidEvidence()
	}
	success := report.Status == "hypothesis" || report.Status == "no_hypothesis"
	if success != (c.Outcome == "succeeded") || (!report.UsageKnown && success) {
		return invalidEvidence()
	}
	if report.Tokens >= a.Reserved.Tokens && success {
		return invalidEvidence()
	}
	if c.Usage.ArtifactBytes < int64(len(c.Result)) {
		return invalidEvidence()
	}
	var evidenceID *string
	if report.Hypothesis != nil {
		if s.evidence == nil || c.Evidence == nil {
			return invalidEvidence()
		}
		sub := c.Evidence
		expected := investigator.NewEvidence(spec, l.AttemptID, report, sub.Record.ObservedAt)
		expectedRaw, _ := json.Marshal(expected.Record)
		givenRaw, _ := json.Marshal(sub.Record)
		if !bytes.Equal(expectedRaw, givenRaw) || !bytes.Equal(expected.Artifact, sub.Artifact) || sub.Record.ObservedAt.Before(started.Add(-5*time.Second)) || sub.Record.ObservedAt.After(now.Add(5*time.Second)) || c.Usage.ArtifactBytes < int64(len(c.Result)+len(sub.Artifact)) {
			return invalidEvidence()
		}
		if _, err := coreclient.Call(ctx, s.evidence.core, map[string]any{"operation": "bind_evidence", "task": raw, "evidence": sub.Record}); err != nil {
			return invalidEvidence()
		}
		if _, err := coreclient.Call(ctx, s.evidence.core, map[string]any{"operation": "verify_digest", "sha256": sub.Record.Artifact.SHA256, "content": string(sub.Artifact)}); err != nil {
			return invalidEvidence()
		}
		if err := s.evidence.blobs.Put(ctx, artifact.Scope(l.ProjectID, l.RunID), sub.Record.Artifact.SHA256, sub.Artifact); err != nil {
			return errors.New("source artifact storage failed")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO evidence_records(project_id,run_id,evidence_id,task_id,attempt_id,candidate_id,digest,byte_length,record) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			l.ProjectID, l.RunID, sub.Record.EvidenceID, l.TaskID, l.AttemptID, sub.Record.CandidateID, sub.Record.Artifact.SHA256, sub.Record.Artifact.Bytes, givenRaw); err != nil {
			return err
		}
		evidenceID = &sub.Record.EvidenceID
	} else if c.Evidence != nil {
		return invalidEvidence()
	}
	if report.Tokens > a.Reserved.Tokens {
		if _, err := tx.Exec(ctx, "UPDATE queue_runs SET model_token_overage=model_token_overage+$3 WHERE project_id=$1 AND run_id=$2", l.ProjectID, l.RunID, report.Tokens-a.Reserved.Tokens); err != nil {
			return err
		}
	}
	var probeID *string
	reason := "no model hypothesis; safety has not been established"
	if report.Hypothesis != nil {
		reason = "source hypothesis only; no authorized runtime probe"
		if spec.Investigator.Probe != nil {
			reason = "runtime probe not scheduled: task capacity or deadline exhausted"
			if r.TaskCount < r.MaxTasks && now.Before(a.Deadline) {
				id, err := s.enqueueProbeTx(ctx, tx, raw, a, now)
				if err != nil {
					return err
				}
				probeID = &id
				reason = "authorized runtime discovery scheduled; independent replay required for confirmation"
			}
		}
	} else if !success {
		reason = "investigation incomplete: " + report.Status
	}
	source, _ := json.Marshal(spec.Target.Source)
	reportRaw, _ := json.Marshal(report)
	_, err := tx.Exec(ctx, `INSERT INTO source_investigations(project_id,run_id,task_id,attempt_id,source,mapping_ref,report,source_evidence_id,probe_task_id,schedule_reason) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		l.ProjectID, l.RunID, l.TaskID, l.AttemptID, source, spec.Target.MappingRef, reportRaw, evidenceID, probeID, reason)
	return err
}
func (s *Store) enqueueProbeTx(ctx context.Context, tx pgx.Tx, raw json.RawMessage, a attempt, now time.Time) (string, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	config := doc["investigator"].(map[string]any)
	doc["check"] = config["probe"]
	delete(doc, "investigator")
	id := "probe-" + randomID()
	doc["task_id"] = id
	doc["created_at"] = now.UTC().Format(time.RFC3339Nano)
	doc["dependencies"] = []string{a.TaskID}
	// The child has no model allowance or model configuration.
	budget := doc["budget"].(map[string]any)
	budget["max_model_tokens"] = 0
	child, _ := json.Marshal(doc)
	if err := s.validator.ValidateTask(ctx, child); err != nil {
		return "", err
	}
	var spec specProjection
	if err := json.Unmarshal(child, &spec); err != nil {
		return "", err
	}
	options, _ := json.Marshal(EnqueueOptions{MaxAttempts: a.MaxAttempts})
	_, err := tx.Exec(ctx, `INSERT INTO queue_tasks(project_id,run_id,task_id,spec,fingerprint,retry_class,max_attempts,reserve_tokens,reserve_requests,reserve_seconds,reserve_cost,deadline,reserve_bytes) VALUES($1,$2,$3,$4,$5,'read_only',$6,0,$7,$8,0,$9,$10)`,
		spec.ProjectID, spec.RunID, id, child, hash(append(child, options...)), a.MaxAttempts, a.Reserved.Requests, a.Reserved.WallSeconds, spec.Deadline, a.Reserved.ArtifactBytes)
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO queue_dependencies VALUES($1,$2,$3,$4)", spec.ProjectID, spec.RunID, id, a.TaskID); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, "UPDATE queue_runs SET task_count=task_count+1 WHERE project_id=$1 AND run_id=$2", spec.ProjectID, spec.RunID); err != nil {
		return "", err
	}
	return id, event(ctx, tx, spec.ProjectID, spec.RunID, id, "source_probe_scheduled", map[string]string{"investigator_task_id": a.TaskID})
}

type InvestigationRecord struct {
	TaskID        string              `json:"task_id"`
	AttemptID     string              `json:"attempt_id"`
	Source        investigator.Source `json:"source"`
	MappingRef    string              `json:"mapping_ref"`
	MappingStatus string              `json:"mapping_status"`
	Report        investigator.Report `json:"report"`
	EvidenceID    *string             `json:"source_evidence_id"`
	ProbeTaskID   *string             `json:"probe_task_id"`
	ProbeStatus   string              `json:"probe_status"`
	Reason        string              `json:"schedule_reason"`
}

func (s *Store) GetInvestigation(ctx context.Context, project, run, task string) (InvestigationRecord, error) {
	var v InvestigationRecord
	var src, report []byte
	err := s.pool.QueryRow(ctx, `SELECT i.task_id,i.attempt_id,i.source,i.mapping_ref,i.report,i.source_evidence_id,i.probe_task_id,COALESCE(p.status,''),i.schedule_reason FROM source_investigations i JOIN queue_attempts a USING(project_id,run_id,attempt_id) LEFT JOIN queue_tasks p ON p.project_id=i.project_id AND p.run_id=i.run_id AND p.task_id=i.probe_task_id WHERE i.project_id=$1 AND i.run_id=$2 AND i.task_id=$3 ORDER BY a.generation DESC LIMIT 1`, project, run, task).Scan(&v.TaskID, &v.AttemptID, &src, &v.MappingRef, &report, &v.EvidenceID, &v.ProbeTaskID, &v.ProbeStatus, &v.Reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if err = json.Unmarshal(src, &v.Source); err != nil {
		return v, err
	}
	if err = json.Unmarshal(report, &v.Report); err != nil {
		return v, err
	}
	v.MappingStatus = "not_applicable"
	if v.MappingRef != "" {
		v.MappingStatus = "operator_asserted_unverified"
	}
	return v, nil
}

type SourceLink struct {
	EvidenceID    string                `json:"evidence_id"`
	Source        investigator.Source   `json:"source"`
	MappingRef    string                `json:"mapping_ref"`
	MappingStatus string                `json:"mapping_status"`
	Anchors       []investigator.Anchor `json:"anchors"`
}

func (s *Store) findingSources(ctx context.Context, project, run, id string) ([]SourceLink, error) {
	rows, err := s.pool.Query(ctx, `SELECT i.source_evidence_id,i.source,i.mapping_ref,e.record->'payload'->'anchors' FROM source_investigations i JOIN evidence_records e ON e.project_id=i.project_id AND e.run_id=i.run_id AND e.evidence_id=i.source_evidence_id WHERE i.project_id=$1 AND i.run_id=$2 AND i.finding_id=$3 ORDER BY i.attempt_id LIMIT 100`, project, run, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	links := []SourceLink{}
	for rows.Next() {
		var v SourceLink
		var src, anchors []byte
		if err = rows.Scan(&v.EvidenceID, &src, &v.MappingRef, &anchors); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(src, &v.Source); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(anchors, &v.Anchors); err != nil {
			return nil, err
		}
		v.MappingStatus = "operator_asserted_unverified"
		links = append(links, v)
	}
	return links, rows.Err()
}

package queue

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"example.com/unified-harness/internal/artifact"
	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/configfile"
	"example.com/unified-harness/internal/coreclient"
	"example.com/unified-harness/internal/investigator"
	"github.com/jackc/pgx/v5"
)

type evidenceConfig struct {
	core  string
	blobs artifact.Store
}

// ConfigureEvidence is startup-only; workers send artifacts to the coordinator.
func (s *Store) ConfigureEvidence(core string, blobs artifact.Store) error {
	if blobs == nil {
		return errors.New("artifact store is required")
	}
	s.evidence = &evidenceConfig{core, blobs}
	return nil
}
func invalidEvidence() error {
	return fmt.Errorf("%w: invalid or incorrectly bound evidence", ErrInvalid)
}
func (s *Store) evidenceTx(ctx context.Context, tx pgx.Tx, l Lease, a attempt, c Completion, now time.Time, r Run) error {
	var raw json.RawMessage
	var started time.Time
	if err := tx.QueryRow(ctx, "SELECT t.spec,a.started_at FROM queue_tasks t JOIN queue_attempts a USING(project_id,run_id,task_id) WHERE a.project_id=$1 AND a.run_id=$2 AND a.attempt_id=$3", l.ProjectID, l.RunID, l.AttemptID).Scan(&raw, &started); err != nil {
		return err
	}
	ispec, err := investigator.Parse(raw)
	if err != nil {
		return invalidEvidence()
	}
	if ispec.Investigator != nil {
		return s.investigationTx(ctx, tx, l, a, c, raw, ispec, started, now, r)
	}
	if c.Investigation != nil {
		return invalidEvidence()
	}
	spec, err := checks.Parse(raw)
	if err != nil {
		return invalidEvidence()
	}
	if spec.Check == nil {
		if c.Evidence != nil {
			return invalidEvidence()
		}
		return nil
	}
	if c.Outcome != "succeeded" {
		if c.Evidence != nil {
			return invalidEvidence()
		}
		return nil
	}
	if s.evidence == nil || c.Evidence == nil {
		return invalidEvidence()
	}
	sub := c.Evidence
	if len(sub.Artifact) == 0 || len(sub.Artifact) > checks.MaxArtifact {
		return invalidEvidence()
	}
	var transcript checks.Transcript
	if configfile.Decode(sub.Artifact, &transcript) != nil || checks.ValidateTranscript(transcript) != nil {
		return invalidEvidence()
	}
	canonicalArtifact, _ := json.Marshal(transcript)
	if !bytes.Equal(canonicalArtifact, sub.Artifact) {
		return invalidEvidence()
	}
	expected := checks.NewEvidence(spec, l.AttemptID, transcript, sub.Record.ObservedAt)
	expectedRaw, _ := json.Marshal(expected.Record)
	givenRaw, _ := json.Marshal(sub.Record)
	if !bytes.Equal(expectedRaw, givenRaw) || sub.Record.ObservedAt.Before(started.Add(-5*time.Second)) || sub.Record.ObservedAt.After(now.Add(5*time.Second)) {
		return invalidEvidence()
	}
	if c.Usage == nil || !c.Usage.within(a.Reserved) || c.Usage.ArtifactBytes < int64(len(sub.Artifact)+len(c.Result)) || c.Usage.Requests < int64(len(transcript.Observations)) {
		return invalidEvidence()
	}
	verdict := checks.Evaluate(transcript)
	resultRaw, _ := json.Marshal(map[string]string{"kind": checks.Version, "verdict": verdict.Verdict, "reason": verdict.Reason, "evidence_id": sub.Record.EvidenceID})
	normalizedResult, _ := canonical(resultRaw)
	if !bytes.Equal(normalizedResult, c.Result) {
		return invalidEvidence()
	}
	if _, err = coreclient.Call(ctx, s.evidence.core, map[string]any{"operation": "bind_evidence", "task": raw, "evidence": sub.Record}); err != nil {
		return invalidEvidence()
	}
	if _, err = coreclient.Call(ctx, s.evidence.core, map[string]any{"operation": "verify_digest", "sha256": sub.Record.Artifact.SHA256, "content": string(sub.Artifact)}); err != nil {
		return invalidEvidence()
	}
	// Blobs are durable before references commit. A rollback can leave an orphan,
	// but can never commit a reference to a blob that failed to write.
	if err = s.evidence.blobs.Put(ctx, artifact.Scope(l.ProjectID, l.RunID), sub.Record.Artifact.SHA256, sub.Artifact); err != nil {
		return errors.New("artifact storage failed")
	}
	_, err = tx.Exec(ctx, `INSERT INTO evidence_records(project_id,run_id,evidence_id,task_id,attempt_id,candidate_id,digest,byte_length,record)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, l.ProjectID, l.RunID, sub.Record.EvidenceID, l.TaskID, l.AttemptID, sub.Record.CandidateID, sub.Record.Artifact.SHA256, sub.Record.Artifact.Bytes, givenRaw)
	if err != nil {
		return err
	}
	if spec.Stage == "validate" {
		status := "inconclusive"
		if verdict.Verdict == "vulnerable" {
			status = "confirmed"
		} else if verdict.Verdict == "not_vulnerable" {
			status = "not_reproduced"
		}
		// Only the coordinator-created validation link can promote a discovery.
		_, err = tx.Exec(ctx, `UPDATE findings SET status=$4,validation_evidence_id=$5,reason=$6,updated_at=$7
 WHERE project_id=$1 AND run_id=$2 AND validation_task_id=$3 AND discovery_task_id<>$3`, l.ProjectID, l.RunID, l.TaskID, status, sub.Record.EvidenceID, verdict.Reason, now)
		return err
	}
	if verdict.Verdict != "vulnerable" {
		return nil
	}
	var exists bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM findings WHERE project_id=$1 AND run_id=$2 AND finding_id=$3)", l.ProjectID, l.RunID, sub.Record.CandidateID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		_, err = tx.Exec(ctx, "UPDATE source_investigations SET finding_id=$4 WHERE project_id=$1 AND run_id=$2 AND probe_task_id=$3", l.ProjectID, l.RunID, l.TaskID, sub.Record.CandidateID)
		return err
	}
	var validationID *string
	status, reason := "unvalidated", "validation could not be scheduled within task capacity or deadline"
	if r.TaskCount < r.MaxTasks && now.Before(a.Deadline) {
		id, err := s.enqueueValidationTx(ctx, tx, raw, a, now)
		if err != nil {
			return err
		}
		validationID = &id
		status = "pending_validation"
		reason = "awaiting an independently leased replay with fresh requests"
	}
	plan, _ := json.Marshal(spec.Check)
	_, err = tx.Exec(ctx, `INSERT INTO findings(project_id,run_id,finding_id,status,origin,deployment_id,check_plan,discovery_task_id,discovery_evidence_id,validation_task_id,reason)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, l.ProjectID, l.RunID, sub.Record.CandidateID, status, spec.Target.Web.Origin, spec.Target.Web.DeploymentID, plan, l.TaskID, sub.Record.EvidenceID, validationID, reason)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE source_investigations SET finding_id=$4 WHERE project_id=$1 AND run_id=$2 AND probe_task_id=$3", l.ProjectID, l.RunID, l.TaskID, sub.Record.CandidateID)
	return err
}
func (s *Store) enqueueValidationTx(ctx context.Context, tx pgx.Tx, raw json.RawMessage, a attempt, now time.Time) (string, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", err
	}
	id := "validate-" + randomID()
	doc["task_id"] = id
	doc["stage"] = "validate"
	doc["created_at"] = now.UTC().Format(time.RFC3339Nano)
	doc["dependencies"] = []string{a.TaskID}
	validation, _ := json.Marshal(doc)
	if err := s.validator.ValidateTask(ctx, validation); err != nil {
		return "", err
	}
	var spec specProjection
	if err := json.Unmarshal(validation, &spec); err != nil {
		return "", err
	}
	options, _ := json.Marshal(EnqueueOptions{MaxAttempts: a.MaxAttempts, CostMicrousd: a.Reserved.CostMicrousd})
	_, err := tx.Exec(ctx, `INSERT INTO queue_tasks(project_id,run_id,task_id,spec,fingerprint,retry_class,max_attempts,reserve_tokens,reserve_requests,reserve_seconds,reserve_cost,deadline,reserve_bytes)
 VALUES($1,$2,$3,$4,$5,'read_only',$6,$7,$8,$9,$10,$11,$12)`, spec.ProjectID, spec.RunID, id, validation, hash(append(validation, options...)), a.MaxAttempts, a.Reserved.Tokens, a.Reserved.Requests, a.Reserved.WallSeconds, a.Reserved.CostMicrousd, spec.Deadline, a.Reserved.ArtifactBytes)
	if err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO queue_dependencies VALUES($1,$2,$3,$4)", spec.ProjectID, spec.RunID, id, a.TaskID); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, "UPDATE queue_runs SET task_count=task_count+1 WHERE project_id=$1 AND run_id=$2", spec.ProjectID, spec.RunID); err != nil {
		return "", err
	}
	return id, event(ctx, tx, spec.ProjectID, spec.RunID, id, "validation_scheduled", map[string]string{"discovery_task_id": a.TaskID})
}

type StoredEvidence struct {
	Record   checks.Evidence `json:"record"`
	Artifact json.RawMessage `json:"artifact"`
}

func (s *Store) GetEvidence(ctx context.Context, project, run, id string) (StoredEvidence, error) {
	var v StoredEvidence
	var raw json.RawMessage
	err := s.pool.QueryRow(ctx, "SELECT record FROM evidence_records WHERE project_id=$1 AND run_id=$2 AND evidence_id=$3", project, run, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	if s.evidence == nil {
		return v, errors.New("artifact store is not configured")
	}
	if err = json.Unmarshal(raw, &v.Record); err != nil {
		return v, err
	}
	v.Artifact, err = s.evidence.blobs.Get(ctx, artifact.Scope(project, run), v.Record.Artifact.SHA256)
	if err == nil && int64(len(v.Artifact)) != v.Record.Artifact.Bytes {
		err = errors.New("artifact length mismatch")
	}
	return v, err
}

type Finding struct {
	SourceLinks          []SourceLink `json:"source_links"`
	ID                   string       `json:"finding_id"`
	Status               string       `json:"status"`
	Origin               string       `json:"origin"`
	DeploymentID         string       `json:"deployment_id"`
	Check                checks.Plan  `json:"check"`
	DiscoveryTaskID      string       `json:"discovery_task_id"`
	DiscoveryEvidenceID  string       `json:"discovery_evidence_id"`
	ValidationTaskID     *string      `json:"validation_task_id"`
	ValidationEvidenceID *string      `json:"validation_evidence_id"`
	Reason               string       `json:"reason"`
	Steps                []string     `json:"reproduction_steps"`
	CreatedAt            time.Time    `json:"created_at"`
	UpdatedAt            time.Time    `json:"updated_at"`
}
type FindingPage struct {
	Findings   []Finding `json:"findings"`
	NextCursor string    `json:"next_cursor,omitempty"`
}

func (s *Store) Findings(ctx context.Context, project, run, id, after string) (FindingPage, error) {
	rows, err := s.pool.Query(ctx, `SELECT f.finding_id,f.status,f.origin,f.deployment_id,f.check_plan,f.discovery_task_id,f.discovery_evidence_id,f.validation_task_id,f.validation_evidence_id,f.reason,f.created_at,f.updated_at,COALESCE(t.status,'')
 FROM findings f LEFT JOIN queue_tasks t ON t.project_id=f.project_id AND t.run_id=f.run_id AND t.task_id=f.validation_task_id
 WHERE f.project_id=$1 AND f.run_id=$2 AND ($3='' OR f.finding_id=$3) AND f.finding_id>$4 ORDER BY f.finding_id LIMIT 101`, project, run, id, after)
	page := FindingPage{Findings: []Finding{}}
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var f Finding
		var plan []byte
		var taskStatus string
		if err = rows.Scan(&f.ID, &f.Status, &f.Origin, &f.DeploymentID, &plan, &f.DiscoveryTaskID, &f.DiscoveryEvidenceID, &f.ValidationTaskID, &f.ValidationEvidenceID, &f.Reason, &f.CreatedAt, &f.UpdatedAt, &taskStatus); err != nil {
			return page, err
		}
		if err = json.Unmarshal(plan, &f.Check); err != nil {
			return page, err
		}
		if f.Status == "pending_validation" && (taskStatus == "failed" || taskStatus == "cancelled" || taskStatus == "blocked_environment" || taskStatus == "needs_reconciliation") {
			f.Status = "inconclusive"
			f.Reason = "validation task " + taskStatus + "; reproduction has not been established"
		}
		f.Steps = []string{
			"GET " + f.Origin + "/exports/" + f.Check.ExportA + " using " + f.Check.IdentityA + "; verify tenant " + f.Check.TenantA,
			"GET " + f.Origin + "/exports/" + f.Check.ExportB + " using " + f.Check.IdentityB + "; verify tenant " + f.Check.TenantB,
			"GET " + f.Origin + "/exports/" + f.Check.ExportB + " using " + f.Check.IdentityA + "; compare ownership and content digest with the second response",
		}
		page.Findings = append(page.Findings, f)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	rows.Close()
	for i := range page.Findings {
		page.Findings[i].SourceLinks, err = s.findingSources(ctx, project, run, page.Findings[i].ID)
		if err != nil {
			return page, err
		}
	}
	if id != "" && len(page.Findings) == 0 {
		return page, ErrNotFound
	}
	if len(page.Findings) > 100 {
		page.Findings = page.Findings[:100]
		page.NextCursor = page.Findings[99].ID
	}
	return page, nil
}

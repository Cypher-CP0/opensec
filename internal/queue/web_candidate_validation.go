package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/webinvestigator"
	"github.com/jackc/pgx/v5"
)

// CandidateValidationRequest is an operator assertion about a web candidate.
// The model's rationale never supplies object ownership or response selectors.
type CandidateValidationRequest struct {
	ProjectID           string      `json:"project_id"`
	RunID               string      `json:"run_id"`
	CandidateEvidenceID string      `json:"candidate_evidence_id"`
	Plan                checks.Plan `json:"plan"`
	MaxAttempts         int         `json:"max_attempts"`
	DeadlineSeconds     int         `json:"deadline_seconds"`
	MaxWallSeconds      int64       `json:"max_wall_seconds"`
	MaxArtifactBytes    int64       `json:"max_artifact_bytes"`
}

type CandidateValidation struct {
	CandidateEvidenceID string `json:"candidate_evidence_id"`
	PreflightTaskID     string `json:"preflight_task_id"`
	DiscoveryTaskID     string `json:"discovery_task_id"`
	FindingID           string `json:"finding_id"`
}

func (s *Store) ScheduleCandidateValidation(ctx context.Context, input CandidateValidationRequest) (CandidateValidation, error) {
	out := CandidateValidation{}
	if !identifier.MatchString(input.ProjectID) || !identifier.MatchString(input.RunID) || !identifier.MatchString(input.CandidateEvidenceID) ||
		input.Plan.Kind != "object_authorization" || input.Plan.Validate() != nil ||
		input.MaxAttempts < 1 || input.MaxAttempts > 3 || input.DeadlineSeconds < 60 || input.DeadlineSeconds > 86400 ||
		input.MaxWallSeconds < 1 || input.MaxWallSeconds > 300 || input.MaxWallSeconds > int64(input.DeadlineSeconds) ||
		input.MaxArtifactBytes < 8192 || input.MaxArtifactBytes > 1<<20 || s.traffic == nil {
		return out, fmt.Errorf("%w: invalid candidate validation controls", ErrInvalid)
	}
	evidence, err := s.GetEvidence(ctx, input.ProjectID, input.RunID, input.CandidateEvidenceID)
	if err != nil {
		return out, err
	}
	if evidence.Record.Payload.Kind != "browser_observation" || checks.Hash(evidence.Artifact) != evidence.Record.Artifact.SHA256 {
		return out, fmt.Errorf("%w: candidate evidence is not a verified browser observation", ErrInvalid)
	}
	var report webinvestigator.Report
	if err = json.Unmarshal(evidence.Artifact, &report); err != nil || report.Status != "candidate" || report.Candidate == nil {
		return out, fmt.Errorf("%w: candidate report is invalid", ErrInvalid)
	}
	requestRaw, _ := json.Marshal(input)
	requestHash := hash(requestRaw)
	tx, run, err := s.locked(ctx, input.ProjectID, input.RunID)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	var oldHash string
	err = tx.QueryRow(ctx, `SELECT request_hash,preflight_task_id,discovery_task_id,finding_id FROM web_candidate_validations
WHERE project_id=$1 AND run_id=$2 AND candidate_evidence_id=$3`, input.ProjectID, input.RunID, input.CandidateEvidenceID).
		Scan(&oldHash, &out.PreflightTaskID, &out.DiscoveryTaskID, &out.FindingID)
	if err == nil {
		if oldHash != requestHash {
			return CandidateValidation{}, ErrConflict
		}
		out.CandidateEvidenceID = input.CandidateEvidenceID
		return out, tx.Commit(ctx)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return CandidateValidation{}, err
	}
	if run.Status != "active" {
		return CandidateValidation{}, ErrRunClosed
	}
	if run.TaskCount+3 > run.MaxTasks {
		return CandidateValidation{}, ErrBudget // reserve room for a fresh replay
	}
	var sourceRaw json.RawMessage
	var sourceStatus string
	err = tx.QueryRow(ctx, `SELECT t.spec,t.status FROM queue_tasks t JOIN evidence_records e
ON e.project_id=t.project_id AND e.run_id=t.run_id AND e.task_id=t.task_id
WHERE e.project_id=$1 AND e.run_id=$2 AND e.evidence_id=$3`,
		input.ProjectID, input.RunID, input.CandidateEvidenceID).Scan(&sourceRaw, &sourceStatus)
	if err != nil {
		return CandidateValidation{}, err
	}
	source, err := webinvestigator.Parse(sourceRaw)
	if err != nil || source.Investigator == nil || source.Target.Web == nil || sourceStatus != "succeeded" ||
		source.Stage != "hunt" || source.TaskID != evidence.Record.TaskID || source.PolicyRef != evidence.Record.PolicyRef ||
		source.Target.Web.DeploymentID != evidence.Record.Payload.DeploymentID ||
		source.Target.Web.ObservationID != evidence.Record.Payload.ObservationID ||
		report.Validate(source) != nil {
		return CandidateValidation{}, fmt.Errorf("%w: candidate scope or report mismatch", ErrInvalid)
	}
	contains := func(ref string) bool {
		for _, allowed := range source.Investigator.IdentityRefs {
			if ref == allowed {
				return true
			}
		}
		return false
	}
	if !contains(input.Plan.IdentityA) || !contains(input.Plan.IdentityB) {
		return CandidateValidation{}, fmt.Errorf("%w: validation identities were not in the investigation scope", ErrInvalid)
	}
	crossURL := source.Target.Web.Origin + input.Plan.Paths()[2]
	observedCrossRead := false
	for _, id := range report.Candidate.ObservationIDs {
		observed := report.Observations[id]
		if observed.URL == crossURL && observed.Method == "GET" && observed.IdentityRef == input.Plan.IdentityA && observed.Status == 200 {
			observedCrossRead = true
			break
		}
	}
	if !observedCrossRead {
		return CandidateValidation{}, fmt.Errorf("%w: plan is not linked to the candidate's observed cross-identity read", ErrInvalid)
	}
	now, err := dbNow(ctx, tx)
	if err != nil {
		return CandidateValidation{}, err
	}
	deadline := now.Add(time.Duration(input.DeadlineSeconds) * time.Second)
	if deadline.Before(now.Add(time.Duration(input.MaxWallSeconds+5) * time.Second)) {
		return CandidateValidation{}, fmt.Errorf("%w: candidate deadline leaves no validation window", ErrInvalid)
	}
	prefix := hash([]byte(input.CandidateEvidenceID + ":" + requestHash))[:32]
	out = CandidateValidation{
		CandidateEvidenceID: input.CandidateEvidenceID,
		PreflightTaskID:     "preflight-web-" + prefix,
		DiscoveryTaskID:     "check-web-" + prefix,
	}
	var findingSpec checks.Spec
	findingSpec.ProjectID, findingSpec.RunID, findingSpec.PolicyRef = input.ProjectID, input.RunID, source.PolicyRef
	findingSpec.Check = &input.Plan
	findingSpec.Target.Web = &struct {
		Origin        string `json:"origin"`
		DeploymentID  string `json:"deployment_id"`
		ObservationID string `json:"observation_id"`
	}{Origin: source.Target.Web.Origin, DeploymentID: source.Target.Web.DeploymentID, ObservationID: source.Target.Web.ObservationID}
	out.FindingID = checks.Candidate(findingSpec)
	var alreadyScheduled bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(
SELECT 1 FROM findings WHERE project_id=$1 AND run_id=$2 AND finding_id=$3
UNION ALL
SELECT 1 FROM web_candidate_validations WHERE project_id=$1 AND run_id=$2 AND finding_id=$3)`,
		input.ProjectID, input.RunID, out.FindingID).Scan(&alreadyScheduled); err != nil {
		return CandidateValidation{}, err
	}
	if alreadyScheduled {
		return CandidateValidation{}, ErrConflict
	}
	paths := input.Plan.Paths()
	for _, stage := range []string{"prepare", "hunt"} {
		id, deps, requests := out.PreflightTaskID, []string{}, 2
		question := "Establish both legitimate object access controls before cross-identity testing."
		if stage == "hunt" {
			id, deps, requests = out.DiscoveryTaskID, []string{out.PreflightTaskID}, 3
			question = "Evaluate the operator-declared object authorization plan with fresh requests."
		}
		task, err := json.Marshal(map[string]any{
			"schema_version": 1, "project_id": input.ProjectID, "run_id": input.RunID, "task_id": id,
			"investigation_id": "candidate-validation-" + prefix, "policy_ref": source.PolicyRef,
			"stage": stage, "retry_class": "read_only", "created_at": now.UTC(), "deadline": deadline.UTC(),
			"dependencies": deps, "question": question, "check": input.Plan,
			"budget": map[string]any{"max_wall_seconds": input.MaxWallSeconds, "max_model_tokens": 0, "max_requests": requests, "max_artifact_bytes": input.MaxArtifactBytes},
			"target": map[string]any{"mode": "web", "web": map[string]any{
				"origin": source.Target.Web.Origin, "deployment_id": source.Target.Web.DeploymentID,
				"observation_id": source.Target.Web.ObservationID,
				"seed_urls":      []string{source.Target.Web.Origin + paths[0], source.Target.Web.Origin + paths[1]},
			}},
		})
		if err != nil {
			return CandidateValidation{}, err
		}
		if err = s.validator.ValidateTask(ctx, task); err != nil {
			return CandidateValidation{}, fmt.Errorf("%w: validation task contract rejected", ErrInvalid)
		}
		if _, err = s.traffic.AuthorizeTask(ctx, task); err != nil {
			return CandidateValidation{}, fmt.Errorf("%w: validation target policy denied", ErrInvalid)
		}
		options, _ := json.Marshal(EnqueueOptions{MaxAttempts: input.MaxAttempts})
		_, err = tx.Exec(ctx, `INSERT INTO queue_tasks(project_id,run_id,task_id,spec,fingerprint,retry_class,max_attempts,reserve_tokens,reserve_requests,reserve_seconds,reserve_cost,deadline,reserve_bytes)
VALUES($1,$2,$3,$4,$5,'read_only',$6,0,$7,$8,0,$9,$10)`,
			input.ProjectID, input.RunID, id, task, hash(append(task, options...)), input.MaxAttempts, requests, input.MaxWallSeconds, deadline, input.MaxArtifactBytes)
		if err != nil {
			return CandidateValidation{}, err
		}
		if stage == "hunt" {
			if _, err = tx.Exec(ctx, "INSERT INTO queue_dependencies VALUES($1,$2,$3,$4)", input.ProjectID, input.RunID, id, out.PreflightTaskID); err != nil {
				return CandidateValidation{}, err
			}
		}
		if err = event(ctx, tx, input.ProjectID, input.RunID, id, "candidate_validation_enqueued", map[string]string{"candidate_evidence_id": input.CandidateEvidenceID, "stage": stage}); err != nil {
			return CandidateValidation{}, err
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO web_candidate_validations(project_id,run_id,candidate_evidence_id,preflight_task_id,discovery_task_id,finding_id,request_hash)
VALUES($1,$2,$3,$4,$5,$6,$7)`, input.ProjectID, input.RunID, input.CandidateEvidenceID, out.PreflightTaskID, out.DiscoveryTaskID, out.FindingID, requestHash); err != nil {
		return CandidateValidation{}, err
	}
	if _, err = tx.Exec(ctx, "UPDATE queue_runs SET task_count=task_count+2 WHERE project_id=$1 AND run_id=$2", input.ProjectID, input.RunID); err != nil {
		return CandidateValidation{}, err
	}
	return out, tx.Commit(ctx)
}

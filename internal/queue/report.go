package queue

import (
	"context"
	"encoding/json"
	"time"

	"example.com/unified-harness/internal/checks"
	"github.com/jackc/pgx/v5"
)

// Reports intentionally project metadata instead of exporting task specs/results.
// Raw results can contain model/source excerpts and are unsuitable for a report.
const ReportTaskLimit = 200
const ReportFindingLimit = 100

type TaskCount struct {
	Stage  string `json:"stage"`
	Status string `json:"status"`
	Count  int64  `json:"count"`
}
type ReportTask struct {
	ID                  string    `json:"task_id"`
	Stage               string    `json:"stage"`
	Mode                string    `json:"mode"`
	CheckKind           string    `json:"check_kind,omitempty"`
	Origin              string    `json:"origin,omitempty"`
	Status              string    `json:"status"`
	Generation          int64     `json:"generation"`
	Verdict             string    `json:"verdict,omitempty"`
	ReasonCode          string    `json:"reason_code,omitempty"`
	CandidateStatus     string    `json:"candidate_status,omitempty"`
	EvidenceID          string    `json:"evidence_id,omitempty"`
	FailedPrerequisites int64     `json:"failed_prerequisites"`
	Deadline            time.Time `json:"deadline"`
}
type ReportFinding struct {
	ID                   string   `json:"finding_id"`
	Status               string   `json:"status"`
	Origin               string   `json:"origin"`
	DeploymentID         string   `json:"deployment_id"`
	DiscoveryTaskID      string   `json:"discovery_task_id"`
	DiscoveryEvidenceID  string   `json:"discovery_evidence_id"`
	ValidationTaskID     *string  `json:"validation_task_id"`
	ValidationEvidenceID *string  `json:"validation_evidence_id"`
	SourceEvidenceIDs    []string `json:"source_evidence_ids"`
	Steps                []string `json:"reproduction_steps"`
}
type RunReport struct {
	Version           string           `json:"version"`
	GeneratedAt       time.Time        `json:"generated_at"`
	Run               Run              `json:"run"`
	TaskCounts        []TaskCount      `json:"task_counts"`
	FindingCounts     map[string]int64 `json:"finding_counts"`
	Tasks             []ReportTask     `json:"tasks"`
	Findings          []ReportFinding  `json:"findings"`
	TasksTruncated    bool             `json:"tasks_truncated"`
	FindingsTruncated bool             `json:"findings_truncated"`
	Limitations       []string         `json:"limitations"`
}

const effectiveFindingStatus = `CASE WHEN f.status='pending_validation' AND t.status IN ('failed','cancelled','blocked_environment','needs_reconciliation') THEN 'inconclusive' ELSE f.status END`

func (s *Store) Report(ctx context.Context, project, run string) (RunReport, error) {
	v := RunReport{Version: "opensec-run-report-v1", TaskCounts: []TaskCount{}, FindingCounts: map[string]int64{}, Tasks: []ReportTask{}, Findings: []ReportFinding{}, Limitations: []string{
		"This snapshot covers only configured tasks and checks; it is not a claim that the target has no vulnerabilities.",
		"Preflight evaluates legitimate object access only. Failed, skipped, blocked, expired or incomplete work does not establish security.",
		"Only confirmed findings have independently reproduced HTTP evidence. Source links and web model candidates are not runtime validation.",
		"Headers, response bodies, credentials, task prompts and model/source excerpts are omitted. Treat identifiers and reproduction URLs as sensitive.",
		"Task and finding detail lists are bounded; aggregate counts include all records in the snapshot.",
	}}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return v, err
	}
	defer tx.Rollback(ctx)
	v.Run, err = scanRun(tx.QueryRow(ctx, "SELECT "+runColumns+" FROM queue_runs WHERE project_id=$1 AND run_id=$2", project, run))
	if err != nil {
		return v, err
	}
	if err = tx.QueryRow(ctx, "SELECT transaction_timestamp()").Scan(&v.GeneratedAt); err != nil {
		return v, err
	}
	rows, err := tx.Query(ctx, `SELECT spec->>'stage',status,count(*) FROM queue_tasks WHERE project_id=$1 AND run_id=$2 GROUP BY 1,2 ORDER BY 1,2`, project, run)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var c TaskCount
		if err = rows.Scan(&c.Stage, &c.Status, &c.Count); err != nil {
			rows.Close()
			return v, err
		}
		v.TaskCounts = append(v.TaskCounts, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	// Verdict fields leave storage only when bound evidence exists for this exact task.
	rows, err = tx.Query(ctx, `SELECT t.task_id,t.spec->>'stage',t.spec#>>'{target,mode}',COALESCE(t.spec#>>'{check,kind}',''),COALESCE(t.spec#>>'{target,web,origin}',''),
t.status,t.generation,CASE WHEN e.evidence_id IS NOT NULL AND t.spec#>>'{check,kind}' IN ('object_authorization','tenant_isolation') THEN COALESCE(a.result->>'verdict','') ELSE '' END,
CASE WHEN e.evidence_id IS NOT NULL AND t.spec#>>'{check,kind}' IN ('object_authorization','tenant_isolation') THEN COALESCE(a.result->>'reason_code','') ELSE '' END,CASE WHEN e.evidence_id IS NOT NULL AND t.spec ? 'web_investigator' THEN COALESCE(a.result#>>'{web_investigation,candidate,status}','') ELSE '' END,COALESCE(e.evidence_id,''),
(SELECT count(*) FROM queue_dependencies d JOIN queue_tasks p ON p.project_id=d.project_id AND p.run_id=d.run_id AND p.task_id=d.depends_on WHERE d.project_id=t.project_id AND d.run_id=t.run_id AND d.task_id=t.task_id AND p.status IN ('failed','cancelled')),t.deadline
FROM queue_tasks t LEFT JOIN queue_attempts a ON a.project_id=t.project_id AND a.run_id=t.run_id AND a.task_id=t.task_id AND a.generation=t.generation
LEFT JOIN evidence_records e ON e.project_id=t.project_id AND e.run_id=t.run_id AND e.task_id=t.task_id AND e.attempt_id=a.attempt_id AND e.evidence_id=COALESCE(a.result->>'evidence_id',a.result->>'web_evidence_id')
WHERE t.project_id=$1 AND t.run_id=$2 ORDER BY t.created_at,t.task_id LIMIT $3`, project, run, ReportTaskLimit+1)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var t ReportTask
		if err = rows.Scan(&t.ID, &t.Stage, &t.Mode, &t.CheckKind, &t.Origin, &t.Status, &t.Generation, &t.Verdict, &t.ReasonCode, &t.CandidateStatus, &t.EvidenceID, &t.FailedPrerequisites, &t.Deadline); err != nil {
			rows.Close()
			return v, err
		}
		v.Tasks = append(v.Tasks, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	if len(v.Tasks) > ReportTaskLimit {
		v.TasksTruncated = true
		v.Tasks = v.Tasks[:ReportTaskLimit]
	}
	rows, err = tx.Query(ctx, "SELECT "+effectiveFindingStatus+`,count(*) FROM findings f LEFT JOIN queue_tasks t ON t.project_id=f.project_id AND t.run_id=f.run_id AND t.task_id=f.validation_task_id WHERE f.project_id=$1 AND f.run_id=$2 GROUP BY 1 ORDER BY 1`, project, run)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var status string
		var n int64
		if err = rows.Scan(&status, &n); err != nil {
			rows.Close()
			return v, err
		}
		v.FindingCounts[status] = n
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	rows, err = tx.Query(ctx, "SELECT f.finding_id,"+effectiveFindingStatus+`,f.origin,f.deployment_id,f.discovery_task_id,f.discovery_evidence_id,f.validation_task_id,f.validation_evidence_id,f.check_plan
FROM findings f LEFT JOIN queue_tasks t ON t.project_id=f.project_id AND t.run_id=f.run_id AND t.task_id=f.validation_task_id
WHERE f.project_id=$1 AND f.run_id=$2 ORDER BY f.finding_id LIMIT $3`, project, run, ReportFindingLimit+1)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var f ReportFinding
		var plan checks.Plan
		var raw []byte
		if err = rows.Scan(&f.ID, &f.Status, &f.Origin, &f.DeploymentID, &f.DiscoveryTaskID, &f.DiscoveryEvidenceID, &f.ValidationTaskID, &f.ValidationEvidenceID, &raw); err != nil {
			rows.Close()
			return v, err
		}
		if err = json.Unmarshal(raw, &plan); err != nil {
			rows.Close()
			return v, err
		}
		f.Steps = checks.ReproductionSteps(f.Origin, plan)
		f.SourceEvidenceIDs = []string{}
		v.Findings = append(v.Findings, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	if len(v.Findings) > ReportFindingLimit {
		v.FindingsTruncated = true
		v.Findings = v.Findings[:ReportFindingLimit]
	}
	// Source evidence IDs remain useful without exporting source content.
	for i := range v.Findings {
		rows, err = tx.Query(ctx, `SELECT DISTINCT source_evidence_id FROM source_investigations WHERE project_id=$1 AND run_id=$2 AND finding_id=$3 AND source_evidence_id IS NOT NULL ORDER BY source_evidence_id LIMIT 101`, project, run, v.Findings[i].ID)
		if err != nil {
			return v, err
		}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return v, err
			}
			v.Findings[i].SourceEvidenceIDs = append(v.Findings[i].SourceEvidenceIDs, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return v, err
		}
		if len(v.Findings[i].SourceEvidenceIDs) > 100 {
			v.Findings[i].SourceEvidenceIDs = v.Findings[i].SourceEvidenceIDs[:100]
			v.FindingsTruncated = true
		}
	}
	return v, tx.Commit(ctx)
}

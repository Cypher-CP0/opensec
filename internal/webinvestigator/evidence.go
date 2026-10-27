package webinvestigator

import (
	"encoding/json"
	"time"

	"example.com/unified-harness/internal/checks"
)

func NewEvidence(s Spec, attempt string, r Report, at time.Time) checks.Submission {
	raw, _ := json.Marshal(r)
	refs := append([]string{}, s.Investigator.IdentityRefs...)
	return checks.Submission{Artifact: raw, Record: checks.Evidence{
		SchemaVersion: 1,
		EvidenceID:    "web-" + checks.Hash([]byte(attempt))[:40],
		CandidateID:   "candidate-" + checks.Hash([]byte(attempt))[:40],
		ProjectID:     s.ProjectID, RunID: s.RunID, TaskID: s.TaskID, AttemptID: attempt, PolicyRef: s.PolicyRef, ObservedAt: at,
		Expected:    "Authorized target behavior under the declared policy",
		Observed:    "Unvalidated model candidate; network observations require independent replay.",
		Redaction:   "web-investigator-v1",
		Limitations: []string{"Model reasoning is an unvalidated candidate, not a confirmed vulnerability.", "Only bounded response metadata and redacted action digests are stored; raw response bodies are omitted.", "A separate, fresh validation run is required before a finding can be confirmed."},
		Artifact:    checks.ArtifactRef{SHA256: checks.Hash(raw), Bytes: int64(len(raw)), MediaType: "application/json"},
		Payload:     checks.Payload{Kind: "browser_observation", DeploymentID: s.Target.Web.DeploymentID, ObservationID: s.Target.Web.ObservationID, IdentityRefs: refs, BrowserVersion: r.BrowserVersion},
	}}
}
func Summary(r Report, attempt string) json.RawMessage {
	evidenceID := ""
	if r.Candidate != nil {
		evidenceID = "web-" + checks.Hash([]byte(attempt))[:40]
	}
	raw, _ := json.Marshal(struct {
		Report     Report `json:"web_investigation"`
		EvidenceID string `json:"web_evidence_id,omitempty"`
	}{r, evidenceID})
	return raw
}

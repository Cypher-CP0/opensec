// Package checks implements versioned, deterministic checks and redacted evidence.
package checks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const Version = "tenant-isolation-v1"
const Redaction = "tenant-summary-v1"
const MaxArtifact = 64 << 10

type Plan struct {
	Kind      string `json:"kind"`
	IdentityA string `json:"identity_a_ref"`
	IdentityB string `json:"identity_b_ref"`
	TenantA   string `json:"tenant_a"`
	TenantB   string `json:"tenant_b"`
	ExportA   string `json:"export_a"`
	ExportB   string `json:"export_b"`
}
type Spec struct {
	ProjectID string `json:"project_id"`
	RunID     string `json:"run_id"`
	TaskID    string `json:"task_id"`
	PolicyRef string `json:"policy_ref"`
	Stage     string `json:"stage"`
	Check     *Plan  `json:"check"`
	Target    struct {
		Web *struct {
			Origin        string `json:"origin"`
			DeploymentID  string `json:"deployment_id"`
			ObservationID string `json:"observation_id"`
		} `json:"web"`
	} `json:"target"`
}

func Parse(raw json.RawMessage) (Spec, error) {
	var s Spec
	err := json.Unmarshal(raw, &s)
	if err == nil && s.Check != nil {
		err = s.Check.Validate()
		if s.Target.Web == nil {
			err = errors.New("check needs a web target")
		}
	}
	return s, err
}
func (p Plan) Validate() error {
	id := regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
	if p.Kind != "tenant_isolation" || p.IdentityA == p.IdentityB || p.TenantA == p.TenantB || p.ExportA == p.ExportB {
		return errors.New("invalid tenant isolation plan")
	}
	for _, v := range []string{p.IdentityA, p.IdentityB, p.TenantA, p.TenantB, p.ExportA, p.ExportB} {
		if !id.MatchString(v) {
			return errors.New("invalid check identifier")
		}
	}
	return nil
}
func Hash(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }
func Candidate(s Spec) string {
	// Run-scoped stable identity. Task/attempt/observation IDs do not create duplicates.
	raw, _ := json.Marshal([]any{s.ProjectID, s.RunID, s.PolicyRef, s.Target.Web.Origin, s.Target.Web.DeploymentID, s.Check})
	return "finding-" + Hash(raw)[:40]
}
func (s Spec) URLs() []string {
	base := strings.TrimRight(s.Target.Web.Origin, "/")
	return []string{base + "/exports/" + url.PathEscape(s.Check.ExportA), base + "/exports/" + url.PathEscape(s.Check.ExportB), base + "/exports/" + url.PathEscape(s.Check.ExportB)}
}

type Observation struct {
	Status        int    `json:"status"`
	BodyBytes     int64  `json:"body_bytes"`
	ExportMatches bool   `json:"export_matches"`
	TenantMatches bool   `json:"tenant_matches"`
	ContentSHA256 string `json:"content_sha256,omitempty"`
}
type Transcript struct {
	Version      string        `json:"check_version"`
	Observations []Observation `json:"observations"`
}
type Result struct {
	Kind       string     `json:"kind"`
	Verdict    string     `json:"verdict"`
	Reason     string     `json:"reason"`
	Transcript Transcript `json:"transcript"`
}

func Summarize(status int, body []byte, export, tenant string) Observation {
	o := Observation{Status: status, BodyBytes: int64(len(body))}
	// Only fixed comparisons and a content digest leave the runner. No headers,
	// raw content, unknown fields, or server-controlled strings are persisted.
	var doc struct {
		Export  string `json:"export_id"`
		Tenant  string `json:"tenant_id"`
		Content string `json:"content"`
	}
	if uniqueObject(body) && json.Unmarshal(body, &doc) == nil {
		o.ExportMatches = doc.Export == export
		o.TenantMatches = doc.Tenant == tenant
		if doc.Content != "" {
			o.ContentSHA256 = Hash([]byte(doc.Content))
		}
	}
	return o
}

// Duplicate JSON keys make response ownership ambiguous across parsers.
func uniqueObject(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return false
		}
		name, ok := key.(string)
		if !ok || seen[strings.ToLower(name)] {
			return false
		}
		seen[strings.ToLower(name)] = true
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
	}
	if _, err = d.Token(); err != nil {
		return false
	}
	var extra any
	return d.Decode(&extra) == io.EOF
}
func Evaluate(t Transcript) Result {
	r := Result{Kind: Version, Verdict: "inconclusive", Reason: "positive controls or response semantics could not be established", Transcript: t}
	if t.Version != Version || len(t.Observations) != 3 {
		return r
	}
	valid := func(o Observation) bool {
		return o.Status == 200 && o.ExportMatches && o.TenantMatches && len(o.ContentSHA256) == 64
	}
	a, b, c := t.Observations[0], t.Observations[1], t.Observations[2]
	if !valid(a) || !valid(b) {
		return r
	}
	if valid(c) && c.ContentSHA256 == b.ContentSHA256 {
		r.Verdict = "vulnerable"
		r.Reason = "tenant A retrieved tenant B's export with matching ownership and content"
	} else if c.Status == 403 || c.Status == 404 {
		r.Verdict = "not_vulnerable"
		r.Reason = "cross-tenant access denied with working positive controls"
	}
	return r
}
func ValidateTranscript(t Transcript) error {
	if t.Version != Version || len(t.Observations) > 3 {
		return errors.New("invalid check transcript")
	}
	digest := regexp.MustCompile("^[0-9a-f]{64}$")
	for _, o := range t.Observations {
		if o.Status < 100 || o.Status > 599 || o.BodyBytes < 0 || o.BodyBytes > MaxArtifact || (o.ContentSHA256 != "" && !digest.MatchString(o.ContentSHA256)) {
			return errors.New("invalid observation")
		}
	}
	return nil
}

type ArtifactRef struct {
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"byte_length"`
	MediaType string `json:"media_type"`
}
type Payload struct {
	Kind          string   `json:"kind"`
	DeploymentID  string   `json:"deployment_id"`
	ObservationID string   `json:"observation_id"`
	IdentityRefs  []string `json:"identity_refs"`
}
type Evidence struct {
	SchemaVersion int         `json:"schema_version"`
	EvidenceID    string      `json:"evidence_id"`
	CandidateID   string      `json:"candidate_id"`
	ProjectID     string      `json:"project_id"`
	RunID         string      `json:"run_id"`
	TaskID        string      `json:"task_id"`
	AttemptID     string      `json:"task_attempt_id"`
	PolicyRef     string      `json:"policy_ref"`
	ObservedAt    time.Time   `json:"observed_at"`
	Expected      string      `json:"expected_property"`
	Observed      string      `json:"observed_result"`
	Redaction     string      `json:"redaction_version"`
	Limitations   []string    `json:"limitations"`
	Artifact      ArtifactRef `json:"artifact"`
	Payload       Payload     `json:"payload"`
}
type Submission struct {
	Record   Evidence        `json:"record"`
	Artifact json.RawMessage `json:"artifact"`
}

func NewEvidence(s Spec, attempt string, t Transcript, at time.Time) Submission {
	raw, _ := json.Marshal(t)
	r := Evaluate(t)
	return Submission{Record: Evidence{
		SchemaVersion: 1, EvidenceID: "evidence-" + Hash([]byte(attempt))[:40], CandidateID: Candidate(s),
		ProjectID: s.ProjectID, RunID: s.RunID, TaskID: s.TaskID, AttemptID: attempt, PolicyRef: s.PolicyRef, ObservedAt: at,
		Expected: "An account can read only its tenant's export", Observed: r.Verdict + ": " + r.Reason, Redaction: Redaction,
		Limitations: []string{"Fixed export JSON contract; this check does not assess other endpoints or vulnerability classes.", "Response content and all headers omitted; content is represented by SHA-256."},
		Artifact:    ArtifactRef{Hash(raw), int64(len(raw)), "application/json"},
		Payload:     Payload{"http_sequence", s.Target.Web.DeploymentID, s.Target.Web.ObservationID, []string{s.Check.IdentityA, s.Check.IdentityB}},
	}, Artifact: raw}
}

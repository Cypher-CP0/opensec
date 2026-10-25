// Package investigator implements a bounded, read-only source hypothesis loop.
// Models are untrusted proposal generators, never vulnerability validators.
package investigator

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"slices"
	"strings"
	"time"

	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/configfile"
)

const Version = "source-investigator-v1"
const MaxSteps = 12
const MaxArtifact = 64 << 10
const MaxExcerpt = 8192
const MaxRationaleBytes = 2048
const MaxHypothesisAnchors = 8

type Config struct {
	ProfileRef string       `json:"profile_ref"`
	MaxSteps   int          `json:"max_steps"`
	Paths      []string     `json:"paths"`
	Probe      *checks.Plan `json:"probe,omitempty"`
}
type Source struct {
	RepositoryID string `json:"repository_id"`
	Commit       string `json:"commit"`
	SHA256       string `json:"snapshot_sha256"`
}
type Spec struct {
	ProjectID    string  `json:"project_id"`
	RunID        string  `json:"run_id"`
	TaskID       string  `json:"task_id"`
	PolicyRef    string  `json:"policy_ref"`
	Question     string  `json:"question"`
	Investigator *Config `json:"investigator"`
	Target       struct {
		Source     *Source `json:"source"`
		MappingRef string  `json:"mapping_ref"`
	} `json:"target"`
}

func Parse(raw json.RawMessage) (Spec, error) {
	var s Spec
	err := json.Unmarshal(raw, &s)
	return s, err
}
func ValidPath(p string) bool {
	return len(p) <= 256 && fs.ValidPath(p) && p != "." && !strings.ContainsAny(p, "\\:\r\n\x00")
}
func ValidPaths(paths []string) bool {
	if len(paths) < 1 || len(paths) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, p := range paths {
		if !ValidPath(p) || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}

type Query struct {
	Kind  string `json:"kind"`
	Path  string `json:"path"`
	Start int    `json:"line_start"`
	End   int    `json:"line_end"`
	Text  string `json:"text"`
}
type Anchor struct {
	Path  string `json:"path"`
	Start int    `json:"line_start"`
	End   int    `json:"line_end"`
}
type Excerpt struct {
	Anchor
	FileSHA256 string `json:"file_sha256"`
	SHA256     string `json:"excerpt_sha256"`
	Text       string `json:"text"`
}
type SourceResult struct {
	Files      []SourceFile   `json:"files,omitempty"`
	TotalLines int            `json:"total_lines,omitempty"`
	Problem    *SourceProblem `json:"problem,omitempty"`
	Matches    []Anchor       `json:"matches,omitempty"`
	Excerpt    *Excerpt       `json:"excerpt,omitempty"`
	Truncated  bool           `json:"truncated"`
}
type Action struct {
	Kind      string `json:"kind"`
	Path      string `json:"path"`
	Start     int    `json:"line_start"`
	End       int    `json:"line_end"`
	Text      string `json:"text"`
	AnchorIDs []int  `json:"anchor_ids"`
}
type Turn struct {
	Action Action
	Tokens int64
}
type Adapter interface {
	Call(context.Context, []byte) (Turn, error)
}
type SourceTool func(context.Context, Query) (SourceResult, error)
type Report struct {
	ToolEvents    []ToolEvent `json:"tool_events,omitempty"`
	ProviderError string      `json:"provider_error,omitempty"`
	ActionError   string      `json:"action_error,omitempty"`
	Version       string      `json:"version"`
	Status        string      `json:"status"`
	Calls         int         `json:"calls"`
	Tokens        int64       `json:"reported_tokens"`
	UsageKnown    bool        `json:"usage_known"`
	Excerpts      []Excerpt   `json:"excerpts"`
	Hypothesis    *Hypothesis `json:"hypothesis,omitempty"`
}
type Hypothesis struct {
	Kind      string `json:"kind"`
	Rationale string `json:"rationale"`
	AnchorIDs []int  `json:"anchor_ids"`
}

func (r Report) Validate(c Config) error {
	if err := r.validateToolEvents(c); err != nil {
		return err
	}
	if r.ProviderError != "" && (r.Status != "provider_error" || !validErrorCode(r.ProviderError)) {
		return errors.New("invalid provider diagnostic")
	}
	if r.ActionError != "" && (r.Status != "invalid_action" || !validActionErrorCode(r.ActionError)) {
		return errors.New("invalid action diagnostic")
	}
	if r.Version != Version || r.Calls < 0 || r.Calls > c.MaxSteps || r.Tokens < 0 || r.Tokens > 1e12 || len(r.Excerpts) > MaxSteps {
		return errors.New("invalid investigation report")
	}
	if !slices.Contains([]string{"hypothesis", "no_hypothesis", "step_limit", "token_limit", "context_limit", "provider_error", "tool_error", "invalid_action"}, r.Status) {
		return errors.New("invalid investigation status")
	}
	if (r.Status == "hypothesis") != (r.Hypothesis != nil) {
		return errors.New("hypothesis status mismatch")
	}
	for _, e := range r.Excerpts {
		if _, err := hex.DecodeString(e.FileSHA256); err != nil {
			return errors.New("invalid source digest")
		}
		if !slices.Contains(c.Paths, e.Path) || e.Start < 1 || e.End < e.Start || e.End-e.Start >= 64 || len(e.Text) > MaxExcerpt || len(e.FileSHA256) != 64 || checks.Hash([]byte(e.Text)) != e.SHA256 {
			return errors.New("invalid source excerpt")
		}
	}
	if h := r.Hypothesis; h != nil {
		if code := hypothesisError(*h, len(r.Excerpts)); code != "" {
			return errors.New(code)
		}
	}
	raw, _ := json.Marshal(r)
	if len(raw) > MaxArtifact {
		return errors.New("report too large")
	}
	return nil
}
func NewEvidence(s Spec, attempt string, r Report, at time.Time) checks.Submission {
	raw, _ := json.Marshal(r)
	anchors := []checks.SourceAnchor{}
	for _, i := range r.Hypothesis.AnchorIDs {
		e := r.Excerpts[i]
		anchors = append(anchors, checks.SourceAnchor{Path: e.Path, Start: e.Start, End: e.End})
	}
	return checks.Submission{Artifact: raw, Record: checks.Evidence{
		SchemaVersion: 1, EvidenceID: "source-" + checks.Hash([]byte(attempt))[:40], CandidateID: "hypothesis-" + checks.Hash([]byte(attempt))[:40],
		ProjectID: s.ProjectID, RunID: s.RunID, TaskID: s.TaskID, AttemptID: attempt, PolicyRef: s.PolicyRef, ObservedAt: at,
		Expected: "An account can read only its tenant's export", Observed: "Unvalidated model hypothesis; source anchors are not proof of exploitability.",
		Redaction:   "operator-selected-source-v1",
		Limitations: []string{"Source excerpts may contain sensitive data; only explicitly allowed files were disclosed.", "Commit-to-deployment mapping is operator asserted and unverified.", "Runtime confirmation requires fresh discovery and independent replay."},
		Artifact:    checks.ArtifactRef{SHA256: checks.Hash(raw), Bytes: int64(len(raw)), MediaType: "application/json"},
		Payload:     checks.Payload{Kind: "source_trace", SnapshotSHA256: s.Target.Source.SHA256, Anchors: anchors},
	}}
}
func Summary(r Report, attempt string) json.RawMessage {
	id := ""
	if r.Hypothesis != nil {
		id = "source-" + checks.Hash([]byte(attempt))[:40]
	}
	raw, _ := json.Marshal(struct {
		Report     Report `json:"investigation"`
		EvidenceID string `json:"source_evidence_id,omitempty"`
	}{r, id})
	return raw
}
func DecodeAction(raw []byte) (Action, error) {
	var a Action
	if err := configfile.Decode(raw, &a); err != nil {
		return a, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if token, err := dec.Token(); err != nil || token != json.Delim('{') {
		return a, errors.New("action must be an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return a, err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return a, errors.New("duplicate action key")
		}
		seen[key] = true
		var value json.RawMessage
		if err = dec.Decode(&value); err != nil {
			return a, err
		}
		if bytes.Equal(value, []byte("null")) {
			return a, errors.New("null action field")
		}
	}
	if len(seen) != 6 {
		return a, errors.New("all six action fields are required")
	}
	return a, nil
}

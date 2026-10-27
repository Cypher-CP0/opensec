// Package webinvestigator runs a bounded model investigation through controlled tools.
package webinvestigator

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"example.com/unified-harness/internal/configfile"
	"example.com/unified-harness/internal/investigator"
	"example.com/unified-harness/internal/policy"
)

const Version = "web-investigator-v1"
const MaxSteps = 24
const MaxArtifact = 64 << 10
const MaxToolOutput = 8192

type Config struct {
	ProfileRef     string   `json:"profile_ref"`
	MaxSteps       int      `json:"max_steps"`
	IdentityRefs   []string `json:"identity_refs"`
	AllowMutations bool     `json:"allow_mutations"`
}
type Spec struct {
	SchemaVersion int       `json:"schema_version"`
	ProjectID     string    `json:"project_id"`
	RunID         string    `json:"run_id"`
	TaskID        string    `json:"task_id"`
	PolicyRef     string    `json:"policy_ref"`
	Question      string    `json:"question"`
	CreatedAt     time.Time `json:"created_at"`
	Deadline      time.Time `json:"deadline"`
	RetryClass    string    `json:"retry_class"`
	Investigator  *Config   `json:"web_investigator"`
	Budget        struct {
		Tokens   int64 `json:"max_model_tokens"`
		Requests int64 `json:"max_requests"`
		Bytes    int64 `json:"max_artifact_bytes"`
		Seconds  int64 `json:"max_wall_seconds"`
	} `json:"budget"`
	Target struct {
		Mode string `json:"mode"`
		Web  *struct {
			Origin        string   `json:"origin"`
			DeploymentID  string   `json:"deployment_id"`
			ObservationID string   `json:"observation_id"`
			Seeds         []string `json:"seed_urls"`
		} `json:"web"`
	} `json:"target"`
}

func Parse(raw json.RawMessage) (Spec, error) {
	var s Spec
	err := json.Unmarshal(raw, &s)
	if err != nil {
		return s, err
	}
	if s.Investigator == nil {
		return s, nil
	}
	if s.SchemaVersion != 1 || s.Target.Mode != "web" || s.Target.Web == nil || s.Investigator.MaxSteps < 1 || s.Investigator.MaxSteps > MaxSteps ||
		len(s.Target.Web.Seeds) == 0 || len(s.Investigator.IdentityRefs) > 8 || s.Budget.Tokens < 1 || s.Budget.Requests < 1 || s.Budget.Bytes < 262144 || !s.Deadline.After(s.CreatedAt) {
		return s, errors.New("invalid web investigation task")
	}
	if s.Investigator.AllowMutations && s.RetryClass != "requires_reconciliation" || !s.Investigator.AllowMutations && s.RetryClass != "read_only" {
		return s, errors.New("mutation authority and retry class mismatch")
	}
	return s, nil
}

type Profile struct {
	ID                    string `json:"id"`
	Provider              string `json:"provider"`
	Executable            string `json:"executable"`
	Model                 string `json:"model"`
	ProjectID             string `json:"project_id"`
	PolicyRef             string `json:"policy_ref"`
	Origin                string `json:"origin"`
	MaxCalls              int    `json:"max_calls"`
	MaxPromptBytes        int    `json:"max_prompt_bytes"`
	CallSeconds           int    `json:"call_seconds"`
	AllowTargetDisclosure bool   `json:"allow_target_disclosure"`
}

func LoadProfiles(path string) ([]Profile, error) {
	if path == "" {
		return nil, nil
	}
	var ps []Profile
	if err := configfile.Read(path, &ps); err != nil {
		return nil, err
	}
	if len(ps) > 32 {
		return nil, errors.New("too many web investigator profiles")
	}
	ids := map[string]bool{}
	for _, p := range ps {
		u, err := url.Parse(p.Origin)
		if err != nil || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && u.Hostname() == "127.0.0.1")) || u.Host == "" || u.Path != "" || u.RawQuery != "" ||
			p.ID == "" || ids[p.ID] || p.Provider != "claude_code" || !filepath.IsAbs(p.Executable) || p.Model == "" || strings.HasPrefix(p.Model, "-") || len(p.Model) > 128 ||
			p.ProjectID == "" || p.PolicyRef == "" || p.MaxCalls < 1 || p.MaxCalls > MaxSteps || p.MaxPromptBytes < 4096 || p.MaxPromptBytes > 65536 || p.CallSeconds < 1 || p.CallSeconds > 120 || !p.AllowTargetDisclosure {
			return nil, errors.New("invalid web investigator profile or target disclosure authority")
		}
		ids[p.ID] = true
	}
	return ps, nil
}
func Select(profiles []Profile, s Spec) (Profile, error) {
	if s.Investigator == nil || s.Target.Web == nil {
		return Profile{}, errors.New("web investigation not configured")
	}
	for _, p := range profiles {
		if p.ID == s.Investigator.ProfileRef {
			if p.ProjectID != s.ProjectID || p.PolicyRef != s.PolicyRef || p.Origin != s.Target.Web.Origin || s.Investigator.MaxSteps > p.MaxCalls || !p.AllowTargetDisclosure {
				return Profile{}, errors.New("web investigator scope denied")
			}
			return p, nil
		}
	}
	return Profile{}, errors.New("web investigator profile unavailable")
}
func CLIProfile(p Profile) investigator.Profile {
	return investigator.Profile{Executable: p.Executable, Model: p.Model, CallSeconds: p.CallSeconds, MaxPromptBytes: p.MaxPromptBytes}
}

type Action struct {
	Kind           string            `json:"kind"`
	URL            string            `json:"url,omitempty"`
	Method         string            `json:"method,omitempty"`
	AllowMutation  bool              `json:"allow_mutation,omitempty"`
	IdentityRef    string            `json:"identity_ref,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           string            `json:"body,omitempty"`
	Selector       string            `json:"selector,omitempty"`
	Value          string            `json:"value,omitempty"`
	Script         string            `json:"script,omitempty"`
	Rationale      string            `json:"rationale,omitempty"`
	ObservationIDs []int             `json:"observation_ids,omitempty"`
}

func DecodeAction(raw []byte) (Action, error) {
	var a Action
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if len(raw) > 16384 || d.Decode(&a) != nil || d.Decode(new(any)) != io.EOF {
		return a, errors.New("invalid web action")
	}
	return a, a.Validate()
}

var idPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

func (a Action) Validate() error {
	if a.AllowMutation && a.Kind != "click" {
		return errors.New("mutation flag is only valid on click actions")
	}
	if a.IdentityRef != "" && !idPattern.MatchString(a.IdentityRef) {
		return errors.New("invalid identity reference")
	}
	if len(a.URL) > 2048 || len(a.Body) > 32768 || len(a.Script) > 4096 || len(a.Selector) > 512 || len(a.Value) > 2048 || len(a.Rationale) > 2048 || len(a.ObservationIDs) > 8 || policy.ValidateHeaders(a.Headers) != nil {
		return errors.New("web action exceeds bounds")
	}
	switch a.Kind {
	case "request":
		if a.URL == "" || a.Script != "" || a.Selector != "" || a.Value != "" || a.Rationale != "" || len(a.ObservationIDs) > 0 {
			return errors.New("invalid request fields")
		}
		switch a.NetworkMethod() {
		case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE":
		default:
			return errors.New("unsupported request method")
		}
		if a.Body != "" && (a.NetworkMethod() == "GET" || a.NetworkMethod() == "HEAD") {
			return errors.New("body is unsupported for read-only methods")
		}
	case "navigate":
		if a.URL == "" || a.Method != "" || len(a.Headers) > 0 || a.Body != "" || a.Selector != "" || a.Value != "" || a.Script != "" || a.Rationale != "" || len(a.ObservationIDs) > 0 {
			return errors.New("invalid navigation fields")
		}
	case "snapshot":
		if a.URL != "" || a.Method != "" || len(a.Headers) > 0 || a.Body != "" || a.Selector != "" || a.Value != "" || a.Script != "" || a.Rationale != "" || len(a.ObservationIDs) > 0 {
			return errors.New("invalid snapshot fields")
		}
	case "click", "fill":
		if a.Selector == "" || a.URL != "" || a.Method != "" || len(a.Headers) > 0 || a.Body != "" || a.Script != "" || a.Rationale != "" || len(a.ObservationIDs) > 0 || (a.Kind == "click" && a.Value != "") {
			return errors.New("invalid browser action fields")
		}
	case "command":
		if strings.TrimSpace(a.Script) == "" || a.URL != "" || a.Method != "" || len(a.Headers) > 0 || a.Body != "" || a.Selector != "" || a.Value != "" || a.Rationale != "" || len(a.ObservationIDs) > 0 {
			return errors.New("invalid command fields")
		}
	case "propose":
		if strings.TrimSpace(a.Rationale) == "" || len(a.ObservationIDs) == 0 || a.URL != "" || a.Method != "" || len(a.Headers) > 0 || a.Body != "" || a.Selector != "" || a.Value != "" || a.Script != "" {
			return errors.New("invalid candidate fields")
		}
	case "stop":
		if a.URL != "" || a.Method != "" || a.IdentityRef != "" || len(a.Headers) > 0 || a.Body != "" || a.Selector != "" || a.Value != "" || a.Script != "" || a.Rationale != "" || len(a.ObservationIDs) > 0 {
			return errors.New("invalid stop fields")
		}
	default:
		return errors.New("unsupported web action")
	}
	return nil
}
func (a Action) NetworkMethod() string {
	if a.Kind == "request" {
		if a.Method != "" {
			return a.Method
		}
		return "GET"
	}
	return "GET"
}
func (a Action) ValidFor(s Spec) error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.IdentityRef != "" {
		found := false
		for _, id := range s.Investigator.IdentityRefs {
			if id == a.IdentityRef {
				found = true
			}
		}
		if !found {
			return errors.New("identity is outside task scope")
		}
	}
	if a.AllowMutation && !s.Investigator.AllowMutations {
		return errors.New("mutations are outside task scope")
	}
	if a.Kind == "request" && a.NetworkMethod() != "GET" && a.NetworkMethod() != "HEAD" && !s.Investigator.AllowMutations {
		return errors.New("mutations are outside task scope")
	}
	return nil
}
func (a Action) Probe() policy.Probe {
	return policy.Probe{URL: a.URL, IdentityRef: a.IdentityRef, Method: a.NetworkMethod(), Body: []byte(a.Body), Headers: a.Headers}
}
func ConfigFile(path string) ([]Profile, error) { return LoadProfiles(path) }

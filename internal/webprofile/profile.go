// Package webprofile prepares an autonomous web investigation without contacting the target.
package webprofile

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"example.com/unified-harness/internal/coreclient"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/webinvestigator"
)

type Identity struct {
	Ref        string `json:"identity_ref"`
	TokenFile  string `json:"token_file"`
	AuthKind   string `json:"auth_kind,omitempty"`
	HeaderName string `json:"header_name,omitempty"`
}
type Profile struct {
	SchemaVersion   int                     `json:"schema_version"`
	ProjectID       string                  `json:"project_id"`
	PolicyRef       string                  `json:"policy_ref"`
	Origin          string                  `json:"origin"`
	DeploymentID    string                  `json:"deployment_id"`
	CIDRs           []string                `json:"allowed_cidrs"`
	AllowPrivate    bool                    `json:"allow_private"`
	Endpoints       []policy.Endpoint       `json:"allowed_endpoints"`
	Traffic         *policy.TrafficLimits   `json:"traffic,omitempty"`
	Seeds           []string                `json:"seed_urls"`
	Identities      []Identity              `json:"identities"`
	Question        string                  `json:"question"`
	MaxSteps        int                     `json:"max_steps"`
	AllowMutations  bool                    `json:"allow_mutations"`
	DeadlineSeconds int                     `json:"deadline_seconds"`
	WallSeconds     int64                   `json:"max_wall_seconds"`
	ArtifactBytes   int64                   `json:"max_artifact_bytes"`
	Tokens          int64                   `json:"max_model_tokens"`
	Requests        int64                   `json:"max_requests"`
	Model           webinvestigator.Profile `json:"model"`
}
type Bundle struct {
	Policy      []policy.Policy
	Credentials []policy.Credential
	Profiles    []webinvestigator.Profile
	Run         queue.RunConfig
	Task        json.RawMessage
	Enqueue     json.RawMessage
}

var validID = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

func Prepare(ctx context.Context, p Profile, run, baseDir, core string, now time.Time) (Bundle, error) {
	var out Bundle
	if p.SchemaVersion != 1 || !validID.MatchString(run) || !validID.MatchString(p.ProjectID) || !validID.MatchString(p.PolicyRef) || !validID.MatchString(p.DeploymentID) ||
		len(p.Question) < 1 || len(p.Question) > 4096 || len(p.Seeds) < 1 || len(p.Seeds) > 16 || len(p.Endpoints) < 1 || len(p.Endpoints) > 128 ||
		len(p.CIDRs) < 1 || len(p.CIDRs) > 32 || len(p.Identities) > 8 || p.MaxSteps < 1 || p.MaxSteps > webinvestigator.MaxSteps ||
		p.DeadlineSeconds < 60 || p.DeadlineSeconds > 86400 || p.WallSeconds < 1 || p.WallSeconds > int64(p.DeadlineSeconds) ||
		p.ArtifactBytes < 262144 || p.ArtifactBytes > 16<<20 || p.Tokens < 1 || p.Tokens > 1000000 || p.Requests < 1 || p.Requests > 1000 {
		return out, errors.New("invalid autonomous web profile identifiers or bounds")
	}
	origin, err := url.Parse(p.Origin)
	if err != nil || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return out, errors.New("invalid target origin")
	}
	if p.AllowMutations {
		writeRule := false
		for _, endpoint := range p.Endpoints {
			if endpoint.Method != "GET" && endpoint.Method != "HEAD" {
				writeRule = true
			}
		}
		if !writeRule {
			return out, errors.New("mutation task requires an explicit write endpoint rule")
		}
	}
	traffic := p.Traffic
	if traffic == nil {
		traffic = policy.DefaultTraffic()
	}
	pol := policy.Policy{Ref: p.PolicyRef, ProjectID: p.ProjectID, Origins: []string{p.Origin}, CIDRs: p.CIDRs, AllowPrivate: p.AllowPrivate, Repositories: []string{}, MaxInputBytes: 1 << 20, Endpoints: p.Endpoints, Traffic: traffic}
	registry, err := policy.New(ctx, []policy.Policy{pol}, core)
	if err != nil {
		return out, err
	}
	seen := map[string]bool{}
	refs := []string{}
	for _, identity := range p.Identities {
		if seen[identity.Ref] {
			return out, errors.New("duplicate identity reference")
		}
		seen[identity.Ref] = true
		ref := policy.Credential{ProjectID: p.ProjectID, PolicyRef: p.PolicyRef, Origin: p.Origin, IdentityRef: identity.Ref, TokenFile: identity.TokenFile, AuthKind: identity.AuthKind, HeaderName: identity.HeaderName}
		if err := policy.ValidateCredential(ref); err != nil {
			return out, err
		}
		if !filepath.IsAbs(ref.TokenFile) {
			ref.TokenFile, err = filepath.Abs(filepath.Join(baseDir, ref.TokenFile))
			if err != nil {
				return out, err
			}
		}
		out.Credentials = append(out.Credentials, ref)
		refs = append(refs, identity.Ref)
	}
	if p.Model.ProjectID != p.ProjectID || p.Model.PolicyRef != p.PolicyRef || p.Model.Origin != p.Origin || p.Model.MaxCalls < p.MaxSteps || p.Model.MaxCalls > webinvestigator.MaxSteps || p.Model.Provider != "claude_code" || !filepath.IsAbs(p.Model.Executable) || p.Model.Model == "" || strings.HasPrefix(p.Model.Model, "-") || len(p.Model.Model) > 128 || !p.Model.AllowTargetDisclosure ||
		p.Model.MaxPromptBytes < 4096 || p.Model.MaxPromptBytes > 65536 || p.Model.CallSeconds < 1 || p.Model.CallSeconds > 120 || !validID.MatchString(p.Model.ID) {
		return out, errors.New("invalid scoped model profile or target disclosure authority")
	}
	retry := "read_only"
	if p.AllowMutations {
		retry = "requires_reconciliation"
	}
	task := map[string]any{
		"schema_version": 1, "project_id": p.ProjectID, "run_id": run, "task_id": "investigate-web", "investigation_id": "web-investigation", "policy_ref": p.PolicyRef,
		"stage": "hunt", "retry_class": retry, "created_at": now.UTC(), "deadline": now.Add(time.Duration(p.DeadlineSeconds) * time.Second).UTC(),
		"dependencies": []string{}, "question": p.Question,
		"budget":           map[string]any{"max_wall_seconds": p.WallSeconds, "max_model_tokens": p.Tokens, "max_requests": p.Requests, "max_artifact_bytes": p.ArtifactBytes},
		"target":           map[string]any{"mode": "web", "web": map[string]any{"origin": p.Origin, "deployment_id": p.DeploymentID, "observation_id": "web-investigation", "seed_urls": p.Seeds}},
		"web_investigator": webinvestigator.Config{ProfileRef: p.Model.ID, MaxSteps: p.MaxSteps, IdentityRefs: refs, AllowMutations: p.AllowMutations},
	}
	raw, err := json.Marshal(task)
	if err != nil {
		return out, err
	}
	if _, err = coreclient.Call(ctx, core, map[string]any{"operation": "validate", "kind": "task", "document": json.RawMessage(raw)}); err != nil {
		return out, err
	}
	if _, err = registry.AuthorizeTask(ctx, raw); err != nil {
		return out, err
	}
	options := queue.EnqueueOptions{MaxAttempts: 1}
	envelope, err := json.Marshal(struct {
		Task    json.RawMessage      `json:"task"`
		Options queue.EnqueueOptions `json:"options"`
	}{raw, options})
	if err != nil {
		return out, err
	}
	out.Policy = []policy.Policy{pol}
	out.Profiles = []webinvestigator.Profile{p.Model}
	out.Run = queue.RunConfig{ProjectID: p.ProjectID, RunID: run, MaxTasks: 1, MaxAttempts: 1, Limits: queue.Units{ArtifactBytes: p.ArtifactBytes, Tokens: p.Tokens, Requests: p.Requests, WallSeconds: p.WallSeconds}}
	out.Task = raw
	out.Enqueue = envelope
	return out, nil
}

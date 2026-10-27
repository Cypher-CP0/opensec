// Package targetprofile prepares web-only tasks without contacting targets or reading secrets.
package targetprofile

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/coreclient"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
)

type Identity struct {
	Ref        string `json:"identity_ref"`
	TokenFile  string `json:"token_file"`
	AuthKind   string `json:"auth_kind,omitempty"`
	HeaderName string `json:"header_name,omitempty"`
}
type NamedCheck struct {
	ID   string      `json:"check_id"`
	Plan checks.Plan `json:"plan"`
}
type Profile struct {
	Traffic         *policy.TrafficLimits `json:"traffic,omitempty"`
	SchemaVersion   int                   `json:"schema_version"`
	ProjectID       string                `json:"project_id"`
	PolicyRef       string                `json:"policy_ref"`
	Origin          string                `json:"origin"`
	DeploymentID    string                `json:"deployment_id"`
	CIDRs           []string              `json:"allowed_cidrs"`
	AllowPrivate    bool                  `json:"allow_private"`
	Identities      []Identity            `json:"identities"`
	Checks          []NamedCheck          `json:"checks"`
	MaxAttempts     int                   `json:"max_attempts"`
	DeadlineSeconds int                   `json:"deadline_seconds"`
	WallSeconds     int64                 `json:"max_wall_seconds"`
	ArtifactBytes   int64                 `json:"max_artifact_bytes"`
}
type PreparedTask struct {
	CheckID string
	Stage   string
	ID      string
	Task    json.RawMessage
	Enqueue json.RawMessage
}
type Bundle struct {
	Policies    []policy.Policy
	Credentials []policy.Credential
	Run         queue.RunConfig
	Tasks       []PreparedTask
}

func validID(s string) bool {
	return regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$").MatchString(s)
}
func Prepare(ctx context.Context, p Profile, run, baseDir, core string, now time.Time) (Bundle, error) {
	out := Bundle{}
	if p.SchemaVersion != 1 || !validID(run) || !validID(p.ProjectID) || !validID(p.PolicyRef) || !validID(p.DeploymentID) ||
		len(p.Checks) < 1 || len(p.Checks) > 64 || len(p.Identities) < 2 || len(p.Identities) > 128 ||
		p.MaxAttempts < 1 || p.MaxAttempts > 3 || p.DeadlineSeconds < 60 || p.DeadlineSeconds > 86400 ||
		p.WallSeconds < 1 || p.WallSeconds > 300 || p.WallSeconds > int64(p.DeadlineSeconds) ||
		p.ArtifactBytes < 8192 || p.ArtifactBytes > 16<<20 || len(p.CIDRs) == 0 {
		return out, errors.New("invalid target profile identifiers, bounds or controls")
	}
	endpoints := []policy.Endpoint{}
	seenPaths := map[string]bool{}
	for _, check := range p.Checks {
		if check.Plan.Kind != "object_authorization" || check.Plan.Validate() != nil {
			return out, errors.New("invalid object check")
		}
		path := check.Plan.Object.PathTemplate
		if !seenPaths[path] {
			endpoints = append(endpoints, policy.Endpoint{Method: "GET", PathTemplate: path})
			seenPaths[path] = true
		}
	}
	traffic := p.Traffic
	if traffic == nil {
		traffic = policy.DefaultTraffic()
	}
	pol := policy.Policy{Endpoints: endpoints, Traffic: traffic, Ref: p.PolicyRef, ProjectID: p.ProjectID, Origins: []string{p.Origin}, CIDRs: p.CIDRs, AllowPrivate: p.AllowPrivate, Repositories: []string{}, MaxInputBytes: 1 << 20}
	registry, err := policy.New(ctx, []policy.Policy{pol}, core)
	if err != nil {
		return out, err
	}
	seen := map[string]bool{}
	for _, identity := range p.Identities {
		if seen[identity.Ref] {
			return out, errors.New("duplicate target identity")
		}
		seen[identity.Ref] = true
		record := policy.Credential{ProjectID: p.ProjectID, PolicyRef: p.PolicyRef, Origin: p.Origin, IdentityRef: identity.Ref, TokenFile: identity.TokenFile, AuthKind: identity.AuthKind, HeaderName: identity.HeaderName}
		if err = policy.ValidateCredential(record); err != nil {
			return out, err
		}
		if !filepath.IsAbs(record.TokenFile) {
			record.TokenFile, err = filepath.Abs(filepath.Join(baseDir, record.TokenFile))
			if err != nil {
				return out, err
			}
		}
		out.Credentials = append(out.Credentials, record)
	}
	ids := map[string]bool{}
	for _, check := range p.Checks {
		if !regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$").MatchString(check.ID) || strings.HasPrefix(strings.ToLower(check.ID), "preflight-") || ids[strings.ToLower(check.ID)] || check.Plan.Kind != "object_authorization" || check.Plan.Validate() != nil ||
			!seen[check.Plan.IdentityA] || !seen[check.Plan.IdentityB] {
			return Bundle{}, errors.New("invalid check or missing identity reference")
		}
		ids[strings.ToLower(check.ID)] = true
		for _, stage := range []string{"prepare", "hunt"} {
			id, dependencies, requests := check.ID, []string{}, 3
			preflightID := "preflight-" + checks.Hash([]byte(check.ID))[:40]
			if stage == "prepare" {
				id, requests = preflightID, 2
			} else {
				dependencies = []string{preflightID}
			}
			question := "Evaluate the configured object authorization controls; this task performs no model investigation."
			if stage == "prepare" {
				question = "Establish two legitimate object access controls before cross-identity testing; preflight makes no cross-identity request."
			}
			// Use the same path generator as the worker; the Rust core independently validates the task.
			paths := check.Plan.Paths()
			task := map[string]any{
				"schema_version": 1, "project_id": p.ProjectID, "run_id": run, "task_id": id, "investigation_id": check.ID, "policy_ref": p.PolicyRef,
				"stage": stage, "retry_class": "read_only", "created_at": now.UTC(), "deadline": now.Add(time.Duration(p.DeadlineSeconds) * time.Second).UTC(),
				"dependencies": dependencies, "question": question,
				"budget": map[string]any{"max_wall_seconds": p.WallSeconds, "max_model_tokens": 0, "max_requests": requests, "max_artifact_bytes": p.ArtifactBytes},
				"check":  &check.Plan,
				"target": map[string]any{"mode": "web", "web": map[string]any{"origin": p.Origin, "deployment_id": p.DeploymentID, "observation_id": check.ID, "seed_urls": []string{p.Origin + paths[0], p.Origin + paths[1]}}},
			}
			raw, err := json.Marshal(task)
			if err != nil {
				return Bundle{}, err
			}
			if _, err = coreclient.Call(ctx, core, map[string]any{"operation": "validate", "kind": "task", "document": json.RawMessage(raw)}); err != nil {
				return Bundle{}, err
			}
			if _, err = registry.AuthorizeTask(ctx, raw); err != nil {
				return Bundle{}, err
			}
			envelope, err := json.Marshal(struct {
				Task    json.RawMessage      `json:"task"`
				Options queue.EnqueueOptions `json:"options"`
			}{raw, queue.EnqueueOptions{MaxAttempts: p.MaxAttempts}})
			if err != nil {
				return Bundle{}, err
			}
			out.Tasks = append(out.Tasks, PreparedTask{CheckID: check.ID, Stage: stage, ID: id, Task: raw, Enqueue: envelope})
		}
	}
	out.Policies = []policy.Policy{pol}
	tasks := int64(len(p.Checks) * 3) // Positive controls, discovery and one fresh replay.
	attempts := tasks * int64(p.MaxAttempts)
	out.Run = queue.RunConfig{ProjectID: p.ProjectID, RunID: run, MaxTasks: tasks, MaxAttempts: attempts, Limits: queue.Units{
		Requests: attempts * 3, WallSeconds: attempts * p.WallSeconds, ArtifactBytes: attempts * p.ArtifactBytes,
	}}
	return out, nil
}

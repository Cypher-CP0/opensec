// Package policy delegates scope decisions to Rust and enforces network bounds.
package policy

import (
	"context"
	"encoding/json"
	"errors"

	"example.com/unified-harness/internal/configfile"
	"example.com/unified-harness/internal/coreclient"
)

type Policy struct {
	Ref           string   `json:"policy_ref"`
	ProjectID     string   `json:"project_id"`
	Origins       []string `json:"allowed_origins"`
	CIDRs         []string `json:"allowed_cidrs"`
	AllowPrivate  bool     `json:"allow_private"`
	Repositories  []string `json:"repository_ids"`
	MaxInputBytes int64    `json:"max_input_bytes"`
}
type Registry struct {
	core     string
	policies map[string]Policy
}

func Load(ctx context.Context, path, core string) (*Registry, error) {
	var entries []Policy
	if err := configfile.Read(path, &entries); err != nil {
		return nil, err
	}
	return New(ctx, entries, core)
}
func New(ctx context.Context, entries []Policy, core string) (*Registry, error) {
	if len(entries) == 0 || len(entries) > 128 {
		return nil, errors.New("provide 1..128 policies")
	}
	r := &Registry{core: core, policies: map[string]Policy{}}
	for _, p := range entries {
		if _, err := coreclient.Call(ctx, core, map[string]any{"operation": "validate_policy", "policy": p}); err != nil {
			return nil, err
		}
		key := p.ProjectID + "/" + p.Ref
		if _, ok := r.policies[key]; ok {
			return nil, errors.New("duplicate project/policy")
		}
		r.policies[key] = p
	}
	return r, nil
}
func (r *Registry) AuthorizeTask(ctx context.Context, raw json.RawMessage) (Policy, error) {
	var ref struct {
		ProjectID string `json:"project_id"`
		PolicyRef string `json:"policy_ref"`
	}
	if err := json.Unmarshal(raw, &ref); err != nil {
		return Policy{}, err
	}
	p, ok := r.policies[ref.ProjectID+"/"+ref.PolicyRef]
	if !ok {
		return Policy{}, errors.New("unknown project/policy")
	}
	_, err := coreclient.Call(ctx, r.core, map[string]any{"operation": "authorize_task", "policy": p, "task": raw})
	return p, err
}
func (r *Registry) AuthorizeNetwork(ctx context.Context, p Policy, url string, addresses []string) error {
	_, err := coreclient.Call(ctx, r.core, map[string]any{"operation": "authorize_network", "policy": p, "url": url, "addresses": addresses})
	return err
}

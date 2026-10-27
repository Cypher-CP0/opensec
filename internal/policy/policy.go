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
	Endpoints     []Endpoint     `json:"allowed_endpoints,omitempty"`
	Traffic       *TrafficLimits `json:"traffic,omitempty"`
	Ref           string         `json:"policy_ref"`
	ProjectID     string         `json:"project_id"`
	Origins       []string       `json:"allowed_origins"`
	CIDRs         []string       `json:"allowed_cidrs"`
	AllowPrivate  bool           `json:"allow_private"`
	Repositories  []string       `json:"repository_ids"`
	MaxInputBytes int64          `json:"max_input_bytes"`
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
	traffic := map[string]*TrafficLimits{}
	for _, p := range entries {
		if p.Endpoints != nil && len(p.Endpoints) == 0 {
			return nil, errors.New("endpoint rules cannot be empty")
		}
		raw, err := coreclient.Call(ctx, core, map[string]any{"operation": "validate_policy", "policy": p})
		if err != nil {
			return nil, err
		}
		var validated struct {
			Origins []string `json:"canonical_origins"`
		}
		if json.Unmarshal(raw, &validated) != nil || len(validated.Origins) != len(p.Origins) {
			return nil, errors.New("invalid canonical policy origins")
		}
		for _, origin := range validated.Origins {
			key := p.ProjectID + "/" + origin
			if previous, ok := traffic[key]; ok {
				if (previous == nil) != (p.Traffic == nil) || previous != nil && *previous != *p.Traffic {
					return nil, errors.New("conflicting traffic limits for the same project and origin")
				}
			}
			traffic[key] = p.Traffic
		}
		key := p.ProjectID + "/" + p.Ref
		if _, ok := r.policies[key]; ok {
			return nil, errors.New("duplicate project/policy")
		}
		r.policies[key] = p
	}
	return r, nil
}
func (r *Registry) RequiresTraffic(project string) bool {
	for _, p := range r.policies {
		if p.ProjectID == project && p.Traffic != nil {
			return true
		}
	}
	return false
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
func (r *Registry) AuthorizeRequest(ctx context.Context, p Policy, raw string) error {
	_, err := r.RequestOrigin(ctx, p, raw)
	return err
}
func (r *Registry) RequestOrigin(ctx context.Context, p Policy, raw string) (string, error) {
	return r.MethodOrigin(ctx, p, raw, "GET")
}
func (r *Registry) MethodOrigin(ctx context.Context, p Policy, raw, method string) (string, error) {
	body, err := coreclient.Call(ctx, r.core, map[string]any{"operation": "authorize_request", "policy": p, "url": raw, "method": method})
	if err != nil {
		return "", err
	}
	var result struct {
		Origin string `json:"origin"`
	}
	if json.Unmarshal(body, &result) != nil || result.Origin == "" {
		return "", errors.New("invalid request origin")
	}
	return result.Origin, nil
}
func (r *Registry) AuthorizeNetwork(ctx context.Context, p Policy, url string, addresses []string) error {
	return r.AuthorizeNetworkMethod(ctx, p, url, "GET", addresses)
}
func (r *Registry) AuthorizeNetworkMethod(ctx context.Context, p Policy, url, method string, addresses []string) error {
	_, err := coreclient.Call(ctx, r.core, map[string]any{"operation": "authorize_network", "policy": p, "url": url, "method": method, "addresses": addresses})
	return err
}

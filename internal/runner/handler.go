package runner

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/configfile"
	"example.com/unified-harness/internal/investigator"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"io"
	"os"
	"time"
)

var randomReader io.Reader = rand.Reader

type Snapshot struct {
	RepositoryID string `json:"repository_id"`
	Commit       string `json:"commit"`
	SHA256       string `json:"snapshot_sha256"`
	Archive      string `json:"archive"`
}

func LoadSnapshots(path string) ([]Snapshot, error) {
	if path == "" {
		return nil, nil
	}
	var snapshots []Snapshot
	err := configfile.Read(path, &snapshots)
	if len(snapshots) > 128 {
		return nil, errors.New("too many registered snapshots")
	}
	return snapshots, err
}

type Executor interface {
	Execute(context.Context, time.Time, Input, int64) (json.RawMessage, error)
}
type Handler struct {
	InvestigatorProfiles []investigator.Profile
	// ModelAdapter is an in-process test seam; production always uses the fixed CLI adapter.
	ModelAdapter func(investigator.Profile) investigator.Adapter
	Policies     *policy.Registry
	Broker       policy.Broker
	Executor     Executor
	Snapshots    []Snapshot
}
type targetSpec struct {
	Target struct {
		Mode string `json:"mode"`
		Web  *struct {
			Seeds []string `json:"seed_urls"`
		} `json:"web"`
		Source *struct {
			RepositoryID string `json:"repository_id"`
			Commit       string `json:"commit"`
			SHA256       string `json:"snapshot_sha256"`
		} `json:"source"`
	} `json:"target"`
}

func (h Handler) Run(ctx context.Context, l queue.Lease) queue.Completion {
	start := time.Now()
	usage := queue.Units{}
	finish := func(outcome, reason string, result json.RawMessage) queue.Completion {
		usage.WallSeconds = min(l.Reserved.WallSeconds, int64(time.Since(start).Seconds())+1)
		return queue.Completion{Outcome: outcome, Reason: reason, Usage: &usage, Result: result}
	}
	if h.Policies == nil || h.Executor == nil {
		return finish("blocked_environment", "runner is not configured", nil)
	}
	p, err := h.Policies.AuthorizeTask(ctx, l.Spec)
	if err != nil {
		return finish("failed", "target policy denied task", nil)
	}
	check, parseErr := checks.Parse(l.Spec)
	if parseErr != nil {
		return finish("failed", "invalid check specification", nil)
	}
	ispec, parseErr := investigator.Parse(l.Spec)
	if parseErr != nil {
		return finish("failed", "invalid investigator specification", nil)
	}
	if ispec.Investigator != nil {
		return h.runInvestigator(ctx, l, p, ispec)
	}
	if check.Check != nil {
		return h.runCheck(ctx, l, p, check)
	}
	var spec targetSpec
	if err = json.Unmarshal(l.Spec, &spec); err != nil {
		return finish("failed", "invalid task target", nil)
	}
	outputLimit := min(int64(MaxOutput), l.Reserved.ArtifactBytes/2)
	if outputLimit < 256 {
		return finish("failed", "artifact allowance is too small for an inspection report", nil)
	}
	input := Input{Observations: []policy.Observation{}}
	if source := spec.Target.Source; source != nil {
		var registered *Snapshot
		for i := range h.Snapshots {
			v := &h.Snapshots[i]
			if v.RepositoryID == source.RepositoryID && v.Commit == source.Commit && v.SHA256 == source.SHA256 {
				registered = v
				break
			}
		}
		if registered == nil {
			return finish("blocked_environment", "immutable source snapshot is not registered", nil)
		}
		input.SourceTar, err = readSnapshot(*registered, p.MaxInputBytes/2)
		if err != nil {
			return finish("blocked_environment", "source snapshot unavailable or digest mismatch", nil)
		}
	}
	if web := spec.Target.Web; web != nil {
		if len(web.Seeds) > 128 {
			return finish("failed", "too many seed URLs for one inspection", nil)
		}
		byteLimit := min(l.Reserved.ArtifactBytes-outputLimit, p.MaxInputBytes/4)
		input.Observations, usage.Requests, usage.ArtifactBytes, err = h.Broker.Fetch(ctx, p, web.Seeds, l.Reserved.Requests, byteLimit)
		if err != nil {
			if errors.Is(err, policy.ErrLimit) {
				return finish("failed", "network resource allowance exhausted", nil)
			}
			return finish("blocked_environment", "target fetch denied or unavailable", nil)
		}
	}
	prepared, err := json.Marshal(input)
	if err != nil || int64(len(prepared)) > p.MaxInputBytes {
		return finish("failed", "prepared input exceeds policy limit", nil)
	}
	result, err := h.Executor.Execute(ctx, l.HardDeadline, input, outputLimit)
	if err != nil {
		return queue.Completion{Outcome: "blocked_environment", Reason: "isolated runner failed; inspect worker configuration", Usage: nil}
	}
	usage.ArtifactBytes += int64(len(result))
	return finish("succeeded", "bounded inspection completed; security judgment not performed", result)
}
func readSnapshot(snapshot Snapshot, maxBytes int64) ([]byte, error) {
	file, err := os.Open(snapshot.Archive)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("snapshot must be a regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxBytes || digest(raw) != snapshot.SHA256 {
		return nil, errors.New("snapshot digest or size mismatch")
	}
	return raw, nil
}

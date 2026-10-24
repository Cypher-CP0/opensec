//go:build container

package runner

import (
	"context"
	"encoding/json"
	"example.com/unified-harness/internal/policy"
	"os"
	"testing"
	"time"
)

type liveCommand struct {
	t       *testing.T
	command DockerCommand
	name    string
}

func (c *liveCommand) Run(ctx context.Context, input []byte, limit int64, args ...string) ([]byte, error) {
	raw, err := c.command.Run(ctx, input, limit, args...)
	if err == nil && args[0] == "create" {
		c.name = args[2]
		inspect, err := c.command.Run(ctx, nil, 128<<10, "inspect", c.name, "--format", "{{json .}}")
		if err != nil {
			c.t.Fatal(err)
		}
		var state struct {
			HostConfig struct {
				NetworkMode                             string
				ReadonlyRootfs, Privileged              bool
				Memory, MemorySwap, NanoCpus, PidsLimit int64
				CapDrop, SecurityOpt                    []string
			}
			Config struct {
				User string
				Env  []string
			}
			Mounts []struct{ Type string }
		}
		if json.Unmarshal(inspect, &state) != nil {
			c.t.Fatal("invalid container config")
		}
		h := state.HostConfig
		if h.NetworkMode != "none" || !h.ReadonlyRootfs || h.Privileged || h.Memory != 128<<20 || h.MemorySwap != h.Memory || h.NanoCpus != 500000000 || h.PidsLimit != 32 || state.Config.User != "65532:65532" {
			c.t.Fatalf("weakened live container configuration: %+v", state)
		}
		for _, mount := range state.Mounts {
			if mount.Type != "tmpfs" {
				c.t.Fatal("unexpected container mount", mount)
			}
		}
	}
	return raw, err
}
func TestRealDockerIsolationAndCleanup(t *testing.T) {
	image := os.Getenv("HARNESS_TEST_RUNNER_IMAGE")
	if image == "" {
		t.Fatal("set HARNESS_TEST_RUNNER_IMAGE to a built immutable image ID; refusing to skip container tests")
	}
	command := &liveCommand{t: t}
	d, err := NewDocker(t.Context(), image, DefaultLimits(), command)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	result, err := d.Execute(ctx, time.Now().Add(20*time.Second), Input{Observations: []policy.Observation{{URL: "http://lab.invalid", Status: 200, Body: []byte("sample")}}}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	if json.Unmarshal(result, &report) != nil || len(report.Responses) != 1 {
		t.Fatal("live inspection failed")
	}
	if _, err = command.command.Run(ctx, nil, 1024, "inspect", command.name); err == nil {
		t.Fatal("completed container still exists")
	}
}

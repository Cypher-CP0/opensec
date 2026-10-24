//go:build integration && container

package coordinator

import (
	"example.com/unified-harness/internal/runner"
	"os"
	"testing"
)

func findingExecutor(t *testing.T) runner.Executor {
	t.Helper()
	image := os.Getenv("HARNESS_TEST_RUNNER_IMAGE")
	if image == "" {
		t.Fatal("HARNESS_TEST_RUNNER_IMAGE is required; refusing to skip real container tests")
	}
	engine, err := runner.NewDocker(t.Context(), image, runner.DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

//go:build integration && !container

package coordinator

import (
	"example.com/unified-harness/internal/runner"
	"testing"
)

func findingExecutor(t *testing.T) runner.Executor { t.Helper(); return inspectionExecutor{} }

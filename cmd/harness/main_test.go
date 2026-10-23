package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRejectNonLoopbackLabBindings(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:8081", "[::]:8081", "example.test:8081", "localhost:8081", "bad"} {
		err := run(context.Background(), []string{"lab", "--listen", addr}, new(bytes.Buffer))
		if err == nil || !strings.Contains(err.Error(), "loopback") {
			t.Fatalf("%s: %v", addr, err)
		}
	}
}
func TestCommandErrors(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"validate"}, {"lab", "--variant", "unknown"}, {"schema", "extra"}} {
		if err := run(context.Background(), args, new(bytes.Buffer)); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

// Package coreclient is the Go-to-Rust contract boundary.
package coreclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type Response struct {
	ProtocolVersion int             `json:"protocol_version"`
	OK              bool            `json:"ok"`
	Data            json.RawMessage `json:"data"`
	Error           string          `json:"error"`
}

func DefaultBinary() string {
	if path := os.Getenv("HARNESS_CORE_BIN"); path != "" {
		return path
	}
	name := "harness-core"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join("target", "debug", name)
}
func Call(ctx context.Context, binary string, request map[string]any) (json.RawMessage, error) {
	requestCopy := make(map[string]any, len(request)+1)
	for k, v := range request {
		requestCopy[k] = v
	}
	requestCopy["protocol_version"] = 1
	input, err := json.Marshal(requestCopy)
	if err != nil {
		return nil, err
	}
	if len(input) > 4*1024*1024 {
		return nil, fmt.Errorf("core request exceeds 4 MiB")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("core execution: %w", ctx.Err())
	}
	var response Response
	if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
		return nil, fmt.Errorf("core did not return a valid response (build it with cargo build): %v", runErr)
	}
	if response.ProtocolVersion != 1 {
		return nil, fmt.Errorf("unsupported core protocol")
	}
	if !response.OK {
		return nil, fmt.Errorf("contract rejected: %s", response.Error)
	}
	if runErr != nil {
		return nil, fmt.Errorf("core execution: %w", runErr)
	}
	return response.Data, nil
}

//go:build linux

package webinvestigator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.com/unified-harness/internal/investigator"
)

func TestCLIModelClassifiesInvalidStructuredAction(t *testing.T) {
	flags := []string{
		"--safe-mode", "--print", "--tools", "--disallowedTools", "--strict-mcp-config", "--mcp-config",
		"--setting-sources", "--settings", "--disable-slash-commands", "--no-chrome", "--no-session-persistence",
		"--permission-mode", "--output-format", "--json-schema", "--model", "--system-prompt",
	}
	script := "#!/bin/sh\nif [ \"$1\" = '--help' ]; then\n" +
		"printf '%s\\n' '" + strings.Join(flags, "\n") + "'\nexit 0\nfi\n" +
		"cat >/dev/null\n" +
		`printf '%s\n' '{"type":"result","subtype":"success","usage":{"input_tokens":5,"output_tokens":2},"structured_output":{"kind":"stop","url":"http://127.0.0.1:8081/healthz"}}'` + "\n"
	executable := filepath.Join(t.TempDir(), "fake-claude")
	if err := os.WriteFile(executable, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cli, err := investigator.NewCLI(t.Context(), investigator.Profile{Executable: executable, Model: "fake", MaxPromptBytes: 4096, CallSeconds: 2})
	if err != nil {
		t.Fatal(err)
	}
	_, tokens, err := (CLIModel{CLI: cli}).Call(t.Context(), []byte("{}"))
	if tokens != 7 || investigator.ErrorCode(err) != "cli_invalid_action" {
		t.Fatalf("tokens=%d code=%s", tokens, investigator.ErrorCode(err))
	}
}

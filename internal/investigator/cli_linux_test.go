//go:build linux

package investigator

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeCLI(t *testing.T, body string, restricted bool) string {
	t.Helper()
	flags := strings.Join(requiredCLIFlags, "\n")
	if restricted {
		flags += "\n--restricted"
	}
	script := "#!/bin/sh\nif [ \"$1\" = '--help' ]; then\ncat <<'HELP'\n" + flags + "\nHELP\nexit 0\nfi\n" + body + "\n"
	file := filepath.Join(t.TempDir(), "fake-cli")
	if err := os.WriteFile(file, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return file
}
func TestCLIProcessTimeoutAndOutputBounds(t *testing.T) {
	for _, tc := range []struct {
		name, body, code string
		seconds          int
	}{
		{"timeout", "sleep 20", "cli_timeout", 1},
		{"stdout", "head -c 262145 /dev/zero", "cli_output_limit", 10},
		{"stderr", "head -c 16385 /dev/zero >&2", "cli_output_limit", 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := fakeCLI(t, tc.body, false)
			cli := CLI{Profile: Profile{Executable: file, Model: "fake", MaxPromptBytes: 4096, CallSeconds: tc.seconds}}
			start := time.Now()
			turn, err := cli.Call(context.Background(), []byte("{}"))
			if ErrorCode(err) != tc.code || turn.Tokens != -1 || time.Since(start) > time.Duration(tc.seconds+5)*time.Second {
				t.Fatal(turn, err, time.Since(start))
			}
		})
	}
}
func TestCLIProcessReadsStructuredResult(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		// Reproduce the installed older CLI: an unsupported --restricted must never
		// appear on the model invocation when help does not advertise it.
		guard := ""
		if !restricted {
			guard = "for arg in \"$@\"; do\nif [ \"$arg\" = '--restricted' ]; then printf '%s\\n' \"error: unknown option '--restricted'\" >&2; exit 2; fi\ndone\n"
		}
		body := guard + `cat >/dev/null
printf '%s\n' '{"type":"result","subtype":"success","usage":{"input_tokens":3,"output_tokens":4},"structured_output":{"kind":"stop","path":"","line_start":0,"line_end":0,"text":"","anchor_ids":[]}}'
`
		file := fakeCLI(t, body, restricted)
		turn, err := (CLI{Profile: Profile{Executable: file, Model: "fake", MaxPromptBytes: 4096, CallSeconds: 2}}).Call(t.Context(), []byte("{}"))
		if err != nil || turn.Tokens != 7 || turn.Action.Kind != "stop" {
			t.Fatal(turn, err)
		}
	}
}
func TestCLIRejectsMissingControlsBeforeModelInvocation(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "called")
	file := fakeCLI(t, "touch '"+marker+"'", false)
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "--safe-mode\n", "", 1))
	if err = os.WriteFile(file, raw, 0700); err != nil {
		t.Fatal(err)
	}
	turn, err := (CLI{Profile: Profile{Executable: file, Model: "fake", MaxPromptBytes: 4096, CallSeconds: 2}}).Call(t.Context(), []byte("{}"))
	if ErrorCode(err) != "unsupported_cli_flags" || turn.Tokens != 0 {
		t.Fatal(turn, err)
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("launched model despite missing isolation flag")
	}
}
func TestCLIStartupErrorHasNoRawProviderText(t *testing.T) {
	file := fakeCLI(t, "printf '%s\\n' 'error: unknown option --unknown SECRET-CREDENTIAL' >&2\nexit 2", false)
	turn, err := (CLI{Profile: Profile{Executable: file, Model: "fake", MaxPromptBytes: 4096, CallSeconds: 2}}).Call(t.Context(), []byte("{}"))
	if ErrorCode(err) != "unsupported_cli_flags" || strings.Contains(err.Error(), "SECRET") || turn.Tokens != -1 {
		t.Fatal(turn, err)
	}
}

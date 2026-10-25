package investigator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Only fixed codes and allowlisted flag names leave the adapter. Provider stdout,
// stderr, prompts and account details never become queue diagnostics.
type CLIError struct {
	Code    string
	Missing []string
}

func (e *CLIError) Error() string {
	if len(e.Missing) > 0 {
		return "Claude CLI lacks required isolation flags: " + strings.Join(e.Missing, ", ")
	}
	return "Claude CLI: " + e.Code
}
func ErrorCode(err error) string {
	var e *CLIError
	if errors.As(err, &e) {
		return e.Code
	}
	return "provider_error"
}
func validErrorCode(code string) bool {
	return slices.Contains([]string{"unsupported_cli_flags", "cli_not_found", "cli_start_failed", "cli_exit", "cli_timeout", "cli_cancelled", "cli_output_limit", "cli_auth_required", "cli_rate_limited", "cli_turn_limit", "cli_invalid_response", "cli_missing_structured_output", "cli_invalid_action", "cli_usage_missing", "cli_unsupported_platform", "provider_error"}, code)
}

var requiredCLIFlags = []string{
	"--safe-mode", "--print", "--tools", "--disallowedTools", "--strict-mcp-config", "--mcp-config",
	"--setting-sources", "--settings", "--disable-slash-commands", "--no-chrome", "--no-session-persistence",
	"--permission-mode", "--output-format", "--json-schema", "--model", "--system-prompt",
}

func hasFlag(help, flag string) bool {
	return regexp.MustCompile("(?m)(^|[[:space:],])" + regexp.QuoteMeta(flag) + "([[:space:],=]|$)").MatchString(help)
}
func checkCLIHelp(help string) (bool, error) {
	var missing []string
	for _, flag := range requiredCLIFlags {
		if !hasFlag(help, flag) {
			missing = append(missing, flag)
		}
	}
	if len(missing) > 0 {
		return false, &CLIError{Code: "unsupported_cli_flags", Missing: missing}
	}
	// --restricted is defense in depth. Safe mode, no native tools, no MCP and
	// disabled settings/hooks remain mandatory on releases without this flag.
	return hasFlag(help, "--restricted"), nil
}
func NewCLI(parent context.Context, p Profile) (*CLI, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	out, errout, err := runCLI(ctx, p, []string{"--help"}, nil)
	if err != nil {
		return nil, classifyProcessError(ctx, errout, err)
	}
	restricted, err := checkCLIHelp(string(out))
	if err != nil {
		return nil, err
	}
	return &CLI{Profile: p, checked: true, restricted: restricted}, nil
}
func runCLI(ctx context.Context, p Profile, args []string, prompt []byte) ([]byte, []byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	dir, err := os.MkdirTemp("", "opensec-model-")
	if err != nil {
		return nil, nil, &CLIError{Code: "cli_start_failed"}
	}
	defer os.RemoveAll(dir)
	cmd := exec.CommandContext(ctx, p.Executable, args...)
	cmd.Dir = dir
	cmd.Env = childEnvironment()
	cmd.Stdin = bytes.NewReader(prompt)
	cmd.WaitDelay = 2 * time.Second
	if err = isolateProcess(cmd); err != nil {
		return nil, nil, &CLIError{Code: "cli_unsupported_platform"}
	}
	defer terminateProcess(cmd)
	stdout := &cappedWriter{limit: 256 << 10, cancel: cancel}
	stderr := &cappedWriter{limit: 16 << 10, cancel: cancel}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		err = &CLIError{Code: "cli_output_limit"}
	}
	return stdout.Bytes(), stderr.Bytes(), err
}
func classifyProcessError(ctx context.Context, stderr []byte, err error) error {
	var known *CLIError
	if errors.As(err, &known) {
		return known
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &CLIError{Code: "cli_timeout"}
	}
	if ctx.Err() != nil {
		return &CLIError{Code: "cli_cancelled"}
	}
	if errors.Is(err, os.ErrNotExist) {
		return &CLIError{Code: "cli_not_found"}
	}
	if code := classifyProviderText(string(stderr)); code != "" {
		return &CLIError{Code: code}
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return &CLIError{Code: "cli_exit"}
	}
	return &CLIError{Code: "cli_start_failed"}
}
func classifyProviderText(text string) string {
	v := strings.ToLower(text)
	switch {
	case strings.Contains(v, "unknown option"), strings.Contains(v, "unknown argument"):
		return "unsupported_cli_flags"
	case strings.Contains(v, "not logged in"), strings.Contains(v, "login required"), strings.Contains(v, "authentication failed"), strings.Contains(v, "please run /login"):
		return "cli_auth_required"
	case strings.Contains(v, "rate limit"), strings.Contains(v, "usage limit"), strings.Contains(v, "quota exceeded"):
		return "cli_rate_limited"
	}
	return ""
}
func envelopeFailure(raw []byte) string {
	var v struct {
		Subtype string   `json:"subtype"`
		Result  string   `json:"result"`
		Errors  []string `json:"errors"`
	}
	if json.Unmarshal(raw, &v) != nil {
		return "cli_invalid_response"
	}
	if v.Subtype == "error_max_turns" {
		return "cli_turn_limit"
	}
	for _, text := range append(v.Errors, v.Result) {
		if code := classifyProviderText(text); code != "" {
			return code
		}
	}
	return "cli_exit"
}

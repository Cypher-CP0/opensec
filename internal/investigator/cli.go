package investigator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"example.com/unified-harness/internal/configfile"
)

type Profile struct {
	ID                    string   `json:"id"`
	Provider              string   `json:"provider"`
	Executable            string   `json:"executable"`
	Model                 string   `json:"model"`
	ProjectID             string   `json:"project_id"`
	PolicyRef             string   `json:"policy_ref"`
	RepositoryID          string   `json:"repository_id"`
	Paths                 []string `json:"paths"`
	MaxCalls              int      `json:"max_calls"`
	MaxPromptBytes        int      `json:"max_prompt_bytes"`
	CallSeconds           int      `json:"call_seconds"`
	AllowSourceDisclosure bool     `json:"allow_source_disclosure"`
}

func LoadProfiles(path string) ([]Profile, error) {
	if path == "" {
		return nil, nil
	}
	var ps []Profile
	if err := configfile.Read(path, &ps); err != nil {
		return nil, err
	}
	if len(ps) > 32 {
		return nil, errors.New("too many investigator profiles")
	}
	seen := map[string]bool{}
	for _, p := range ps {
		if p.ID == "" || seen[p.ID] || p.Provider != "claude_code" || !filepath.IsAbs(p.Executable) || p.Model == "" || len(p.Model) > 128 || strings.HasPrefix(p.Model, "-") || p.ProjectID == "" || p.PolicyRef == "" || p.RepositoryID == "" || !ValidPaths(p.Paths) || p.MaxCalls < 1 || p.MaxCalls > MaxSteps || p.MaxPromptBytes < 4096 || p.MaxPromptBytes > 65536 || p.CallSeconds < 1 || p.CallSeconds > 120 || !p.AllowSourceDisclosure {
			return nil, errors.New("invalid investigator profile; explicit source disclosure and scoped limits required")
		}
		seen[p.ID] = true
	}
	return ps, nil
}
func Select(ps []Profile, s Spec) (Profile, error) {
	if s.Investigator == nil || s.Target.Source == nil {
		return Profile{}, errors.New("missing investigator source")
	}
	for _, p := range ps {
		if p.ID != s.Investigator.ProfileRef {
			continue
		}
		if p.ProjectID != s.ProjectID || p.PolicyRef != s.PolicyRef || p.RepositoryID != s.Target.Source.RepositoryID || !p.AllowSourceDisclosure || s.Investigator.MaxSteps > p.MaxCalls {
			return Profile{}, errors.New("investigator profile scope denied")
		}
		for _, path := range s.Investigator.Paths {
			if !slices.Contains(p.Paths, path) {
				return Profile{}, errors.New("source disclosure denied")
			}
		}
		return p, nil
	}
	return Profile{}, errors.New("investigator profile unavailable")
}

const ActionSchema = `{"type":"object","additionalProperties":false,"required":["kind","path","line_start","line_end","text","anchor_ids"],"properties":{"kind":{"type":"string","enum":["list","search","read","propose","stop"]},"path":{"type":"string","description":"Selected path for read or search; empty for list, propose and stop."},"line_start":{"type":"integer","description":"First source line for read; zero for all other actions."},"line_end":{"type":"integer","description":"Last source line for read, at most 64 lines; zero for all other actions."},"text":{"type":"string","description":"For propose: a short nonempty rationale, at most 2048 UTF-8 bytes. For search: a literal substring, at most 128 UTF-8 bytes. Empty otherwise."},"anchor_ids":{"type":"array","description":"For propose: 1 to 8 distinct zero-based indexes from available_anchor_ids. Never source line numbers or tool call numbers. Empty otherwise.","items":{"type":"integer"}}}}`

type CLI struct {
	Profile    Profile
	checked    bool
	restricted bool
}

func CLIArgs(p Profile, restricted bool) []string {
	// No user/project customizations, hooks, native tools, MCP, browser, or persistence.
	// --bare is deliberately absent: it disables subscription OAuth authentication.
	args := []string{"--safe-mode", "--print", "--tools", "", "--disallowedTools", "mcp__*",
		"--strict-mcp-config", "--mcp-config", `{"mcpServers":{}}`, "--setting-sources", "",
		"--settings", `{"forceLoginMethod":"claudeai","disableAllHooks":true}`,
		"--disable-slash-commands", "--no-chrome", "--no-session-persistence",
		"--permission-mode", "dontAsk", "--max-turns", "1", "--output-format", "json",
		"--json-schema", ActionSchema, "--model", p.Model, "--system-prompt", Instructions}
	if restricted {
		args = append([]string{"--restricted"}, args...)
	}
	return args
}
func childEnvironment() []string {
	// Do not pass coordinator/database/probe credentials, API keys, provider overrides,
	// Node injection variables, or arbitrary CLI settings through the environment.
	keys := []string{"HOME", "USERPROFILE", "PATH", "SYSTEMROOT", "WINDIR", "TMP", "TEMP", "TMPDIR", "LOCALAPPDATA", "APPDATA", "LANG", "LC_ALL"}
	env := []string{}
	for _, k := range keys {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return append(env, "CLAUDE_CODE_SAFE_MODE=1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1")
}

type cappedWriter struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (w *cappedWriter) Bytes() []byte { return w.buffer.Bytes() }
func (w *cappedWriter) Write(b []byte) (int, error) {
	if len(b) > w.limit-w.buffer.Len() {
		w.exceeded = true
		w.cancel()
		return 0, errors.New("CLI output limit")
	}
	return w.buffer.Write(b)
}
func (c CLI) Call(parent context.Context, prompt []byte) (Turn, error) {
	if len(prompt) > c.Profile.MaxPromptBytes {
		return Turn{Tokens: 0}, &CLIError{Code: "cli_invalid_action"}
	}
	if !c.checked {
		prepared, err := NewCLI(parent, c.Profile)
		if err != nil {
			return Turn{Tokens: 0}, err
		}
		c = *prepared
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.Profile.CallSeconds)*time.Second)
	defer cancel()
	out, stderr, processErr := runCLI(ctx, c.Profile, CLIArgs(c.Profile, c.restricted), prompt)
	turn, parseErr := ParseCLIResult(out)
	if processErr != nil {
		if parseErr != nil && turn.Tokens >= 0 {
			return turn, parseErr
		}
		if parseErr == nil {
			return Turn{Tokens: turn.Tokens}, classifyProcessError(ctx, stderr, processErr)
		}
		return turn, classifyProcessError(ctx, stderr, processErr)
	}
	return turn, parseErr
}
func ParseCLIResult(raw []byte) (Turn, error) {
	fail := &CLIError{Code: "cli_invalid_response"}
	var doc struct {
		Type    string          `json:"type"`
		Subtype string          `json:"subtype"`
		IsError bool            `json:"is_error"`
		Output  json.RawMessage `json:"structured_output"`
		Usage   *struct {
			Input       int64 `json:"input_tokens"`
			Output      int64 `json:"output_tokens"`
			CacheRead   int64 `json:"cache_read_input_tokens"`
			CacheCreate int64 `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	// Provider envelopes evolve; only the model's action is a closed contract.
	t := Turn{Tokens: -1}
	if len(raw) > 256<<10 || json.Unmarshal(raw, &doc) != nil {
		return t, fail
	}
	if u := doc.Usage; u != nil {
		total := int64(0)
		for _, n := range []int64{u.Input, u.Output, u.CacheRead, u.CacheCreate} {
			if n < 0 || n > 1e12-total {
				return t, fail
			}
			total += n
		}
		t.Tokens = total
	}
	if doc.Type != "result" {
		return t, fail
	}
	if doc.Subtype != "success" || doc.IsError {
		return t, &CLIError{Code: envelopeFailure(raw)}
	}
	if doc.Usage == nil || t.Tokens <= 0 {
		return t, &CLIError{Code: "cli_usage_missing"}
	}
	if len(doc.Output) == 0 || string(doc.Output) == "null" {
		return t, &CLIError{Code: "cli_missing_structured_output"}
	}
	a, err := DecodeAction(doc.Output)
	if err != nil {
		return t, &CLIError{Code: "cli_invalid_action"}
	}
	t.Action = a
	return t, nil
}

package investigator

import (
	"context"
	"encoding/json"
	"time"
)

// CallStructured uses the same isolated Claude Code process as source
// investigation, with a separate closed schema for the web tool protocol.
func (c CLI) CallStructured(parent context.Context, prompt []byte, schema, system string) (json.RawMessage, int64, error) {
	if len(prompt) > c.Profile.MaxPromptBytes {
		return nil, 0, &CLIError{Code: "cli_invalid_action"}
	}
	if !c.checked {
		prepared, err := NewCLI(parent, c.Profile)
		if err != nil {
			return nil, 0, err
		}
		c = *prepared
	}
	args := CLIArgs(c.Profile, c.restricted)
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--json-schema" {
			args[i+1] = schema
		}
		if args[i] == "--system-prompt" {
			args[i+1] = system
		}
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(c.Profile.CallSeconds)*time.Second)
	defer cancel()
	out, stderr, processErr := runCLI(ctx, c.Profile, args, prompt)
	payload, tokens, parseErr := ParseStructuredResult(out)
	if processErr != nil {
		if parseErr != nil && tokens >= 0 {
			return nil, tokens, parseErr
		}
		return nil, tokens, classifyProcessError(ctx, stderr, processErr)
	}
	return payload, tokens, parseErr
}

func ParseStructuredResult(raw []byte) (json.RawMessage, int64, error) {
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
	if len(raw) > 256<<10 || json.Unmarshal(raw, &doc) != nil {
		return nil, -1, fail
	}
	tokens := int64(-1)
	if doc.Usage != nil {
		tokens = 0
		for _, n := range []int64{doc.Usage.Input, doc.Usage.Output, doc.Usage.CacheRead, doc.Usage.CacheCreate} {
			if n < 0 || n > 1e12-tokens {
				return nil, -1, fail
			}
			tokens += n
		}
	}
	if doc.Type != "result" {
		return nil, tokens, fail
	}
	if doc.Subtype != "success" || doc.IsError {
		return nil, tokens, &CLIError{Code: envelopeFailure(raw)}
	}
	if tokens <= 0 {
		return nil, tokens, &CLIError{Code: "cli_usage_missing"}
	}
	if len(doc.Output) == 0 || string(doc.Output) == "null" || !json.Valid(doc.Output) {
		return nil, tokens, &CLIError{Code: "cli_missing_structured_output"}
	}
	return doc.Output, tokens, nil
}

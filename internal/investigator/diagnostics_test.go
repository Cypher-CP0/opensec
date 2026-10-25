package investigator

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestCapabilityNegotiationPreservesRequiredControls(t *testing.T) {
	legacy := strings.Join(requiredCLIFlags, "\n")
	optional, err := checkCLIHelp(legacy)
	if err != nil || optional {
		t.Fatal(optional, err)
	}
	if optional, err = checkCLIHelp(legacy + "\n --restricted text"); err != nil || !optional {
		t.Fatal(optional, err)
	}
	for _, required := range requiredCLIFlags {
		_, err = checkCLIHelp(strings.Replace(legacy, required, "--unrelated", 1))
		if ErrorCode(err) != "unsupported_cli_flags" {
			t.Fatal(required, err)
		}
	}
	for _, restricted := range []bool{false, true} {
		args := CLIArgs(Profile{Model: "fake"}, restricted)
		if slices.Contains(args, "--restricted") != restricted {
			t.Fatal(args)
		}
		for _, flag := range requiredCLIFlags {
			if !slices.Contains(args, flag) {
				t.Fatal("weakened controls", flag)
			}
		}
	}
}
func TestStructuredProviderFailuresAndUsage(t *testing.T) {
	for _, tc := range []struct {
		raw, code string
		tokens    int64
	}{
		{`{"type":"result","subtype":"error_max_turns","usage":{"input_tokens":5,"output_tokens":8}}`, "cli_turn_limit", 13},
		{`{"type":"result","subtype":"success","usage":{"input_tokens":5,"output_tokens":8}}`, "cli_missing_structured_output", 13},
		{`{"type":"result","subtype":"error_during_execution","result":"Not logged in SECRET"}`, "cli_auth_required", -1},
		{`{"type":"result","subtype":"error_during_execution","errors":["Usage limit reached SECRET"]}`, "cli_rate_limited", -1},
	} {
		turn, err := ParseCLIResult([]byte(tc.raw))
		if ErrorCode(err) != tc.code || turn.Tokens != tc.tokens || strings.Contains(err.Error(), "SECRET") {
			t.Fatal(turn, err)
		}
	}
}

type knownFailure struct{}

func (knownFailure) Call(context.Context, []byte) (Turn, error) {
	return Turn{Tokens: 13}, &CLIError{Code: "cli_turn_limit"}
}
func TestLoopRetainsKnownFailureUsageAndSafeDiagnostic(t *testing.T) {
	r := Run(t.Context(), Config{MaxSteps: 2, Paths: []string{"a.go"}}, "check", 100, 4096, knownFailure{}, func(context.Context, Query) (SourceResult, error) {
		return SourceResult{}, errors.New("unexpected tool")
	})
	if r.Status != "provider_error" || !r.UsageKnown || r.Tokens != 13 || r.ProviderError != "cli_turn_limit" {
		t.Fatal(r)
	}
	if r.Validate(Config{MaxSteps: 2, Paths: []string{"a.go"}}) != nil {
		t.Fatal("valid diagnostic rejected")
	}
	r.ProviderError = "raw stderr SECRET"
	if r.Validate(Config{MaxSteps: 2, Paths: []string{"a.go"}}) == nil {
		t.Fatal("unbounded diagnostic accepted")
	}
}

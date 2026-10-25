package investigator

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestRejectedActionsHaveSanitizedDiagnostics(t *testing.T) {
	cfg := Config{MaxSteps: 4, Paths: []string{"handler.go"}}
	raw := snapshot(t, map[string]string{"handler.go": "return exports[id]\n"})
	read := Turn{Tokens: 10, Action: Action{Kind: "read", Path: "handler.go", Start: 1, End: 1}}
	for _, tc := range []struct {
		name string
		a    Action
		code string
	}{
		{"long-rationale", Action{Kind: "propose", Text: strings.Repeat("sensitive-model-text", 128), AnchorIDs: []int{0}}, "rationale_too_large"},
		{"utf8-byte-limit", Action{Kind: "propose", Text: strings.Repeat("界", 683), AnchorIDs: []int{0}}, "rationale_too_large"},
		{"empty-rationale", Action{Kind: "propose", Text: " \n", AnchorIDs: []int{0}}, "empty_rationale"},
		{"missing-anchors", Action{Kind: "propose", Text: "sensitive-model-text"}, "invalid_anchor_count"},
		{"too-many-anchors", Action{Kind: "propose", Text: "sensitive-model-text", AnchorIDs: make([]int, 9)}, "invalid_anchor_count"},
		{"unread-anchor", Action{Kind: "propose", Text: "sensitive-model-text", AnchorIDs: []int{1}}, "unread_anchor"},
		{"negative-anchor", Action{Kind: "propose", Text: "sensitive-model-text", AnchorIDs: []int{-1}}, "unread_anchor"},
		{"repeated-anchor", Action{Kind: "propose", Text: "sensitive-model-text", AnchorIDs: []int{0, 0}}, "repeated_anchor"},
		{"proposal-fields", Action{Kind: "propose", Path: "private.key", Text: "sensitive-model-text", AnchorIDs: []int{0}}, "unused_action_fields"},
		{"stop-fields", Action{Kind: "stop", Text: "sensitive-model-text"}, "unused_action_fields"},
		{"unexpected-anchors", Action{Kind: "read", Path: "handler.go", Start: 1, End: 1, AnchorIDs: []int{0}}, "unexpected_anchors"},
		{"unknown-action", Action{Kind: "sensitive-model-text", Path: "private.key"}, "unsupported_action"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeAdapter{turns: []Turn{read, {Tokens: 20, Action: tc.a}}}
			sourceCalls := 0
			r := Run(t.Context(), cfg, "check", 100, 65536, f, func(_ context.Context, q Query) (SourceResult, error) {
				sourceCalls++
				return QuerySource(raw, cfg.Paths, q)
			})
			if r.Status != "invalid_action" || r.ActionError != tc.code || r.Hypothesis != nil ||
				r.Calls != 2 || r.Tokens != 30 || !r.UsageKnown || sourceCalls != 1 || r.Validate(cfg) != nil {
				t.Fatal(r, sourceCalls)
			}
			stored := Summary(r, "attempt")
			if bytes.Contains(stored, []byte("sensitive-model-text")) || bytes.Contains(stored, []byte("private.key")) {
				t.Fatal("rejected action leaked into report")
			}
			r.ActionError = "sensitive-model-text"
			if r.Validate(cfg) == nil {
				t.Fatal("unknown action diagnostic accepted")
			}
			r.ActionError, r.Status = tc.code, "no_hypothesis"
			if r.Validate(cfg) == nil {
				t.Fatal("action diagnostic accepted with wrong status")
			}
			r.ActionError, r.Status = "", "invalid_action"
			if err := r.Validate(cfg); err != nil {
				t.Fatal("older reports must remain valid", err)
			}
		})
	}
}

func TestProposalPromptAndBoundary(t *testing.T) {
	cfg := Config{MaxSteps: 4, Paths: []string{"handler.go"}}
	raw := snapshot(t, map[string]string{"handler.go": "return exports[id]\n"})
	read := Turn{Tokens: 10, Action: Action{Kind: "read", Path: "handler.go", Start: 1, End: 1}}
	f := &fakeAdapter{turns: []Turn{read, read, {Tokens: 10, Action: Action{Kind: "propose", Text: strings.Repeat("x", 2048), AnchorIDs: []int{0, 1}}}}}
	r := Run(t.Context(), cfg, "check", 100, 65536, f, func(_ context.Context, q Query) (SourceResult, error) {
		return QuerySource(raw, cfg.Paths, q)
	})
	if r.Status != "hypothesis" || r.ActionError != "" || r.Validate(cfg) != nil {
		t.Fatal(r)
	}
	for i, raw := range f.prompts {
		var prompt struct {
			AnchorIDs []int `json:"available_anchor_ids"`
		}
		want := make([]int, i)
		for j := range want {
			want[j] = j
		}
		if err := json.Unmarshal(raw, &prompt); err != nil || !slices.Equal(prompt.AnchorIDs, want) {
			t.Fatal("prompt must identify only already-read anchors", i, prompt, err)
		}
	}
	if !json.Valid([]byte(ActionSchema)) {
		t.Fatal("invalid action schema")
	}
	for _, text := range []string{Instructions, ActionSchema} {
		if !strings.Contains(text, "2048 UTF-8 bytes") || !strings.Contains(text, "1 to 8 distinct zero-based indexes") {
			t.Fatal("proposal constraints missing from model contract")
		}
	}
}

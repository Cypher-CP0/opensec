package investigator

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"example.com/unified-harness/internal/checks"
)

func TestSourceReadEOFAndLimits(t *testing.T) {
	text := strings.Repeat("line\n", 118) + "last"
	raw := snapshot(t, map[string]string{"handler.go": text})
	paths := []string{"handler.go"}
	out, err := QuerySource(raw, paths, Query{Kind: "read", Path: "handler.go", Start: 65, End: 128})
	want := strings.Repeat("line\n", 54) + "last"
	if err != nil || out.Excerpt == nil || out.Excerpt.Start != 65 || out.Excerpt.End != 119 ||
		out.TotalLines != 119 || out.Excerpt.Text != want || out.Excerpt.SHA256 != checks.Hash([]byte(want)) ||
		out.Excerpt.FileSHA256 != checks.Hash([]byte(text)) {
		t.Fatal(out, err)
	}
	for _, tc := range []struct {
		q    Query
		code string
	}{
		{Query{Kind: "read", Path: "handler.go", Start: 65, End: 129}, "read_range_too_large"},
		{Query{Kind: "read", Path: "handler.go", Start: 120, End: 128}, "read_start_past_eof"},
		{Query{Kind: "read", Path: "handler.go", Start: 0, End: 1}, "invalid_query"},
		{Query{Kind: "read", Path: "secret.key", Start: 1, End: 1}, "path_not_allowed"},
	} {
		out, err = QuerySource(raw, paths, tc.q)
		if err == nil || SourceDiagnostic(err).Code != tc.code || out.Excerpt != nil {
			t.Fatal(tc, out, err)
		}
		if tc.code == "read_start_past_eof" && SourceDiagnostic(err).TotalLines != 119 {
			t.Fatal(err)
		}
	}
	for _, text := range []string{"", strings.Repeat("x", MaxExcerpt+1)} {
		raw = snapshot(t, map[string]string{"handler.go": text})
		_, err = QuerySource(raw, paths, Query{Kind: "read", Path: "handler.go", Start: 1, End: 1})
		want := "excerpt_too_large"
		if text == "" {
			want = "read_start_past_eof"
		}
		if err == nil || SourceDiagnostic(err).Code != want {
			t.Fatal(err, want)
		}
	}
}

func TestSourceToolRecoveryIsBounded(t *testing.T) {
	cfg := Config{MaxSteps: 6, Paths: []string{"handler.go"}}
	raw := snapshot(t, map[string]string{"handler.go": "one\nreturn exports[id]\n"})
	invalid := Turn{Tokens: 10, Action: Action{Kind: "read", Path: "handler.go", Start: 3, End: 64}}
	large := Turn{Tokens: 10, Action: Action{Kind: "read", Path: "handler.go", Start: 1, End: 65}}
	read := Turn{Tokens: 10, Action: Action{Kind: "read", Path: "handler.go", Start: 1, End: 64}}
	propose := Turn{Tokens: 10, Action: Action{Kind: "propose", Text: "Missing tenant predicate", AnchorIDs: []int{0}}}
	for _, tc := range []struct {
		name         string
		turns        []Turn
		steps        int
		tokens       int64
		status       string
		calls, tools int
	}{
		{"corrected", []Turn{invalid, read, propose}, 6, 100, "hypothesis", 3, 2},
		{"two-corrections", []Turn{large, invalid, read, propose}, 6, 100, "hypothesis", 4, 2},
		{"third-error", []Turn{invalid, invalid, invalid, read, propose}, 6, 100, "tool_error", 3, 3},
		{"step-limit", []Turn{invalid, read, propose}, 1, 100, "step_limit", 1, 1},
		{"token-limit", []Turn{invalid, read, propose}, 6, 20, "token_limit", 2, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			c.MaxSteps = tc.steps
			tools := 0
			f := &fakeAdapter{turns: tc.turns}
			source := func(_ context.Context, q Query) (SourceResult, error) {
				tools++
				return QuerySource(raw, c.Paths, q)
			}
			r := Run(t.Context(), c, "check", tc.tokens, 65536, f, source)
			if r.Status != tc.status || r.Calls != tc.calls || tools != tc.tools || r.Tokens != int64(tc.calls*10) || r.Validate(c) != nil {
				t.Fatal(r, tools)
			}
			if tc.status == "hypothesis" && (len(r.Excerpts) != 1 || r.Excerpts[0].End != 2) {
				t.Fatal(r)
			}
			if len(f.prompts) > 1 && !bytes.Contains(f.prompts[1], []byte("problem")) {
				t.Fatal("missing feedback")
			}
		})
	}
}

func TestSourceFailuresAreScopedAndSanitized(t *testing.T) {
	cfg := Config{MaxSteps: 4, Paths: []string{"handler.go"}}
	f := &fakeAdapter{turns: []Turn{{Tokens: 10, Action: Action{Kind: "read", Path: "secret.key", Start: 1, End: 1}}}}
	source := func(context.Context, Query) (SourceResult, error) {
		t.Fatal("scope bypass")
		return SourceResult{}, nil
	}
	r := Run(t.Context(), cfg, "check", 100, 65536, f, source)
	if r.Status != "tool_error" || r.Calls != 1 || len(r.ToolEvents) != 1 || r.ToolEvents[0].Code != "path_not_allowed" ||
		r.ToolEvents[0].Path != "" || r.Validate(cfg) != nil {
		t.Fatal(r)
	}
	if bytes.Contains(Summary(r, "attempt"), []byte("secret.key")) {
		t.Fatal("stored rejected path")
	}

	f = &fakeAdapter{turns: []Turn{{Tokens: 10, Action: Action{Kind: "read", Path: "handler.go", Start: 1, End: 1}}}}
	r = Run(t.Context(), cfg, "check", 100, 65536, f, func(context.Context, Query) (SourceResult, error) {
		return SourceResult{}, errors.New("raw credentials or provider details")
	})
	if r.Status != "tool_error" || r.Calls != 1 || r.ToolEvents[0].Code != "runner_failed" || r.Validate(cfg) != nil {
		t.Fatal(r)
	}
	r.ToolEvents[0].Code = "raw secret error"
	if r.Validate(cfg) == nil {
		t.Fatal("accepted unknown diagnostic")
	}
	r.ToolEvents[0].Code = "runner_failed"
	r.ToolEvents[0].Path = "secret.key"
	if r.Validate(cfg) == nil {
		t.Fatal("accepted unselected diagnostic path")
	}
}

func TestStructuredSourceProblemReachesModel(t *testing.T) {
	cfg := Config{MaxSteps: 3, Paths: []string{"handler.go"}}
	f := &fakeAdapter{turns: []Turn{
		{Tokens: 10, Action: Action{Kind: "read", Path: "handler.go", Start: 2, End: 3}},
		{Tokens: 10, Action: Action{Kind: "stop"}},
	}}
	r := Run(t.Context(), cfg, "check", 100, 65536, f, func(context.Context, Query) (SourceResult, error) {
		return SourceResult{Problem: &SourceProblem{Code: "read_start_past_eof", TotalLines: 1}}, nil
	})
	if r.Status != "no_hypothesis" || len(r.ToolEvents) != 1 || r.ToolEvents[0].TotalLines != 1 ||
		!bytes.Contains(f.prompts[1], []byte("read_start_past_eof")) || r.Validate(cfg) != nil {
		t.Fatal(r)
	}
}

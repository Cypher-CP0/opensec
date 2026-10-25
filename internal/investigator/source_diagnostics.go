package investigator

import (
	"errors"
	"slices"
)

const MaxToolCorrections = 2

// SourceProblem contains only fixed codes and bounded metadata, never raw errors.
type SourceProblem struct {
	Code       string `json:"code"`
	TotalLines int    `json:"total_lines"`
}

func (p *SourceProblem) Error() string { return p.Code }
func (p *SourceProblem) Recoverable() bool {
	return slices.Contains([]string{"invalid_query", "read_range_too_large", "read_start_past_eof", "excerpt_too_large"}, p.Code)
}
func (p *SourceProblem) valid() bool {
	return p != nil && p.TotalLines >= 0 && p.TotalLines <= 512<<10 &&
		slices.Contains([]string{"invalid_query", "read_range_too_large", "read_start_past_eof", "excerpt_too_large", "path_not_allowed", "invalid_snapshot", "selected_file_unavailable", "unsupported_source_file", "runner_failed", "runner_report_invalid", "source_allowance_exhausted"}, p.Code)
}
func SourceDiagnostic(err error) *SourceProblem {
	var p *SourceProblem
	if errors.As(err, &p) && p.valid() {
		return &SourceProblem{Code: p.Code, TotalLines: p.TotalLines}
	}
	return &SourceProblem{Code: "runner_failed"}
}

// ValidateQuery is also applied before starting an inspector container.
func ValidateQuery(paths []string, q Query) error {
	if !ValidPaths(paths) {
		return &SourceProblem{Code: "invalid_snapshot"}
	}
	if q.Path != "" && !slices.Contains(paths, q.Path) {
		return &SourceProblem{Code: "path_not_allowed"}
	}
	switch q.Kind {
	case "list":
		if q.Path == "" && q.Text == "" && q.Start == 0 && q.End == 0 {
			return nil
		}
	case "search":
		if len(q.Text) >= 1 && len(q.Text) <= 128 && q.Start == 0 && q.End == 0 {
			return nil
		}
	case "read":
		if q.Path != "" && q.Text == "" && q.Start >= 1 && q.End >= q.Start {
			if q.End-q.Start >= 64 {
				return &SourceProblem{Code: "read_range_too_large"}
			}
			return nil
		}
	}
	return &SourceProblem{Code: "invalid_query"}
}

type SourceFile struct {
	Path       string `json:"path"`
	TotalLines int    `json:"total_lines"`
}
type ToolEvent struct {
	Call       int    `json:"call"`
	Kind       string `json:"kind"`
	Path       string `json:"path,omitempty"`
	Start      int    `json:"line_start,omitempty"`
	End        int    `json:"line_end,omitempty"`
	Code       string `json:"code"`
	TotalLines int    `json:"total_lines"`
}

func toolEvent(call int, q Query, paths []string, result SourceResult) ToolEvent {
	e := ToolEvent{Call: call, Kind: q.Kind, Start: q.Start, End: q.End, Code: "ok", TotalLines: result.TotalLines}
	// Never retain invented paths, search text or raw error messages.
	if slices.Contains(paths, q.Path) {
		e.Path = q.Path
	}
	if result.Problem != nil {
		e.Code = result.Problem.Code
		e.TotalLines = result.Problem.TotalLines
	}
	return e
}
func (r Report) validateToolEvents(c Config) error {
	if len(r.ToolEvents) > r.Calls {
		return errors.New("too many tool events")
	}
	previous := 0
	for _, e := range r.ToolEvents {
		if e.Call <= previous || e.Call > r.Calls || !slices.Contains([]string{"list", "search", "read"}, e.Kind) ||
			(e.Path != "" && !slices.Contains(c.Paths, e.Path)) ||
			e.TotalLines < 0 || e.TotalLines > 512<<10 ||
			(e.Code != "ok" && !(&SourceProblem{Code: e.Code, TotalLines: e.TotalLines}).valid()) {
			return errors.New("invalid tool diagnostic")
		}
		previous = e.Call
	}
	return nil
}

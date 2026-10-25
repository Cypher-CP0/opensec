package investigator

import (
	"slices"
	"strings"
)

// Action diagnostics contain fixed codes only. Rejected model text, paths and
// anchor values must not be copied into reports or task reasons.
func validActionErrorCode(code string) bool {
	return slices.Contains([]string{
		"invalid_configuration", "unexpected_anchors", "unused_action_fields",
		"empty_rationale", "rationale_too_large", "invalid_anchor_count",
		"unread_anchor", "repeated_anchor", "unsupported_hypothesis",
		"unsupported_action", "invalid_report",
	}, code)
}

func hypothesisError(h Hypothesis, excerptCount int) string {
	if h.Kind != "tenant_isolation" {
		return "unsupported_hypothesis"
	}
	if strings.TrimSpace(h.Rationale) == "" {
		return "empty_rationale"
	}
	if len(h.Rationale) > MaxRationaleBytes {
		return "rationale_too_large"
	}
	if len(h.AnchorIDs) < 1 || len(h.AnchorIDs) > MaxHypothesisAnchors {
		return "invalid_anchor_count"
	}
	seen := map[int]bool{}
	for _, i := range h.AnchorIDs {
		if i < 0 || i >= excerptCount {
			return "unread_anchor"
		}
		if seen[i] {
			return "repeated_anchor"
		}
		seen[i] = true
	}
	return ""
}

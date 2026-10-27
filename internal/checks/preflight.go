package checks

const PreflightVersion = "object-preflight-v1"

func VersionForSpec(s Spec) string {
	if s.Stage == "prepare" {
		return PreflightVersion
	}
	return VersionFor(*s.Check)
}

// Summary is shared by the runner and coordinator's independent evidence checks.
func Summary(r Result, evidenceID string) map[string]string {
	s := map[string]string{"kind": r.Kind, "verdict": r.Verdict, "reason": r.Reason, "evidence_id": evidenceID}
	if r.ReasonCode != "" {
		s["reason_code"] = r.ReasonCode
	}
	return s
}

func evaluatePreflight(t Transcript) Result {
	r := Result{Kind: t.Version, Verdict: "inconclusive", ReasonCode: "incomplete_observations", Reason: "both positive controls were not completed", Transcript: t}
	for _, o := range t.Observations {
		switch o.Status {
		case 429, 503:
			r.Verdict, r.ReasonCode, r.Reason = "not_ready", "target_backoff", "target requested a pause; preflight did not complete"
			return r
		case 401:
			r.Verdict, r.ReasonCode, r.Reason = "not_ready", "authentication_failed", "a configured identity was not authenticated"
			return r
		case 403:
			r.Verdict, r.ReasonCode, r.Reason = "not_ready", "positive_control_denied", "a configured identity could not read its own object"
			return r
		case 404:
			r.Verdict, r.ReasonCode, r.Reason = "not_ready", "positive_control_not_found", "a configured positive-control object was not found"
			return r
		}
	}
	if len(t.Observations) != 2 {
		return r
	}
	for _, o := range t.Observations {
		if o.Status != 200 || !o.ExportMatches || !o.TenantMatches {
			r.ReasonCode, r.Reason = "selectors_not_established", "successful object and ownership controls could not be established"
			return r
		}
		if len(o.ContentSHA256) != 64 {
			r.ReasonCode, r.Reason = "protected_value_missing", "a configured protected value could not be established"
			return r
		}
	}
	if t.Observations[0].ContentSHA256 == t.Observations[1].ContentSHA256 {
		r.ReasonCode, r.Reason = "controls_not_distinct", "the positive controls did not expose distinct protected values"
		return r
	}
	r.Verdict, r.ReasonCode, r.Reason = "ready", "controls_established", "both identities read their own distinct configured protected object"
	return r
}

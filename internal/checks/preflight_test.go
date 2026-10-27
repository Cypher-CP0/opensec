package checks

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPreflightReadinessIsSeparateFromSecurityVerdict(t *testing.T) {
	a := Observation{Status: 200, BodyBytes: 12, ExportMatches: true, TenantMatches: true, ContentSHA256: Hash([]byte("a"))}
	b := a
	b.ContentSHA256 = Hash([]byte("b"))
	for _, c := range []struct {
		name          string
		observations  []Observation
		verdict, code string
	}{
		{"ready", []Observation{a, b}, "ready", "controls_established"},
		{"incomplete", []Observation{a}, "inconclusive", "incomplete_observations"},
		{"authentication", []Observation{{Status: 401}, b}, "not_ready", "authentication_failed"},
		{"denied", []Observation{a, {Status: 403}}, "not_ready", "positive_control_denied"},
		{"missing", []Observation{a, {Status: 404}}, "not_ready", "positive_control_not_found"},
		{"backoff", []Observation{{Status: 429}}, "not_ready", "target_backoff"},
		{"unavailable", []Observation{{Status: 503}}, "not_ready", "target_backoff"},
		{"bad-selectors", []Observation{{Status: 200}, b}, "inconclusive", "selectors_not_established"},
		{"same-data", []Observation{a, a}, "inconclusive", "controls_not_distinct"},
	} {
		t.Run(c.name, func(t *testing.T) {
			transcript := Transcript{Version: PreflightVersion, Observations: c.observations}
			if err := ValidateTranscript(transcript); err != nil {
				t.Fatal(err)
			}
			result := Evaluate(transcript)
			if result.Verdict != c.verdict || result.ReasonCode != c.code {
				t.Fatal(result)
			}
			raw, err := json.Marshal(transcript)
			if err != nil || strings.Contains(string(raw), "tenant_matches") || !strings.Contains(string(raw), "resource_matches") {
				t.Fatal(string(raw), err)
			}
			var roundTrip Transcript
			if err = json.Unmarshal(raw, &roundTrip); err != nil || Evaluate(roundTrip).Verdict != c.verdict {
				t.Fatal(roundTrip, err)
			}
		})
	}
	if ValidateTranscript(Transcript{Version: PreflightVersion, Observations: []Observation{a, b, a}}) == nil {
		t.Fatal("accepted cross-identity third response in preflight")
	}
}

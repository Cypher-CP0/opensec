package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

type legacyTranscript Transcript
type objectObservation struct {
	Status          int    `json:"status"`
	BodyBytes       int64  `json:"body_bytes"`
	ResourceMatches bool   `json:"resource_matches"`
	OwnerMatches    bool   `json:"owner_matches"`
	ContentSHA256   string `json:"content_sha256,omitempty"`
}
type objectTranscript struct {
	Version      string              `json:"check_version"`
	Observations []objectObservation `json:"observations"`
}

// Preserve legacy transcript bytes, while the new version uses resource-neutral names.
func (t Transcript) MarshalJSON() ([]byte, error) {
	if t.Version != ObjectVersion && t.Version != PreflightVersion {
		return json.Marshal(legacyTranscript(t))
	}
	out := objectTranscript{Version: t.Version, Observations: []objectObservation{}}
	for _, o := range t.Observations {
		out.Observations = append(out.Observations, objectObservation{o.Status, o.BodyBytes, o.ExportMatches, o.TenantMatches, o.ContentSHA256})
	}
	return json.Marshal(out)
}
func (t *Transcript) UnmarshalJSON(raw []byte) error {
	var version struct {
		Version string `json:"check_version"`
	}
	if err := json.Unmarshal(raw, &version); err != nil {
		return err
	}
	decode := func(out any) error {
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(out); err != nil {
			return err
		}
		if d.Decode(new(any)) != io.EOF {
			return errors.New("trailing transcript data")
		}
		return nil
	}
	if version.Version != ObjectVersion && version.Version != PreflightVersion {
		var out legacyTranscript
		if err := decode(&out); err != nil {
			return err
		}
		*t = Transcript(out)
		return nil
	}
	var out objectTranscript
	if err := decode(&out); err != nil {
		return err
	}
	*t = Transcript{Version: out.Version, Observations: []Observation{}}
	for _, o := range out.Observations {
		t.Observations = append(t.Observations, Observation{o.Status, o.BodyBytes, o.ResourceMatches, o.OwnerMatches, o.ContentSHA256})
	}
	return nil
}

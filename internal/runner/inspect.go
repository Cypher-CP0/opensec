// Package runner executes a fixed offline inspector in a constrained container.
package runner

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/policy"
	"io"
	"io/fs"
	"strings"
)

const MaxInput = 32 << 20
const MaxOutput = 1 << 20

type Input struct {
	Check        *checks.Plan         `json:"check,omitempty"`
	Observations []policy.Observation `json:"observations"`
	SourceTar    []byte               `json:"source_tar,omitempty"`
}
type File struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type Response struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type Report struct {
	Check            *checks.Result `json:"check,omitempty"`
	Kind             string         `json:"kind"`
	Files            []File         `json:"files"`
	Responses        []Response     `json:"responses"`
	SecurityJudgment string         `json:"security_judgment"`
}

func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

// Inspect inventories input without extracting archives or executing target code.
func Inspect(input Input) (Report, error) {
	report := Report{Kind: "inspection", Files: []File{}, Responses: []Response{}, SecurityJudgment: "not_performed"}
	var total int64
	if len(input.SourceTar) > MaxInput {
		return report, errors.New("snapshot input too large")
	}
	archive := tar.NewReader(bytes.NewReader(input.SourceTar))
	seen := map[string]bool{}
	for entries := 0; len(input.SourceTar) > 0; entries++ {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, errors.New("invalid source archive")
		}
		if entries >= 512 {
			return report, errors.New("source archive has too many entries")
		}
		name := strings.TrimSuffix(header.Name, "/")
		if !fs.ValidPath(name) || name == "." || strings.Contains(name, `\`) {
			return report, errors.New("unsafe archive path")
		}
		if seen[name] {
			return report, errors.New("duplicate archive path")
		}
		seen[name] = true
		if header.Typeflag == tar.TypeDir {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > MaxInput-total {
			return report, errors.New("unsupported archive entry or size")
		}
		h := sha256.New()
		n, err := io.Copy(h, archive)
		if err != nil || n != header.Size {
			return report, errors.New("incomplete archive entry")
		}
		total += n
		report.Files = append(report.Files, File{name, n, hex.EncodeToString(h.Sum(nil))})
	}
	if len(input.Observations) > 128 {
		return report, errors.New("too many observations")
	}
	for _, o := range input.Observations {
		total += int64(len(o.Body))
		if total > MaxInput {
			return report, errors.New("observation input too large")
		}
		report.Responses = append(report.Responses, Response{o.URL, o.Status, len(o.Body), digest(o.Body)})
	}
	if input.Check != nil {
		if err := input.Check.Validate(); err != nil {
			return report, err
		}
		t := checks.Transcript{Version: checks.Version, Observations: []checks.Observation{}}
		if len(input.Observations) > 3 {
			return report, errors.New("too many check responses")
		}
		exports := []string{input.Check.ExportA, input.Check.ExportB, input.Check.ExportB}
		tenants := []string{input.Check.TenantA, input.Check.TenantB, input.Check.TenantB}
		for i, o := range input.Observations {
			t.Observations = append(t.Observations, checks.Summarize(o.Status, o.Body, exports[i], tenants[i]))
		}
		result := checks.Evaluate(t)
		report.Check = &result
		report.SecurityJudgment = "deterministic_check"
	}
	return report, nil
}
func InspectStream(input io.Reader, output io.Writer) error {
	raw, err := io.ReadAll(io.LimitReader(input, MaxInput+1))
	if err != nil {
		return err
	}
	if len(raw) > MaxInput || !json.Valid(raw) {
		return errors.New("invalid inspector input")
	}
	var value Input
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&value); err != nil {
		return err
	}
	report, err := Inspect(value)
	if err != nil {
		return err
	}
	raw, err = json.Marshal(report)
	if err != nil {
		return err
	}
	if len(raw) > MaxOutput {
		return errors.New("inspector output too large")
	}
	_, err = output.Write(raw)
	return err
}

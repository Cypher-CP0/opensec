package investigator

import (
	"archive/tar"
	"bytes"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"example.com/unified-harness/internal/checks"
)

// QuerySource runs inside the fixed inspector. It never extracts or executes target files.
func QuerySource(raw []byte, paths []string, q Query) (SourceResult, error) {
	out := SourceResult{}
	if err := ValidateQuery(paths, q); err != nil {
		return out, err
	}
	bad := &SourceProblem{Code: "invalid_snapshot"}
	if len(raw) > 16<<20 {
		return out, bad
	}
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	seen := map[string]bool{}
	for count := 0; ; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || count >= 512 {
			return out, bad
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !ValidPath(name) || seen[name] {
			return out, bad
		}
		seen[name] = true
		if h.Typeflag == tar.TypeDir {
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > 16<<20 {
			return out, bad
		}
		if !slices.Contains(paths, name) {
			continue
		}
		if h.Size > 512<<10 {
			return out, &SourceProblem{Code: "unsupported_source_file"}
		}
		b, err := io.ReadAll(io.LimitReader(tr, (512<<10)+1))
		if err != nil || int64(len(b)) != h.Size {
			return out, bad
		}
		if !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
			return out, &SourceProblem{Code: "unsupported_source_file"}
		}
		files[name] = b
	}
	// Validate every selected file even when a query returns early.
	for _, p := range paths {
		if _, ok := files[p]; !ok {
			return out, &SourceProblem{Code: "selected_file_unavailable"}
		}
	}
	for _, p := range paths {
		b := files[p]
		lines := strings.SplitAfter(string(b), "\n")
		if len(lines) > 0 && lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
		if q.Kind == "list" {
			out.Files = append(out.Files, SourceFile{Path: p, TotalLines: len(lines)})
			continue
		}
		if q.Path != "" && q.Path != p {
			continue
		}
		if q.Kind == "read" {
			if q.Start > len(lines) {
				return out, &SourceProblem{Code: "read_start_past_eof", TotalLines: len(lines)}
			}
			end := min(q.End, len(lines))
			text := strings.Join(lines[q.Start-1:end], "")
			if len(text) > MaxExcerpt {
				return out, &SourceProblem{Code: "excerpt_too_large", TotalLines: len(lines)}
			}
			out.TotalLines = len(lines)
			out.Excerpt = &Excerpt{Anchor: Anchor{p, q.Start, end}, FileSHA256: checks.Hash(b), SHA256: checks.Hash([]byte(text)), Text: text}
			return out, nil
		}
		for i, line := range lines {
			if strings.Contains(line, q.Text) {
				if len(out.Matches) == 32 {
					out.Truncated = true
					return out, nil
				}
				out.Matches = append(out.Matches, Anchor{p, i + 1, i + 1})
			}
		}
	}
	return out, nil
}

package checks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const ObjectVersion = "object-authorization-v1"

type ObjectCheck struct {
	PathTemplate string         `json:"path_template"`
	ResourceA    string         `json:"resource_a"`
	ResourceB    string         `json:"resource_b"`
	OwnerA       string         `json:"owner_a,omitempty"`
	OwnerB       string         `json:"owner_b,omitempty"`
	Response     ObjectResponse `json:"response"`
}
type ObjectResponse struct {
	ResourceID     string `json:"resource_id"`
	OwnerID        string `json:"owner_id,omitempty"`
	ProtectedValue string `json:"protected_value"`
}

func VersionFor(p Plan) string {
	if p.Kind == "object_authorization" {
		return ObjectVersion
	}
	return Version
}
func validID(s string) bool {
	return regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$").MatchString(s)
}
func (o ObjectCheck) Validate() error {
	if !validID(o.ResourceA) || !validID(o.ResourceB) || o.ResourceA == o.ResourceB || !validTemplate(o.PathTemplate) {
		return errors.New("invalid object resources or endpoint template")
	}
	if !validPointer(o.Response.ResourceID) || !validPointer(o.Response.ProtectedValue) || o.Response.ResourceID == o.Response.ProtectedValue {
		return errors.New("invalid or repeated response selector")
	}
	if o.Response.OwnerID == "" {
		if o.OwnerA != "" || o.OwnerB != "" {
			return errors.New("owner IDs require an owner selector")
		}
	} else if !validPointer(o.Response.OwnerID) || !validID(o.OwnerA) || !validID(o.OwnerB) ||
		o.OwnerA == o.OwnerB || o.Response.OwnerID == o.Response.ResourceID || o.Response.OwnerID == o.Response.ProtectedValue {
		return errors.New("invalid owner controls")
	}
	return nil
}
func validTemplate(s string) bool {
	if len(s) > 512 || !strings.HasPrefix(s, "/") || strings.Count(s, "{id}") != 1 {
		return false
	}
	parts := strings.Split(s[1:], "/")
	if len(parts) > 32 {
		return false
	}
	for _, p := range parts {
		if p == "{id}" {
			continue
		}
		if p == "" || p == "." || p == ".." {
			return false
		}
		for _, c := range p {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
				return false
			}
		}
	}
	return true
}
func validPointer(s string) bool {
	if len(s) < 2 || len(s) > 256 || s[0] != '/' || len(strings.Split(s[1:], "/")) > 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] == 127 {
			return false
		}
		if s[i] == '~' {
			i++
			if i >= len(s) || s[i] != '0' && s[i] != '1' {
				return false
			}
		}
	}
	return true
}

// decodeValue rejects duplicate keys at every level before extracting selected values.
func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("JSON nesting exceeds limit")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	switch t {
	case json.Delim('{'):
		v := map[string]any{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return nil, err
			}
			k, ok := key.(string)
			if !ok {
				return nil, errors.New("invalid JSON key")
			}
			if _, ok = v[k]; ok {
				return nil, errors.New("duplicate JSON key")
			}
			v[k], err = decodeValue(d, depth+1)
			if err != nil {
				return nil, err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("invalid JSON object")
		}
		return v, nil
	case json.Delim('['):
		v := []any{}
		for d.More() {
			item, err := decodeValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			v = append(v, item)
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("invalid JSON array")
		}
		return v, nil
	}
	if _, bad := t.(json.Delim); bad {
		return nil, errors.New("unexpected JSON delimiter")
	}
	return t, nil
}
func pointer(v any, p string) (any, bool) {
	for _, s := range strings.Split(p[1:], "/") {
		key := strings.ReplaceAll(strings.ReplaceAll(s, "~1", "/"), "~0", "~")
		switch node := v.(type) {
		case map[string]any:
			var ok bool
			v, ok = node[key]
			if !ok {
				return nil, false
			}
		case []any:
			if key == "" || len(key) > 1 && key[0] == '0' {
				return nil, false
			}
			n, err := strconv.Atoi(key)
			if err != nil || n < 0 || n >= len(node) {
				return nil, false
			}
			v = node[n]
		default:
			return nil, false
		}
	}
	return v, true
}
func identifier(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return string(v)
	}
	return ""
}
func protectedDigest(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		if v == "" {
			return ""
		}
	case []any:
		if len(v) == 0 {
			return ""
		}
	case map[string]any:
		if len(v) == 0 {
			return ""
		}
	case bool, json.Number:
		return "" // A status flag or count is not a protected-content control.
	default:
		return ""
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return Hash(raw)
}
func SummarizePlan(p Plan, status int, body []byte, index int) Observation {
	if p.Kind != "object_authorization" {
		resources := []string{p.ExportA, p.ExportB, p.ExportB}
		owners := []string{p.TenantA, p.TenantB, p.TenantB}
		return Summarize(status, body, resources[index], owners[index])
	}
	out := Observation{Status: status, BodyBytes: int64(len(body))}
	if p.Validate() != nil || index < 0 || index > 2 || len(body) > MaxArtifact || !utf8.Valid(body) {
		return out
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	v, err := decodeValue(d, 0)
	if err != nil {
		return out
	}
	if _, err = d.Token(); err != io.EOF {
		return out
	}
	o := p.Object
	resource, owner := o.ResourceB, o.OwnerB
	if index == 0 {
		resource, owner = o.ResourceA, o.OwnerA
	}
	id, ok := pointer(v, o.Response.ResourceID)
	out.ExportMatches = ok && identifier(id) == resource
	out.TenantMatches = o.Response.OwnerID == ""
	if o.Response.OwnerID != "" {
		id, ok = pointer(v, o.Response.OwnerID)
		out.TenantMatches = ok && identifier(id) == owner
	}
	if value, ok := pointer(v, o.Response.ProtectedValue); ok {
		out.ContentSHA256 = protectedDigest(value)
	}
	return out
}
func (p Plan) Paths() []string {
	if p.Kind == "object_authorization" && p.Object != nil {
		a := strings.Replace(p.Object.PathTemplate, "{id}", url.PathEscape(p.Object.ResourceA), 1)
		b := strings.Replace(p.Object.PathTemplate, "{id}", url.PathEscape(p.Object.ResourceB), 1)
		return []string{a, b, b}
	}
	return []string{"/exports/" + url.PathEscape(p.ExportA), "/exports/" + url.PathEscape(p.ExportB), "/exports/" + url.PathEscape(p.ExportB)}
}
func ReproductionSteps(origin string, p Plan) []string {
	paths := p.Paths()
	return []string{
		fmt.Sprintf("GET %s%s using %s; establish the first positive control", origin, paths[0], p.IdentityA),
		fmt.Sprintf("GET %s%s using %s; establish the protected object's positive control", origin, paths[1], p.IdentityB),
		fmt.Sprintf("GET %s%s using %s; compare the configured object, ownership and protected-content controls", origin, paths[2], p.IdentityA),
	}
}

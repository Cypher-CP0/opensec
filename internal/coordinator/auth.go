// Package coordinator exposes a scoped, authenticated queue API.
package coordinator

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"example.com/unified-harness/internal/configfile"
)

var idPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

type Credential struct {
	Subject     string              `json:"subject"`
	Role        string              `json:"role"`
	TokenSHA256 string              `json:"token_sha256"`
	Scopes      map[string][]string `json:"scopes"`
}
type Auth struct{ credentials []Credential }

func LoadAuth(path string) (*Auth, error) {
	var credentials []Credential
	if err := configfile.Read(path, &credentials); err != nil {
		return nil, err
	}
	return NewAuth(credentials)
}
func NewAuth(credentials []Credential) (*Auth, error) {
	if len(credentials) == 0 || len(credentials) > 128 {
		return nil, errors.New("provide 1..128 credentials")
	}
	seen := map[string]bool{}
	for _, c := range credentials {
		raw, err := hex.DecodeString(c.TokenSHA256)
		if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != c.TokenSHA256 || seen[c.TokenSHA256] || !idPattern.MatchString(c.Subject) || (c.Role != "operator" && c.Role != "worker") || len(c.Scopes) == 0 {
			return nil, errors.New("invalid or duplicate credential")
		}
		seen[c.TokenSHA256] = true
		for project, runs := range c.Scopes {
			if !idPattern.MatchString(project) || len(runs) == 0 {
				return nil, errors.New("empty or invalid project/run scope")
			}
			for _, run := range runs {
				if run != "*" && !idPattern.MatchString(run) {
					return nil, errors.New("invalid run scope")
				}
			}
		}
	}
	// Decode a copy so external callers cannot mutate authorization maps.
	raw, _ := jsonBytes(credentials)
	var copied []Credential
	if err := configfile.Decode(raw, &copied); err != nil {
		return nil, err
	}
	return &Auth{copied}, nil
}
func (a *Auth) authenticate(r *http.Request) (Credential, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return Credential{}, false
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, " \r\n\t") {
		return Credential{}, false
	}
	sum := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(sum[:])
	for _, c := range a.credentials {
		if subtle.ConstantTimeCompare([]byte(digest), []byte(c.TokenSHA256)) == 1 {
			return c, true
		}
	}
	return Credential{}, false
}
func (c Credential) allows(project, run string) bool {
	if !idPattern.MatchString(project) || !idPattern.MatchString(run) {
		return false
	}
	for _, scope := range c.Scopes[project] {
		if scope == "*" || scope == run {
			return true
		}
	}
	return false
}

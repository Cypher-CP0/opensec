package policy

import (
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"example.com/unified-harness/internal/configfile"
)

// Credentials never cross the worker boundary. Paths are operator configuration,
// not task input, and tokens are looked up only for the exact authorized scope.
type Credential struct {
	ProjectID   string `json:"project_id"`
	PolicyRef   string `json:"policy_ref"`
	Origin      string `json:"origin"`
	IdentityRef string `json:"identity_ref"`
	TokenFile   string `json:"token_file"`
}
type Credentials struct{ tokens map[string]string }

func credentialKey(project, policy, origin, identity string) string {
	return strings.Join([]string{project, policy, origin, identity}, "\x00")
}
func LoadCredentials(path string) (*Credentials, error) {
	c := &Credentials{tokens: map[string]string{}}
	if path == "" {
		return c, nil
	}
	var records []Credential
	if err := configfile.Read(path, &records); err != nil {
		return nil, errors.New("cannot load probe credential configuration")
	}
	if len(records) > 128 {
		return nil, errors.New("too many probe credentials")
	}
	id := regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
	for _, r := range records {
		u, err := url.Parse(r.Origin)
		if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Host, "%") {
			return nil, errors.New("invalid credential origin")
		}
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
			return nil, errors.New("probe credentials require HTTPS except literal loopback")
		}
		if !id.MatchString(r.ProjectID) || !id.MatchString(r.PolicyRef) || !id.MatchString(r.IdentityRef) || r.TokenFile == "" {
			return nil, errors.New("invalid credential scope")
		}
		file := r.TokenFile
		if !filepath.IsAbs(file) {
			file = filepath.Join(filepath.Dir(path), file)
		}
		info, err := os.Stat(file)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
			return nil, errors.New("probe token file unavailable or oversized")
		}
		raw, err := os.ReadFile(file)
		token := strings.TrimSpace(string(raw))
		if err != nil || len(token) < 8 || len(token) > 4096 || strings.ContainsAny(token, " \r\n\t") {
			return nil, errors.New("invalid probe token")
		}
		key := credentialKey(r.ProjectID, r.PolicyRef, r.Origin, r.IdentityRef)
		if _, exists := c.tokens[key]; exists {
			return nil, errors.New("duplicate probe credential scope")
		}
		c.tokens[key] = token
	}
	return c, nil
}
func (c *Credentials) token(p Policy, raw, identity string) (string, error) {
	if identity == "" {
		return "", nil
	}
	if c == nil {
		return "", errors.New("probe identity unavailable")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("invalid probe URL")
	}
	token, ok := c.tokens[credentialKey(p.ProjectID, p.Ref, u.Scheme+"://"+u.Host, identity)]
	if !ok {
		return "", errors.New("probe identity is not authorized for target")
	}
	return token, nil
}

type Probe struct{ URL, IdentityRef string }

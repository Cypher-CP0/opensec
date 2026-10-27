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

// Credential files belong to the worker. Tasks carry only scoped identity references.
type Credential struct {
	ProjectID   string `json:"project_id"`
	PolicyRef   string `json:"policy_ref"`
	Origin      string `json:"origin"`
	IdentityRef string `json:"identity_ref"`
	TokenFile   string `json:"token_file"`
	AuthKind    string `json:"auth_kind,omitempty"`
	HeaderName  string `json:"header_name,omitempty"`
}
type secretHeader struct{ name, value string }
type Credentials struct{ headers map[string]secretHeader }

func credentialKey(project, policy, origin, identity string) string {
	return strings.Join([]string{project, policy, origin, identity}, "\x00")
}

// ValidateCredential validates non-secret configuration without reading a token file.
func ValidateCredential(r Credential) error {
	u, err := url.Parse(r.Origin)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Host, "%") {
		return errors.New("invalid credential origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return errors.New("probe credentials require HTTPS except literal loopback")
	}
	id := regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
	if !id.MatchString(r.ProjectID) || !id.MatchString(r.PolicyRef) || !id.MatchString(r.IdentityRef) || r.TokenFile == "" {
		return errors.New("invalid credential scope")
	}
	switch r.AuthKind {
	case "", "bearer", "cookie":
		if r.HeaderName != "" {
			return errors.New("custom header name requires api_key authentication")
		}
	case "api_key":
		// Custom credentials cannot override transport, routing or built-in headers.
		if !regexp.MustCompile("(?i)^X-[A-Za-z0-9-]{1,62}$").MatchString(r.HeaderName) {
			return errors.New("API key header must be an X- prefixed header")
		}
		switch strings.ToLower(r.HeaderName) {
		case "x-forwarded-host", "x-forwarded-for", "x-forwarded-proto", "x-original-url", "x-rewrite-url", "x-http-method-override":
			return errors.New("routing override headers are not credentials")
		}
	default:
		return errors.New("unsupported probe authentication kind")
	}
	return nil
}
func LoadCredentials(path string) (*Credentials, error) {
	c := &Credentials{headers: map[string]secretHeader{}}
	if path == "" {
		return c, nil
	}
	var records []Credential
	if configfile.Read(path, &records) != nil {
		return nil, errors.New("cannot load probe credential configuration")
	}
	if len(records) > 128 {
		return nil, errors.New("too many probe credentials")
	}
	for _, r := range records {
		if err := ValidateCredential(r); err != nil {
			return nil, err
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
		value := strings.TrimSpace(string(raw))
		if err != nil || len(value) < 8 || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("invalid probe secret")
		}
		name := r.HeaderName
		switch r.AuthKind {
		case "", "bearer":
			if strings.ContainsAny(value, " \t") {
				return nil, errors.New("invalid bearer token")
			}
			name, value = "Authorization", "Bearer "+value
		case "cookie":
			if strings.ContainsAny(value, "\t") || !strings.Contains(value, "=") {
				return nil, errors.New("invalid cookie secret")
			}
			name = "Cookie"
		case "api_key":
			if strings.ContainsAny(value, " \t") {
				return nil, errors.New("invalid API key")
			}
		}
		key := credentialKey(r.ProjectID, r.PolicyRef, r.Origin, r.IdentityRef)
		if _, ok := c.headers[key]; ok {
			return nil, errors.New("duplicate probe credential scope")
		}
		c.headers[key] = secretHeader{name, value}
	}
	return c, nil
}
func (c *Credentials) header(p Policy, raw, identity string) (secretHeader, error) {
	if identity == "" {
		return secretHeader{}, nil
	}
	if c == nil {
		return secretHeader{}, errors.New("probe identity unavailable")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return secretHeader{}, errors.New("invalid probe URL")
	}
	value, ok := c.headers[credentialKey(p.ProjectID, p.Ref, u.Scheme+"://"+u.Host, identity)]
	if !ok {
		return secretHeader{}, errors.New("probe identity is not authorized for target")
	}
	return value, nil
}

type Probe struct {
	URL, IdentityRef string
	Method           string
	Body             []byte
	Headers          map[string]string
}

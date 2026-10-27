package policy

import (
	"bytes"
	"errors"
	"net/http"
	"net/textproto"
	"strings"
)

// Routing, transport and identity remain broker-owned.
func ValidateHeaders(headers map[string]string) error {
	if len(headers) > 16 {
		return errors.New("too many headers")
	}
	for name, value := range headers {
		if len(name) > 64 || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") || textproto.CanonicalMIMEHeaderKey(name) == "" {
			return errors.New("invalid header")
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return errors.New("invalid header name")
			}
		}
		switch strings.ToLower(name) {
		case "accept", "content-type", "if-match", "if-none-match", "x-requested-with":
		default:
			return errors.New("header is not supported by controlled requests")
		}
	}
	return nil
}
func SafeResponseHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, key := range []string{"Content-Type", "Content-Encoding", "Location", "Content-Security-Policy", "X-Frame-Options", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Cache-Control"} {
		if value := h.Get(key); len(value) > 0 && len(value) <= 4096 {
			out[strings.ToLower(key)] = value
		}
	}
	return out
}

// Redact known worker secrets before untrusted observations enter the guest/model.
func (c *Credentials) Redact(body []byte) []byte {
	if c == nil {
		return body
	}
	for _, header := range c.headers {
		values := []string{header.value}
		if header.name == "Authorization" {
			values = append(values, strings.TrimPrefix(header.value, "Bearer "))
		}
		if header.name == "Cookie" {
			for _, part := range strings.Split(header.value, ";") {
				if _, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
					values = append(values, v)
				}
			}
		}
		for _, v := range values {
			if len(v) >= 4 {
				body = bytes.ReplaceAll(body, []byte(v), []byte("[REDACTED]"))
			}
		}
	}
	return body
}

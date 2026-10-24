package policy

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var ErrLimit = errors.New("request or response byte limit exceeded")

type Observation struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Body   []byte `json:"body"`
}
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type Broker struct {
	Policies *Registry
	Resolver Resolver
}

// Fetch permits GET only. It never follows redirects, uses environment proxies,
// forwards credentials, or lets the transport resolve a hostname a second time.
func (b Broker) Fetch(ctx context.Context, p Policy, urls []string, requestLimit, byteLimit int64) (observations []Observation, requests, bytes int64, err error) {
	if b.Policies == nil {
		return nil, 0, 0, errors.New("policy registry is required")
	}
	if int64(len(urls)) > requestLimit || byteLimit < 0 {
		return nil, 0, 0, ErrLimit
	}
	resolver := b.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	for _, raw := range urls {
		u, e := url.Parse(raw)
		if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.Contains(u.Host, "%") {
			return observations, requests, bytes, errors.New("invalid target URL")
		}
		var addresses []netip.Addr
		if ip, e := netip.ParseAddr(u.Hostname()); e == nil {
			addresses = []netip.Addr{ip}
		} else {
			lookup, done := context.WithTimeout(ctx, 5*time.Second)
			addresses, e = resolver.LookupNetIP(lookup, "ip", u.Hostname())
			done()
			if e != nil {
				return observations, requests, bytes, errors.New("target DNS resolution failed")
			}
		}
		if len(addresses) > 64 {
			return observations, requests, bytes, errors.New("too many DNS answers")
		}
		ips := make([]string, 0, len(addresses))
		for _, ip := range addresses {
			ips = append(ips, ip.Unmap().String())
		}
		if e = b.Policies.AuthorizeNetwork(ctx, p, raw, ips); e != nil {
			return observations, requests, bytes, e
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		pinned := net.JoinHostPort(ips[0], port)
		transport := &http.Transport{
			Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
			MaxResponseHeaderBytes: 16 << 10, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", pinned)
			},
		}
		client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are disabled") }}
		request, e := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if e != nil {
			return observations, requests, bytes, e
		}
		request.Header.Set("User-Agent", "opensec-mvp/1")
		request.Header.Set("Accept-Encoding", "identity")
		requests++ // Failed network attempts still consume the allowance.
		response, e := client.Do(request)
		if e != nil {
			transport.CloseIdleConnections()
			return observations, requests, bytes, errors.New("target request failed or redirected")
		}
		remaining := byteLimit - bytes
		body, readErr := io.ReadAll(io.LimitReader(response.Body, remaining+1))
		response.Body.Close()
		transport.CloseIdleConnections()
		if int64(len(body)) > remaining {
			bytes = byteLimit
			return observations, requests, bytes, ErrLimit
		}
		bytes += int64(len(body))
		if readErr != nil {
			return observations, requests, bytes, errors.New("target response read failed")
		}
		observations = append(observations, Observation{URL: raw, Status: response.StatusCode, Body: body})
	}
	return
}

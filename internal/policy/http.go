package policy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	Headers map[string]string `json:"headers,omitempty"`
	URL     string            `json:"url"`
	Status  int               `json:"status"`
	Body    []byte            `json:"body"`
}
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type Broker struct {
	Policies    *Registry
	Resolver    Resolver
	Credentials *Credentials
	Gate        TrafficGate
}

func (b Broker) Fetch(ctx context.Context, p Policy, urls []string, requestLimit, byteLimit int64) ([]Observation, int64, int64, error) {
	probes := make([]Probe, len(urls))
	for i, u := range urls {
		probes[i] = Probe{URL: u}
	}
	return b.FetchProbes(ctx, p, probes, requestLimit, byteLimit)
}

// FetchProbes prevalidates all endpoint and credential references before the first request.
func (b Broker) FetchProbes(ctx context.Context, p Policy, probes []Probe, requestLimit, byteLimit int64) (observations []Observation, requests, bodyBytes int64, err error) {
	if b.Policies == nil {
		return nil, 0, 0, errors.New("policy registry is required")
	}
	if int64(len(probes)) > requestLimit || byteLimit < 0 {
		return nil, 0, 0, ErrLimit
	}
	if p.Traffic != nil && b.Gate == nil {
		return nil, 0, 0, ErrTrafficUnavailable
	}
	headers := make([]secretHeader, len(probes))
	for i := range probes {
		probe := &probes[i]
		if probe.Method == "" {
			probe.Method = http.MethodGet
		}
		if len(probe.Body) > 32768 || ((probe.Method == "GET" || probe.Method == "HEAD") && len(probe.Body) > 0) || ValidateHeaders(probe.Headers) != nil {
			return nil, 0, 0, errors.New("invalid bounded request")
		}
		if _, err = b.Policies.MethodOrigin(ctx, p, probe.URL, probe.Method); err != nil {
			return nil, 0, 0, err
		}
		headers[i], err = b.Credentials.header(p, probe.URL, probe.IdentityRef)
		if err != nil {
			return nil, 0, 0, err
		}
	}
	resolver := b.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	for i, probe := range probes {
		u, e := url.Parse(probe.URL)
		if e != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.Contains(u.Host, "%") {
			return observations, requests, bodyBytes, errors.New("invalid target URL")
		}
		var addresses []netip.Addr
		if ip, e := netip.ParseAddr(u.Hostname()); e == nil {
			addresses = []netip.Addr{ip}
		} else {
			lookup, cancel := context.WithTimeout(ctx, 5*time.Second)
			addresses, e = resolver.LookupNetIP(lookup, "ip", u.Hostname())
			cancel()
			if e != nil {
				return observations, requests, bodyBytes, errors.New("target DNS resolution failed")
			}
		}
		if len(addresses) > 64 {
			return observations, requests, bodyBytes, errors.New("too many DNS answers")
		}
		ips := make([]string, 0, len(addresses))
		for _, ip := range addresses {
			ips = append(ips, ip.Unmap().String())
		}
		if e = b.Policies.AuthorizeNetworkMethod(ctx, p, probe.URL, probe.Method, ips); e != nil {
			return observations, requests, bodyBytes, e
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
		obs, n, e := func() (observation *Observation, n int64, problem error) {
			requestCtx := ctx
			if p.Traffic != nil {
				var entropy [16]byte
				if _, e := rand.Read(entropy[:]); e != nil {
					return nil, 0, ErrTrafficUnavailable
				}
				id := hex.EncodeToString(entropy[:])
				for {
					started := time.Now()
					var grant TrafficGrant
					var e error
					if probe.Method == "GET" {
						grant, e = b.Gate.Acquire(ctx, probe.URL, id)
					} else if gate, ok := b.Gate.(MethodTrafficGate); ok {
						grant, e = gate.AcquireMethod(ctx, probe.URL, probe.Method, id)
					} else {
						return nil, 0, ErrTrafficUnavailable
					}
					if e != nil {
						return nil, 0, ErrTrafficUnavailable
					}
					if grant.Granted {
						requests++ // An admission is conservatively charged even if no connection follows.
						defer func() {
							cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
							defer cancel()
							status := 0
							if observation != nil {
								status = observation.Status
							}
							if b.Gate.Release(cleanup, id, status) != nil {
								problem = ErrTrafficUnavailable
							}
						}()
						if grant.ValidForMS < 1 || grant.ValidForMS > 15000 {
							return nil, 0, ErrTrafficUnavailable
						}
						// Start before the RPC: elapsed RPC time shortens validity, independent of host clock offsets.
						deadline := started.Add(time.Duration(grant.ValidForMS)*time.Millisecond - 100*time.Millisecond)
						if !deadline.After(time.Now()) {
							return nil, 0, ErrTrafficUnavailable
						}
						bounded, cancel := context.WithDeadline(ctx, deadline)
						defer cancel()
						requestCtx = bounded
						break
					}
					if grant.RetryAfterMS < 1 || grant.RetryAfterMS > 301000 {
						return nil, 0, ErrTrafficUnavailable
					}
					timer := time.NewTimer(time.Duration(grant.RetryAfterMS) * time.Millisecond)
					select {
					case <-ctx.Done():
						timer.Stop()
						return nil, 0, ctx.Err()
					case <-timer.C:
					}
				}
			}
			transport := &http.Transport{
				Proxy: nil, DisableCompression: true, DisableKeepAlives: true, MaxResponseHeaderBytes: 16 << 10,
				TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", pinned)
				},
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are disabled") }}
			request, e := http.NewRequestWithContext(requestCtx, probe.Method, probe.URL, bytes.NewReader(probe.Body))
			if e != nil {
				return nil, 0, errors.New("invalid target request")
			}
			for name, value := range probe.Headers {
				request.Header.Set(name, value)
			}
			if headers[i].name != "" {
				request.Header.Set(headers[i].name, headers[i].value)
			}
			request.Header.Set("User-Agent", "opensec-mvp/1")
			request.Header.Set("Accept-Encoding", "identity")
			if p.Traffic == nil {
				requests++
			}
			response, e := client.Do(request)
			if e != nil {
				return nil, 0, errors.New("target request failed or redirected")
			}
			defer response.Body.Close()
			observation = &Observation{URL: probe.URL, Status: response.StatusCode, Headers: SafeResponseHeaders(response.Header)}
			if response.StatusCode == 429 || response.StatusCode == 503 {
				// Error bodies are not needed for the verdict. Close immediately,
				// then record the shared cooldown before this broker can proceed.
				return observation, 0, ErrTargetBackoff
			}
			remaining := byteLimit - bodyBytes
			body, e := io.ReadAll(io.LimitReader(response.Body, remaining+1))
			if int64(len(body)) > remaining {
				return observation, remaining, ErrLimit
			}
			if e != nil {
				return observation, int64(len(body)), errors.New("target response read failed")
			}
			observation.Body = body
			return observation, int64(len(body)), nil
		}()
		bodyBytes += n
		if obs != nil {
			observations = append(observations, *obs)
		}
		if e != nil {
			return observations, requests, bodyBytes, e
		}
	}
	return
}

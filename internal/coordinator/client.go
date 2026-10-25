package coordinator

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"example.com/unified-harness/internal/queue"
)

type Client struct {
	base, token   string
	http          *http.Client
	leaseDuration time.Duration
}

func NewClient(base, token, caFile string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("coordinator URL must be an origin")
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "https" && !(u.Scheme == "http" && ip != nil && ip.IsLoopback()) {
		return nil, errors.New("coordinator requires HTTPS except literal loopback")
	}
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, " \r\n\t") {
		return nil, errors.New("invalid bearer token")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		certs, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(certs) {
			return nil, errors.New("invalid CA bundle")
		}
		tlsConfig.RootCAs = roots
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: tlsConfig, MaxResponseHeaderBytes: 16 << 10}
	return &Client{strings.TrimRight(base, "/"), token, &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("API redirects refused") }}, 30 * time.Second}, nil
}
func (c *Client) Close()                       { c.http.CloseIdleConnections() }
func (c *Client) LeaseDuration() time.Duration { return c.leaseDuration }
func (c *Client) call(ctx context.Context, method, path string, input, out any) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if len(raw) > 4<<20 {
		return errors.New("API input exceeds 4 MiB")
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+c.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.http.Do(request)
	if err != nil {
		return errors.New("coordinator request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil || len(body) > 4<<20 {
		return errors.New("invalid or oversized coordinator response")
	}
	if response.StatusCode == 204 {
		return queue.ErrNoWork
	}
	if response.StatusCode != 200 {
		var problem ErrorResponse
		_ = json.Unmarshal(body, &problem)
		switch problem.Error {
		case "budget_exhausted":
			return queue.ErrBudget
		case "invalid_lease":
			return queue.ErrLease
		case "conflict":
			return queue.ErrConflict
		case "run_closed":
			return queue.ErrRunClosed
		case "not_found":
			return queue.ErrNotFound
		}
		return fmt.Errorf("coordinator rejected request (HTTP %d)", response.StatusCode)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}
func (c *Client) Info(ctx context.Context) (Info, error) {
	var v Info
	err := c.call(ctx, http.MethodGet, "/v1/info", nil, &v)
	if err == nil {
		if v.LeaseMilliseconds < 1 || v.LeaseMilliseconds > 300000 {
			return v, errors.New("invalid server lease configuration")
		}
		c.leaseDuration = time.Duration(v.LeaseMilliseconds) * time.Millisecond
	}
	return v, err
}
func (c *Client) Call(ctx context.Context, operation string, input json.RawMessage) (json.RawMessage, error) {
	switch operation {
	case "create-run", "enqueue", "run", "task", "claim", "heartbeat", "finish", "cancel", "reap", "resume", "close", "evidence", "finding", "findings", "investigation":
	default:
		return nil, errors.New("unknown API operation")
	}
	var raw json.RawMessage
	err := c.call(ctx, http.MethodPost, "/v1/queue/"+operation, input, &raw)
	return raw, err
}
func (c *Client) Claim(ctx context.Context, project, run, worker string) (queue.Lease, error) {
	var l queue.Lease
	err := c.call(ctx, "POST", "/v1/queue/claim", Scope{ProjectID: project, RunID: run}, &l)
	return l, err
}
func (c *Client) Heartbeat(ctx context.Context, l queue.Lease) (time.Time, error) {
	var v struct {
		ExpiresAt time.Time `json:"expires_at"`
	}
	err := c.call(ctx, "POST", "/v1/queue/heartbeat", LeaseRequest{Lease: l}, &v)
	return v.ExpiresAt, err
}
func (c *Client) Finish(ctx context.Context, l queue.Lease, completion queue.Completion) (string, error) {
	var v struct {
		Status string `json:"task_status"`
	}
	err := c.call(ctx, "POST", "/v1/queue/finish", LeaseRequest{l, &completion}, &v)
	return v.Status, err
}
func (c *Client) Reap(ctx context.Context, project, run string) (int, error) {
	var v struct {
		Reaped int `json:"reaped"`
	}
	err := c.call(ctx, "POST", "/v1/queue/reap", Scope{ProjectID: project, RunID: run}, &v)
	return v.Reaped, err
}

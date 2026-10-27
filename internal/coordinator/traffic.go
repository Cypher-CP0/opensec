package coordinator

import (
	"context"

	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
)

type TrafficRequest struct {
	Method    string      `json:"method,omitempty"`
	Lease     queue.Lease `json:"lease"`
	URL       string      `json:"url,omitempty"`
	RequestID string      `json:"request_id"`
	Status    int         `json:"response_status,omitempty"`
}

func (c *Client) AcquireTraffic(ctx context.Context, l queue.Lease, raw, id string) (policy.TrafficGrant, error) {
	var grant policy.TrafficGrant
	err := c.call(ctx, "POST", "/v1/queue/traffic-acquire", TrafficRequest{Lease: l, URL: raw, RequestID: id}, &grant)
	return grant, err
}
func (c *Client) AcquireTrafficMethod(ctx context.Context, l queue.Lease, raw, method, id string) (policy.TrafficGrant, error) {
	var grant policy.TrafficGrant
	err := c.call(ctx, "POST", "/v1/queue/traffic-acquire", TrafficRequest{Lease: l, URL: raw, Method: method, RequestID: id}, &grant)
	return grant, err
}
func (c *Client) ReleaseTraffic(ctx context.Context, l queue.Lease, id string, status int) error {
	return c.call(ctx, "POST", "/v1/queue/traffic-release", TrafficRequest{Lease: l, RequestID: id, Status: status}, nil)
}

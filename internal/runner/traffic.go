package runner

import (
	"context"

	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
)

type TrafficStore interface {
	AcquireTraffic(context.Context, queue.Lease, string, string) (policy.TrafficGrant, error)
	ReleaseTraffic(context.Context, queue.Lease, string, int) error
}
type leaseGate struct {
	store TrafficStore
	lease queue.Lease
}

func (g leaseGate) Acquire(ctx context.Context, raw, id string) (policy.TrafficGrant, error) {
	return g.store.AcquireTraffic(ctx, g.lease, raw, id)
}
func (g leaseGate) AcquireMethod(ctx context.Context, raw, method, id string) (policy.TrafficGrant, error) {
	if store, ok := g.store.(interface {
		AcquireTrafficMethod(context.Context, queue.Lease, string, string, string) (policy.TrafficGrant, error)
	}); ok {
		return store.AcquireTrafficMethod(ctx, g.lease, raw, method, id)
	}
	return policy.TrafficGrant{}, policy.ErrTrafficUnavailable
}
func (g leaseGate) Release(ctx context.Context, id string, status int) error {
	return g.store.ReleaseTraffic(ctx, g.lease, id, status)
}

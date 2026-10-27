//go:build integration

package queue

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/testdb"
)

func trafficSetup(t *testing.T) (*Store, string, *policy.Registry, Lease, Lease) {
	t.Helper()
	s, dsn := setup(t, config())
	p := policy.Policy{Ref: "local-lab-v1", ProjectID: project, Origins: []string{"http://127.0.0.1:8081"}, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true,
		Repositories: []string{}, MaxInputBytes: 1 << 20, Endpoints: []policy.Endpoint{{Method: "GET", PathTemplate: "/healthz"}},
		Traffic: &policy.TrafficLimits{MinIntervalMS: 200, MaxConcurrent: 1, BackoffSeconds: 1}}
	registry, err := policy.New(t.Context(), []policy.Policy{p}, testdb.Core())
	check(t, err)
	check(t, s.ConfigureTraffic(registry))
	for _, id := range []string{"traffic-a", "traffic-b"} {
		var task map[string]any
		check(t, json.Unmarshal(testdb.Task(t, "web", id, "read_only"), &task))
		task["budget"].(map[string]any)["max_requests"] = 2
		task["target"].(map[string]any)["web"].(map[string]any)["seed_urls"] = []string{"http://127.0.0.1:8081/healthz"}
		raw, err := json.Marshal(task)
		check(t, err)
		check(t, s.Enqueue(t.Context(), raw, EnqueueOptions{MaxAttempts: 2}))
	}
	a, err := s.Claim(t.Context(), project, runID, "worker-a")
	check(t, err)
	b, err := s.Claim(t.Context(), project, runID, "worker-b")
	check(t, err)
	return s, dsn, registry, a, b
}
func TestTrafficSharedAcrossStoreInstancesAndFenced(t *testing.T) {
	s, dsn, registry, a, b := trafficSetup(t)
	other, err := Open(t.Context(), dsn, CoreValidator{testdb.Core()}, DefaultSettings())
	check(t, err)
	defer other.Close()
	check(t, other.ConfigureTraffic(registry))
	u := "http://127.0.0.1:8081/healthz"
	first, err := s.AcquireTraffic(t.Context(), a, u, "request-a")
	check(t, err)
	if !first.Granted || first.ValidForMS < 500 || first.ValidForMS > 15000 {
		t.Fatal(first)
	}
	retry, err := other.AcquireTraffic(t.Context(), a, u, "request-a")
	check(t, err)
	if !retry.Granted {
		t.Fatal("admission retry was not idempotent", retry)
	}
	blocked, err := other.AcquireTraffic(t.Context(), b, u, "request-b")
	check(t, err)
	if blocked.Granted || blocked.RetryAfterMS < 1 {
		t.Fatal("shared concurrency or interval bypass", blocked)
	}
	var spacing int64
	check(t, s.pool.QueryRow(t.Context(), `SELECT (extract(epoch from(t.next_at-p.acquired_at))*1000)::bigint FROM target_traffic t JOIN traffic_permits p USING(project_id,origin) WHERE p.request_id='request-a'`).Scan(&spacing))
	if spacing < 200 {
		t.Fatal("admission spacing not retained", spacing)
	}
	sql(t, s, "UPDATE target_traffic SET next_at=clock_timestamp()-interval '1 second'")
	blocked, err = other.AcquireTraffic(t.Context(), b, u, "request-b")
	check(t, err)
	if blocked.Granted {
		t.Fatal("active permit ignored")
	}
	foreign := a
	foreign.Token = "forged"
	_, err = other.AcquireTraffic(t.Context(), foreign, u, "forged")
	expect(t, err, ErrLease)
	_, err = other.AcquireTraffic(t.Context(), a, "http://127.0.0.1:8081/admin", "wrong-path")
	expect(t, err, ErrInvalid)
	check(t, s.ReleaseTraffic(t.Context(), a, "request-a", 200))
	check(t, s.ReleaseTraffic(t.Context(), a, "request-a", 200))
	expect(t, s.ReleaseTraffic(t.Context(), a, "request-a", 429), ErrConflict)
	second, err := other.AcquireTraffic(t.Context(), b, u, "request-b")
	check(t, err)
	if !second.Granted {
		t.Fatal(second)
	}
	_, err = s.AcquireTraffic(t.Context(), a, u, "request-a")
	expect(t, err, ErrConflict)
	_, err = s.Finish(t.Context(), a, Completion{Outcome: "succeeded", Reason: "test", Usage: &Units{}})
	expect(t, err, ErrInvalid)
	_, err = s.Finish(t.Context(), a, Completion{Outcome: "succeeded", Reason: "test", Usage: &Units{Requests: 1}})
	check(t, err)
	_, err = s.AcquireTraffic(t.Context(), a, u, "after-finish")
	expect(t, err, ErrLease)
}
func TestTrafficCooldownExpiryBudgetAndCancellation(t *testing.T) {
	s, _, _, a, b := trafficSetup(t)
	u := "http://127.0.0.1:8081/healthz"
	g, err := s.AcquireTraffic(t.Context(), a, u, "limited")
	check(t, err)
	if !g.Granted {
		t.Fatal(g)
	}
	check(t, s.ReleaseTraffic(t.Context(), a, "limited", 429))
	sql(t, s, "UPDATE target_traffic SET next_at=clock_timestamp()-interval '1 second'")
	g, err = s.AcquireTraffic(t.Context(), b, u, "blocked")
	check(t, err)
	if g.Granted || g.RetryAfterMS < 1 {
		t.Fatal("cooldown ignored", g)
	}
	sql(t, s, "UPDATE target_traffic SET cooldown_until=clock_timestamp()-interval '1 second'")
	g, err = s.AcquireTraffic(t.Context(), a, u, "crashed")
	check(t, err)
	if !g.Granted {
		t.Fatal(g)
	}
	sql(t, s, `UPDATE traffic_permits SET acquired_at=clock_timestamp()-interval '2 seconds',expires_at=clock_timestamp()-interval '1 second' WHERE request_id='crashed'`)
	sql(t, s, "UPDATE target_traffic SET next_at=clock_timestamp()-interval '1 second'")
	g, err = s.AcquireTraffic(t.Context(), b, u, "after-crash")
	check(t, err)
	if !g.Granted {
		t.Fatal("expired permit retained capacity", g)
	}
	_, err = s.AcquireTraffic(t.Context(), a, u, "over-budget")
	expect(t, err, ErrBudget)
	check(t, s.Cancel(t.Context(), project, runID, b.TaskID, "stop target"))
	_, err = s.AcquireTraffic(t.Context(), b, u, "after-cancel")
	expect(t, err, ErrLease)
	check(t, s.ReleaseTraffic(t.Context(), b, "after-crash", 0))
	forged := b
	forged.Generation++
	if err = s.ReleaseTraffic(t.Context(), forged, "after-crash", 0); !errors.Is(err, ErrLease) {
		t.Fatal("release ownership bypass", err)
	}
}

func TestTrafficConcurrentAdmissionAcrossRuns(t *testing.T) {
	s, dsn, registry, a, b := trafficSetup(t)
	other, err := Open(t.Context(), dsn, CoreValidator{testdb.Core()}, DefaultSettings())
	check(t, err)
	defer other.Close()
	check(t, other.ConfigureTraffic(registry))
	leases := []Lease{a, b}
	for i := 0; i < 2; i++ {
		cfg := config()
		cfg.RunID = fmt.Sprintf("other-run-%d", i)
		check(t, s.CreateRun(t.Context(), cfg))
		var doc map[string]any
		check(t, json.Unmarshal(testdb.Task(t, "web", "traffic-task", "read_only"), &doc))
		doc["run_id"] = cfg.RunID
		doc["target"].(map[string]any)["web"].(map[string]any)["seed_urls"] = []string{"http://127.0.0.1:8081/healthz"}
		raw, err := json.Marshal(doc)
		check(t, err)
		check(t, s.Enqueue(t.Context(), raw, EnqueueOptions{MaxAttempts: 1}))
		l, err := s.Claim(t.Context(), project, cfg.RunID, "worker-other")
		check(t, err)
		leases = append(leases, l)
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	type result struct {
		grant policy.TrafficGrant
		err   error
	}
	results := make(chan result, len(leases))
	for i, l := range leases {
		wg.Add(1)
		go func(i int, l Lease) {
			defer wg.Done()
			<-start
			store := s
			if i%2 == 1 {
				store = other
			}
			g, err := store.AcquireTraffic(t.Context(), l, "http://127.0.0.1:8081/healthz", fmt.Sprintf("request-%d", i))
			results <- result{g, err}
		}(i, l)
	}
	close(start)
	wg.Wait()
	close(results)
	granted := 0
	for r := range results {
		check(t, r.err)
		if r.grant.Granted {
			granted++
		}
	}
	if granted != 1 {
		t.Fatal("concurrent admission bypassed target capacity", granted)
	}
	var permitCount int
	check(t, s.pool.QueryRow(t.Context(), "SELECT count(*) FROM traffic_permits").Scan(&permitCount))
	if permitCount != 1 {
		t.Fatal("denied waits consumed request budget", permitCount)
	}
}

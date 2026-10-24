//go:build integration

package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"example.com/unified-harness/internal/artifact"
	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/lab"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/runner"
	"example.com/unified-harness/internal/testdb"
	"example.com/unified-harness/internal/worker"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func tenantTask(t *testing.T, origin, id string) json.RawMessage {
	var task map[string]any
	if err := json.Unmarshal(testdb.Task(t, "web", id, "read_only"), &task); err != nil {
		t.Fatal(err)
	}
	web := task["target"].(map[string]any)["web"].(map[string]any)
	web["origin"] = origin
	web["seed_urls"] = []string{origin + "/exports"}
	task["check"] = checks.Plan{Kind: "tenant_isolation", IdentityA: "tenant-a-reader", IdentityB: "tenant-b-reader", TenantA: "tenant-a", TenantB: "tenant-b", ExportA: "export-a", ExportB: "export-b"}
	raw, _ := json.Marshal(task)
	return raw
}
func tenantHandler(t *testing.T, origin string, credentials bool) runner.Handler {
	policies, err := policy.New(t.Context(), []policy.Policy{{Ref: "local-lab-v1", ProjectID: "lab-project", Origins: []string{origin}, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{}, MaxInputBytes: 1 << 20}}, testdb.Core())
	if err != nil {
		t.Fatal(err)
	}
	var creds *policy.Credentials
	if credentials {
		dir := t.TempDir()
		records := []policy.Credential{}
		for _, letter := range []string{"a", "b"} {
			name := "tenant-" + letter + ".token"
			if err = os.WriteFile(filepath.Join(dir, name), []byte("lab-only-token-"+letter), 0600); err != nil {
				t.Fatal(err)
			}
			records = append(records, policy.Credential{ProjectID: "lab-project", PolicyRef: "local-lab-v1", Origin: origin, IdentityRef: "tenant-" + letter + "-reader", TokenFile: name})
		}
		raw, _ := json.Marshal(records)
		file := filepath.Join(dir, "credentials.json")
		if err = os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		creds, err = policy.LoadCredentials(file)
		if err != nil {
			t.Fatal(err)
		}
	}
	return runner.Handler{Policies: policies, Broker: policy.Broker{Policies: policies, Credentials: creds}, Executor: findingExecutor(t)}
}
func evidenceStore(t *testing.T, store *queue.Store) (*artifact.Local, string) {
	dir := t.TempDir()
	blobs, err := artifact.OpenLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = blobs.Close() })
	if err = store.ConfigureEvidence(testdb.Core(), blobs); err != nil {
		t.Fatal(err)
	}
	return blobs, dir
}
func findings(t *testing.T, op *Client) queue.FindingPage {
	raw, _ := json.Marshal(Scope{ProjectID: "lab-project", RunID: "run-test"})
	data, err := op.Call(t.Context(), "findings", raw)
	if err != nil {
		t.Fatal(err)
	}
	var page queue.FindingPage
	if err = json.Unmarshal(data, &page); err != nil {
		t.Fatal(err)
	}
	return page
}
func submitTenant(t *testing.T, op *Client, origin, id string) {
	raw, _ := json.Marshal(EnqueueRequest{tenantTask(t, origin, id), queue.EnqueueOptions{MaxAttempts: 3}})
	if _, err := op.Call(t.Context(), "enqueue", raw); err != nil {
		t.Fatal(err)
	}
}
func TestTenantFindingEndToEnd(t *testing.T) {
	for _, scenario := range []string{"vulnerable", "patched", "changes-before-validation", "missing-credentials"} {
		t.Run(scenario, func(t *testing.T) {
			vulnerable, _ := lab.New("vulnerable")
			patched, _ := lab.New("patched")
			var repaired atomic.Bool
			var calls atomic.Int64
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if scenario == "patched" || repaired.Load() {
					patched.ServeHTTP(w, r)
				} else {
					vulnerable.ServeHTTP(w, r)
				}
			}))
			defer target.Close()
			store, api, op, wr := setupAPI(t, target.URL)
			evidenceStore(t, store)
			create(t, op)
			submitTenant(t, op, target.URL, "tenant-hunt")
			handler := tenantHandler(t, target.URL, scenario != "missing-credentials")
			w := worker.Worker{Store: wr, ProjectID: "lab-project", RunID: "run-test", WorkerID: "worker-one", HeartbeatEvery: time.Second}
			status, err := w.RunOnce(t.Context(), handler.Run)
			if err != nil || status != "succeeded" {
				t.Fatal(status, err)
			}
			task, err := store.GetTask(t.Context(), "lab-project", "run-test", "tenant-hunt")
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]string
			_ = json.Unmarshal(task.Result, &result)
			if scenario == "patched" || scenario == "missing-credentials" {
				want := "not_vulnerable"
				if scenario == "missing-credentials" {
					want = "inconclusive"
				}
				if result["verdict"] != want || len(findings(t, op).Findings) != 0 {
					t.Fatal(result)
				}
				if scenario == "missing-credentials" && calls.Load() != 0 {
					t.Fatal("request sent without both credentials")
				}
				return
			}
			page := findings(t, op)
			if len(page.Findings) != 1 || page.Findings[0].Status != "pending_validation" || page.Findings[0].ValidationTaskID == nil {
				t.Fatal(page)
			}
			discovery := page.Findings[0]
			code, _ := apiRequest(t, api, opToken, "evidence", Scope{ProjectID: "other", RunID: "run-test", EvidenceID: discovery.DiscoveryEvidenceID})
			if code != 403 {
				t.Fatal("evidence scope bypass", code)
			}
			if scenario == "changes-before-validation" {
				repaired.Store(true)
			}
			status, err = w.RunOnce(t.Context(), handler.Run)
			if err != nil || status != "succeeded" {
				t.Fatal(status, err)
			}
			page = findings(t, op)
			want := "confirmed"
			if scenario == "changes-before-validation" {
				want = "not_reproduced"
			}
			if page.Findings[0].Status != want || calls.Load() != 6 {
				t.Fatal(page, calls.Load())
			}
			f := page.Findings[0]
			if f.ValidationEvidenceID == nil || *f.ValidationEvidenceID == f.DiscoveryEvidenceID {
				t.Fatal("validation reused discovery evidence")
			}
			first, err := store.GetEvidence(t.Context(), "lab-project", "run-test", f.DiscoveryEvidenceID)
			if err != nil {
				t.Fatal(err)
			}
			second, err := store.GetEvidence(t.Context(), "lab-project", "run-test", *f.ValidationEvidenceID)
			if err != nil {
				t.Fatal(err)
			}
			if first.Record.AttemptID == second.Record.AttemptID || first.Record.TaskID == second.Record.TaskID {
				t.Fatal("validation reused discovery attempt")
			}
			for _, v := range []queue.StoredEvidence{first, second} {
				raw, _ := json.Marshal(v)
				if strings.Contains(string(raw), "lab-only-token") || strings.Contains(string(raw), "SYNTHETIC export") {
					t.Fatal("sensitive response content persisted")
				}
			}
			run, err := store.GetRun(t.Context(), "lab-project", "run-test")
			if err != nil {
				t.Fatal(err)
			}
			if run.Charged.Requests != 6 || run.Reserved != (queue.Units{}) || run.AttemptCount != 2 {
				t.Fatal(run)
			}
			if scenario == "vulnerable" {
				submitTenant(t, op, target.URL, "tenant-hunt-again")
				if _, err = w.RunOnce(t.Context(), handler.Run); err != nil {
					t.Fatal(err)
				}
				if page = findings(t, op); len(page.Findings) != 1 || page.Findings[0].Status != "confirmed" {
					t.Fatal(page)
				}
			}
		})
	}
}

type failingBlobs struct{}

func (failingBlobs) Put(context.Context, string, string, []byte) error {
	return errors.New("injected disk failure")
}
func (failingBlobs) Get(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("injected disk failure")
}
func TestEvidenceFencingTamperingAtomicityAndIdempotency(t *testing.T) {
	labHandler, _ := lab.New("vulnerable")
	target := httptest.NewServer(labHandler)
	defer target.Close()
	store, api, op, wr := setupAPI(t, target.URL)
	blobs, dir := evidenceStore(t, store)
	create(t, op)
	submitTenant(t, op, target.URL, "evidence-hunt")
	l, err := wr.Claim(t.Context(), "lab-project", "run-test", "")
	if err != nil {
		t.Fatal(err)
	}
	completion := tenantHandler(t, target.URL, true).Run(t.Context(), l)
	if completion.Evidence == nil {
		t.Fatal(completion)
	}
	saved := completion.Evidence.Record.AttemptID
	completion.Evidence.Record.AttemptID = "forged"
	if _, err = wr.Finish(t.Context(), l, completion); err == nil {
		t.Fatal("wrong attempt accepted")
	}
	completion.Evidence.Record.AttemptID = saved
	original := append(json.RawMessage{}, completion.Evidence.Artifact...)
	completion.Evidence.Artifact = json.RawMessage(`{"check_version":"tampered","observations":[]}`)
	if _, err = wr.Finish(t.Context(), l, completion); err == nil {
		t.Fatal("tampered artifact accepted")
	}
	completion.Evidence.Artifact = original
	if err = store.ConfigureEvidence(testdb.Core(), failingBlobs{}); err != nil {
		t.Fatal(err)
	}
	if _, err = wr.Finish(t.Context(), l, completion); err == nil {
		t.Fatal("storage failure accepted")
	}
	task, _ := store.GetTask(t.Context(), "lab-project", "run-test", l.TaskID)
	if task.Status != "running" || len(findings(t, op).Findings) != 0 {
		t.Fatal("partial commit", task)
	}
	if err = store.ConfigureEvidence(testdb.Core(), blobs); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		status, err := wr.Finish(t.Context(), l, completion)
		if err != nil || status != "succeeded" {
			t.Fatal(status, err)
		}
	}
	page := findings(t, op)
	if len(page.Findings) != 1 {
		t.Fatal(page)
	}
	code, _ := apiRequest(t, api, opToken, "evidence", Scope{ProjectID: "lab-project", RunID: "run-test", EvidenceID: completion.Evidence.Record.EvidenceID})
	if code != 200 {
		t.Fatal("retrieval failed", code)
	}
	path := filepath.Join(dir, artifact.Scope("lab-project", "run-test")+"-"+completion.Evidence.Record.Artifact.SHA256+".json")
	if err = os.WriteFile(path, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	code, body := apiRequest(t, api, opToken, "evidence", Scope{ProjectID: "lab-project", RunID: "run-test", EvidenceID: completion.Evidence.Record.EvidenceID})
	if code != 500 || strings.Contains(string(body), dir) {
		t.Fatal("corruption not detected or leaked path", code, string(body))
	}
	validation, err := wr.Claim(t.Context(), "lab-project", "run-test", "")
	if err != nil {
		t.Fatal(err)
	}
	replay := tenantHandler(t, target.URL, true).Run(t.Context(), validation)
	if err = store.Cancel(t.Context(), "lab-project", "run-test", validation.TaskID, "operator cancellation"); err != nil {
		t.Fatal(err)
	}
	if _, err = wr.Finish(t.Context(), validation, replay); !errors.Is(err, queue.ErrLease) {
		t.Fatal("revoked worker published", err)
	}
	page = findings(t, op)
	if page.Findings[0].Status != "inconclusive" {
		t.Fatal(page)
	}
}

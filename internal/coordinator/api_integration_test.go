//go:build integration

package coordinator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/runner"
	"example.com/unified-harness/internal/testdb"
	"example.com/unified-harness/internal/worker"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const opToken = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const workerToken = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const otherToken = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

func credential(token, subject, role string) Credential {
	sum := sha256.Sum256([]byte(token))
	return Credential{subject, role, hex.EncodeToString(sum[:]), map[string][]string{"lab-project": {"run-test"}}}
}
func setupAPI(t *testing.T, origins ...string) (*queue.Store, *httptest.Server, *Client, *Client) {
	t.Helper()
	store, err := queue.Open(t.Context(), testdb.New(t), queue.CoreValidator{Binary: testdb.Core()}, queue.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err = store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuth([]Credential{credential(opToken, "operator", "operator"), credential(workerToken, "worker-one", "worker"), credential(otherToken, "worker-two", "worker")})
	if err != nil {
		t.Fatal(err)
	}
	if len(origins) == 0 {
		origins = []string{"http://127.0.0.1:8081"}
	}
	policies, err := policy.New(t.Context(), []policy.Policy{{Ref: "local-lab-v1", ProjectID: "lab-project", Origins: origins, CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Repositories: []string{}, MaxInputBytes: 1 << 20}}, testdb.Core())
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(store, auth, policies)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	op, err := NewClient(server.URL, opToken, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(op.Close)
	wr, err := NewClient(server.URL, workerToken, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(wr.Close)
	return store, server, op, wr
}
func apiRequest(t *testing.T, server *httptest.Server, token, operation string, value any) (int, []byte) {
	t.Helper()
	raw, _ := json.Marshal(value)
	request, err := http.NewRequest("POST", server.URL+"/v1/queue/"+operation, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}
func create(t *testing.T, op *Client) {
	t.Helper()
	config := queue.RunConfig{ProjectID: "lab-project", RunID: "run-test", MaxTasks: 10, MaxAttempts: 10, Limits: queue.Units{Tokens: 1000, Requests: 100, WallSeconds: 1000, ArtifactBytes: 1000000}}
	raw, _ := json.Marshal(config)
	if _, err := op.Call(t.Context(), "create-run", raw); err != nil {
		t.Fatal(err)
	}
}
func enqueueAPI(t *testing.T, op *Client, id string) {
	t.Helper()
	raw, _ := json.Marshal(EnqueueRequest{testdb.Task(t, "web", id, "read_only"), queue.EnqueueOptions{MaxAttempts: 3}})
	if _, err := op.Call(t.Context(), "enqueue", raw); err != nil {
		t.Fatal(err)
	}
}
func TestAPIAuthenticationRoleScopeAndLeaseOwnership(t *testing.T) {
	store, server, op, wr := setupAPI(t)
	scope := Scope{ProjectID: "lab-project", RunID: "run-test"}
	for _, token := range []string{"", strings.Repeat("x", 64)} {
		code, _ := apiRequest(t, server, token, "run", scope)
		if code != 401 {
			t.Fatal("missing/invalid token accepted", code)
		}
	}
	for _, tc := range []struct {
		token, op string
		scope     Scope
	}{
		{workerToken, "create-run", scope}, {opToken, "claim", scope},
		{opToken, "run", Scope{ProjectID: "other", RunID: "run-test"}},
		{workerToken, "claim", Scope{ProjectID: "lab-project", RunID: "other"}},
	} {
		code, _ := apiRequest(t, server, tc.token, tc.op, tc.scope)
		if code != 403 {
			t.Fatal("authorization bypass", tc, code)
		}
	}
	create(t, op)
	enqueueAPI(t, op, "api-task")
	l, err := wr.Claim(t.Context(), "lab-project", "run-test", "forged-worker")
	if err != nil {
		t.Fatal(err)
	}
	if l.WorkerID != "worker-one" {
		t.Fatal("worker identity was taken from client input")
	}
	code, _ := apiRequest(t, server, otherToken, "heartbeat", LeaseRequest{Lease: l})
	if code != 403 {
		t.Fatal("other worker renewed lease")
	}
	forged := l
	forged.WorkerID = "worker-two"
	code, _ = apiRequest(t, server, otherToken, "finish", LeaseRequest{forged, &queue.Completion{Outcome: "succeeded", Reason: "forged"}})
	if code != 409 {
		t.Fatal("forged lease accepted", code)
	}
	finish := queue.Completion{Outcome: "succeeded", Reason: "complete", Usage: &queue.Units{Requests: 1}}
	if _, err = wr.Finish(t.Context(), l, finish); err != nil {
		t.Fatal(err)
	}
	if _, err = wr.Finish(t.Context(), l, finish); err != nil {
		t.Fatal("API completion replay", err)
	}
	run, err := store.GetRun(t.Context(), "lab-project", "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if run.Charged.Requests != 1 || run.Reserved != (queue.Units{}) {
		t.Fatal("API double-charged completion")
	}
}
func TestAPIPolicyValidationAndBoundedInput(t *testing.T) {
	store, server, op, _ := setupAPI(t)
	create(t, op)
	raw := testdb.Task(t, "web", "out-of-scope", "read_only")
	var document map[string]any
	_ = json.Unmarshal(raw, &document)
	target := document["target"].(map[string]any)["web"].(map[string]any)
	target["origin"] = "http://127.0.0.1:9999"
	target["seed_urls"] = []string{"http://127.0.0.1:9999/"}
	raw, _ = json.Marshal(document)
	code, _ := apiRequest(t, server, opToken, "enqueue", EnqueueRequest{raw, queue.EnqueueOptions{MaxAttempts: 1}})
	if code != 403 {
		t.Fatal("out of policy enqueue accepted", code)
	}
	r, err := store.GetRun(t.Context(), "lab-project", "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if r.TaskCount != 0 {
		t.Fatal("denied admission changed DB")
	}
	code, _ = apiRequest(t, server, opToken, "run", map[string]any{"project_id": "lab-project", "run_id": "run-test", "unexpected": true})
	if code != 400 {
		t.Fatal("unknown fields accepted")
	}
	code, body := apiRequest(t, server, opToken, "run", map[string]any{"padding": strings.Repeat("x", 4<<20)})
	if code != 413 || bytes.Contains(body, []byte("postgres")) {
		t.Fatal("body not bounded or internals leaked")
	}
	store.Close()
	code, body = apiRequest(t, server, opToken, "run", Scope{ProjectID: "lab-project", RunID: "run-test"})
	if code != 500 || string(body) != "{\"error\":\"internal_error\"}\n" {
		t.Fatalf("database failure response: %d %s", code, body)
	}
}
func TestRemoteWorkerCancellationAndBudgetSettlement(t *testing.T) {
	store, _, op, wr := setupAPI(t)
	create(t, op)
	enqueueAPI(t, op, "cancel-task")
	info, err := wr.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	w := worker.Worker{Store: wr, ProjectID: "lab-project", RunID: "run-test", WorkerID: info.Subject, HeartbeatEvery: 50 * time.Millisecond}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = w.RunOnce(ctx, func(execution context.Context, l queue.Lease) queue.Completion {
		raw, _ := json.Marshal(Scope{ProjectID: l.ProjectID, RunID: l.RunID, TaskID: l.TaskID, Reason: "cancel remotely"})
		if _, err := op.Call(ctx, "cancel", raw); err != nil {
			t.Error(err)
		}
		<-execution.Done()
		return queue.Completion{Outcome: "succeeded", Reason: "must be rejected"}
	})
	if err == nil {
		t.Fatal("remote worker published after revocation")
	}
	r, err := store.GetRun(t.Context(), "lab-project", "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Reserved != (queue.Units{}) || r.Charged.Requests != 10 {
		t.Fatal("remote cancellation accounting incorrect")
	}
}

type inspectionExecutor struct{}

func (inspectionExecutor) Execute(ctx context.Context, deadline time.Time, input runner.Input, limit int64) (json.RawMessage, error) {
	// Protocol/handler fixture only; real container isolation has its own test tag.
	raw, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = runner.InspectStream(bytes.NewReader(raw), &out)
	return out.Bytes(), err
}
func TestAPIWorkerBrokerInspectorFlow(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("synthetic health")) }))
	defer target.Close()
	store, server, op, wr := setupAPI(t, target.URL)
	create(t, op)
	raw := testdb.Task(t, "web", "full-flow", "read_only")
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	web := doc["target"].(map[string]any)["web"].(map[string]any)
	web["origin"] = target.URL
	web["seed_urls"] = []string{target.URL + "/healthz"}
	raw, _ = json.Marshal(doc)
	request, _ := json.Marshal(EnqueueRequest{raw, queue.EnqueueOptions{MaxAttempts: 2}})
	if _, err := op.Call(t.Context(), "enqueue", request); err != nil {
		t.Fatal(err)
	}
	policies := server.Config.Handler.(*Server).policies
	handler := runner.Handler{Policies: policies, Broker: policy.Broker{Policies: policies}, Executor: inspectionExecutor{}}
	w := worker.Worker{Store: wr, ProjectID: "lab-project", RunID: "run-test", WorkerID: "worker-one", HeartbeatEvery: time.Second}
	status, err := w.RunOnce(t.Context(), handler.Run)
	if err != nil || status != "succeeded" {
		t.Fatal(status, err)
	}
	request, _ = json.Marshal(Scope{ProjectID: "lab-project", RunID: "run-test", TaskID: "full-flow"})
	receipt, err := op.Call(t.Context(), "task", request)
	if err != nil {
		t.Fatal(err)
	}
	var task queue.Task
	if json.Unmarshal(receipt, &task) != nil || len(task.Result) == 0 {
		t.Fatal("API did not persist/return the inspection result")
	}
	var report runner.Report
	if json.Unmarshal(task.Result, &report) != nil || report.SecurityJudgment != "not_performed" || len(report.Responses) != 1 {
		t.Fatal("invalid inspection receipt")
	}
	r, err := store.GetRun(t.Context(), "lab-project", "run-test")
	if err != nil {
		t.Fatal(err)
	}
	if r.Charged.Requests != 1 || r.Charged.ArtifactBytes == 0 || r.Reserved != (queue.Units{}) {
		t.Fatal("end-to-end usage did not settle")
	}
}

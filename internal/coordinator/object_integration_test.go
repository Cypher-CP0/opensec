//go:build integration

package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"example.com/unified-harness/internal/checks"
	"example.com/unified-harness/internal/policy"
	"example.com/unified-harness/internal/queue"
	"example.com/unified-harness/internal/runner"
	"example.com/unified-harness/internal/targetprofile"
	"example.com/unified-harness/internal/testdb"
	"example.com/unified-harness/internal/worker"
)

func TestObjectAuthorizationFindings(t *testing.T) {
	for _, scenario := range []string{"bearer", "cookie", "api_key", "patched", "changes-before-validation", "ambiguous-json", "rate-limited", "expired-auth", "missing-control", "denied-control", "indistinct-controls", "cancelled-validation"} {
		t.Run(scenario, func(t *testing.T) {
			kind := scenario
			if kind != "cookie" && kind != "api_key" {
				kind = "bearer"
			}
			var calls atomic.Int64
			var crossReads atomic.Int64
			var repaired atomic.Bool
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				identity := ""
				switch kind {
				case "bearer":
					identity = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer fixture-secret-")
				case "cookie":
					c, err := r.Cookie("session")
					if err == nil {
						identity = strings.TrimPrefix(c.Value, "fixture-secret-")
					}
				case "api_key":
					identity = strings.TrimPrefix(r.Header.Get("X-API-Key"), "fixture-secret-")
				}
				if identity != "a" && identity != "b" {
					w.WriteHeader(401)
					return
				}
				if scenario == "expired-auth" || scenario == "missing-control" || scenario == "denied-control" {
					status := 401
					if scenario == "missing-control" {
						status = 404
					}
					if scenario == "denied-control" {
						status = 403
					}
					w.WriteHeader(status)
					return
				}
				if scenario == "rate-limited" {
					w.WriteHeader(429)
					_, _ = w.Write([]byte("DO-NOT-STORE-error"))
					return
				}
				id := strings.TrimPrefix(r.URL.Path, "/api/invoices/")
				if id != "invoice-a" && id != "invoice-b" {
					w.WriteHeader(404)
					return
				}
				if (scenario == "patched" || repaired.Load()) && identity == "a" && id == "invoice-b" {
					w.WriteHeader(404)
					return
				}
				if identity == "a" && id == "invoice-b" {
					crossReads.Add(1)
				}
				owner := "account-" + strings.TrimPrefix(id, "invoice-")
				w.Header().Set("Content-Type", "application/json")
				if scenario == "ambiguous-json" {
					_, _ = w.Write([]byte(`{"data":{"id":"invoice-a","id":"invoice-b","owner":"account-b","private":{"secret":"DO-NOT-STORE"}}}`))
					return
				}
				secret := "DO-NOT-STORE-" + id
				if scenario == "indistinct-controls" {
					secret = "DO-NOT-STORE-same"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"dynamic_time": time.Now(), "data": map[string]any{"id": id, "owner": owner, "private": map[string]string{"secret": secret}}})
			}))
			defer target.Close()
			dir := t.TempDir()
			identities := []targetprofile.Identity{}
			for _, letter := range []string{"a", "b"} {
				value := "fixture-secret-" + letter
				if kind == "cookie" {
					value = "session=" + value
				}
				name := letter + ".token"
				if err := os.WriteFile(filepath.Join(dir, name), []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
				header := ""
				if kind == "api_key" {
					header = "X-API-Key"
				}
				identities = append(identities, targetprofile.Identity{Ref: "reader-" + letter, TokenFile: name, AuthKind: kind, HeaderName: header})
			}
			plan := checks.Plan{Kind: "object_authorization", IdentityA: "reader-a", IdentityB: "reader-b", Object: &checks.ObjectCheck{
				PathTemplate: "/api/invoices/{id}", ResourceA: "invoice-a", ResourceB: "invoice-b", OwnerA: "account-a", OwnerB: "account-b",
				Response: checks.ObjectResponse{ResourceID: "/data/id", OwnerID: "/data/owner", ProtectedValue: "/data/private"},
			}}
			profile := targetprofile.Profile{SchemaVersion: 1, ProjectID: "lab-project", PolicyRef: "local-lab-v1", Origin: target.URL, DeploymentID: "invoice-api",
				CIDRs: []string{"127.0.0.1/32"}, AllowPrivate: true, Identities: identities, Checks: []targetprofile.NamedCheck{{ID: "invoice-access", Plan: plan}},
				MaxAttempts: 1, DeadlineSeconds: 300, WallSeconds: 60, ArtifactBytes: 262144}
			bundle, err := targetprofile.Prepare(t.Context(), profile, "run-test", dir, testdb.Core(), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 {
				t.Fatal("preparation contacted target")
			}
			registry, err := policy.New(t.Context(), bundle.Policies, testdb.Core())
			if err != nil {
				t.Fatal(err)
			}
			store, _, op, wr := setupAPIUsing(t, registry)
			evidenceStore(t, store)
			raw, _ := json.Marshal(bundle.Run)
			if _, err = op.Call(t.Context(), "create-run", raw); err != nil {
				t.Fatal(err)
			}
			for _, task := range bundle.Tasks {
				if _, err = op.Call(t.Context(), "enqueue", task.Enqueue); err != nil {
					t.Fatal(err)
				}
			}
			credRaw, _ := json.Marshal(bundle.Credentials)
			file := filepath.Join(dir, "credentials.json")
			if err = os.WriteFile(file, credRaw, 0600); err != nil {
				t.Fatal(err)
			}
			creds, err := policy.LoadCredentials(file)
			if err != nil {
				t.Fatal(err)
			}
			handler := runner.Handler{TrafficStore: wr, Policies: registry, Broker: policy.Broker{Policies: registry, Credentials: creds}, Executor: findingExecutor(t)}
			w := worker.Worker{Store: wr, ProjectID: "lab-project", RunID: "run-test", WorkerID: "worker-one", HeartbeatEvery: time.Second}
			// The first task performs only the two legitimate reads, even when
			// the target is vulnerable. It cannot produce a finding.
			preflightStatus, err := w.RunOnce(t.Context(), func(ctx context.Context, l queue.Lease) queue.Completion {
				c := handler.Run(ctx, l)
				if c.Evidence == nil {
					t.Error("missing preflight evidence")
					return c
				}
				forged := c
				forged.Outcome = "succeeded"
				if c.Outcome == "succeeded" {
					forged.Outcome = "failed"
				}
				if _, err := wr.Finish(ctx, l, forged); err == nil {
					t.Error("coordinator accepted inconsistent preflight outcome")
				}
				return c
			})
			failedPreflight := scenario == "ambiguous-json" || scenario == "rate-limited" || scenario == "expired-auth" || scenario == "missing-control" || scenario == "denied-control" || scenario == "indistinct-controls"
			wantStatus := "succeeded"
			if failedPreflight {
				wantStatus = "failed"
			}
			if err != nil || preflightStatus != wantStatus {
				t.Fatal(preflightStatus, err)
			}
			if len(findings(t, op).Findings) != 0 {
				t.Fatal("preflight created a finding")
			}
			preflightTask, err := store.GetTask(t.Context(), "lab-project", "run-test", bundle.Tasks[0].ID)
			if err != nil {
				t.Fatal(err)
			}
			var preflightResult map[string]string
			if err = json.Unmarshal(preflightTask.Result, &preflightResult); err != nil {
				t.Fatal(err)
			}
			preflightEvidence, err := store.GetEvidence(t.Context(), "lab-project", "run-test", preflightResult["evidence_id"])
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(preflightEvidence.Artifact), "DO-NOT-STORE") || strings.Contains(string(preflightEvidence.Artifact), "fixture-secret") {
				t.Fatal("preflight leaked data")
			}
			var preflightTranscript checks.Transcript
			if err = json.Unmarshal(preflightEvidence.Artifact, &preflightTranscript); err != nil || preflightTranscript.Version != checks.PreflightVersion {
				t.Fatal(preflightEvidence, err)
			}
			wantCalls := int64(2)
			if scenario == "rate-limited" {
				wantCalls = 1
			}
			if calls.Load() != wantCalls || crossReads.Load() != 0 {
				t.Fatal("preflight made cross-identity or extra requests", calls.Load(), crossReads.Load())
			}
			if failedPreflight {
				if _, err = wr.Claim(t.Context(), "lab-project", "run-test", "worker-one"); !errors.Is(err, queue.ErrNoWork) {
					t.Fatal("dependent hunt was claimable", err)
				}
				if _, err = store.Reap(t.Context(), "lab-project", "run-test"); err != nil {
					t.Fatal(err)
				}
				task, err := store.GetTask(t.Context(), "lab-project", "run-test", "invoice-access")
				if err != nil || task.Status != "failed" || task.Generation != 0 {
					t.Fatal(task, err)
				}
				report := runReport(t, op)
				if report.Run.Charged.Requests != wantCalls || len(report.Findings) != 0 || report.Tasks[1].FailedPrerequisites != 1 || report.Tasks[1].Verdict != "" || report.Tasks[0].EvidenceID == "" {
					t.Fatal(report)
				}
				return
			}
			execute := handler.Run
			if scenario == "bearer" {
				execute = func(ctx context.Context, l queue.Lease) queue.Completion {
					c := handler.Run(ctx, l)
					if c.Evidence == nil {
						t.Error("discovery evidence missing")
						return c
					}
					var transcript checks.Transcript
					if err := json.Unmarshal(c.Evidence.Artifact, &transcript); err != nil {
						t.Error(err)
						return c
					}
					// A worker cannot relabel this check using the legacy transcript
					// semantics and still have its result accepted.
					transcript.Version = checks.Version
					spec, _ := checks.Parse(l.Spec)
					altered := checks.NewEvidence(spec, l.AttemptID, transcript, c.Evidence.Record.ObservedAt)
					forged := c
					forged.Evidence = &altered
					verdict := checks.Evaluate(transcript)
					forged.Result, _ = json.Marshal(map[string]string{"kind": checks.ObjectVersion, "verdict": verdict.Verdict, "reason": verdict.Reason, "evidence_id": altered.Record.EvidenceID})
					if _, err := wr.Finish(ctx, l, forged); err == nil {
						t.Error("coordinator accepted mismatched transcript semantics")
					}
					return c
				}
			}
			status, err := w.RunOnce(t.Context(), execute)
			if err != nil || status != "succeeded" {
				t.Fatal(status, err)
			}
			page := findings(t, op)
			if scenario == "patched" {
				wantCalls := int64(5)
				if len(page.Findings) != 0 || calls.Load() != wantCalls {
					t.Fatal(page, calls.Load())
				}
				task, err := store.GetTask(t.Context(), "lab-project", "run-test", "invoice-access")
				if err != nil {
					t.Fatal(err)
				}
				var result map[string]string
				_ = json.Unmarshal(task.Result, &result)
				want := "not_vulnerable"
				if scenario == "ambiguous-json" || scenario == "rate-limited" {
					want = "inconclusive"
				}
				if result["verdict"] != want {
					t.Fatal(result)
				}
				return
			}
			if len(page.Findings) != 1 || page.Findings[0].Status != "pending_validation" {
				t.Fatal(page)
			}
			pendingReport := runReport(t, op)
			if pendingReport.FindingCounts["pending_validation"] != 1 || pendingReport.Run.Charged.Requests != 5 {
				t.Fatal(pendingReport)
			}
			if scenario == "cancelled-validation" {
				input, _ := json.Marshal(Scope{ProjectID: "lab-project", RunID: "run-test", TaskID: *page.Findings[0].ValidationTaskID, Reason: "test cancellation"})
				if _, err = op.Call(t.Context(), "cancel", input); err != nil {
					t.Fatal(err)
				}
				report := runReport(t, op)
				if report.FindingCounts["inconclusive"] != 1 || report.Findings[0].Status != "inconclusive" || report.Findings[0].ValidationEvidenceID != nil || calls.Load() != 5 {
					t.Fatal(report)
				}
				return
			}
			if scenario == "changes-before-validation" {
				repaired.Store(true)
			}
			status, err = w.RunOnce(t.Context(), handler.Run)
			if err != nil || status != "succeeded" {
				t.Fatal(status, err)
			}
			page = findings(t, op)
			finding := page.Findings[0]
			want := "confirmed"
			if scenario == "changes-before-validation" {
				want = "not_reproduced"
			}
			if finding.Status != want || calls.Load() != 8 || len(finding.SourceLinks) != 0 || !strings.Contains(finding.Steps[0], "/api/invoices/invoice-a") {
				t.Fatal(finding, calls.Load())
			}
			report := runReport(t, op)
			if len(report.Tasks) != 3 || len(report.Findings) != 1 || report.FindingCounts[want] != 1 || report.Findings[0].Status != want || report.Run.Charged.Requests != 8 {
				t.Fatal(report)
			}
			reportRaw, _ := json.Marshal(report)
			if strings.Contains(string(reportRaw), "DO-NOT-STORE") || strings.Contains(string(reportRaw), "fixture-secret") {
				t.Fatal("report leaked protected data")
			}
			if finding.ValidationEvidenceID == nil || *finding.ValidationEvidenceID == finding.DiscoveryEvidenceID {
				t.Fatal("replay evidence missing")
			}
			first, err := store.GetEvidence(t.Context(), "lab-project", "run-test", finding.DiscoveryEvidenceID)
			if err != nil {
				t.Fatal(err)
			}
			second, err := store.GetEvidence(t.Context(), "lab-project", "run-test", *finding.ValidationEvidenceID)
			if err != nil {
				t.Fatal(err)
			}
			if first.Record.AttemptID == second.Record.AttemptID {
				t.Fatal("reused attempt")
			}
			for _, e := range []queue.StoredEvidence{first, second} {
				raw, _ := json.Marshal(e)
				if strings.Contains(string(raw), "DO-NOT-STORE") || strings.Contains(string(raw), "fixture-secret") {
					t.Fatal("credential or protected value persisted")
				}
				if !strings.Contains(string(raw), "resource_matches") {
					t.Fatal("generic transcript missing")
				}
			}
			run, err := store.GetRun(t.Context(), "lab-project", "run-test")
			if err != nil || run.Charged.Requests != 8 || run.Reserved != (queue.Units{}) {
				t.Fatal(run, err)
			}
		})
	}
}

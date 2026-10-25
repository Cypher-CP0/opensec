# Evidence and verified tenant-isolation findings — milestone 4

For the source/model extension and current additive migration 003, see [investigator.md](investigator.md). The deterministic flow below remains supported.

This milestone detects one explicit authorization failure against the lab's export JSON contract. It needs no model: the task names two identities, their tenants and two export IDs. A model can later propose checks; execution policy, evidence binding, budgets and independent reproduction remain harness responsibilities.

The check makes three fresh GET requests, in order:

1. Identity A reads export A; its export ID, tenant and nonempty content must match the positive control.
2. Identity B reads export B; the same checks establish a second positive control.
3. Identity A requests export B. A 200 response must contain B's expected export ID and tenant, with the same content digest as the second response, to report a candidate vulnerability.

With working controls, 403 or 404 in the third response means this check did not find the issue. Missing credentials, failed controls, network failures, mismatched objects and ambiguous responses are inconclusive. A successful task means the check ran; inspect its verdict separately.

## Build and test

Run from the repository root, conventionally named opensec. Use the existing Go/Rust, PostgreSQL and Linux Docker setup from [services.md](services.md). Rebuild both binaries and the runner image because this milestone changes their protocol.

~~~sh
cd opensec
export HARNESS_POSTGRES_PASSWORD='local-dev-change-me'
export HARNESS_DATABASE_URL="postgres://harness:$HARNESS_POSTGRES_PASSWORD@127.0.0.1:55432/harness?sslmode=disable"
export HARNESS_TEST_DATABASE_URL="$HARNESS_DATABASE_URL"
docker compose up -d --wait postgres

sh scripts/check.sh
sh scripts/check-postgres.sh
sh scripts/check-postgres.sh -race

# Builds the runner, then runs the full findings integration suite with real containers.
sh scripts/check-findings.sh

# Applies migration 002 without replacing existing queue tables or records.
./bin/harness queue migrate
~~~

Use your existing database password if different. Set the database variables again in a new coordinator terminal; exported variables do not carry into independently opened shells.

The regular PostgreSQL tests exercise the real API, database, Rust contracts and HTTP lab with an in-process inspector fixture. check-findings.sh replaces that fixture with the constrained Docker runner. Neither suite silently skips missing dependencies. The PowerShell equivalent is scripts/check-findings.ps1.

## Run both lab variants

Keep each command running in its own terminal, from the repository root. Reuse lab processes already listening on these ports.

~~~sh
./bin/harness lab --variant vulnerable --listen 127.0.0.1:8081
~~~

~~~sh
./bin/harness lab --variant patched --listen 127.0.0.1:8082
~~~

## Start a fresh demonstration

In the coordinator terminal, with HARNESS_DATABASE_URL set:

~~~sh
sh scripts/prepare-finding-demo.sh tenant-demo
./bin/harness auth-init --out work/tenant-demo/auth --project lab-project --run tenant-demo

./bin/harness serve \
  --listen 127.0.0.1:8090 \
  --auth work/tenant-demo/auth/credentials.json \
  --policies examples/policies.lab.json \
  --artifacts work/artifacts
~~~

Stop the previous coordinator on port 8090 before starting this one. The demo generator refuses to overwrite a directory. For another run, choose a fresh identifier and substitute it consistently for tenant-demo. Run the generated tasks within one hour of preparation.

The generator writes only synthetic lab credentials to ignored work/ files. API operator/worker tokens are separate from the target's tenant credentials. A worker credential configuration looks like:

~~~json
[
  {
    "project_id": "lab-project",
    "policy_ref": "local-lab-v1",
    "origin": "http://127.0.0.1:8081",
    "identity_ref": "tenant-a-reader",
    "token_file": "tenant-a.token"
  }
]
~~~

Token paths are resolved relative to the credential configuration file. Tokens stay on the worker and are selected by exact project, policy, origin and identity reference. Both identities must be available before any request is sent. Public credential-bearing origins require HTTPS; literal loopback HTTP is allowed for the lab. Redirects and environment proxies remain disabled, and all existing DNS/IP policy checks apply.

In another terminal, from the repository root:

~~~sh
demo=work/tenant-demo

./bin/harness api --token-file "$demo/auth/operator.token" \
  --operation create-run --file "$demo/run.json"
./bin/harness api --token-file "$demo/auth/operator.token" \
  --operation enqueue --file "$demo/vulnerable.json"
./bin/harness api --token-file "$demo/auth/operator.token" \
  --operation enqueue --file "$demo/patched.json"

# Two discovery tasks plus one automatic validation task.
for attempt in 1 2 3; do
  ./bin/harness worker \
    --token-file "$demo/auth/worker.token" \
    --project lab-project --run tenant-demo \
    --policies examples/policies.lab.json \
    --probe-credentials "$demo/probe-credentials.json" \
    --image "$(cat work/runner-image.txt)" \
    --once || break
done

./bin/harness api --token-file "$demo/auth/operator.token" \
  --operation task --file "$demo/vulnerable-task.json"
./bin/harness api --token-file "$demo/auth/operator.token" \
  --operation task --file "$demo/patched-task.json"
./bin/harness api --token-file "$demo/auth/operator.token" \
  --operation findings --file "$demo/scope.json"
./bin/harness api --token-file "$demo/auth/operator.token" \
  --operation run --file "$demo/scope.json"
~~~

Expect a vulnerable discovery verdict, a not_vulnerable patched verdict, and exactly one confirmed finding. The finding links two different tasks, attempts and evidence records. The run should have three attempts, nine charged requests and zero outstanding reservations. If Docker, credentials or network access are unavailable, inspect the task status/verdict instead of assuming a clean scan.

## Retrieve a finding and its evidence

All retrieval uses the authenticated API with the same project/run authorization as queue reads. Both operator and worker roles can read their authorized runs.

| Operation | Request fields | Response |
| --- | --- | --- |
| findings | project_id, run_id, optional after | findings array and optional next_cursor |
| finding | project_id, run_id, finding_id | one-entry findings array |
| evidence | project_id, run_id, evidence_id | evidence record and redacted JSON artifact |

Lists return at most 100 records. Supply next_cursor as after for the next page. A missing individual record returns 404; a scope violation returns 403. Artifacts are retrieved through evidence IDs, never arbitrary filenames or naked hashes.

Copy discovery_evidence_id or validation_evidence_id from a finding into:

~~~json
{"project_id":"lab-project","run_id":"tenant-demo","evidence_id":"REPLACE_WITH_EVIDENCE_ID"}
~~~

Save that as work/tenant-demo/evidence-request.json, then:

~~~sh
./bin/harness api --token-file "$demo/auth/operator.token" \
  --operation evidence --file "$demo/evidence-request.json"

./bin/harness api --token-file "$demo/auth/operator.token" \
  --operation close --file "$demo/scope.json"
~~~

The finding includes origin, deployment, check configuration, reproduction steps, discovery/validation evidence IDs and validation state. The digest is rechecked when an artifact is read; damaged or missing blobs cause an error.

## Persistence, validation and limits

The optional task check field is part of the published Rust task schema. Its kind is tenant_isolation. Rust requires distinct identity, tenant and export identifiers, a web-capable target, hunt or validate stage, read_only retry semantics, at least three requests and at least 8192 artifact bytes. Existing tasks without check retain the inspection behavior. For a hybrid task, this check evaluates only the web portion; it does not establish source/deployment provenance.

Only the coordinator creates validation tasks. A positive discovery atomically saves its evidence, completes the attempt, creates a deduplicated candidate and queues a validation task depending on the discovery. The replay obtains a new lease and its own budget reservation, repeats all three network requests, and uses the same versioned check. It may run on the same worker host; independence here means a separate execution with fresh observations, not a different implementation or trusted third party.

A candidate starts pending_validation. A reproduced positive becomes confirmed; working controls with denied cross-tenant access become not_reproduced; failed controls or unavailable validation become inconclusive. If task capacity prevents scheduling, the candidate remains unvalidated. Budget exhaustion can leave validation queued; cancellation/deadline recovery cannot turn it into a confirmed finding. Unvalidated findings cause run closure to be partial. Finding identity is stable within a project/run/target/check, so retries or repeated discovery tasks do not duplicate it. There is no cross-run deduplication or manual promotion endpoint.

Evidence is accepted only with a live, correctly owned attempt completion. The coordinator uses the task and reservation stored in PostgreSQL, verifies the exact redacted evidence shape, invokes Rust task/evidence binding and digest verification, and recomputes the deterministic verdict. Evidence storage, finding changes, validation scheduling, completion and budget settlement commit in one database transaction. Identical completion retries use the existing receipt; conflicting retries and stale leases are rejected.

The local artifact adapter stores scoped SHA-256 objects, capped at 64 KiB per transcript, under the operator-selected private root. It writes and syncs a temporary file before publishing the object; supported Unix filesystems also sync the directory. PostgreSQL stores metadata and references. Both stores must be backed up together. A failed database transaction can leave an unreferenced blob, which is not accessible through the API. Automatic orphan collection, retention policies and an object-storage adapter remain future work. This local backend is for development; do not assume shared-filesystem or power-loss guarantees across every platform.

Stored transcripts contain response statuses, byte counts, expected-object/tenant comparison results and content digests. Raw response content, Authorization headers, cookies, and arbitrary server-provided strings are omitted before the artifact is hashed. Digests can still reveal equality and are not encryption. Source evidence and generic artifact uploads are not enabled by this first ingestion path.

The target credentials, broker, coordinator, worker and locally selected image remain trusted components. A compromised worker could fabricate observations; hashes and a second execution are not remote attestation. The Docker runner still has no network or secrets and retains the resource controls from milestone 3.

No model is configured or charged. This milestone covers one explicit export authorization contract. It does not crawl arbitrary APIs, discover account relationships, analyze source code for vulnerabilities, or conclude that a target is generally secure.

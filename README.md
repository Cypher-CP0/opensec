# OpenSec

OpenSec coordinates bounded vulnerability checks, evidence storage and fresh replay. Go runs the coordinator, workers and CLI; Rust validates versioned contracts, target policy and evidence binding. PostgreSQL persists execution and findings. A fixed Docker inspector evaluates prepared observations without network access. A separate disposable Linux/Chromium workspace lets a bounded model investigate scoped web targets through the policy checked broker.

The implemented deterministic checks cover tenant-export isolation and configurable object authorization. The web-only path also supports a bounded Claude Code investigator with browser, HTTP and shell actions; source access is optional. Source-assisted investigation remains available through the existing Claude Code adapter.

## Build and test

Use Go 1.26+, Rust/Cargo 1.85+, PostgreSQL 17 and Linux Docker with cgroup v2. Live CLI investigation and container integration run in Linux/WSL. Build both Go and Rust binaries.

~~~sh
sh scripts/check.sh

export HARNESS_TEST_DATABASE_URL="$HARNESS_DATABASE_URL"
sh scripts/check-postgres.sh -race
sh scripts/check-web.sh
sh scripts/check-web-agent.sh
~~~

The database URLs must refer to a development database. Integration tests create isolated schemas. `check-web.sh` exercises preflight, reports, configured checks, evidence and replay on synthetic targets. `check-web-agent.sh` builds the Chromium workspace and tests the scripted model loop, candidate storage, container isolation and cleanup. Neither script makes live model calls or external target requests.

For initial local database setup:

~~~sh
export HARNESS_POSTGRES_PASSWORD='choose-a-local-development-password'
docker compose up -d --wait postgres
~~~

Set HARNESS_DATABASE_URL for the coordinator and migration command. URL-encode any reserved characters in the password. The Compose service binds PostgreSQL to loopback port 55432. Keep existing passwords and volumes when continuing an installation.

~~~sh
./bin/harness queue migrate
~~~

This applies additive migration 004_target_traffic.sql, which creates shared target-admission and permit tables. Existing queue, evidence and finding records are preserved. Stop older coordinators/workers, rebuild, migrate, then restart both components. The new coordinator checks for these tables at startup.

## Prepare a web-only run

Copy examples/target.web.json to an ignored working file, then configure the target:

~~~sh
mkdir -p work/secrets
cp examples/target.web.json work/target.json
~~~

Replace the placeholder origin and documentation CIDR with the authorized origin and actual permitted destination CIDRs. Configure the two test identities, known resource IDs, endpoint template and JSON response selectors. The example cannot scan a real target unchanged.

A check has this shape:

~~~json
{
  "kind": "object_authorization",
  "identity_a_ref": "reader-a",
  "identity_b_ref": "reader-b",
  "object": {
    "path_template": "/api/invoices/{id}",
    "resource_a": "invoice-a",
    "resource_b": "invoice-b",
    "owner_a": "account-a",
    "owner_b": "account-b",
    "response": {
      "resource_id": "/data/id",
      "owner_id": "/data/account_id",
      "protected_value": "/data/details"
    }
  }
}
~~~

Selectors use JSON Pointer syntax, including nested fields, array indexes and ~0/~1 escaping. Resource/owner fields may be strings or integer identifiers. The selected protected value must contain nonempty string/object/array data, and the two positive controls must have distinct protected-data digests. Select a stable confidential field or subtree; unrelated dynamic response fields are ignored. Duplicate JSON keys, missing fields, ambiguous controls or mismatched content yield inconclusive results.

If the response does not expose ownership, omit owner_a, owner_b and response.owner_id together. The operator must still supply known resource ownership and the intended confidentiality rule. A successful HTTP status alone cannot establish a finding.

Place secrets in private worker-local files; the profile contains only file references:

| auth_kind | Secret-file content | Additional configuration |
|---|---|---|
| bearer (default) | Raw token | No header_name |
| cookie | Cookie request value, such as session=...; tenant=... | No header_name |
| api_key | Raw key | header_name, such as X-API-Key |

API-key headers must start with X-; common routing override headers are denied. Public authenticated targets require HTTPS. Credentials are scoped to project, policy, origin and identity. Login automation and refresh are not implemented.

Generate configuration in the same OS environment as the worker, because credential file references become absolute paths. Relative secret paths resolve from the input profile's directory. Preparation validates contracts and policy but does not read secrets, resolve DNS, send requests or invoke a model.

~~~sh
./bin/harness target-prepare \
  --file work/target.json --run web-pilot-1 --out work/web-pilot-1
~~~

Preparation derives GET endpoint rules from the configured check templates. The output directory must be new. It contains policies.json, probe-credentials.json, run.json, scope.json, and enqueue/task files for each check's preflight and hunt. Run capacity includes both tasks and a fresh replay for each discovery. Task deadlines begin at preparation time. Check IDs must be unique ignoring case; the preflight- prefix is reserved for generated files and task IDs.

## Endpoint scope and shared traffic controls

New target profiles use these defaults, which can be configured through the profile's traffic object:

~~~json
{"min_interval_ms": 500, "max_concurrent": 1, "backoff_seconds": 30}
~~~

PostgreSQL coordinates permits across workers and runs for the same project and canonical origin. min_interval_ms spaces admissions, max_concurrent bounds active client requests, and 429/503 responses record a shared cooldown. Error bodies are discarded and the current sequence stops immediately. Retry-After headers do not override the configured bounded cooldown. A task deadline can end a wait.

Endpoint rules allow declared methods on exact paths or one full {id} segment. Mutation methods (POST, PUT, PATCH, DELETE) and query strings require explicit rules; extra segments, dot traversal and encoded paths are rejected. The coordinator checks configured probe endpoints at admission; workers check every requested endpoint and resolved destination. The traffic API additionally checks the actual stored task and a live owned lease, so changing a caller's lease copy cannot expand scope or budget.

Permits are idempotent per logical request, expire within 15 seconds and the current lease, and bound the broker's HTTP deadline. Every granted admission consumes a request allowance, including a connection that never starts. Unknown admission/release outcomes retain conservative reservation accounting. This design assumes trusted workers use the broker; it does not meter traffic from unrelated applications.

Traffic settings persist across runs. Conflicting settings for an existing project/origin fail closed; use consistent coordinator/worker policy configuration. Legacy policies without endpoint/traffic fields retain origin/CIDR behavior. Newly prepared profiles always enable these controls. There is no operator API for relaxing persisted limits yet.

## Execute and inspect

The example profile uses project pilot-project and check invoice-access. Adjust these names if you changed the profile.

~~~sh
./bin/harness auth-init --out work/web-pilot-1/auth \
  --project pilot-project --run web-pilot-1
~~~

Start the coordinator with HARNESS_DATABASE_URL exported:

~~~sh
./bin/harness serve --listen 127.0.0.1:8090 \
  --auth work/web-pilot-1/auth/credentials.json \
  --policies work/web-pilot-1/policies.json \
  --artifacts work/artifacts
~~~

In another terminal, submit the run, preflight, then hunt (dependencies must be enqueued first):

~~~sh
./bin/harness api --token-file work/web-pilot-1/auth/operator.token \
  --operation create-run --file work/web-pilot-1/run.json

./bin/harness api --token-file work/web-pilot-1/auth/operator.token \
  --operation enqueue --file work/web-pilot-1/enqueue-preflight-invoice-access.json

./bin/harness api --token-file work/web-pilot-1/auth/operator.token \
  --operation enqueue --file work/web-pilot-1/enqueue-invoice-access.json

./bin/harness worker \
  --token-file work/web-pilot-1/auth/worker.token \
  --project pilot-project --run web-pilot-1 \
  --policies work/web-pilot-1/policies.json \
  --probe-credentials work/web-pilot-1/probe-credentials.json \
  --image "$(cat work/runner-image.txt)"
~~~

Preflight makes two legitimate reads: A reads A's resource and B reads B's resource. Both identities must establish matching resource/ownership selectors and distinct protected values. It stores redacted evidence with a ready, not_ready or inconclusive result. Only ready succeeds; the dependent hunt cannot run after a failed preflight. The recovery sweep marks that unattempted hunt failed. Authentication failure, missing/denied controls, ambiguous responses or backoff never count as a passed security check. Fix the configuration or sessions and prepare a new run.

After preflight succeeds, the hunt makes three requests: A reads A, B reads B, then A reads B. A positive discovery schedules a separately leased replay; confirmation requires fresh observations. A confirmed run normally uses eight requests (two preflight, three discovery, three replay). Keep the worker running to process replay. Preflight uses the same lease, policy, pacing, request budget and isolated inspector as other checks.

~~~sh
./bin/harness api --token-file work/web-pilot-1/auth/operator.token \
  --operation task --file work/web-pilot-1/task-preflight-invoice-access.json

./bin/harness api --token-file work/web-pilot-1/auth/operator.token \
  --operation task --file work/web-pilot-1/task-invoice-access.json

./bin/harness api --token-file work/web-pilot-1/auth/operator.token \
  --operation findings --file work/web-pilot-1/scope.json

./bin/harness api --token-file work/web-pilot-1/auth/operator.token \
  --operation run --file work/web-pilot-1/scope.json
~~~

A succeeded task means execution completed; inspect its verdict. A denied cross-identity request with working controls yields not_vulnerable for this check. During the hunt or replay, authentication failures, rate limits, missing controls and ambiguous responses are inconclusive. Preflight instead reports readiness and fails its task when the controls are not established. Confirmed findings carry discovery/replay evidence IDs and reproduction steps using the configured endpoint. Web-only findings have no source links.

## Export a run report

~~~sh
./bin/harness report --token-file work/web-pilot-1/auth/operator.token \
  --file work/web-pilot-1/scope.json --format markdown --out work/web-pilot-1/report.md

./bin/harness report --token-file work/web-pilot-1/auth/operator.token \
  --file work/web-pilot-1/scope.json --format json --out work/web-pilot-1/report.json
~~~

Reports use an authenticated, run-scoped, read-only PostgreSQL snapshot. They include aggregate task/finding counts, preflight and security verdicts with evidence IDs, reproduction steps, validation outcomes and budget charges/reservations. A failed or cancelled validation remains inconclusive. Active runs are provisional. Reports omit raw results, response bodies, headers, credentials and source/model excerpts; identifiers and reproduction URLs may still be sensitive.

Output files are private and must be new. Task details are limited to 200 rows, finding details to 100 and source evidence references to 100 per finding; truncation is explicit and aggregate counts include all rows. Retrieve additional task/finding details through the existing scoped APIs. Snapshot export does not perform target requests, DNS resolution or model calls. It adds no database migration beyond 004.

## Bounded autonomous web investigation (preview)

A scoped web investigator uses Claude Code CLI for one structured action per turn. Native CLI tools are disabled. The worker executes actions through a disposable Playwright/Chromium and Linux workspace. The container has no direct network, host mounts or credentials. Chromium keeps its own sandbox; Docker drops all capabilities except SYS_CHROOT, which Chromium needs during startup. HTTP requests from browser pages and the shell's `opensec-http` client go through the host broker, which checks method, endpoint, origin, resolved IP, identity, shared pacing and the remaining task budget. Browser contexts are separated by identity reference. Authenticated responses are redacted before the workspace or model sees them.

The model can request HTTP, navigate, inspect a page, click, fill, run bounded shell/Python commands, stop, or propose a candidate tied to observed request IDs. It cannot change scope. A write is allowed only when `allow_mutations` is true **and** the policy names that method and endpoint. Browser form submissions also require an explicit `click` action with `allow_mutation=true`; navigation, snapshots and fills cannot submit writes. Mutating tasks use one attempt and require reconciliation if execution becomes uncertain. Candidate evidence stores redacted metadata and hashes, not raw response bodies. A candidate is **not a confirmed finding**; it needs fresh independent validation.

The local example in [target.autonomous-lab.json](examples/target.autonomous-lab.json) is read-only. Set its `model.executable` to the absolute output of `command -v claude` in WSL. The synthetic lab uses disposable fixture tokens; create the files referenced by the example:

~~~sh
mkdir -p work
printf 'lab-only-token-a' > work/lab-a.token
printf 'lab-only-token-b' > work/lab-b.token
chmod 600 work/lab-*.token
./bin/harness lab --variant vulnerable --listen 127.0.0.1:8081
~~~

In another terminal, build and verify the two isolated images and prepare the run. The test script uses scripted model actions and does not call Claude:

~~~sh
export HARNESS_TEST_DATABASE_URL="$HARNESS_DATABASE_URL"
sh scripts/check-runner.sh
sh scripts/check-web-agent.sh
go build -buildvcs=false -o bin/harness ./cmd/harness
./bin/harness web-prepare --file examples/target.autonomous-lab.json --run lab-agent-1 --out work/lab-agent-1
./bin/harness auth-init --out work/lab-agent-1/auth --project lab-project --run lab-agent-1
~~~

Start the coordinator with the prepared policy and auth files:

~~~sh
./bin/harness serve --listen 127.0.0.1:8090 \
  --auth work/lab-agent-1/auth/credentials.json \
  --policies work/lab-agent-1/policies.json \
  --artifacts work/artifacts
~~~

In another terminal, create and enqueue the run, then start the worker with both immutable image IDs:

~~~sh
./bin/harness api --token-file work/lab-agent-1/auth/operator.token \
  --operation create-run --file work/lab-agent-1/run.json
./bin/harness api --token-file work/lab-agent-1/auth/operator.token \
  --operation enqueue --file work/lab-agent-1/enqueue.json
~~~



~~~sh
./bin/harness worker --project lab-project --run lab-agent-1 \
  --token-file work/lab-agent-1/auth/worker.token \
  --policies work/lab-agent-1/policies.json \
  --probe-credentials work/lab-agent-1/probe-credentials.json \
  --web-investigators work/lab-agent-1/web-investigators.json \
  --image "$(cat work/runner-image.txt)" \
  --workspace-image "$(cat work/workspace-image.txt)"
~~~

This worker makes live Claude CLI calls and scoped requests once a task is queued. Inspect `work/lab-agent-1/task.json` through the authenticated `task` API. A candidate result includes a `web_evidence_id`; the existing authenticated `evidence` API retrieves its stored trace. The `findings` API lists only separately validated findings.

## Current scope and next work

The generic check supports configured GET routes and JSON responses. Existing tenant_isolation tasks and stored evidence remain supported. The broker enforces exact origins and destination CIDRs, pins approved DNS results, refuses redirects and separates credentials from evidence.

Queued online preflight, JSON/Markdown report export and a bounded web model investigator are implemented. The browser/Linux workspace uses Docker without direct network access; every target request passes through the worker broker and shared traffic admission. Model web candidates remain unvalidated until a separate replay confirms them. OpenAPI import and browser login are subsequent work. Preparation commands remain offline. Source-only model hypotheses remain unvalidated until a supported runtime check can reproduce them.

The docs/ directory contains local design notes and is excluded from Git. Runtime examples and published schemas are under examples/ and schemas/. Neither the model nor queue infrastructure provides general vulnerability coverage without implemented checks and validation.

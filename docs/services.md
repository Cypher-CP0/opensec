# Authenticated services and isolated runner — milestone 3

Go exposes the queue through a scoped authenticated API and runs remote workers. Rust authorizes task targets and resolved network destinations. The first runner inventories source archives and bounded HTTP responses. It reports "security_judgment": "not_performed": task success means inspection completed, not that a vulnerability was found.

## Run and test in WSL

Prerequisites: the existing Go/Rust toolchains, PostgreSQL 17, and a local Docker Linux engine with cgroup v2, seccomp, and memory/swap/CPU/PID enforcement. Docker Desktop must expose its engine to your WSL distribution. The worker refuses unsupported isolation; there is no unsandboxed fallback.

The examples use `opensec`, the default directory name when cloning this repository. Run commands from the repository root; skip `cd opensec` if you are already there:

~~~sh
cd opensec

# Reuse the existing password if you already initialized this Docker volume.
export HARNESS_POSTGRES_PASSWORD='local-dev-change-me'
docker compose up -d --wait postgres
export HARNESS_DATABASE_URL="postgres://harness:$HARNESS_POSTGRES_PASSWORD@127.0.0.1:55432/harness?sslmode=disable"
export HARNESS_TEST_DATABASE_URL="$HARNESS_DATABASE_URL"

sh scripts/check.sh
sh scripts/check-postgres.sh
sh scripts/check-runner.sh

# Optional with a working C compiler:
sh scripts/check-postgres.sh -race
~~~

The ordinary checks cover Rust contracts/policy, Go packages, the lab, broker behavior, and simulated Docker lifecycle failures. PostgreSQL checks add real API/queue/worker and handler tests. The runner check builds Dockerfile.runner, records its immutable image ID in work/runner-image.txt, and tests a real container, including its in-container kernel checks and removal. Missing prerequisites fail this check instead of silently skipping it. The PowerShell equivalent is scripts/check-runner.ps1.

Changing POSTGRES_PASSWORD does not change a password already stored in an existing PostgreSQL volume. Use your existing database credentials or a separate development database. URL-encode reserved characters in connection passwords.

## Start the coordinator

Initialize tables and generate two separate random credentials:

~~~sh
./bin/harness queue migrate
./bin/harness auth-init --out work/auth --project lab-project --run queue-demo

./bin/harness serve \
  --listen 127.0.0.1:8090 \
  --auth work/auth/credentials.json \
  --policies examples/policies.lab.json
~~~

Keep this terminal running. auth-init refuses to overwrite an existing directory. It writes:

- operator.token: permits run creation, task submission, cancellation, resumption, closure and reads in the configured scope.
- worker.token: permits claiming, lease renewal, completion, recovery sweeps and reads in that scope.
- credentials.json: subjects, roles, project/run scopes and SHA-256 token hashes; no plaintext tokens.

Tokens are generated from 32 random bytes and are not printed. Files use restrictive Unix permissions and are ignored by Git. In WSL, keep credentials on a filesystem with appropriate access controls; Windows-backed mounts can have different permission semantics.

The API uses HTTP only on literal loopback addresses. A listener on any other address requires --tls-cert and --tls-key. Workers and the API CLI require HTTPS for non-loopback origins and verify certificates. --ca supplies an additional trusted CA. Redirects and environment proxies are disabled for API clients.

The credential file is loaded at startup. To rotate/revoke, prepare a replacement file and restart the coordinator. Existing workers lose authority on their next failed heartbeat. There is no OIDC, short-lived token issuer, hot reload, or public registration endpoint in this milestone.

## Start the lab and submit work

In a second terminal:

~~~sh
cd opensec
./bin/harness lab --variant patched --listen 127.0.0.1:8082
~~~

In a third terminal:

~~~sh
cd opensec

# Generates a request with current timestamps. It sends no network requests.
sh scripts/prepare-api-demo.sh

./bin/harness api --token-file work/auth/operator.token \
  --operation create-run --file examples/queue-run.json

./bin/harness api --token-file work/auth/operator.token \
  --operation enqueue --file work/api-enqueue.json

./bin/harness worker \
  --token-file work/auth/worker.token \
  --project lab-project --run queue-demo \
  --policies examples/policies.lab.json \
  --image "$(cat work/runner-image.txt)" \
  --once

./bin/harness api --token-file work/auth/operator.token \
  --operation task --file work/api-task.json

./bin/harness api --token-file work/auth/operator.token \
  --operation run --file work/api-scope.json

./bin/harness api --token-file work/auth/operator.token \
  --operation close --file work/api-scope.json
~~~

The default API URL is http://127.0.0.1:8090; --url overrides it. The worker has no database credentials configured through its CLI. The coordinator owns PostgreSQL access.

Expect task status succeeded with a result containing one HTTP response's status, byte length and digest, plus security_judgment=not_performed. Run accounting shows one request, bounded artifact bytes and elapsed attempt seconds. No response credentials or raw response body appear in that report.

Omit --once to poll continuously. Stop a process with Ctrl+C. Cancelling through the operator API revokes the lease; a worker stops on its next heartbeat and removes any active container. If a worker process is killed before cleanup, the inspector's own deadline watchdog still ends execution. A stopped container can remain for operator cleanup; list only harness containers with:

~~~sh
docker ps -a --filter label=opensec.runner=1
~~~

For repeated independent demos, use a fresh run ID in the run configuration, generated request and credentials. Replaying an unchanged request is idempotent; regenerating timestamps for an existing task ID changes its content and correctly conflicts. A closed/cancelled run cannot accept new work.

## Source and hybrid input

The worker only accepts source snapshots registered by its operator. It does not fetch arbitrary repositories, resolve mutable branches, run a build, or execute scripts supplied in a task.

Create an immutable tar snapshot from a repository commit, without placing the archive inside the committed tree:

~~~sh
git archive --format=tar --output=work/source.tar HEAD
commit=$(git rev-parse HEAD)
digest=$(sha256sum work/source.tar | cut -d ' ' -f 1)

cat > work/snapshots.json <<EOF
[
  {
    "repository_id": "lab-repository",
    "commit": "$commit",
    "snapshot_sha256": "$digest",
    "archive": "work/source.tar"
  }
]
EOF
~~~

Use examples/task.source.json or examples/task.hybrid.json as a template. Set its commit, snapshot_sha256, run_id and timestamps to the actual values, and submit it inside the same {"task": ..., "options": ...} envelope used for web tasks. Pass --snapshots work/snapshots.json to the worker. For hybrid tasks, choose an allowed running lab origin and seed URLs.

The worker matches repository ID, commit and snapshot digest against this manifest, reads a bounded regular file, and verifies its digest over the exact bytes passed to the container. The manifest's commit-to-archive association is an operator assertion. Hybrid mapping_ref also remains an assertion; this milestone does not verify a deployment's provenance.

The inspector reads tar entries without extracting them. It rejects traversal, absolute paths, backslashes, links, duplicate names, unsupported entry types, more than 512 entries, and oversized inputs. Source code is inventoried, not executed.

## API contract

Every request requires one Authorization: Bearer token header. POST bodies require Content-Type: application/json, are limited to 4 MiB, and reject unknown JSON fields. Responses use Cache-Control: no-store. The server bounds request concurrency, body/header sizes and timeouts. Internal database errors are returned without SQL or connection details.

GET /v1/info returns the authenticated subject, role and lease interval. All queue operations use POST /v1/queue/<operation>:

| Operation | Role | JSON body |
| --- | --- | --- |
| create-run | operator | Existing RunConfig |
| enqueue | operator | task and options (max_attempts, cost_microusd) |
| claim | worker | project_id, run_id |
| heartbeat | worker | lease |
| finish | worker | lease and completion |
| run | either | project_id, run_id |
| task | either | project_id, run_id, task_id |
| reap | either | project_id, run_id |
| cancel | operator | project_id, run_id, optional task_id, reason |
| resume | operator | project_id, run_id, task_id, reason, state_reconciled |
| close | operator | project_id, run_id |

The server obtains worker identity from the credential, never from a claim's caller-controlled worker ID. Heartbeat/finish additionally require that identity to match the lease and pass the database's token/generation/expiry checks. Project and run scopes apply to every operation before database work. A literal "*" in a credential's run list explicitly grants every run in that project.

Success is 200; no available work is 204. Authentication failure is 401, scope/role/policy denial 403, absent records 404, lease/conflict/budget/closed-run errors 409, oversized bodies 413, and internal failures 500. Existing lease fencing, idempotent receipts, retries and conservative unknown-usage accounting remain in force.

The task response now includes the current attempt's operational result. This is not evidence ingestion, and result JSON is not a confirmed security finding.

## Target policy and limits

examples/policies.lab.json is a deliberately narrow private lab policy. It allows only two exact loopback origins, the 127.0.0.1/32 destination prefix and lab-repository. A task must match both project_id and policy_ref. Workers repeat authorization even if someone inserted a task directly through the trusted database CLI.

For external targets, an operator supplies exact HTTP(S) origins and explicit destination CIDRs. There is no wildcard-host or unrestricted-public-network default. Private/loopback addresses require allow_private=true plus an allowed CIDR. DNS changes outside those prefixes fail closed. Link-local, known cloud metadata, transition and reserved address classes are denied even in a private lab policy.

The first HTTP broker permits GET only. It authorizes every resolved address, rejects mixed allowed/denied DNS answers, and pins an approved IP in its connection dialer. TLS still verifies the original hostname. It refuses redirects, disables environment proxies and automatic decompression, forwards no credentials, and bounds requests, headers, body bytes, DNS/connect/read times and the enclosing task deadline. Authorized GET requests can still have effects in a poorly designed target; the operator's target policy remains necessary.

The container has no network access. It receives only the prepared observations/archive on stdin, with no source-directory mount, Docker socket, credential environment variables or arbitrary command. Runtime settings are:

| Resource | Default ceiling |
| --- | --- |
| CPU | 0.5 CPU |
| Memory / swap | 128 MiB / no additional swap |
| Processes | 32 |
| Scratch /tmp | 16 MiB tmpfs, noexec/nosuid/nodev |
| Open descriptors | 64 |
| Input / output | 32 MiB / 1 MiB, further constrained by task/policy |
| Execution time | Earlier of task deadline, attempt wall allowance and five minutes |
| Privilege | UID/GID 65532, no capabilities, no-new-privileges, default seccomp |
| Filesystem/network | Read-only root, private cgroup namespace, no external network, no shared IPC |

The trusted inspector verifies its real UID, capabilities, seccomp state, network interfaces, cgroup limits and mount flags before reading input. Its internal watchdog survives loss of the host worker. The worker caps stdout/stderr and removes the container after completion, failure, overflow or cancellation. Unconfirmed execution/cleanup charges the whole reservation, rather than refunding unknown usage.

Task request and artifact allowances are enforced before/while collecting input. Half of the artifact allowance, capped at 1 MiB, is reserved for the operational report. Model token and cost consumption are zero for this fixed inspector. Budgets smaller than 512 artifact bytes cannot run it.

Docker containers share the daemon host's kernel. The operator controls the local image, worker configuration and Docker daemon; image IDs prevent tag drift but are not attestations. This boundary does not claim protection against a compromised host/daemon or kernel escape. Stronger VM isolation, arbitrary untrusted builds, browser sessions, model agents, centralized identity, evidence blob storage and independent vulnerability validation remain later work.

Docker references: [resource constraints](https://docs.docker.com/engine/containers/resource_constraints/), [network isolation](https://docs.docker.com/engine/network/drivers/none/), [container runtime options](https://docs.docker.com/reference/cli/docker/container/run/).

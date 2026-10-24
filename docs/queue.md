# PostgreSQL queue — milestone 2

The Go coordinator stores immutable Rust-validated task specifications in PostgreSQL. Source, web, and hybrid tasks share this queue. The Rust task, attempt, and evidence contracts remain unchanged. Queue tables are internal scheduling records; they are not serialized Rust TaskAttempt records.

## Start PostgreSQL and run the tests

Use PostgreSQL 17 and a dedicated development database. The test role needs CREATE SCHEMA permission. Tests create a random schema per test and drop only that schema during cleanup. Integration tests fail if the database variable is absent; they never silently skip.

PowerShell, with Docker Compose:

```powershell
$env:HARNESS_POSTGRES_PASSWORD = 'choose-a-local-development-password'
docker compose up -d --wait postgres
$env:HARNESS_DATABASE_URL = "postgres://harness:$($env:HARNESS_POSTGRES_PASSWORD)@127.0.0.1:55432/harness?sslmode=disable"
$env:HARNESS_TEST_DATABASE_URL = $env:HARNESS_DATABASE_URL
./scripts/check.ps1
./scripts/check-postgres.ps1
# Optional, with a working supported C compiler:
./scripts/check-postgres.ps1 -Race
```

The example password must be URL-encoded if it contains reserved URI characters. Set connection credentials in the environment; do not commit them. The Compose port binds only to loopback and the named volume persists data across restarts. Stop it with `docker compose stop postgres`.

In WSL/Linux/macOS, from this checkout:

```sh
export HARNESS_POSTGRES_PASSWORD='choose-a-local-development-password'
docker compose up -d --wait postgres
export HARNESS_DATABASE_URL="postgres://harness:$HARNESS_POSTGRES_PASSWORD@127.0.0.1:55432/harness?sslmode=disable"
export HARNESS_TEST_DATABASE_URL="$HARNESS_DATABASE_URL"
sh scripts/check.sh
sh scripts/check-postgres.sh
# Optional:
sh scripts/check-postgres.sh -race
```

An existing local PostgreSQL instance works too; replace the connection URL. Docker is optional. Keep PostgreSQL's normal durable commit settings enabled. TLS, role provisioning, backups, and a restricted application role belong to deployment configuration.

The normal check script builds both binaries and runs the existing contract/lab checks. The PostgreSQL check additionally runs the queue, worker, and CLI integration tests with caching disabled. It builds the Rust executable because enqueue tests invoke the real validator.

## Try the queue CLI

Run from the repository root after building. Use `bin/harness.exe` on Windows or `bin/harness` on Linux. The following PowerShell example refreshes the fixed example timestamps:

```powershell
./bin/harness.exe queue migrate
./bin/harness.exe queue create-run --file examples/queue-run.json
New-Item -ItemType Directory -Force work | Out-Null
$task = Get-Content examples/task.web.json -Raw | ConvertFrom-Json
$task.run_id = 'queue-demo'
$task.created_at = [DateTimeOffset]::UtcNow.AddSeconds(-1).ToString('o')
$task.deadline = [DateTimeOffset]::UtcNow.AddHours(1).ToString('o')
$taskPath = Join-Path (Get-Location) 'work/queue-task.json'
[IO.File]::WriteAllText($taskPath, ($task | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
./bin/harness.exe queue enqueue --file work/queue-task.json --max-attempts 3 --cost-microusd 0
$lease = ./bin/harness.exe queue claim --project lab-project --run queue-demo --worker local-worker
$leasePath = Join-Path (Get-Location) 'work/lease.json'
[IO.File]::WriteAllText($leasePath, ($lease -join [Environment]::NewLine), [Text.UTF8Encoding]::new($false))
./bin/harness.exe queue heartbeat --lease work/lease.json
./bin/harness.exe queue finish --lease work/lease.json --file examples/queue-completion.json
./bin/harness.exe queue task --project lab-project --run queue-demo --task task-lab-web
./bin/harness.exe queue run --project lab-project --run queue-demo
./bin/harness.exe queue close --project lab-project --run queue-demo
```

Finish within the default 30-second lease; heartbeat renews it up to the fixed task/attempt deadline. This example exercises bookkeeping only. It does not send HTTP traffic or confirm a vulnerability. Use a new run ID and matching task run_id for a subsequent independent run. Do not regenerate timestamps when replaying the same enqueue operation: a changed specification correctly conflicts.

Keep the lease JSON private: it contains the random capability token. Only its SHA-256 hash is stored in PostgreSQL. The CLI prints JSON to stdout and errors to stderr; errors exit nonzero. `HARNESS_CORE_BIN` or `--core` overrides the Rust binary location.

Other commands:

```text
harness queue reap --project lab-project --run queue-demo
harness queue cancel --project lab-project --run queue-demo --task task-lab-web --reason "operator stopped task"
harness queue cancel --project lab-project --run queue-demo --reason "operator stopped run"
harness queue resume --project lab-project --run queue-demo --task task-lab-web --reason "fixture reset verified" --state-reconciled
```

## Durable state and concurrency

| Table | Contents |
| --- | --- |
| harness_migrations | Applied migration version and checksum |
| queue_runs | Run status, admission limits, reserved and charged budgets |
| queue_tasks | Immutable task JSON, scheduling options, generation, deadline, status |
| queue_dependencies | Prerequisites scoped to one project/run |
| queue_attempts | Worker identity, hashed lease token, deadlines, reservations, usage, completion receipt and JSON result |
| queue_events | Transactional admission, claim, finish, cancellation, resume, recovery and close events |

Migrations execute transactionally under an advisory lock and reject changed applied SQL. There are no automatic destructive down migrations. Apply migrations explicitly before starting workers.

Every state-changing operation locks the run row first, followed by task/attempt rows. Claims use `FOR UPDATE SKIP LOCKED` and atomically reserve budget, insert an attempt, and move the task to running. Short transactions within one run are serialized for simple, reliable budget accounting; separate runs can progress concurrently. This is an MVP throughput tradeoff.

Task identity is (project_id, run_id, task_id). Re-enqueueing exactly the same normalized task and options succeeds without spending another task slot. Changed content or options conflict. Dependencies must already exist in that run, preventing cycles and forward references. A task becomes eligible only when every prerequisite succeeds.

Each claim receives a fresh attempt ID, generation, worker ID and random token. Heartbeats and completions check all of them against the database, along with database time and current generation. A stale worker cannot renew or publish after expiry, cancellation, or replacement. Worker-supplied deadlines, usage reservations and task content cannot override the database record.

A completion, its budget settlement, task transition, result and event commit together. Retrying an identical completion returns its original receipt without charging twice, including after a newer attempt starts. Changed completion payloads conflict. This is not exactly-once external execution: lost workers may already have performed external work.

## Leases, retries and cancellation

The default lease is 30 seconds. A heartbeat never extends the fixed attempt hard deadline: the earlier of the task deadline and claim time plus max_wall_seconds. Expiry checks use PostgreSQL time after acquiring locks.

Recovery sweeps settle up to 100 expired attempts per call. Read-only attempts use exponential backoff, starting at one second and capped at one minute, within their attempt limit and task deadline. Attempts classified resettable or requires_reconciliation enter needs_reconciliation after a retryable failure or lost lease. They require explicit operator reconciliation/reset before resumption.

blocked_environment remains distinct from vulnerability results. Resuming a read-only environment failure requires a reason. Resuming a reconciliation task or any potentially mutating task also requires --state-reconciled. Resumption never bypasses attempt or deadline limits.

Cancellation immediately revokes execution authority in the database, settles running attempts, and cancels queued/blocked tasks. Repeating cancellation does not double-charge usage. Already terminal tasks retain their outcome. Dependency failure and queued task deadlines are propagated by recovery sweeps; long dependency chains may need multiple sweeps.

Closing a run requires every task to be terminal. It becomes completed when all tasks succeeded, or partial when any failed or were cancelled. Whole-run cancellation remains cancelled. Budget exhaustion is a visible scheduling error; it does not turn unexecuted work into success or silently close the run.

## Budget accounting

Budgets track integer tokens, requests, aggregate attempt wall seconds, artifact bytes, and cost in millionths of one USD. Run limits also bound admitted tasks and started attempts. Each task's existing Rust budget supplies the per-attempt reservation; --cost-microusd adds its cost cap. Reservations are exposed in the lease for handlers.

The invariant for every resource is:

```text
charged + reserved <= run limit
```

Claim checks and reservation occur under the same lock. Completion reports usage bounded by the reservation, charges that usage, and releases the remainder. A missing/null usage report, expired lease, or cancelled running attempt charges the entire reservation and sets usage_uncertain. Measured zero usage must be an explicit zero-valued object. Unknown spend is never silently refunded. Retries consume new reservations and new attempt slots.

Budget units are bounded to 10^12 per resource for predictable integer accounting. Wall seconds count aggregate execution capacity across attempts, not elapsed run duration. Task deadlines separately bound real time. Task budgets apply afresh on each attempt; the run limits bound total retry spend.

The queue enforces admission and accounting. Trusted handlers must enforce request, token, artifact and cost caps before performing external actions; the queue cannot meter third-party services or stop an arbitrary process itself. Artifact bytes are accounted for, but artifact blob storage and evidence ingestion are later work. Completion JSON is limited to 1 MiB and is an operational result, not validated security evidence.

## Worker integration and remaining boundary

`internal/worker.Worker.RunOnce` claims work, maintains heartbeats, gives the handler a cancellable context with a hard deadline, and submits a completion. If renewal fails or cannot finish by the last confirmed lease expiry, it cancels the handler context and refuses its result. Handlers must honor cancellation and propagate it to network requests/processes.

`Worker.Run` polls one run and performs recovery sweeps. Use a heartbeat interval comfortably shorter than the lease (for example 5 seconds for a 30-second lease), plus a positive poll interval of at most one minute. Closed runs stop the loop. Database errors return to the caller for supervised restart. `RunOnce` users must arrange periodic `Reap` calls themselves.

The queue API is for trusted local coordinators/workers with database credentials. Project scoping prevents accidental cross-run access through this API; it is not a database tenant-security boundary. Lease tokens fence claims but do not authenticate remote callers. An authenticated service boundary, isolated runners, outbound target policy, actual model/scanner handlers, evidence blob storage, and independent finding validation remain subsequent milestones.

Tests cover all target modes, real contract validation, migration drift, durable reconnect, concurrent ownership, all budget dimensions, aggregate ledger consistency, duplicate receipts, retry limits/backoff, lease fencing, environment/reconciliation holds, cancellation races, deadline/dependency failure, worker heartbeats/cancellation/blocked renewals, and the CLI lifecycle.

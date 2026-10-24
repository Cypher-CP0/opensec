**Unified vulnerability harness — milestone 2**

Go hosts the CLI, laboratory, PostgreSQL queue, and worker lifecycle. Rust owns versioned task, attempt, and evidence contracts, semantic validation, evidence-to-task binding, and artifact digest verification. The languages communicate through a bounded, versioned JSON subprocess protocol.

This milestone adds PostgreSQL persistence, durable leases, bounded retries, cancellation, and budget accounting to the existing contracts and deterministic lab. Model/scanner handlers, execution isolation, and independent security judgment remain future work. A schema-valid evidence record is not a confirmed vulnerability.

**Build and verify from this directory.**

Prerequisites: Go 1.26 or newer; Rust 1.85 or newer with Cargo, rustfmt, and Clippy; a native linker required by the Rust toolchain. Development here was verified with Go 1.26.0 and Rust 1.98.0 on Windows. Cargo.lock pins Rust dependencies. Go uses pgx/v5 for PostgreSQL; go.mod and go.sum pin its dependencies. PostgreSQL 17 is required for queue integration tests.

On PowerShell:

```powershell
./scripts/check.ps1
```

On Linux/macOS:

```sh
sh scripts/check.sh
```

For individual commands:

```text
cargo build --locked
go build -buildvcs=false -o bin/harness ./cmd/harness
go run ./cmd/harness validate --kind task --file examples/task.web.json
go run ./cmd/harness validate --kind task --file examples/task.source.json
go run ./cmd/harness validate --kind task --file examples/task.hybrid.json
go run ./cmd/harness validate --kind evidence --file examples/evidence.http.json
```

The CLI locates the Rust executable at target/debug/harness-core (with .exe on Windows), relative to the working directory. HARNESS_CORE_BIN or --core selects a different binary. Build both executables for distribution; the Go executable alone cannot perform contract validation.

**Run the local laboratory.**

```text
go run ./cmd/harness lab --variant vulnerable --listen 127.0.0.1:8081
go run ./cmd/harness lab --variant patched --listen 127.0.0.1:8082
```

Run those commands in separate terminals. The default variant is patched. The CLI accepts literal loopback bindings only. Stop a server with Ctrl+C. Startup reloads the immutable synthetic fixture; this milestone has no mutation/reset endpoint.

Public fixture tokens:

| Identity | Tenant | Bearer token |
|---|---|---|
| tenant-a-reader | tenant-a | lab-only-token-a |
| tenant-b-reader | tenant-b | lab-only-token-b |

Routes: GET /healthz, GET /metadata, GET /exports, GET /exports/{id}. List operations return only the authenticated tenant's exports in both variants. Both variants reject missing or invalid credentials. Only the vulnerable variant omits the per-object ownership check.

Example PowerShell requests:

```powershell
$labHeaders = @{ Authorization = 'Bearer lab-only-token-a' }
Invoke-RestMethod -Uri http://127.0.0.1:8081/exports/export-a -Headers $labHeaders
Invoke-RestMethod -Uri http://127.0.0.1:8081/exports/export-b -Headers $labHeaders
Invoke-RestMethod -Uri http://127.0.0.1:8082/exports/export-b -Headers $labHeaders
```

The first two requests return their respective synthetic resources; the third returns 404. Tests check actual resource ownership/content and normal controls, not merely response codes. The seed intentionally demonstrates tenant isolation failure. It has no filesystem access, arbitrary command execution, or outbound network functionality.

Metadata reports fixture identity and digest. It does not claim the fixture digest is a source commit or a verified deployment mapping.

**The core is the contract authority.**

- crates/harness-core/src/lib.rs: types, semantic checks, evidence binding, hashing.
- crates/harness-core/src/main.rs: one bounded JSON request per process.
- schemas/: generated JSON Schemas for external consumers.
- examples/: valid contract examples for all three modes and evidence.
- internal/coreclient/: Go subprocess adapter with timeout and protocol checks.
- internal/lab/: HTTP service and regression tests.
- internal/queue/: pgx store, embedded migration, transactional scheduling and accounting.
- internal/worker/: lease-aware handler execution, heartbeats and recovery polling.
- compose.yaml: optional local PostgreSQL with persistent storage.
- fixtures/: embedded, language-independent public dataset.
- docs/: laboratory expectations, protocol, and language decision.

Regenerate schemas after an intentional contract change:

```text
cargo build --locked
go run ./cmd/harness schema --out schemas
```

Tests compare published schemas with generated Rust definitions. JSON Schema describes structure and local constraints; the compiled core additionally checks URL origins, timestamps, dependencies, lifecycle consistency, and cross-record relationships. Always call the core for authoritative validation.

Example timestamps are fixed, example source commits/digests are placeholders, and the example evidence explicitly identifies itself as synthetic. They document contracts; they are not scan findings. The example HTTP artifact has a real digest over its stored bytes.

**What the tests establish.**

Rust tests cover all mode examples, invalid versions, unknown fields, malformed origins, out-of-origin seeds, invalid budgets, invalid attempt completion, artifact references, source anchors, evidence binding, schema drift, and protocol failures.

Go tests cover normal tenant access, cross-tenant access in both variants, authentication, missing objects, concurrent identity isolation, variant metadata, mutation rejection, loopback binding, and CLI errors. Integration tests send real loopback HTTP requests, capture synthetic evidence without authorization headers, and validate/bind/hash-check that evidence through the compiled Rust binary.

This milestone does not enforce DNS/egress policy for arbitrary targets, provide a sandbox, authenticate remote workers, or assess exploitability. The CLI's loopback binding limits its own lab server exposure, not future scanner traffic.

**PostgreSQL queue:** See [docs/queue.md](docs/queue.md) for setup, CLI examples, retry and cancellation semantics, budget accounting, worker integration, and limitations. Run scripts/check-postgres.ps1 or scripts/check-postgres.sh with HARNESS_TEST_DATABASE_URL set; the ordinary checks do not exercise a database.

**Next implementation step:** authenticated coordinator/worker service boundary and an isolated runner that enforces target policy and resource limits, followed by evidence persistence and validated scanner execution.

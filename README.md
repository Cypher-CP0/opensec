**OpenSec vulnerability harness — milestone 4**

Go hosts the CLI, laboratory, PostgreSQL queue, and worker lifecycle. Rust owns versioned task, attempt, and evidence contracts, semantic validation, evidence-to-task binding, and artifact digest verification. The languages communicate through a bounded, versioned JSON subprocess protocol.

This milestone adds scoped evidence storage, authenticated probes, a deterministic tenant-isolation check, independently scheduled validation, and finding retrieval. A confirmed finding requires a positive discovery and fresh successful replay. Tasks without an explicit check still inventory inputs; general vulnerability discovery and model integration remain future work. See the [findings walkthrough](docs/findings.md) for setup, tests and a complete lab demonstration.

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
- internal/worker/: lease-aware handler execution over PostgreSQL or the API.
- internal/coordinator/: scoped bearer authentication and remote queue client/server.
- internal/policy/: Rust policy adapter, scoped target credentials and bounded HTTP broker.
- internal/artifact/: scoped local content-addressed evidence storage.
- internal/checks/: deterministic tenant check and redacted transcript format.
- internal/runner/ and cmd/inspector/: constrained Docker lifecycle and offline inspector.
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

The API authenticates scoped workers, and the runner uses a constrained container with mediated HTTP access. The explicit tenant check can reproduce one export authorization failure; it does not execute arbitrary target programs or discover general vulnerability classes. The CLI's loopback binding limits its own lab server exposure, not scanner traffic.

**PostgreSQL queue:** See [docs/queue.md](docs/queue.md) for setup, CLI examples, retry and cancellation semantics, budget accounting, worker integration, and limitations. Run scripts/check-postgres.ps1 or scripts/check-postgres.sh with HARNESS_TEST_DATABASE_URL set; the ordinary checks do not exercise a database.

**Services and isolated runner:** See [docs/services.md](docs/services.md) for a complete WSL walkthrough, API roles, policy rules, source snapshots, container limits and real Docker tests.

**Evidence and findings:** See [docs/findings.md](docs/findings.md) for the authenticated tenant check, evidence storage, independent replay, findings API and WSL demo. Run scripts/check-findings.sh for the full API/PostgreSQL/Docker integration suite.

**Next implementation step:** add a source-code analyzer using the same task/evidence boundaries, then hybrid correlation and model-driven hypothesis generation.

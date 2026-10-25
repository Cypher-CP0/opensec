**Go ↔ Rust core protocol v1**

One JSON object is read from stdin, followed by EOF. The binary writes one JSON object to stdout. Diagnostic logging must use stderr. Input is limited to 4 MiB. The Go adapter applies a ten-second process timeout and invokes a binary directly, without a shell.

Successful response: {"protocol_version":1,"ok":true,"data":{...}}, exit code 0.
Validation/protocol failure: {"protocol_version":1,"ok":false,"error":"..."}, exit code 2.

Operations:

```json
{"protocol_version":1,"operation":"schemas"}
```

```json
{"protocol_version":1,"operation":"validate","kind":"task","document":{}}
```

Kinds are task, attempt, and evidence. Empty document above is illustrative and will fail validation.

```json
{"protocol_version":1,"operation":"bind_evidence","task":{},"evidence":{}}
```

Binding checks contract validity, project/run/task/policy identity, the task time window, artifact-size allowance, and the applicable source snapshot or deployment observation. It does not look up database records, verify current lease authority, establish mapping truth, or judge a security claim. Those are separate coordinator and validation responsibilities.

```json
{"protocol_version":1,"operation":"verify_digest","sha256":"<digest>","content":"<UTF-8 artifact bytes>"}
```

The digest operation compares SHA-256 of the UTF-8 content and returns its byte count. Arbitrary binary artifacts need a later streaming/file capability rather than expanding this small control protocol. The digest operation and evidence binding are separate mechanical checks; callers must perform both when admitting an artifact.

TaskSpec is immutable requested work. TaskAttempt describes execution state separately. Evidence has no confirmed/status field. A future coordinator must verify that the referenced attempt belongs to the task and holds the current lease before accepting its evidence.

Unknown fields and unsupported protocol/schema versions are rejected. Generated JSON Schemas are structural contracts; cross-field semantic checks remain in Rust.

Milestone 3 adds three operations to protocol version 1: validate_policy accepts policy; authorize_task accepts policy and task; authorize_network accepts policy, url and addresses. Policies are strict JSON objects with policy_ref, project_id, allowed_origins, allowed_cidrs, allow_private, repository_ids and max_input_bytes. Rust performs the semantic decisions; Go resolves DNS, pins approved addresses and enforces runtime resource limits. Existing task/attempt/evidence schemas are unchanged.
Milestone 4 adds an optional `check` to the task document, currently `tenant_isolation`, with explicit identity references, tenants and export IDs. Rust validates it along with target/stage/retry/budget constraints. Rebuild coordinator, workers and runner together before submitting these tasks; older validators reject the new field. Existing tasks without `check` remain valid. Evidence uses the existing `http_sequence` contract and bind/digest operations. See [findings.md](findings.md) for the redacted transcript and independently leased validation workflow.

Milestone 5 adds optional investigator configuration (profile_ref, max_steps, exact paths and an optional probe template). Rust limits investigators to source-capable hunt tasks with read-only retry semantics and explicit budgets. Source hypotheses use the existing source_trace evidence payload. The coordinator binds and hashes artifacts before linking an investigation to an authorized discovery task. Migration 003 records these links and CLI token overage. See [investigator.md](investigator.md) for accounting and trust boundaries.

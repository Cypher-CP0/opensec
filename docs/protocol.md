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

# Bounded source investigator and hybrid findings — milestone 5

The first adapter uses a locally authenticated **Claude Code CLI**. OpenSec controls source reads, target policy, credentials, evidence and independent validation. The model can list selected files, search literal text, read up to 64 lines, propose a tenant-isolation hypothesis citing prior reads, or stop. It cannot supply commands, URLs, requests, credentials or replacement check plans.

A proposal must contain a nonempty rationale of at most 2,048 UTF-8 bytes and 1–8 distinct zero-based excerpt indexes. Every prompt supplies `available_anchor_ids`; these refer to `read_excerpts`, not source line numbers or model call numbers. The action schema descriptions and instructions state these limits. The worker independently validates them before accepting a hypothesis.

A source-only hypothesis remains unvalidated source evidence. In hybrid mode, an operator-authored `investigator.probe` permits a discovery check. A positive discovery schedules a separate replay; only a positive fresh replay confirms the finding. Web-only tasks retain their existing deterministic checks. No hypothesis never means secure.

## Scope and trust

A worker profile binds one project, target policy, repository and exact file allowlist. Tasks can select a subset and a smaller call allowance. Profiles require `allow_source_disclosure: true`: selected excerpts are sent to the configured model service and stored in scoped reports/evidence. This is not automatic secret redaction. Review selected files before enabling disclosure.

The worker verifies the registered archive's byte digest. A fixed Docker inspector parses it without extracting or executing source. Queries use the existing no-network container policy, CPU/memory/PID limits and deadline cleanup. Traversal, duplicate entries and links are rejected. Selected files must be UTF-8 text, at most 512 KiB each. Searches return at most 32 matches; reads return at most 8 KiB. File listings include line counts. A valid read of at most 64 lines clamps its end to EOF and records the actual returned range and digest. Reading past EOF at the start, requesting too many lines, or exceeding the excerpt byte limit returns bounded feedback. The model may correct up to two query mistakes per attempt; those calls still consume the original step, token, prompt and time allowances. Unselected paths, unsafe snapshots and runner failures stop the attempt.

The CLI runs in a fresh temporary directory with native tools and MCP disabled, safe mode (plus restricted mode when supported), hooks/customizations disabled, no browser and no session persistence. OpenSec does not forward database/probe credentials, API-key variables, provider overrides or Node injection variables. The CLI manages its own authentication. The installed CLI, host and administrator-managed settings remain trusted; the CLI process is not inside the offline inspector container.

Live adapter execution requires Linux/WSL for process-group cancellation. Authenticate using `claude auth login` in the same WSL account. OpenSec forces the Claude account login method. It does not use `--bare`, which disables subscription OAuth. Account limits, extra-usage settings and provider terms still apply; a subscription is not unlimited inference.

**Codex is not enabled yet.** The Go adapter interface supports adding it later. A Codex read-only filesystem sandbox alone does not provide the same tool-less boundary.

Official references: [CLI options](https://code.claude.com/docs/en/cli-reference), [programmatic execution](https://code.claude.com/docs/en/headless), [authentication](https://code.claude.com/docs/en/authentication). Workers check local CLI capabilities before claiming any task. Required controls such as safe mode, no native tools and no MCP must be supported. The extra --restricted flag is used only when advertised by the CLI; older releases such as 2.1.205 do not advertise it. Automated tests make no live model calls.

## Limits and accounting

| Resource | Enforcement |
|---|---|
| Calls | At most 12 per attempt; task/profile can lower this |
| CLI time | At most 120 seconds per call, also bounded by task deadline and lease cancellation |
| Prompt | At most 64 KiB per call, including accumulated context |
| CLI output | 256 KiB stdout and 16 KiB stderr; overflow terminates the process group |
| Report | 64 KiB; task reserves at least 256 KiB for tool outputs, report and evidence |
| Tokens | **Soft threshold**, checked after each call; reaching it stops further actions/calls |
| Requests | Existing reservation, target policy and authenticated probe limits |
| Cost | Direct API cost is zero for this subscription adapter; estimates are not invoices |

CLI usage arrives after a call. OpenSec counts reported input/output/cache-read/cache-creation tokens. A call can cross the threshold. The report retains full `reported_tokens`; `charged.tokens` contains usage up to each reservation and `model_token_overage` records the excess. Future claims subtract both. Effective recorded consumption is their sum. Concurrent calls already in flight can still finish.

Missing usage conservatively charges the token reservation and marks `usage_known` false. A structured provider failure with known usage retains that usage. Capability checks run before model invocation and do not consume a token reservation. Lost leases/crashes retain conservative settlement. This is not a hard provider-side token/spending cap. Provider failures require operator attention; queue recovery can retry a crashed read-only attempt up to `max_attempts`.

## Verify and migrate

From the repo root (conventionally `opensec`), keep the existing development database URL/password:

~~~sh
export HARNESS_TEST_DATABASE_URL="$HARNESS_DATABASE_URL"
sh scripts/check.sh
sh scripts/check-postgres.sh -race
sh scripts/check-investigator.sh
~~~

The last script uses scripted responses, PostgreSQL and real Docker. It tests source-only/hybrid behavior, vulnerable/patched controls, source-query correction and EOF reads through the real inspector, changes before replay, scope, invalid anchors, token overage, task capacity, evidence fencing and idempotency. No Claude login is needed for tests.

Stop existing coordinator/workers and use the rebuilt binary:

~~~sh
./bin/harness queue migrate
~~~

This applies **003_investigator.sql**, adding the source-investigation table and token-overage counter. Migrations 001/002 remain unchanged; existing records are preserved. Restart components with the new binaries and runner image. Do not reset the database.

## Optional live lab demo

Running the worker below consumes your CLI account allowance. Complete the scripted tests first. Choose a model supported by your account (the example uses the `sonnet` alias):

~~~sh
claude auth login
go run ./cmd/prepare-investigator-demo --run investigator-demo --model sonnet
./bin/harness auth-init --out work/investigator-demo/auth \
  --project lab-project --run investigator-demo
./bin/harness investigator-check --profiles work/investigator-demo/investigators.json
~~~

Preparation sends no requests. It archives `internal/lab/lab.go` from the current commit, records the real archive digest, and creates scoped synthetic credentials and two hybrid tasks. It rejects uncommitted changes to that source file. Review `work/investigator-demo/investigators.json`. Generated files remain under ignored `work/`.

Run each lab in a separate terminal:

~~~sh
./bin/harness lab --variant vulnerable --listen 127.0.0.1:8081
~~~
~~~sh
./bin/harness lab --variant patched --listen 127.0.0.1:8082
~~~

Start the coordinator in another terminal with `HARNESS_DATABASE_URL` exported:

~~~sh
./bin/harness serve --listen 127.0.0.1:8090 \
  --auth work/investigator-demo/auth/credentials.json \
  --policies examples/policies.lab.json --artifacts work/artifacts
~~~

Create the run and enqueue:

~~~sh
./bin/harness api --token-file work/investigator-demo/auth/operator.token \
  --operation create-run --file work/investigator-demo/run.json
./bin/harness api --token-file work/investigator-demo/auth/operator.token \
  --operation enqueue --file work/investigator-demo/vulnerable.json
~~~

This worker invokes Claude Code and then polls for any scheduled discovery/replay:

~~~sh
./bin/harness worker \
  --token-file work/investigator-demo/auth/worker.token \
  --project lab-project --run investigator-demo \
  --policies examples/policies.lab.json \
  --snapshots work/investigator-demo/snapshots.json \
  --investigators work/investigator-demo/investigators.json \
  --probe-credentials work/investigator-demo/probe-credentials.json \
  --image "$(cat work/runner-image.txt)"
~~~

Query progress in another terminal:

~~~sh
./bin/harness api --token-file work/investigator-demo/auth/operator.token \
  --operation task --file work/investigator-demo/vulnerable-task.json
./bin/harness api --token-file work/investigator-demo/auth/operator.token \
  --operation investigation --file work/investigator-demo/vulnerable-task.json
./bin/harness api --token-file work/investigator-demo/auth/operator.token \
  --operation findings --file work/investigator-demo/scope.json
./bin/harness api --token-file work/investigator-demo/auth/operator.token \
  --operation run --file work/investigator-demo/scope.json
~~~

`investigation` returns the latest committed report, source tuple/evidence ID, probe task ID/status and scheduling reason. Before a report commits it returns not-found; use `task` for running/blocked state. Query the returned probe task ID with `task` for its deterministic verdict. Use the returned source evidence ID with the existing scoped `evidence` operation (a JSON request containing project_id, run_id and evidence_id).

Enqueue `patched.json` for the negative control, then query `patched-task.json`. A live model may stop, exhaust limits or fail to propose a hypothesis. No finding is not a successful negative control unless a deterministic probe actually ran and its verdict was inspected.

Hybrid findings include `source_links` with evidence ID, repository/commit/snapshot, line anchors and `mapping_status: operator_asserted_unverified`. These explain a candidate cause; runtime replay proves behavior, not the deployed commit. Retrieval includes up to 100 source links per finding.

Source-only tasks use `target.mode: source` and omit `investigator.probe`; they never schedule web requests. Close finished runs with `close`, cancelling pending work first if budgets block further claims. A hybrid hypothesis whose required probe could not be scheduled makes the closed run partial.


## Diagnosing a source-tool failure

An investigation can fail after successful model calls but before any runtime probe. In that case an empty findings list does not establish safety.

New reports include a bounded `tool_events` list: model call number, query kind, selected path, requested line range, fixed result code and available line count. Search text, invented paths and raw process errors are excluded. A successful read's excerpt contains its actual range. Terminal tool failures also append the last code to `task.last_reason`.

| Code | Behavior |
|---|---|
| invalid_query | Correct the fields for the selected action |
| read_range_too_large | Request at most 64 lines |
| read_start_past_eof | Use the returned line count; empty files have no readable lines |
| excerpt_too_large | Request fewer lines, within 8 KiB |
| path_not_allowed | Terminal; the path is outside the operator's selection |
| invalid_snapshot / selected_file_unavailable / unsupported_source_file | Terminal; check the registered source archive |
| runner_failed / runner_report_invalid | Terminal; check the runner and matching worker/image versions |
| source_allowance_exhausted | Terminal; the remaining artifact allowance cannot support another query |

Only the first four codes permit correction, at most twice per attempt. The third failed query stops with `tool_error`. The remaining budgets may stop the loop sooner.

Older reports without `tool_events` cannot reveal which query failed. For example, versions before this fix rejected reads whose end extended past EOF even when the start and requested size were valid. That failure can be reproduced, but an old generic `tool_error` alone does not prove it was the cause.

After updating, rebuild the harness and runner image, then restart both coordinator and worker. `sh scripts/check-investigator.sh` rebuilds and tests the runner; `go build -buildvcs=false -o bin/harness ./cmd/harness` rebuilds the harness. No additional migration is needed for these JSON diagnostic fields. Run the scripted checks before spending more live model calls. A failed demo task has exhausted its one attempt; use a new demo run ID to retry after verification.

## Diagnosing a blocked CLI task

### Rejected actions after successful source reads

`invalid_action` means the loop rejected an action or hypothesis after decoding it. New reports include a fixed `action_error`, also appended to `task.last_reason`. Rejected text, paths and anchor values are not persisted. These errors are terminal and consume the calls/tokens already used; they do not grant additional corrections or attempts.

| Code | Meaning |
|---|---|
| unused_action_fields / unexpected_anchors | The action populated fields that must be empty or zero |
| empty_rationale / rationale_too_large | The proposal needs a nonblank rationale of at most 2,048 UTF-8 bytes |
| invalid_anchor_count | A proposal must cite 1–8 excerpts |
| unread_anchor / repeated_anchor | Anchor indexes must be distinct and refer to previously read excerpts |
| unsupported_action / unsupported_hypothesis | The action or hypothesis kind is outside the contract |
| invalid_configuration / invalid_report | Check the worker configuration and report validation |

The existing `investigator-demo-3` attempt failed on its fourth call after successful listing and two reads (lines 1–64 and 65–119). It reported 12,144 tokens and made no runtime probe requests. Its older report contains only `invalid_action`, so the exact rejected field cannot be recovered. The missing proposal limits in the earlier model instructions were a reproducible contract gap, not proof of that attempt's precise cause. Existing reports remain readable; the optional diagnostic field needs no migration.

### CLI capability and provider errors

The local capability check invokes only help. It does not verify your account or contact a model:

~~~sh
./bin/harness investigator-check --profiles work/investigator-demo/investigators.json
~~~

A successful result contains `"model_calls": 0`. Missing mandatory flags stop the worker before claiming a task. On CLI versions without `--restricted`, the adapter retains the required safe-mode, no-tools, no-MCP and disabled-settings controls.

After a model invocation, `task.last_reason` and `investigation.report.provider_error` contain a fixed diagnostic code. Raw CLI stdout/stderr, prompts and account details are never stored in the error field:

| Code | Meaning |
|---|---|
| unsupported_cli_flags | Required controls are missing, or the CLI rejected an argument |
| cli_auth_required | The provider reported that authentication is needed |
| cli_rate_limited | The provider reported a usage/rate limit |
| cli_timeout / cli_cancelled | The deadline or cancellation stopped the CLI |
| cli_output_limit | CLI output exceeded the bounded buffers |
| cli_turn_limit | The CLI stopped at its internal turn limit |
| cli_missing_structured_output / cli_invalid_action | The result did not satisfy the action contract |
| cli_usage_missing | Usage was absent or invalid |
| cli_exit / cli_invalid_response | The CLI failed without a recognized structured error |

These are classifications, not raw provider messages. A capability check passing does not guarantee account access, model availability or successful inference.

The demo uses `max_attempts: 1`. After its first blocked attempt, re-enqueueing the same task is idempotent and `resume` cannot exceed the attempt limit. Use a fresh demo run ID (for example `investigator-demo-2`), generate its credentials, and restart the coordinator/worker with that directory. Existing blocked records and conservative charges remain intact; no database reset or additional migration is needed for this adapter fix.

When copying terminal commands, copy only the command lines inside a code block. Markdown fence markers such as `~~~` are not shell commands.

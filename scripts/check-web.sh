#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${HARNESS_TEST_DATABASE_URL:?Set HARNESS_TEST_DATABASE_URL to a development PostgreSQL database}"
cargo build --locked
sh scripts/check-runner.sh
HARNESS_TEST_RUNNER_IMAGE=$(cat work/runner-image.txt)
export HARNESS_TEST_RUNNER_IMAGE
go vet -tags=integration,container ./...
go test -count=1 ./internal/checks ./internal/targetprofile ./internal/policy ./cmd/harness
go test -tags=integration -run 'TestTraffic|TestReport' -count=1 ./internal/queue
go test -tags=integration,container -run 'TestReport|TestTraffic|TestObjectAuthorization|TestTenant|TestInvestigator|TestEvidence' -count=1 -timeout=5m ./internal/coordinator
printf '%s\n' 'Web preflight, configurable authorization, reports, traffic controls and fresh replay passed with PostgreSQL and real Docker. No model calls or external target requests were made.'

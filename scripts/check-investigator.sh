#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${HARNESS_TEST_DATABASE_URL:?Set HARNESS_TEST_DATABASE_URL to a development PostgreSQL database}"
cargo build --locked
sh scripts/check-runner.sh
HARNESS_TEST_RUNNER_IMAGE=$(cat work/runner-image.txt)
export HARNESS_TEST_RUNNER_IMAGE
go vet -tags=integration,container ./internal/coordinator
go test -count=1 ./internal/investigator
go test -tags=integration,container -run 'TestInvestigator|TestTenant|TestEvidence' -count=1 -timeout=5m ./internal/coordinator
printf '%s\n' 'Source investigation, evidence links, bounded accounting and independent replay passed with scripted models, PostgreSQL and real Docker.'

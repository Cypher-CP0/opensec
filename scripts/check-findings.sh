#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${HARNESS_TEST_DATABASE_URL:?Set HARNESS_TEST_DATABASE_URL to a development PostgreSQL database}"
cargo build --locked
sh scripts/check-runner.sh
HARNESS_TEST_RUNNER_IMAGE=$(cat work/runner-image.txt)
export HARNESS_TEST_RUNNER_IMAGE
go vet -tags=integration,container ./internal/coordinator
go test -tags=integration,container -run 'TestTenant|TestEvidence' -count=1 -timeout=3m ./internal/coordinator
printf '%s\n' 'Authenticated probes, evidence, replay and findings passed against PostgreSQL and real Docker.'

#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${HARNESS_TEST_DATABASE_URL:?Set HARNESS_TEST_DATABASE_URL to a development PostgreSQL database}"
cargo build --locked
go vet -tags=integration ./...
# Use: sh scripts/check-postgres.sh -race (requires a supported C compiler).
go test -tags=integration -count=1 -timeout=3m "$@" ./...
printf '%s\n' 'PostgreSQL queue and worker tests passed.'

#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${HARNESS_TEST_DATABASE_URL:?Set HARNESS_TEST_DATABASE_URL to a development PostgreSQL database}"
command -v docker >/dev/null || { printf '%s\n' 'Docker is required for workspace tests.' >&2; exit 1; }
cargo build --locked
go test -count=1 ./internal/webinvestigator ./internal/webprofile
go test -tags=integration -run '^TestWebCandidateIsStoredButNotPromotedToFinding$|^TestMutationTrafficPermitBindsMethodAndSingleAttempt$' -count=1 ./internal/coordinator
docker build -f Dockerfile.workspace -t opensec-workspace:local .
HARNESS_TEST_WORKSPACE_IMAGE=$(docker image inspect opensec-workspace:local --format '{{.Id}}')
export HARNESS_TEST_WORKSPACE_IMAGE
mkdir -p work
printf '%s\n' "$HARNESS_TEST_WORKSPACE_IMAGE" > work/workspace-image.txt
go test -tags=container -run '^TestRealWorkspace' -count=1 -timeout=3m ./internal/runner
printf '%s\n' 'Web model loop, candidate persistence, browser isolation and cleanup passed. No live model calls were made.'

#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
command -v docker >/dev/null || { printf '%s\n' 'Docker is required for real container tests.' >&2; exit 1; }
docker build -f Dockerfile.runner -t opensec-runner:local .
HARNESS_TEST_RUNNER_IMAGE=$(docker image inspect opensec-runner:local --format '{{.Id}}')
export HARNESS_TEST_RUNNER_IMAGE
mkdir -p work
printf '%s\n' "$HARNESS_TEST_RUNNER_IMAGE" > work/runner-image.txt
go vet -tags=container ./internal/runner
go test -tags=container -run TestRealDocker -count=1 -timeout=90s ./internal/runner
printf '%s\n' 'Real Docker isolation and cleanup checks passed.'

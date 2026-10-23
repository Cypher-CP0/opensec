#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
cargo fmt --all -- --check
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
unformatted=$(gofmt -l cmd internal fixtures)
test -z "$unformatted" || { printf '%s\n' "$unformatted"; exit 1; }
go vet ./...
go test ./...
mkdir -p bin
go build -buildvcs=false -o bin/harness ./cmd/harness
printf '%s\n' 'All milestone checks passed.'

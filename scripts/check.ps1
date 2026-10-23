$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) { throw 'Rust formatting failed' }
    cargo build --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust build failed' }
    cargo test --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust tests failed' }
    cargo clippy --locked --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Rust lint failed' }
    $unformatted = gofmt -l cmd internal fixtures
    if ($LASTEXITCODE -ne 0 -or $unformatted) { throw "Go formatting failed: $unformatted" }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go vet failed' }
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
    New-Item -ItemType Directory -Force -Path bin | Out-Null
    go build -buildvcs=false -o bin/harness.exe ./cmd/harness
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed' }
    Write-Output 'All milestone checks passed.'
} finally {
    Pop-Location
}

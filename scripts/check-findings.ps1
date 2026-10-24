$ErrorActionPreference = 'Stop'
if (-not $env:HARNESS_TEST_DATABASE_URL) { throw 'HARNESS_TEST_DATABASE_URL is required.' }
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    cargo build --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust build failed' }
    & ./scripts/check-runner.ps1
    $env:HARNESS_TEST_RUNNER_IMAGE = (Get-Content work/runner-image.txt -Raw).Trim()
    go vet '-tags=integration,container' ./internal/coordinator
    if ($LASTEXITCODE -ne 0) { throw 'Findings integration vet failed' }
    go test '-tags=integration,container' -run 'TestTenant|TestEvidence' -count=1 -timeout=3m ./internal/coordinator
    if ($LASTEXITCODE -ne 0) { throw 'Real findings integration tests failed' }
    Write-Output 'Authenticated probes, evidence, replay and findings passed against PostgreSQL and real Docker.'
} finally { Pop-Location }

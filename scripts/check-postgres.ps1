param([switch]$Race)
$ErrorActionPreference = 'Stop'
if (-not $env:HARNESS_TEST_DATABASE_URL) { throw 'Set HARNESS_TEST_DATABASE_URL to a development PostgreSQL database before running queue tests.' }
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    cargo build --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust build failed' }
    go vet -tags=integration ./...
    if ($LASTEXITCODE -ne 0) { throw 'Go integration vet failed' }
    $testFlags = @('test', '-tags=integration', '-count=1', '-timeout=3m')
    if ($Race) { $testFlags += '-race' }
    & go @testFlags ./...
    if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL integration tests failed' }
    Write-Output 'PostgreSQL queue and worker tests passed.'
} finally {
    Pop-Location
}

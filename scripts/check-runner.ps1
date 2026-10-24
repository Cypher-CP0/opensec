$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    docker build -f Dockerfile.runner -t opensec-runner:local .
    if ($LASTEXITCODE -ne 0) { throw 'Runner image build failed' }
    $env:HARNESS_TEST_RUNNER_IMAGE = docker image inspect opensec-runner:local --format '{{.Id}}'
    if ($LASTEXITCODE -ne 0) { throw 'Runner image lookup failed' }
    New-Item -ItemType Directory -Force work | Out-Null
    [IO.File]::WriteAllText((Join-Path $projectRoot 'work/runner-image.txt'), $env:HARNESS_TEST_RUNNER_IMAGE, [Text.UTF8Encoding]::new($false))
    go vet -tags=container ./internal/runner
    if ($LASTEXITCODE -ne 0) { throw 'Runner vet failed' }
    go test -tags=container -run TestRealDocker -count=1 -timeout=90s ./internal/runner
    if ($LASTEXITCODE -ne 0) { throw 'Real container checks failed' }
    Write-Output 'Real Docker isolation and cleanup checks passed.'
} finally { Pop-Location }

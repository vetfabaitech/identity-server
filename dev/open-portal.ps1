<#
.SYNOPSIS
  Starts everything the developer portal needs locally and opens it in your browser.

.DESCRIPTION
  Postgres (docker) -> migrations -> a dev administrator -> the identity service on :8200 -> the portal in your browser.
  Safe to run again: it reuses what is already up. Local development only (throwaway database, public dev credentials).

.EXAMPLE
  .\dev\open-portal.ps1          # start (if needed) and open http://localhost:8200/developer/services
  .\dev\open-portal.ps1 -Stop    # stop the identity service this script started
#>
param([switch]$Stop, [switch]$NoBrowser)

# Native tools (docker, alembic) write progress to stderr, which Windows PowerShell 5.1 would treat as an error under
# "Stop"; every step below checks its exit code explicitly instead.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo
$url = "http://localhost:8200/developer/services"
$pidFile = Join-Path $repo ".dev-portal.pid"
$logFile = Join-Path $repo ".dev-portal.log"

if ($Stop) {
    if (Test-Path $pidFile) {
        Stop-Process -Id (Get-Content $pidFile) -Force -ErrorAction SilentlyContinue
        Remove-Item $pidFile
        Write-Host "Stopped the identity service."
    } else { Write-Host "Nothing started by this script is running." }
    return
}

# Everything the identity service reads, for a local development run. The service's own origin is a return origin so the
# portal's sign-in can come back to it.
$env:IDENTITY_ENVIRONMENT = "development"
$env:IDENTITY_DATABASE_URL = "postgresql://identity:identity-local-only@127.0.0.1:54331/identity"
$env:IDENTITY_ISSUER = "http://localhost:8200/auth"
$env:IDENTITY_AUDIENCE = "vetfab"
$env:IDENTITY_APP_ORIGINS = "http://localhost:8200"
$env:IDENTITY_KEYS_DIR = Join-Path $repo ".dev-keys"
$env:IDENTITY_REGISTRY_REFRESH_SECONDS = "1"

# GitHub / Google sign-in: if deploy/.env (gitignored) has provider credentials, use them so the buttons appear locally.
# The provider app must list http://localhost:8200/auth/oauth/<provider>/callback as a callback URL for this to work.
$envFile = Join-Path $repo "deploy\.env"
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if ($line -match '^(GITHUB|GOOGLE)_CLIENT_(ID|SECRET)=(.+)$') {
            Set-Item -Path "env:IDENTITY_$($Matches[1])_CLIENT_$($Matches[2])" -Value $Matches[3].Trim()
        }
    }
}

function Test-Port([int]$port) { [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue) }

# 1. Docker and Postgres
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Starting Docker Desktop..."
    Start-Process "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    for ($i = 0; $i -lt 60; $i++) { Start-Sleep 3; docker info *> $null; if ($LASTEXITCODE -eq 0) { break } }
    if ($LASTEXITCODE -ne 0) { throw "Docker did not start. Start Docker Desktop and run this again." }
}
docker compose -f dev/docker-compose.yml up -d *> $null
for ($i = 0; $i -lt 30; $i++) {
    docker compose -f dev/docker-compose.yml exec -T postgres pg_isready *> $null
    if ($LASTEXITCODE -eq 0) { break }
    Start-Sleep 2
}
if ($LASTEXITCODE -ne 0) { throw "Postgres did not become ready." }

# 2. Python environment, schema, administrator
if (-not (Test-Path ".venv\Scripts\python.exe")) { python -m uv sync | Out-Null }
$py = Join-Path $repo ".venv\Scripts\python.exe"
& $py -m alembic upgrade head 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Migrations failed (run: python -m uv run alembic upgrade head)." }
$env:PYTHONPATH = $repo
& $py dev\portal_dev.py seed

# 3. The identity service
if (Test-Port 8200) {
    Write-Host "Something is already listening on :8200; using it."
} else {
    $proc = Start-Process -FilePath $py -ArgumentList "dev\portal_dev.py", "serve" -WorkingDirectory $repo `
        -WindowStyle Hidden -PassThru -RedirectStandardOutput $logFile -RedirectStandardError "$logFile.err"
    $proc.Id | Set-Content $pidFile
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep 0.5
        try { if ((Invoke-WebRequest "http://localhost:8200/auth/health" -UseBasicParsing -TimeoutSec 2).StatusCode -eq 200) { break } } catch {}
    }
    if (-not (Test-Port 8200)) { throw "The identity service did not start. See $logFile.err" }
}

Write-Host ""
Write-Host "Developer portal: $url"
Write-Host "Sign in with:     admin@dev.vetfab.local / correct horse battery"
Write-Host "Stop with:        .\dev\open-portal.ps1 -Stop"
if (-not $NoBrowser) { Start-Process $url }

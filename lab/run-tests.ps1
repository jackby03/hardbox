# hardbox Testing Lab — Vagrant-powered automation
#
# Prerequisites:
#   1. VirtualBox + Vagrant installed
#   2. Run this from the project root
#
# Usage:
#   .\lab\run-tests.ps1              # Full run: compile + test
#   .\lab\run-tests.ps1 -SkipBuild   # Skip compilation (use existing binary)
#   .\lab\run-tests.ps1 -Clean       # Destroy VM after run (fresh start next time)
#   .\lab\run-tests.ps1 -Destroy     # Tear down VM completely

param(
    [switch]$SkipBuild,
    [switch]$Clean,
    [switch]$Destroy
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

function Write-Step { Write-Host "`n>>> " -NoNewline -ForegroundColor Cyan; Write-Host $args[0] }
function Write-Ok   { Write-Host "  " -NoNewline; Write-Host $args[0] -ForegroundColor Green }

# ── 0. teardown if requested ──────────────────────────────────────────

if ($Destroy) {
    Write-Step "Destroying VM..."
    Push-Location $scriptDir
    vagrant destroy -f
    Pop-Location
    Write-Ok "VM destroyed. Run again without -Destroy to recreate."
    exit 0
}

# ── 1. start / create VM ──────────────────────────────────────────────

Write-Step "Starting VM (Vagrant)"
Push-Location $scriptDir
try {
    vagrant up 2>&1 | Select-Object -Last 3
    Write-Ok "VM is running at 192.168.56.50"
} catch {
    Write-Host "ERROR: vagrant up failed. Is VirtualBox installed?" -ForegroundColor Red
    Pop-Location
    exit 1
}
Pop-Location

# ── 2. cross-compile ──────────────────────────────────────────────────

if (-not $SkipBuild) {
    Write-Step "Cross-compiling hardbox for Linux amd64"
    Push-Location $projectRoot
    $env:GOOS = "linux"; $env:GOARCH = "amd64"; $env:CGO_ENABLED = "0"
    go build -ldflags="-s -w" -o "$scriptDir\hardbox" .\cmd\hardbox
    if ($LASTEXITCODE -ne 0) { throw "go build failed" }
    Pop-Location
    Write-Ok "Binary: lab/hardbox ($((Get-Item "$scriptDir\hardbox").Length) bytes)"
} else {
    if (-not (Test-Path "$scriptDir\hardbox")) {
        Write-Host "ERROR: No binary at lab/hardbox. Run without -SkipBuild first." -ForegroundColor Red
        exit 1
    }
}

# ── 3. run test suite ─────────────────────────────────────────────────

Write-Step "Running test suite inside VM"
Push-Location $scriptDir
vagrant ssh -c "sudo bash /vagrant/test-suite.sh" 2>&1 | ForEach-Object {
    $line = $_
    Write-Host $line
    $line
} | Set-Content -Path "$scriptDir\last-results.txt"
Pop-Location

# ── 4. optional cleanup ───────────────────────────────────────────────

if ($Clean) {
    Write-Step "Cleaning up VM..."
    Push-Location $scriptDir
    vagrant destroy -f
    Pop-Location
    Write-Ok "VM destroyed"
} else {
    Write-Host "`nVM kept alive. Use -Clean to destroy after run." -ForegroundColor DarkGray
}

Write-Host "`nResults saved: lab/last-results.txt" -ForegroundColor Cyan

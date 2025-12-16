# ============================================
# T1003.001 - LSASS Memory Dump (DEMO VERSION)
# ============================================
# This script simulates credential dumping attack
# Safe for demo - creates fake dump file
# ============================================

Write-Host "`n[ATTACK] T1003.001 - OS Credential Dumping: LSASS Memory" -ForegroundColor Red
Write-Host "============================================`n" -ForegroundColor Red

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[WARN] Not running as Administrator — continuing in demo mode" -ForegroundColor Yellow
}

Write-Host "[PHASE 1] Locating LSASS process..." -ForegroundColor Cyan
$lsassProcess = Get-Process lsass -ErrorAction SilentlyContinue

if ($lsassProcess) {
    Write-Host "[SUCCESS] LSASS found - PID: $($lsassProcess.Id)" -ForegroundColor Green
} else {
    Write-Host "[WARN] Cannot locate LSASS process, continuing in demo mode" -ForegroundColor Yellow
}

# Create output directory
$outputDir = "$env:TEMP\MultiKG_Demo"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

Write-Host "`n[PHASE 2] Simulating memory dump..." -ForegroundColor Cyan
Write-Host "[INFO] Output: $outputDir\lsass.dmp" -ForegroundColor Gray

# Simulate technique by launching a benign process whose command-line
# contains the keywords the detector looks for (e.g. "procdump" and "lsass").
Write-Host "[SIMULATION] Spawning benign process with detection keywords" -ForegroundColor Yellow

$dumpFile = "$outputDir\lsass.dmp"

try {
    # Create a small fake dump file (harmless)
    $fakeContent = "FAKE_LSASS_DUMP_FOR_DEMO_" * 100
    Set-Content -Path $dumpFile -Value $fakeContent -Force

    # Build a simple cmd.exe invocation that includes the keywords.
    $filePath = Join-Path $outputDir 'lsass_sim_cmd.txt'
    $quotedPath = '"' + $filePath + '"'
    $cmdText = "/c echo Simulating LSASS dump & echo procdump -ma lsass > $quotedPath"

    Start-Process -FilePath (Join-Path $env:WINDIR 'system32\cmd.exe') -ArgumentList $cmdText -WindowStyle Hidden

    Write-Host "[SUCCESS] Fake dump created: $dumpFile" -ForegroundColor Green
    Write-Host "[INFO] Spawned cmd.exe with arguments containing procdump and lsass" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Simulation failed: $_" -ForegroundColor Red
}

Write-Host "`n[PHASE 3] Post-dump operations..." -ForegroundColor Cyan

# Simulate exfiltration preparation
Write-Host "[INFO] Compressing dump file..." -ForegroundColor Gray
$zipFile = "$outputDir\credentials.zip"

try {
    Compress-Archive -Path $dumpFile -DestinationPath $zipFile -Force
    Write-Host "[SUCCESS] Compressed: $zipFile" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Compression failed" -ForegroundColor Yellow
}

Write-Host "`n[ATTACK COMPLETE]" -ForegroundColor Red
Write-Host "Artifacts created in: $outputDir" -ForegroundColor Gray
Write-Host "`n[DETECTION SYSTEM] Should detect this activity within 30 seconds..." -ForegroundColor Cyan

# Cleanup prompt
Write-Host "`nPress any key to cleanup artifacts..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Remove-Item -Path $outputDir -Recurse -Force
Write-Host "[CLEANUP] Artifacts removed" -ForegroundColor Green

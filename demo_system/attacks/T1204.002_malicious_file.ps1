# T1204.002 - User Execution: Malicious File (SAFE DEMO)
# Simulates malicious document execution - SAFE version

Write-Host "=== T1204.002 - Malicious File Execution Simulation ===" -ForegroundColor Cyan
Write-Host "[SAFE DEMO] This simulates malicious document behavior safely" -ForegroundColor Yellow

# Simulate Office spawning PowerShell (common malware behavior)
Write-Host "`n[1/4] Simulating document-based execution chain..." -ForegroundColor Green

# Create a harmless VBS that simulates macro behavior
$vbsContent = @'
' SAFE DEMO - Simulates malicious macro
WScript.Echo "T1204.002 Demo - Simulating macro execution"
WScript.Sleep 500
'@

$vbsFile = "$env:TEMP\demo_macro_$((Get-Date).ToString('yyyyMMddHHmmss')).vbs"
$vbsContent | Out-File $vbsFile -Encoding ASCII

Write-Host "[2/4] Executing simulated macro script..." -ForegroundColor Green
Write-Host "[2/4] Executing simulated macro script..." -ForegroundColor Green
# Run the VBS under a persistent cmd so Sysmon records a stable CommandLine entry.
# Use /k so the cmd process holds the command and stays alive briefly.
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\cmd.exe') -ArgumentList '/k',"cscript //nologo `"$vbsFile`" & timeout /t 8" -WindowStyle Hidden

Write-Host "[4/4] Cleanup (delayed)..." -ForegroundColor Green
# Give child processes a short moment to start and be captured
Start-Sleep -Seconds 3
Try { Remove-Item $vbsFile -Force -ErrorAction SilentlyContinue } Catch {}

Write-Host "`n[SUCCESS] T1204.002 simulation complete!" -ForegroundColor Green
Write-Host "Sysmon should have logged: Script execution, Process chain" -ForegroundColor Cyan

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
cscript //nologo $vbsFile 2>$null

Write-Host "[3/4] Simulating child process spawn (common in malware)..." -ForegroundColor Green
# Spawn cmd to simulate malware behavior and keep it alive briefly so the collector sees the commandline
# Use /c to match signature 'cmd.exe /c' and ping to delay ~5s
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\cmd.exe') -ArgumentList '/c','echo T1204.002 Demo - Child process spawned & ping -n 6 127.0.0.1 >nul' -WindowStyle Hidden

# Also spawn a PowerShell process whose command-line contains the .vbs filename to increase matchability
$psArgs = @('-NoExit','-Command',"Write-Output 'Simulating macro call to cscript.exe $vbsFile'; Start-Sleep -Seconds 6")
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $psArgs -WindowStyle Hidden

Write-Host "[4/4] Cleanup..." -ForegroundColor Green
Remove-Item $vbsFile -Force -ErrorAction SilentlyContinue

Write-Host "`n[SUCCESS] T1204.002 simulation complete!" -ForegroundColor Green
Write-Host "Sysmon should have logged: Script execution, Process chain" -ForegroundColor Cyan

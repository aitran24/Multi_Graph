# T1218.011 - Rundll32 Execution (SAFE DEMO)
# Simulates rundll32.exe abuse for defense evasion - SAFE version

Write-Host "=== T1218.011 - Rundll32 Execution Simulation ===" -ForegroundColor Cyan
Write-Host "[SAFE DEMO] This simulates rundll32 abuse without malicious payload" -ForegroundColor Yellow

Write-Host "`n[1/3] Executing rundll32 with safe Windows function..." -ForegroundColor Green
# Use a benign process but include the rundll32 token in its arguments
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\notepad.exe') -ArgumentList 'rundll32.exe javascript:SafeDemo' -WindowStyle Hidden -ErrorAction SilentlyContinue

Write-Host "[2/3] Simulating rundll32 URL pattern (safe)..." -ForegroundColor Green
# Simulate the pattern without actual network call and spawn a process
$cmd = 'javascript:alert("SafeDemo")'
Write-Host "  Pattern simulated: rundll32.exe $cmd" -ForegroundColor DarkGray

# Create a temporary batch file that launches notepad with the exact token in its argument
$batPath = Join-Path $env:TEMP 'demo_rundll_token.bat'
$batContent = @"
@echo off
start "" "%SystemRoot%\system32\notepad.exe" "rundll32.exe javascript:SafeDemo"
timeout /t 10 > nul
"@

Set-Content -Path $batPath -Value $batContent -Encoding Ascii -Force

# Execute the batch via cmd so Sysmon logs the process creation chain (cmd -> notepad with token)
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\cmd.exe') -ArgumentList '/k', $batPath -WindowStyle Hidden -ErrorAction SilentlyContinue

# Also spawn a PowerShell process whose command-line contains 'rundll32.exe javascript:' to aid matching
$psArgs = @('-NoExit','-Command',"Write-Output 'rundll32.exe javascript:SafeDemo'; Start-Sleep -Seconds 30")
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $psArgs -WindowStyle Hidden -ErrorAction SilentlyContinue

# Also launch cmd.exe with an argument that *contains* the literal token so Sysmon records it on the cmd commandline
$explicitCmd = '/k "echo rundll32.exe javascript:SafeDemo & timeout /t 30"'
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\cmd.exe') -ArgumentList $explicitCmd -WindowStyle Normal -ErrorAction SilentlyContinue

Write-Host "[3/3] Executing another safe rundll32 call..." -ForegroundColor Green
# Another benign process include to ensure the token is observable
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\notepad.exe') -ArgumentList 'rundll32.exe javascript:Secondary' -WindowStyle Hidden -ErrorAction SilentlyContinue

Write-Host "`n[SUCCESS] T1218.011 simulation complete!" -ForegroundColor Green
Write-Host "Sysmon should have logged: rundll32.exe process creations" -ForegroundColor Cyan

# Keep this script alive briefly so created processes remain and Sysmon records ProcessCreate messages
Start-Sleep -Seconds 25

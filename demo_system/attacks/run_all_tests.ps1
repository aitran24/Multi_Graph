# Run all attacks and check detection
Write-Host "`n=== TESTING ALL 10 MITRE TECHNIQUES ===" -ForegroundColor Cyan
Write-Host "Waiting 5s between each attack for detection...`n" -ForegroundColor Yellow

$attacks = @(
    @{Script = "T1059.001_powershell_execution.ps1"; Name = "T1059.001 - PowerShell"},
    @{Script = "T1112_registry_defense_evasion.ps1"; Name = "T1112 - Registry Defense Evasion"},
    @{Script = "T1547.001_persistence.ps1"; Name = "T1547.001 - Run Keys Persistence"},
    @{Script = "T1218.005_mshta.ps1"; Name = "T1218.005 - Mshta"},
    @{Script = "T1218.011_rundll32.ps1"; Name = "T1218.011 - Rundll32"},
    @{Script = "T1482_domain_trust.ps1"; Name = "T1482 - Domain Trust Discovery"}
)

foreach ($attack in $attacks) {
    Write-Host "`n[$($attack.Name)]" -ForegroundColor Green
    Write-Host "Running: $($attack.Script)" -ForegroundColor Gray
    & ".\$($attack.Script)"
    Write-Host "Waiting 5s for detection..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}

Write-Host "`n=== ALL ATTACKS COMPLETED ===" -ForegroundColor Cyan
Write-Host "Checking detections..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

$data = Get-Content "..\logs\realtime_data.json" -Raw | ConvertFrom-Json
Write-Host "`n=== DETECTION RESULTS ===" -ForegroundColor Cyan
$data.detections | Where-Object { $_.timestamp -like "*$(Get-Date -Format 'yyyy-MM-dd')*" } | 
    Select-Object -Last 10 | 
    Format-Table technique_id, technique_name, timestamp, confidence -AutoSize

# Test Individual Attacks - After Backend Restart
# Run this script to test each attack one by one

param(
    [string]$TechniqueID = "all"
)

$attacks = @{
    "T1003.002" = @{Script="T1003.002_sam_dump.ps1"; Name="SAM Dump"; Fixed=$true}
    "T1003.001" = @{Script="T1003.001_lsass_dump_safe.ps1"; Name="LSASS Dump"; Fixed=$true}
    "T1059.001" = @{Script="T1059.001_powershell_execution.ps1"; Name="PowerShell"; Fixed=$true}
    "T1112" = @{Script="T1112_registry_defense_evasion.ps1"; Name="Registry Mod"; Fixed=$true}
    "T1204.002" = @{Script="T1204.002_malicious_file.ps1"; Name="Malicious File"; Fixed=$false}
    "T1218.005" = @{Script="T1218.005_mshta.ps1"; Name="Mshta"; Fixed=$true}
    "T1218.011" = @{Script="T1218.011_rundll32.ps1"; Name="Rundll32"; Fixed=$true}
    "T1482" = @{Script="T1482_domain_trust.ps1"; Name="Domain Trust"; Fixed=$true}
    "T1547.001" = @{Script="T1547.001_persistence.ps1"; Name="Persistence"; Fixed=$true}
    "T1548.002" = @{Script="T1548.002_uac_bypass.ps1"; Name="UAC Bypass"; Fixed=$true}
}

function Test-SingleAttack {
    param($ID, $Info)
    
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  TEST: $ID - $($Info.Name)" -ForegroundColor Yellow
    Write-Host ("=" * 80) -ForegroundColor Cyan
    
    # Record start time, then run attack
    $startTime = Get-Date
    Write-Host "`n[1/2] Running attack... (start: $startTime)" -ForegroundColor Cyan
    & ".\$($Info.Script)"

    # Wait for backend (give collector extra time)
    Write-Host "`n[2/2] Waiting for detection (8 seconds)..." -ForegroundColor Cyan
    Start-Sleep -Seconds 8
    
    # Check result
    Write-Host "`nResult:" -ForegroundColor Cyan
    try {
        $data = Get-Content "..\logs\realtime_data.json" -Raw | ConvertFrom-Json
        $relevant = $data.detections | Where-Object { $_.technique_id -eq $ID } | 
                    Sort-Object timestamp -Descending | Select-Object -First 1
        
        if ($relevant) {
            # Parse timestamp and ensure it's recent relative to the attack start time
            try {
                $detTime = [datetime]$relevant.timestamp
            }
            catch {
                $detTime = Get-Date 0
            }

            if ($detTime -lt $startTime.AddSeconds(-5)) {
                $ageSec = (Get-Date) - $detTime
                Write-Host "  Status: DETECTED (old record, ignored)" -ForegroundColor Yellow
                Write-Host "  Timestamp: $($relevant.timestamp) (age: $([int]$ageSec.TotalSeconds)s)" -ForegroundColor Gray
                Write-Host "  Treating as NOT DETECTED for this run." -ForegroundColor Yellow
                return $false
            }

            Write-Host "  Status: DETECTED" -ForegroundColor Green
            Write-Host "  Confidence: $($relevant.confidence)%" -ForegroundColor White
            Write-Host "  Patterns: $($relevant.patterns -join ', ')" -ForegroundColor White
            Write-Host "  Timestamp: $($relevant.timestamp)" -ForegroundColor Gray
            return $true
        }
        else {
            Write-Host "  Status: NOT DETECTED" -ForegroundColor Red
            Write-Host "  Latest detections:" -ForegroundColor Yellow
            $data.detections | Sort-Object timestamp -Descending | Select-Object -First 3 |
                Select-Object technique_id, confidence | Format-Table -AutoSize
            return $false
        }
    }
    catch {
        Write-Host "  ERROR: $_" -ForegroundColor Red
        return $false
    }
}

# Main
Write-Host ("=" * 80) -ForegroundColor Cyan
Write-Host "  Individual Attack Testing" -ForegroundColor Yellow
Write-Host ("=" * 80) -ForegroundColor Cyan

if ($TechniqueID -eq "all") {
    $results = @{}
    foreach ($id in $attacks.Keys | Sort-Object) {
        $detected = Test-SingleAttack -ID $id -Info $attacks[$id]
        $results[$id] = $detected
        
        if (-not $detected) {
            Write-Host "`nContinue to next test? (Y/N): " -ForegroundColor Yellow -NoNewline
            $response = Read-Host
            if ($response -ne "Y" -and $response -ne "y") {
                break
            }
        }
    }
    
    # Summary
    Write-Host "`n" -NoNewline
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host "  SUMMARY" -ForegroundColor Yellow
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    
    $detected = ($results.Values | Where-Object { $_ -eq $true }).Count
    $total = $results.Count
    
    Write-Host "Detected: $detected / $total" -ForegroundColor $(if ($detected -eq $total) { "Green" } else { "Yellow" })
    Write-Host ""
    
    foreach ($id in $results.Keys | Sort-Object) {
        $status = if ($results[$id]) { "PASS" } else { "FAIL" }
        $color = if ($results[$id]) { "Green" } else { "Red" }
        Write-Host "  [$status] $id - $($attacks[$id].Name)" -ForegroundColor $color
    }
}
else {
    if ($attacks.ContainsKey($TechniqueID)) {
        Test-SingleAttack -ID $TechniqueID -Info $attacks[$TechniqueID]
    }
    else {
        Write-Host "Unknown technique ID: $TechniqueID" -ForegroundColor Red
        Write-Host "Available: $($attacks.Keys -join ', ')" -ForegroundColor Yellow
    }
}

Write-Host ""

# T1482 - Domain Trust Discovery (SAFE DEMO)
# Simulates domain trust enumeration - SAFE version (read-only)

Write-Host "=== T1482 - Domain Trust Discovery Simulation ===" -ForegroundColor Cyan
Write-Host "[SAFE DEMO] This simulates domain trust enumeration (read-only, no changes)" -ForegroundColor Yellow

Write-Host "`n[1/4] Running nltest /domain_trusts..." -ForegroundColor Green
$marker = "T1482_MARKER_$(Get-Date -Format yyyyMMddHHmmss)"
try {
    Start-Process -FilePath "cmd.exe" -ArgumentList '/c',"nltest /domain_trusts & echo $marker" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
} catch { nltest /domain_trusts 2>$null }
Start-Sleep -Seconds 2

Write-Host "`n[2/4] Running nltest /dclist..." -ForegroundColor Green  
try {
    Start-Process -FilePath "cmd.exe" -ArgumentList '/c',"nltest /dclist & echo $marker" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
} catch { nltest /dclist 2>$null }
Start-Sleep -Seconds 2

Write-Host "`n[3/4] Querying domain via net view..." -ForegroundColor Green
# Query net view with marker appended so Sysmon logs include the marker on cmd.exe
try {
    Start-Process -FilePath "cmd.exe" -ArgumentList '/c',"net view /domain & echo $marker" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
} catch { net view /domain 2>$null | Out-Null }
Start-Sleep -Seconds 2
# Note: dsquery requires AD tools, using alternatives
try {
    Start-Process -FilePath "cmd.exe" -ArgumentList '/c',"net group \"Domain Admins\" /domain & echo $marker" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
} catch { net group "Domain Admins" /domain 2>$null | Out-Null }
Start-Sleep -Seconds 2

Write-Host "[4/4] Querying trusted domains via PowerShell..." -ForegroundColor Green
try {
    Get-WmiObject -Class Win32_NTDomain -ErrorAction SilentlyContinue | 
        Select-Object -First 3 DomainName, DnsForestName, Status | 
        Format-Table -AutoSize
    Start-Sleep -Seconds 1
} catch {
    Write-Host "  (Domain query completed - may show empty if not domain-joined)" -ForegroundColor DarkGray
}

Write-Host "`n[SUCCESS] T1482 simulation complete!" -ForegroundColor Green
Write-Host "Sysmon should have logged: nltest.exe process creations" -ForegroundColor Cyan

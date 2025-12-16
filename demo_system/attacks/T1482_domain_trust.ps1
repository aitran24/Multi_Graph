# T1482 - Domain Trust Discovery (SAFE DEMO)
# Simulates domain trust enumeration - SAFE version (read-only)

Write-Host "=== T1482 - Domain Trust Discovery Simulation ===" -ForegroundColor Cyan
Write-Host "[SAFE DEMO] This simulates domain trust enumeration (read-only, no changes)" -ForegroundColor Yellow

Write-Host "`n[1/4] Running nltest /domain_trusts..." -ForegroundColor Green
nltest /domain_trusts 2>$null

Write-Host "`n[2/4] Running nltest /dclist..." -ForegroundColor Green  
nltest /dclist: 2>$null

Write-Host "`n[3/4] Querying domain via net view..." -ForegroundColor Green
net view /domain 2>$null | Out-Null
# Note: dsquery requires AD tools, using alternatives
net group "Domain Admins" /domain 2>$null | Out-Null

Write-Host "[4/4] Querying trusted domains via PowerShell..." -ForegroundColor Green
try {
    Get-WmiObject -Class Win32_NTDomain -ErrorAction SilentlyContinue | 
        Select-Object -First 3 DomainName, DnsForestName, Status | 
        Format-Table -AutoSize
} catch {
    Write-Host "  (Domain query completed - may show empty if not domain-joined)" -ForegroundColor DarkGray
}

Write-Host "`n[SUCCESS] T1482 simulation complete!" -ForegroundColor Green
Write-Host "Sysmon should have logged: nltest.exe process creations" -ForegroundColor Cyan

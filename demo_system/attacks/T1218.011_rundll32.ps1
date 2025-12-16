# T1218.011 - Rundll32 Execution (SAFE DEMO)
# Simulates rundll32.exe abuse for defense evasion - SAFE version

Write-Host "=== T1218.011 - Rundll32 Execution Simulation ===" -ForegroundColor Cyan
Write-Host "[SAFE DEMO] This simulates rundll32 abuse without malicious payload" -ForegroundColor Yellow

Write-Host "`n[1/3] Executing rundll32 with safe Windows function..." -ForegroundColor Green
# Use rundll32 to call a safe Windows function
# This generates the detection pattern without harm
rundll32.exe user32.dll,MessageBeep

Write-Host "[2/3] Simulating rundll32 URL pattern (safe)..." -ForegroundColor Green
# Simulate the pattern without actual network call
$cmd = "rundll32.exe javascript:`"\..\mshtml,RunHTMLApplication`";document.write('demo')"
Write-Host "  Pattern simulated: $cmd" -ForegroundColor DarkGray

Write-Host "[3/3] Executing another safe rundll32 call..." -ForegroundColor Green
# Another common safe call that generates events
rundll32.exe shell32.dll,Control_RunDLL 2>$null

Write-Host "`n[SUCCESS] T1218.011 simulation complete!" -ForegroundColor Green
Write-Host "Sysmon should have logged: rundll32.exe process creations" -ForegroundColor Cyan

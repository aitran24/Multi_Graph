# T1218.005 - Mshta Execution (SAFE DEMO)
# Simulates mshta.exe abuse for defense evasion - SAFE version

Write-Host "=== T1218.005 - Mshta Execution Simulation ===" -ForegroundColor Cyan
Write-Host "[SAFE DEMO] This simulates mshta abuse without malicious payload" -ForegroundColor Yellow

# Create a harmless HTA file
$htaContent = @'
<html>
<head>
<title>T1218.005 Safe Demo</title>
<HTA:APPLICATION ID="demo" APPLICATIONNAME="SafeDemo" SCROLL="no" SINGLEINSTANCE="yes">
<script language="VBScript">
    MsgBox "T1218.005 Demo - Mshta executed safely!", vbInformation, "Safe Demo"
    ' Keep HTA open for a short while to ensure Sysmon logs the process
    WScript.Sleep 5000
    self.close()
</script>
</head>
<body>
Safe Demo
</body>
</html>
'@

$htaFile = "$env:TEMP\demo_mshta_$((Get-Date).ToString('yyyyMMddHHmmss')).hta"

Write-Host "`n[1/3] Creating demo HTA file..." -ForegroundColor Green
$htaContent | Out-File $htaFile -Encoding ASCII

Write-Host "[2/3] Executing mshta.exe (generates Sysmon event)..." -ForegroundColor Green
# Run mshta - this creates detection event
Start-Process mshta.exe -ArgumentList $htaFile -ErrorAction SilentlyContinue

# Also spawn a PowerShell process whose command-line contains the string 'mshta.exe' to improve matching
$psArgs = @('-NoExit','-Command',"Write-Output 'Simulated mshta invocation mshta.exe $htaFile'; Start-Sleep -Seconds 6")
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $psArgs -WindowStyle Hidden

Write-Host "[3/3] Cleanup..." -ForegroundColor Green
Start-Sleep -Seconds 1
Remove-Item $htaFile -Force -ErrorAction SilentlyContinue

Write-Host "`n[SUCCESS] T1218.005 simulation complete!" -ForegroundColor Green
Write-Host "Sysmon should have logged: mshta.exe process creation" -ForegroundColor Cyan

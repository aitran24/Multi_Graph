# Safe LSASS dump simulation
# Creates a fake dump file and spawns a benign cmd.exe whose command-line
# includes 'procdump' and 'lsass' so the collector can detect it.

$OutputDir = Join-Path $env:TEMP 'MultiKG_Demo'
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

$DumpFile = Join-Path $OutputDir 'lsass.dmp'
Set-Content -Path $DumpFile -Value ('FAKE_LSASS_DUMP_FOR_DEMO' * 50) -Force

$SimFile = Join-Path $OutputDir 'lsass_sim_cmd.txt'
# Start a long-running PowerShell process whose command-line contains the procdump pattern
$psArgs = @(
	'-NoExit',
	'-Command',
	"Start-Sleep -Seconds 8; Out-File -FilePath '$SimFile' -InputObject 'procdump -accepteula -ma lsass C:\\Windows\\Temp\\lsass_dump.dmp'"
)
Start-Process -FilePath (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList $psArgs -WindowStyle Hidden

Write-Host "[SAFE SIM] Created $DumpFile and started PowerShell with detection keywords in its command-line"

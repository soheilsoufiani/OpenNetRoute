param([switch]$OutputToConsole)
# Self-elevating runner for the WinDivert spike.
# Run this script as a normal user; it re-launches itself elevated via UAC.
$spike = 'C:\Users\aghai\Workspace\MyProxy\spikes\WinDivertSpike\bin\Debug\net10.0-windows\WinDivertSpike.exe'
$log = 'C:\Users\aghai\Workspace\MyProxy\spikes\WinDivertSpike\spike-log.txt'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'Rel launching elevated (UAC)...'
    Remove-Item $log -ErrorAction SilentlyContinue
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File', $PSCommandPath) -Wait
    Write-Host 'Elevated run finished. Log:'
    Get-Content $log -ErrorAction SilentlyContinue
    exit
}
# Elevated path:
& $spike *> $log
exit $LASTEXITCODE

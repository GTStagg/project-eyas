# Shared preamble: assert elevation, pin TLS 1.2, emit a start marker.
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Not elevated. RTR runscript must run under SYSTEM or an admin context."
    exit 2
}

Write-Output "[eyas] start $(Get-Date -Format o) host=$env:COMPUTERNAME"

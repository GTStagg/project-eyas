$ErrorActionPreference = 'Stop'
$ip = $Params.RemoteIp

if ([string]::IsNullOrWhiteSpace($ip)) {
    Write-Output "remote_ip is empty"
    exit 1
}

if ($ip -match '^(0\.|10\.|127\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|255\.)') {
    Write-Output "refusing to block private/loopback/link-local IP: $ip"
    exit 1
}

$ruleName = "FalconCleanup-Block-$ip"

$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Output "block rule already exists for $ip (name='$ruleName')"
    exit 0
}

try {
    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Outbound `
        -Action Block `
        -RemoteAddress $ip `
        -Profile Any `
        -Enabled True `
        -Description "Created by falcon-extras cleanup at $(Get-Date -Format o)" | Out-Null
    Write-Output "created outbound block rule '$ruleName' for $ip"
} catch {
    Write-Output "firewall rule create failed for $ip: $_"
    exit 1
}

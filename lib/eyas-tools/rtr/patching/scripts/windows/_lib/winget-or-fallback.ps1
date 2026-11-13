# Helper: resolve a working app-installer command. Prefer winget (modern,
# Microsoft-supported), fall back to choco when present. Callers use
# Invoke-AppUpgrade -Id <winget-id> -ChocoId <choco-id>.

function Get-WingetPath {
    $cmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # winget under SYSTEM context is sometimes not on PATH; resolve from WindowsApps.
    $candidates = Get-ChildItem -Path "$env:ProgramFiles\WindowsApps" -Filter "winget.exe" -Recurse -ErrorAction SilentlyContinue
    if ($candidates) { return $candidates[0].FullName }
    return $null
}

function Invoke-AppUpgrade {
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [string]$ChocoId
    )
    $winget = Get-WingetPath
    if ($winget) {
        Write-Output "[eyas] using winget: $winget"
        & $winget upgrade --id $Id --silent --accept-package-agreements --accept-source-agreements --disable-interactivity
        return $LASTEXITCODE
    }
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco -and $ChocoId) {
        Write-Output "[eyas] using choco: $($choco.Source)"
        & $choco.Source upgrade $ChocoId -y --no-progress
        return $LASTEXITCODE
    }
    Write-Error "No supported package manager (winget/choco) found on this host."
    return 3
}

$ErrorActionPreference = 'Stop'
$user = $Params.Username

if ([string]::IsNullOrWhiteSpace($user)) {
    Write-Output "username is empty"
    exit 1
}

$blocked = @('SYSTEM','NETWORK SERVICE','LOCAL SERVICE','DWM','UMFD')
foreach ($b in $blocked) {
    if ($user -ieq $b -or $user -like ($b + '*')) {
        Write-Output "refusing to log off protected account: $b"
        exit 1
    }
}

$raw = & quser.exe 2>$null
if (-not $raw) {
    Write-Output "no interactive sessions reported by quser on this host"
    exit 0
}

$sessions = @()
foreach ($line in ($raw | Select-Object -Skip 1)) {
    $cols = ($line -replace '^\s*>?\s*','') -split '\s+'
    if ($cols.Count -ge 3 -and $cols[0] -ieq $user) {
        $sid = if ($cols[2] -match '^\d+$') { $cols[2] } else { $cols[1] }
        if ($sid -match '^\d+$') { $sessions += [int]$sid }
    }
}

if (-not $sessions) {
    Write-Output "no active session for user '$user'"
    exit 0
}

$loggedOff = @()
$failed = @()
foreach ($sid in $sessions) {
    try {
        & logoff.exe $sid 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) { $loggedOff += $sid } else { $failed += $sid }
    } catch {
        $failed += $sid
    }
}

if ($loggedOff.Count -gt 0) {
    Write-Output "logged off user '$user' from session(s): $($loggedOff -join ', ')"
}
if ($failed.Count -gt 0) {
    Write-Output "logoff failed for session(s): $($failed -join ', ')"
    exit 1
}

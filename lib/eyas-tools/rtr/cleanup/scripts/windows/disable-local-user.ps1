$ErrorActionPreference = 'Stop'
$user = $Params.Username

if ([string]::IsNullOrWhiteSpace($user)) {
    Write-Output "username is empty"
    exit 1
}

$blocked = @('Administrator','DefaultAccount','Guest','WDAGUtilityAccount','SYSTEM')
foreach ($b in $blocked) {
    if ($user -ieq $b) {
        Write-Output "refusing to disable protected account: $b"
        exit 1
    }
}

$u = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
if (-not $u) {
    Write-Output "no local user '$user' on this host"
    exit 0
}

if (-not $u.Enabled) {
    Write-Output "local user '$user' is already disabled"
    exit 0
}

try {
    Disable-LocalUser -Name $user
    Write-Output "disabled local user '$user' (sid=$($u.SID.Value))"
} catch {
    Write-Output "disable failed for '$user': $_"
    exit 1
}

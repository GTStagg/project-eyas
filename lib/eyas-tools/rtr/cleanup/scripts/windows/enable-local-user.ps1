$ErrorActionPreference = 'Stop'
$user = $Params.Username

if ([string]::IsNullOrWhiteSpace($user)) {
    Write-Output "username is empty"
    exit 1
}

$blocked = @('DefaultAccount','Guest','WDAGUtilityAccount','SYSTEM')
foreach ($b in $blocked) {
    if ($user -ieq $b) {
        Write-Output "refusing to enable protected account: $b"
        exit 1
    }
}

$u = Get-LocalUser -Name $user -ErrorAction SilentlyContinue
if (-not $u) {
    Write-Output "no local user '$user' on this host"
    exit 1
}

if ($u.Enabled) {
    Write-Output "local user '$user' is already enabled"
    exit 0
}

try {
    Enable-LocalUser -Name $user
    Write-Output "enabled local user '$user' (sid=$($u.SID.Value))"
} catch {
    Write-Output "enable failed for '$user': $_"
    exit 1
}

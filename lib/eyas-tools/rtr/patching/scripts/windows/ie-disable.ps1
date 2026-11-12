# Disable Internet Explorer 11 via DISM. IE11 is retired (Microsoft 2022-06-15)
# and Spotlight's recommended remediation on hosts where it is still surfaced
# is the optional-feature removal path. The binary stays on disk but is
# unregistered, which clears the Spotlight finding once the host reboots.
# Idempotent: checks current feature state first and no-ops when already
# disabled.
$ErrorActionPreference = "Continue"

$feature = "Internet-Explorer-Optional-amd64"

$info = & dism.exe /online /Get-FeatureInfo /FeatureName:$feature 2>&1
$rcInfo = $LASTEXITCODE
$stateMatch = $info | Select-String -Pattern "^State\s*:\s*(\S+)" | Select-Object -First 1
$state = if ($stateMatch) { $stateMatch.Matches.Groups[1].Value } else { $null }

if (-not $state) {
    Write-Output "[falcon-extras] could not read DISM state for $feature (rc=$rcInfo) host=$env:COMPUTERNAME"
    Write-Output "----- dism output -----"
    $info | ForEach-Object { Write-Output $_ }
    exit 2
}

Write-Output "[falcon-extras] $feature current state: $state host=$env:COMPUTERNAME"

if ($state -eq "Disabled" -or $state -eq "DisabledWithPayloadRemoved") {
    Write-Output "[falcon-extras] already disabled, no-op"
    exit 0
}

Write-Output "[falcon-extras] disabling $feature (no restart) ..."
$disable = & dism.exe /online /Disable-Feature /FeatureName:$feature /NoRestart 2>&1
$rc = $LASTEXITCODE
$disable | ForEach-Object { Write-Output $_ }

# DISM returns 0 on success, 3010 on success-pending-reboot. Both are wins.
if ($rc -eq 0 -or $rc -eq 3010) {
    Write-Output "[falcon-extras] ie-disable done (exit=$rc, reboot required to fully apply) host=$env:COMPUTERNAME"
    exit 0
}

Write-Output "[falcon-extras] dism Disable-Feature failed, exit=$rc"
exit $rc

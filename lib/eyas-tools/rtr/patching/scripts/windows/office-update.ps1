# Microsoft 365 / Office Click-to-Run update via OfficeC2RClient.
# Channel parameter is informational; the binary respects tenant policy.
$ErrorActionPreference = "Stop"

$c2r = "C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
if (-not (Test-Path $c2r)) {
    $c2r86 = "C:\Program Files (x86)\Common Files\Microsoft Shared\ClickToRun\OfficeC2RClient.exe"
    if (Test-Path $c2r86) { $c2r = $c2r86 }
}
if (-not (Test-Path $c2r)) {
    Write-Error "OfficeC2RClient.exe not found. This host may have an MSI install of Office; use win-update-install instead."
    exit 4
}

Write-Output "[eyas] channel hint: $($Params.Channel)"
Write-Output "[eyas] launching: $c2r /update user displaylevel=false"
& $c2r /update user displaylevel=false forceappshutdown=false
Write-Output "[eyas] OfficeC2RClient exit=$LASTEXITCODE host=$env:COMPUTERNAME"
exit $LASTEXITCODE

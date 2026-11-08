# Generic Windows installer -- the runtime-extensible engine. Unlike the
# per-app scripts (chrome-update.ps1, etc.) that bake a fixed vendor URL, this
# script takes the download URL, product name, installer kind, and optional
# integrity pin as validated params. The agent never authors bytes; it supplies
# params that pass the manifest regex in library.py::_validate_params. Declared
# last in the manifest with no spotlight_match, so it never auto-resolves over a
# specific app script -- it is explicit-invoke only.
#
# Params (PascalCase-rendered by library.py from the snake_case manifest schema):
#   $Params.Url        -- vendor HTTPS download URL
#   $Params.Product    -- friendly name for log lines
#   $Params.Kind       -- 'msi' or 'exe'
#   $Params.Sha256     -- optional integrity pin; verify-or-abort host-side
#   $Params.SilentArgs -- exe-only silent switches (ignored for kind=msi)

# Runtime integrity banner. ASCII only -- library.py::_ascii_coerce strips any
# non-7-bit byte from the rendered body, so no check marks / em dashes here.
if ($Params.Sha256) {
    Write-Output "[falcon-extras] integrity: HASH-PINNED ($($Params.Sha256))"
} else {
    Write-Output "[falcon-extras] integrity: UNVERIFIED (no hash pin) -- proceeds on HTTPS + operator approval only"
}

$exit = Install-FromUrl -Url $Params.Url -ProductName $Params.Product -Kind $Params.Kind -SilentArgs $Params.SilentArgs -Sha256 $Params.Sha256
Write-Output "[falcon-extras] win-app-install product='$($Params.Product)' kind=$($Params.Kind) exit=$exit host=$env:COMPUTERNAME"
exit $exit

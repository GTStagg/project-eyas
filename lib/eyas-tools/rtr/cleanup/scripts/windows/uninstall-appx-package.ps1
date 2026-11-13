# Generic AppX/MSIX package removal — for sideloaded or attacker-installed
# Store packages that don't have a dedicated cleanup primitive (Claude
# Desktop, Cursor, etc. each have their own scripts). Use when:
#   - A Shadow-AI / IR finding identifies an MSIX package by name and there
#     is no dedicated `host-uninstall-<product>` primitive.
#   - The package is in C:\Program Files\WindowsApps (which `host-delete-
#     folder` refuses by design — that path is system-protected).
#   - A package-bundled service (CoworkVMService et al.) needs to go away
#     with the package — Remove-AppxPackage cleans up bundled services.
#
# Matches packages by Get-AppxPackage's -Name pattern (the package family
# name, e.g. "Claude" or "TeamViewer.RemoteSupport") and removes every
# install for every user via Remove-AppxPackage -AllUsers. Also walks
# Get-AppxProvisionedPackage and removes provisioned entries so the
# package doesn't re-install on next user logon.
#
# Refuses to touch the well-known set of system-shipped Microsoft
# packages (Edge, WebView2Runtime, AppInstaller, StorePurchaseApp, the
# Windows shell stack) — accidental removal of those triggers cascading
# repair flows that take a host out of service.

$pattern = $Params.PackageNamePattern

# Reject the obviously-Microsoft system stack outright. The PackageNamePattern
# regex passes through to Get-AppxPackage's -Name argument, which supports
# wildcards; this guard runs against the supplied PATTERN to catch things
# like '*' / 'Microsoft.*' / 'Windows*' before they touch the system.
$forbiddenPatterns = @(
    '\*$',                          # bare wildcard
    '^Microsoft\.',                 # any Microsoft.* family
    '^Windows\.',                   # any Windows.* family
    '\.WebView',                    # WebView2 + variants
    '\.Edge',                       # Edge family
    '\.AppInstaller',               # AppInstaller (needed for MSIX itself)
    '\.StorePurchaseApp',
    '\.WindowsStore'
)
foreach ($fp in $forbiddenPatterns) {
    if ($pattern -match $fp) {
        Write-Output "[eyas] refused: pattern '$pattern' matches forbidden system package class '$fp'"
        exit 0
    }
}

$removed = 0
$provisioningRemoved = 0
$failed = 0
$found = 0

try {
    $packages = @(Get-AppxPackage -AllUsers -Name $pattern -ErrorAction Stop)
} catch {
    Write-Output "[eyas] Get-AppxPackage failed for pattern '$pattern': $($_.Exception.Message)"
    exit 0
}

$found = $packages.Count
if ($found -eq 0) {
    Write-Output "[eyas] no packages match pattern '$pattern' — nothing to remove"
    exit 0
}

foreach ($pkg in $packages) {
    Write-Output "[eyas] found $($pkg.PackageFullName) (publisher=$($pkg.Publisher))"
    try {
        Remove-AppxPackage -AllUsers -Package $pkg.PackageFullName -ErrorAction Stop
        $removed += 1
        Write-Output "[eyas] removed package $($pkg.PackageFullName)"
    } catch {
        $failed += 1
        Write-Output "[eyas] failed to remove $($pkg.PackageFullName): $($_.Exception.Message)"
    }
}

# Provisioned-package leg: removes the system-wide registration so the
# package doesn't auto-install for new users on next logon. Requires admin
# (RTR runs as SYSTEM). Match on DisplayName since provisioned-package
# objects don't carry the same name format as installed packages.
try {
    $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop |
        Where-Object { $_.DisplayName -like $pattern })
    foreach ($pp in $provisioned) {
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
            $provisioningRemoved += 1
            Write-Output "[eyas] removed provisioned $($pp.PackageName)"
        } catch {
            Write-Output "[eyas] failed to remove provisioned $($pp.PackageName): $($_.Exception.Message)"
        }
    }
} catch {
    Write-Output "[eyas] Get-AppxProvisionedPackage failed: $($_.Exception.Message)"
}

Write-Output "[eyas] summary: pattern=$pattern found=$found removed=$removed provisioning_removed=$provisioningRemoved failed=$failed"

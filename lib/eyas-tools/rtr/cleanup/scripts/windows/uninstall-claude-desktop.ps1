# Shadow-AI eviction: Claude Desktop (Anthropic).
#
# Claude Desktop ships in TWO distribution formats and we must handle both:
#   1. Squirrel/Electron per-user install at %LOCALAPPDATA%\AnthropicClaude
#      with Update.exe alongside. Standard for x64 Windows installs from
#      claude.ai's download link.
#   2. MSIX/Store package at C:\Program Files\WindowsApps\Claude_<ver>_<arch>__<publisher>.
#      This is the path on Windows 11 ARM64 (and increasingly x64 when
#      the Store install is preferred). Squirrel's uninstaller never sees
#      these — they require Remove-AppxPackage. Without this leg, the
#      InstalledProgram audit returns clean while the Store package is
#      still resident and reappears on next user logon if the
#      AppxProvisionedPackage entry survives.
#
# The MCP-host capability is what makes this Shadow-AI-relevant:
# claude_desktop_config.json registers MCP servers the user wired up
# (file-system, github, shell, etc.) and those agents inherit the user's
# local privileges. The config file lives at
# %APPDATA%\Claude\claude_desktop_config.json and is the artifact most
# operators want preserved for forensic review -- DO NOT delete it
# without copy. We rename to .quarantined-<stamp> before any sweep.

$swept = 0
$uninstallerRan = 0
$appxRemoved = 0
$appxProvisionedRemoved = 0
$killed = 0
$configsPreserved = 0

$killed += Stop-ProcessesByName @('Claude', 'claude-helper', 'AnthropicClaude')

# Preserve MCP config files for forensics before any sweep. Note the
# variable interpolation: ${cfg} (not $cfg) avoids PowerShell parsing
# `$cfg:` as a scope-qualified variable lookup (like $global:foo).
foreach ($profile in Get-UserProfilePaths) {
    $cfg = Join-Path $profile.AppData 'Claude\claude_desktop_config.json'
    if (Test-Path -LiteralPath $cfg) {
        try {
            $stamp = (Get-Date).ToString('yyyyMMddTHHmmss')
            $dest = "${cfg}.quarantined-$stamp"
            Move-Item -LiteralPath $cfg -Destination $dest -Force -ErrorAction Stop
            $configsPreserved += 1
            Write-Output "[eyas] preserved MCP config: $dest"
        } catch {
            Write-Output "[eyas] failed to preserve MCP config ${cfg}: $($_.Exception.Message)"
        }
    }
}

$uninstallerRan += Invoke-VendorUninstall -DisplayNameRegex '^Claude( Desktop)?$' -SilentArgs '--silent'

# MSIX / Store package leg. Filter on Publisher containing Anthropic so
# we don't catch unrelated apps named "Claude" from other publishers.
# Get-AppxPackage -AllUsers requires SYSTEM or admin (RTR runs SYSTEM).
try {
    $appxPkgs = @(Get-AppxPackage -AllUsers -ErrorAction Stop |
        Where-Object { $_.Name -like '*Claude*' -and $_.Publisher -match 'Anthropic' })
    foreach ($pkg in $appxPkgs) {
        try {
            Remove-AppxPackage -AllUsers -Package $pkg.PackageFullName -ErrorAction Stop
            $appxRemoved += 1
            Write-Output "[eyas] removed Appx package: $($pkg.PackageFullName)"
        } catch {
            Write-Output "[eyas] failed to remove Appx package $($pkg.PackageFullName): $($_.Exception.Message)"
        }
    }
} catch {
    Write-Output "[eyas] Get-AppxPackage failed: $($_.Exception.Message)"
}

# Provisioned-package leg — without this, removing the package per-user
# leaves the provisioning entry, which auto-installs Claude for any new
# user account on next logon. Online provisioning store is system-wide.
try {
    $provPkgs = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop |
        Where-Object { $_.DisplayName -like '*Claude*' -and $_.PublisherId -match 'Anthropic|pzs8sxrjxfjjc' })
    foreach ($pp in $provPkgs) {
        try {
            Remove-AppxProvisionedPackage -Online -PackageName $pp.PackageName -ErrorAction Stop | Out-Null
            $appxProvisionedRemoved += 1
            Write-Output "[eyas] removed provisioned Appx: $($pp.PackageName)"
        } catch {
            Write-Output "[eyas] failed to remove provisioned Appx $($pp.PackageName): $($_.Exception.Message)"
        }
    }
} catch {
    Write-Output "[eyas] Get-AppxProvisionedPackage failed: $($_.Exception.Message)"
}

$candidates = @(
    "$env:ProgramFiles\AnthropicClaude",
    "${env:ProgramFiles(x86)}\AnthropicClaude"
)
foreach ($profile in Get-UserProfilePaths) {
    $candidates += @(
        "$($profile.LocalAppData)\AnthropicClaude",
        "$($profile.LocalAppData)\Programs\Claude",
        "$($profile.AppData)\Claude\Cache",
        "$($profile.AppData)\Claude\Code Cache",
        "$($profile.AppData)\Claude\GPUCache"
    )
}
$swept += Sweep-Paths -Paths $candidates

$pendingRebootCount = $script:PendingRebootPaths.Count
Write-Output "[eyas] uninstall-claude-desktop done uninstaller_ran=$uninstallerRan appx_removed=$appxRemoved appx_provisioned_removed=$appxProvisionedRemoved processes_killed=$killed swept=$swept configs_preserved=$configsPreserved pending_reboot=$pendingRebootCount host=$env:COMPUTERNAME"
if ($pendingRebootCount -gt 0) {
    Write-Output "[eyas] pending-reboot paths: $($script:PendingRebootPaths -join '; ')"
}

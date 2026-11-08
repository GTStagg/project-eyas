# Shadow-AI eviction: Cursor (agentic IDE).
#
# Cursor is an Electron / Squirrel build of VS Code with a built-in MCP
# client and a hosted agent loop. Installs per-user under
# %LOCALAPPDATA%\Programs\cursor\Cursor.exe -- so cleanup under SYSTEM
# has to walk every user profile, not just the running user's. The
# Squirrel installer registers an UninstallString per user-hive; the
# vendor uninstaller (Update.exe --uninstall) handles the install root,
# but per-user data dirs (~\AppData\Roaming\Cursor, MCP server configs,
# auth tokens) are left behind and must be swept.
#
# This evicts the AGENT, not the user's source code. ~\.cursor (project
# config) is intentionally left in place; if the user re-sanctions Cursor
# later, their workspace settings survive. Only the agent runtime + MCP
# config + auth state are removed.

$swept = 0
$uninstallerRan = 0
$killed = 0

# 1. Stop running processes. Cursor spawns Cursor.exe + a swarm of
# Electron renderer children with the same image name; killing all is
# fine, the uninstaller will still complete.
$killed += Stop-ProcessesByName @('Cursor', 'cursor-tunnel', 'cursor-helper')

# 2. Vendor uninstaller. Squirrel registers DisplayName=Cursor.
$uninstallerRan += Invoke-VendorUninstall -DisplayNameRegex '^Cursor( \(User\))?$' -SilentArgs '--silent'

# 3. Sweep per-user install roots. Cover the system-wide install variant
# too in case an enterprise pushed it via MSI.
$candidates = @(
    "$env:ProgramFiles\Cursor",
    "${env:ProgramFiles(x86)}\Cursor"
)
foreach ($profile in Get-UserProfilePaths) {
    $candidates += @(
        "$($profile.LocalAppData)\Programs\cursor",
        "$($profile.LocalAppData)\Programs\Cursor",
        "$($profile.AppData)\Cursor",
        # MCP server configs + auth tokens — the agent state proper.
        "$($profile.AppData)\Cursor\User\globalStorage",
        "$($profile.AppData)\Cursor\Cache",
        "$($profile.AppData)\Cursor\Code Cache"
    )
}
$swept += Sweep-Paths -Paths $candidates

$pendingRebootCount = $script:PendingRebootPaths.Count
Write-Output "[falcon-extras] uninstall-cursor done uninstaller_ran=$uninstallerRan processes_killed=$killed swept=$swept pending_reboot=$pendingRebootCount host=$env:COMPUTERNAME"
if ($pendingRebootCount -gt 0) {
    Write-Output "[falcon-extras] pending-reboot paths: $($script:PendingRebootPaths -join '; ')"
}

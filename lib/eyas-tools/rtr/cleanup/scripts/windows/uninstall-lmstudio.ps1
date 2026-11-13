# Shadow-AI eviction: LM Studio (local-inference desktop app).
#
# LM Studio is a Squirrel-installed Electron app. Installs per-user at
# %LOCALAPPDATA%\Programs\LM Studio\LM Studio.exe. Models cached at
# %USERPROFILE%\.cache\lm-studio\models (or %USERPROFILE%\.lmstudio
# depending on version); sweeping this is intentional for the same
# data-egress reason as Ollama.
#
# LM Studio also exposes an OpenAI-compatible local server on 1234 by
# default; that is process-bound (not a service), so the process kill
# below severs it.

$swept = 0
$uninstallerRan = 0
$killed = 0

$killed += Stop-ProcessesByName @('LM Studio', 'lms', 'lm-studio-helper')

$uninstallerRan += Invoke-VendorUninstall -DisplayNameRegex '^LM Studio$' -SilentArgs '--silent'

$candidates = @(
    "$env:ProgramFiles\LM Studio",
    "${env:ProgramFiles(x86)}\LM Studio"
)
foreach ($profile in Get-UserProfilePaths) {
    $candidates += @(
        "$($profile.LocalAppData)\Programs\LM Studio",
        "$($profile.LocalAppData)\LM-Studio",
        "$($profile.LocalAppData)\LMStudio",
        "$($profile.AppData)\LM Studio",
        # Model cache — main data-egress surface.
        "$($profile.Home)\.cache\lm-studio",
        "$($profile.Home)\.lmstudio"
    )
}
$swept += Sweep-Paths -Paths $candidates

$pendingRebootCount = $script:PendingRebootPaths.Count
Write-Output "[eyas] uninstall-lmstudio done uninstaller_ran=$uninstallerRan processes_killed=$killed swept=$swept pending_reboot=$pendingRebootCount host=$env:COMPUTERNAME"
if ($pendingRebootCount -gt 0) {
    Write-Output "[eyas] pending-reboot paths: $($script:PendingRebootPaths -join '; ')"
}

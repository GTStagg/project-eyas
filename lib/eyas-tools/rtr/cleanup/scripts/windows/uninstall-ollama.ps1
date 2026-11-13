# Shadow-AI eviction: Ollama (local-inference runtime).
#
# Ollama runs local LLMs and exposes a REST API on 11434. Installer is
# OllamaSetup.exe (Inno Setup) and lands at %LOCALAPPDATA%\Programs\Ollama
# per user. Recent versions register a Windows service named "Ollama"
# AND start a tray app via Run-key. Models are pulled into
# %USERPROFILE%\.ollama\models -- typically multi-GB; sweeping that is
# intentional because (a) it's the data-egress concern and (b) leaving
# it behind means a re-installed Ollama re-exposes the same models
# without operator review.

$swept = 0
$uninstallerRan = 0
$killed = 0
$serviceRemoved = $false

# 1. Service teardown. Ollama installs as service "Ollama" on recent
# versions; older versions ran tray-only.
if (Stop-AndRemoveService -ServiceName 'Ollama') {
    $serviceRemoved = $true
}

# 2. Process kill. Cover the tray app, the daemon, and the per-model
# llama-runner spawned children.
$killed += Stop-ProcessesByName @('ollama', 'ollama app', 'ollama_llama_server', 'ollama-runner')

# 3. Vendor uninstaller (Inno Setup unins000.exe).
$uninstallerRan += Invoke-VendorUninstall -DisplayNameRegex '^Ollama( for Windows)?$' -SilentArgs '/SILENT /SUPPRESSMSGBOXES /NORESTART'

# 4. Sweep install + data dirs across every user profile.
$candidates = @(
    "$env:ProgramFiles\Ollama",
    "${env:ProgramFiles(x86)}\Ollama",
    "$env:ProgramData\Ollama"
)
foreach ($profile in Get-UserProfilePaths) {
    $candidates += @(
        "$($profile.LocalAppData)\Programs\Ollama",
        "$($profile.LocalAppData)\Ollama",
        # Model store — main data-egress surface.
        "$($profile.Home)\.ollama"
    )
}
$swept += Sweep-Paths -Paths $candidates

# 5. Per-user Run-key cleanup (tray autostart). We don't touch other
# values; only the Ollama key is removed.
foreach ($profile in Get-UserProfilePaths) {
    $sid = (Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -eq $profile.Home }).SID
    if (-not $sid) { continue }
    $runKey = "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Run"
    if (Test-Path -LiteralPath $runKey) {
        try {
            Remove-ItemProperty -LiteralPath $runKey -Name 'Ollama' -Force -ErrorAction Stop
            Write-Output "[eyas] removed Run-key Ollama for $($profile.User)"
        } catch { }
    }
}

$pendingRebootCount = $script:PendingRebootPaths.Count
Write-Output "[eyas] uninstall-ollama done service_removed=$serviceRemoved uninstaller_ran=$uninstallerRan processes_killed=$killed swept=$swept pending_reboot=$pendingRebootCount host=$env:COMPUTERNAME"
if ($pendingRebootCount -gt 0) {
    Write-Output "[eyas] pending-reboot paths: $($script:PendingRebootPaths -join '; ')"
}

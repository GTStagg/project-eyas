# Shadow-AI eviction: ComfyUI (image / video generation).
#
# ComfyUI is NOT a packaged installer -- it's a Python project the user
# clones (or extracts the "ComfyUI portable" zip) into a folder of their
# choice. There is no DisplayName / UninstallString to walk; eviction is
# (a) kill the python.exe process whose cmdline references ComfyUI's
# main.py and (b) sweep candidate install roots.
#
# Model cache is a real concern: ComfyUI checkpoints live under
# `<root>\models\checkpoints` and are typically multi-GB. Sweeping the
# install root removes them; the operator can preserve them by copying
# the models/ subtree before approving this run.
#
# Unlike the other Shadow-AI scripts, this one accepts an optional
# install_root param. When supplied (typical case: the scan output named
# the path), only that root is swept. When omitted, the script falls
# back to a candidate-list sweep of common locations.

$swept = 0
$killed = 0

# 1. Kill any python.exe whose cmdline references ComfyUI's main.py or
# the ComfyUI server module. CIM_Process .CommandLine is the reliable
# source for full cmdline under SYSTEM.
$pythonImages = @('python.exe', 'pythonw.exe', 'python3.exe')
$comfyRx = '(?i)comfyui|ComfyUI[\\/](?:main|server)\.py'
Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
        $_.Name -and ($pythonImages -contains $_.Name.ToLower()) -and
        $_.CommandLine -and ($_.CommandLine -match $comfyRx)
    } |
    ForEach-Object {
        try {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
            $killed += 1
            Write-Output "[falcon-extras] killed ComfyUI python pid=$($_.ProcessId)"
        } catch {
            Write-Output "[falcon-extras] failed to kill pid=$($_.ProcessId): $_"
        }
    }

# 2. Sweep. If $InstallRoot is supplied via $Params, that wins; otherwise
# walk a candidate list across user profiles + common locations.
$installRoot = $null
if ($Params -and $Params.ContainsKey('install_root')) {
    $installRoot = $Params['install_root']
}

if ($installRoot) {
    $swept += Sweep-Paths -Paths @($installRoot)
} else {
    $candidates = @(
        'C:\ComfyUI',
        'C:\ComfyUI_windows_portable',
        'C:\AI\ComfyUI',
        'C:\Tools\ComfyUI',
        "$env:ProgramFiles\ComfyUI",
        "${env:ProgramFiles(x86)}\ComfyUI"
    )
    foreach ($profile in Get-UserProfilePaths) {
        $candidates += @(
            "$($profile.Home)\ComfyUI",
            "$($profile.Home)\ComfyUI_windows_portable",
            "$($profile.Home)\Documents\ComfyUI",
            "$($profile.Home)\Desktop\ComfyUI",
            "$($profile.Home)\Downloads\ComfyUI",
            "$($profile.Home)\Downloads\ComfyUI_windows_portable",
            "$($profile.LocalAppData)\ComfyUI",
            "$($profile.LocalAppData)\Programs\ComfyUI"
        )
    }
    $swept += Sweep-Paths -Paths $candidates
}

# 3. Pinokio launcher residue (commonly bundled to install ComfyUI).
foreach ($profile in Get-UserProfilePaths) {
    $pinokio = "$($profile.Home)\pinokio\api\comfy.git"
    if (Test-Path -LiteralPath $pinokio) {
        if (Remove-OrSchedulePendingReboot -Path $pinokio) {
            $swept += 1
            Write-Output "[falcon-extras] swept Pinokio comfy.git for $($profile.User)"
        }
    }
}

$pendingRebootCount = $script:PendingRebootPaths.Count
Write-Output "[falcon-extras] uninstall-comfyui done processes_killed=$killed swept=$swept pending_reboot=$pendingRebootCount host=$env:COMPUTERNAME"
if ($pendingRebootCount -gt 0) {
    Write-Output "[falcon-extras] pending-reboot paths: $($script:PendingRebootPaths -join '; ')"
}

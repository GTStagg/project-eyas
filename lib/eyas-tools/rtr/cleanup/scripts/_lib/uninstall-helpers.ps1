# Shared helpers for Shadow-AI per-product uninstall scripts.
#
# Concerns covered:
#   * MoveFileEx pending-reboot fallback for locked files (same idiom used
#     in uninstall-anydesk.ps1; centralized here so the per-product
#     scripts stay short).
#   * User-profile enumeration. Most modern AI desktop apps ship as
#     Electron / Squirrel installs under per-user %LOCALAPPDATA%; cleanup
#     under SYSTEM has to walk every user profile, not just the running
#     user's. Get-UserProfilePaths returns hashtables with {User, Home,
#     LocalAppData, AppData} for every non-system profile on the box.
#   * Registry-driven vendor-uninstaller invocation. Most Squirrel /
#     NSIS / Inno installers register an UninstallString under
#     HKCU/HKLM Software\Microsoft\Windows\CurrentVersion\Uninstall\<key>;
#     Invoke-VendorUninstall walks 32-bit + 64-bit + per-user hives,
#     finds entries whose DisplayName matches a regex, and runs each
#     UninstallString with vendor-supplied silent flags appended.
#   * Service teardown shorthand.
#
# All helpers are SilentlyContinue-friendly; per-product scripts inspect
# return values to build the structured summary line.

$ErrorActionPreference = 'SilentlyContinue'

if (-not ('NativeMethods.Kernel32' -as [type])) {
    Add-Type -Namespace 'NativeMethods' -Name 'Kernel32' -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto, SetLastError=true)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
"@ -ErrorAction SilentlyContinue
}

# Module-scope buffer for pending-reboot paths. Per-product scripts read
# it after the sweep and surface the count in the summary line.
$script:PendingRebootPaths = @()

function Remove-OrSchedulePendingReboot {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        return $true
    } catch {
        try {
            $scheduled = [NativeMethods.Kernel32]::MoveFileEx($Path, $null, 4)
            if ($scheduled) {
                $script:PendingRebootPaths += $Path
                Write-Output "[eyas] $Path locked -- scheduled for deletion at next reboot"
                return $true
            }
        } catch { }
        Write-Output "[eyas] failed to remove ${Path}: $_"
        return $false
    }
}

function Get-UserProfilePaths {
    # Walk every Win32_UserProfile that's not Special (excludes SYSTEM /
    # NetworkService / LocalService / DefaultAppPool). Returns one
    # hashtable per profile.
    $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { -not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) }
    foreach ($p in $profiles) {
        $home = $p.LocalPath
        [pscustomobject]@{
            User         = Split-Path -Leaf $home
            Home         = $home
            LocalAppData = Join-Path $home 'AppData\Local'
            AppData      = Join-Path $home 'AppData\Roaming'
        }
    }
}

function Stop-AndRemoveService {
    param([Parameter(Mandatory)][string]$ServiceName)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) { return $false }
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    }
    $out = & sc.exe delete $ServiceName 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Output "[eyas] removed service $ServiceName"
        return $true
    }
    Write-Output "[eyas] sc.exe delete $ServiceName failed: $out"
    return $false
}

function Stop-ProcessesByName {
    param([Parameter(Mandatory)][string[]]$Names)
    $killed = 0
    foreach ($name in $Names) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                Stop-Process -Id $_.Id -Force -ErrorAction Stop
                $killed += 1
                Write-Output "[eyas] killed $name pid=$($_.Id)"
            } catch {
                Write-Output "[eyas] failed to kill $name pid=$($_.Id): $_"
            }
        }
    }
    return $killed
}

function Invoke-VendorUninstall {
    # Walk Uninstall hives for entries whose DisplayName matches
    # $DisplayNameRegex. Run each entry's UninstallString (or
    # QuietUninstallString if present) with $SilentArgs appended.
    # Returns the count of uninstallers actually invoked.
    param(
        [Parameter(Mandatory)][string]$DisplayNameRegex,
        [string]$SilentArgs = '/S'
    )
    $hives = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    # Per-user HKU walk: enumerate loaded user hives so we catch other
    # users' Squirrel installs even when running as SYSTEM.
    try {
        New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
        Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match 'S-1-5-21-' -and $_.Name -notmatch '_Classes$'
        } | ForEach-Object {
            $hives += "HKU:\$(($_.Name -split '\\')[-1])\Software\Microsoft\Windows\CurrentVersion\Uninstall"
        }
    } catch { }

    $invoked = 0
    foreach ($hive in $hives) {
        if (-not (Test-Path -LiteralPath $hive)) { continue }
        $entries = Get-ChildItem -LiteralPath $hive -ErrorAction SilentlyContinue
        foreach ($e in $entries) {
            $props = Get-ItemProperty -LiteralPath $e.PSPath -ErrorAction SilentlyContinue
            $display = $props.DisplayName
            if (-not $display) { continue }
            if ($display -notmatch $DisplayNameRegex) { continue }

            $cmd = $props.QuietUninstallString
            if (-not $cmd) { $cmd = $props.UninstallString }
            if (-not $cmd) { continue }

            Write-Output "[eyas] uninstalling '$display' via $cmd"
            try {
                $exe = $null; $rest = $null
                if ($cmd.StartsWith('"')) {
                    $idx = $cmd.IndexOf('"', 1)
                    if ($idx -gt 0) {
                        $exe = $cmd.Substring(1, $idx - 1)
                        $rest = $cmd.Substring($idx + 1).Trim()
                    }
                } else {
                    $first = $cmd.IndexOf(' ')
                    if ($first -gt 0) {
                        $exe = $cmd.Substring(0, $first)
                        $rest = $cmd.Substring($first + 1).Trim()
                    } else {
                        $exe = $cmd
                        $rest = ''
                    }
                }
                if (-not $exe -or -not (Test-Path -LiteralPath $exe)) {
                    Write-Output "[eyas] uninstaller exe not found: $exe"
                    continue
                }
                $argList = if ($rest) { "$rest $SilentArgs" } else { $SilentArgs }
                $p = Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru -NoNewWindow -ErrorAction Stop
                $invoked += 1
                Write-Output "[eyas] '$display' uninstaller exit=$($p.ExitCode)"
            } catch {
                Write-Output "[eyas] uninstall '$display' failed: $_"
            }
        }
    }
    return $invoked
}

function Sweep-Paths {
    # Best-effort recursive sweep of a list of candidate paths. Returns
    # the count actually removed (or scheduled for pending-reboot).
    param([Parameter(Mandatory)][string[]]$Paths)
    $swept = 0
    foreach ($p in $Paths) {
        if (-not $p) { continue }
        if (-not (Test-Path -LiteralPath $p)) { continue }
        if (Remove-OrSchedulePendingReboot -Path $p) {
            $swept += 1
            Write-Output "[eyas] swept $p"
        }
    }
    return $swept
}

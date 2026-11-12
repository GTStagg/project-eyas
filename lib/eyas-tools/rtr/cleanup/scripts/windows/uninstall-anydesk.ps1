# RMM-persistence removal: AnyDesk.
#
# AnyDesk is heavily abused as an attacker-deployed remote-access tool
# (BlackByte, Conti spinoffs, BlackCat, Akira). This script evicts every
# install variant we have seen in the wild:
#   1. The portable / self-contained variant (run from %APPDATA% or
#      %ProgramData%) -- no service, no installer, just a binary the
#      operator launched once.
#   2. The fully-installed variant under %ProgramFiles(x86)% / %ProgramFiles%
#      with the AnyDesk service registered.
#
# Strategy:
#   a) Stop and delete the AnyDesk service (sc.exe delete).
#   b) Kill any AnyDesk.exe still running (covers the portable variant).
#   c) Try the vendor uninstaller first: AnyDesk.exe --remove --silent.
#      Falls back gracefully if the binary is missing.
#   d) Sweep known install + config dirs.
#
# This is destructive and cannot self-restore. Do not run on hosts where
# IT has legitimately deployed AnyDesk for support purposes.

$ErrorActionPreference = 'SilentlyContinue'
$swept = 0
$serviceRemoved = $false
$uninstallerRan = $false
$pendingReboot = @()

# MoveFileEx fallback for files that are still locked after service stop +
# uninstaller. Schedules deletion at next reboot (MOVEFILE_DELAY_UNTIL_REBOOT
# = 0x4). The attacker's persistence mechanism is severed (service removed,
# binary marked for deletion) even if the on-disk bytes survive until the
# operator reboots.
if (-not ('NativeMethods' -as [type])) {
    Add-Type -Namespace 'NativeMethods' -Name 'Kernel32' -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto, SetLastError=true)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
"@ -ErrorAction SilentlyContinue
}
function Remove-OrSchedulePendingReboot {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $true }
    try {
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
        return $true
    } catch {
        # Try MoveFileEx pending-reboot deletion. 0x4 = MOVEFILE_DELAY_UNTIL_REBOOT.
        try {
            $scheduled = [NativeMethods.Kernel32]::MoveFileEx($Path, $null, 4)
            if ($scheduled) {
                $script:pendingReboot += $Path
                Write-Output "[falcon-extras] $Path locked -- scheduled for deletion at next reboot"
                return $true
            }
        } catch { }
        Write-Output "[falcon-extras] failed to remove ${Path}: $_"
        return $false
    }
}

# 1. Service teardown.
$svc = Get-Service -Name 'AnyDesk' -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name 'AnyDesk' -Force -ErrorAction SilentlyContinue
    }
    $out = & sc.exe delete 'AnyDesk' 2>&1
    if ($LASTEXITCODE -eq 0) {
        $serviceRemoved = $true
        Write-Output "[falcon-extras] removed AnyDesk service"
    } else {
        Write-Output "[falcon-extras] sc.exe delete AnyDesk failed: $out"
    }
}

# 2. Kill any lingering AnyDesk processes.
Get-Process -Name 'AnyDesk' -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        Stop-Process -Id $_.Id -Force -ErrorAction Stop
        Write-Output "[falcon-extras] killed AnyDesk pid=$($_.Id)"
    } catch {
        Write-Output "[falcon-extras] failed to kill AnyDesk pid=$($_.Id): $_"
    }
}

# 3. Try the vendor uninstaller from each known install root. Includes
# attacker-portable drop locations (root-of-drive `C:\AnyDesk.exe`, common
# attacker staging dirs) -- the official installer never lands there, but
# attacker tooling routinely drops the portable binary at C:\ root or in
# C:\Temp / C:\Windows\Temp where any user-context process can write.
$candidates = @(
    "$env:ProgramFiles\AnyDesk\AnyDesk.exe",
    "${env:ProgramFiles(x86)}\AnyDesk\AnyDesk.exe",
    "$env:ProgramData\AnyDesk\AnyDesk.exe",
    "C:\AnyDesk.exe",
    "C:\Temp\AnyDesk.exe",
    "C:\Windows\Temp\AnyDesk.exe",
    "$env:APPDATA\AnyDesk.exe",
    "$env:LOCALAPPDATA\AnyDesk.exe"
)
foreach ($exe in $candidates) {
    if (-not $exe) { continue }
    if (-not (Test-Path $exe)) { continue }
    try {
        $proc = Start-Process -FilePath $exe -ArgumentList '--remove','--silent' `
            -Wait -PassThru -NoNewWindow -ErrorAction Stop
        $uninstallerRan = $true
        Write-Output "[falcon-extras] AnyDesk --remove from $exe exit=$($proc.ExitCode)"
    } catch {
        Write-Output "[falcon-extras] AnyDesk --remove failed at ${exe}: $_"
    }
}

# 4. Sweep install + config dirs. Vendor uninstaller leaves config behind
# (settings, trace logs, install id) -- that residue is exactly what
# attacker tooling reuses to re-authenticate, so wipe it. Uses
# Remove-OrSchedulePendingReboot so locked files (driver-held, in-use by a
# zombie process the kill missed, etc.) get scheduled for next-reboot
# delete via MoveFileEx instead of leaving the install partially intact.
$dirs = @(
    "$env:ProgramFiles\AnyDesk",
    "${env:ProgramFiles(x86)}\AnyDesk",
    "$env:ProgramData\AnyDesk",
    "$env:APPDATA\AnyDesk",
    "$env:LOCALAPPDATA\AnyDesk"
)
foreach ($dir in $dirs) {
    if (-not $dir) { continue }
    if (Test-Path $dir) {
        if (Remove-OrSchedulePendingReboot -Path $dir) {
            $swept += 1
            Write-Output "[falcon-extras] swept $dir"
        }
    }
}

# 5. Sweep portable / root-of-drive binaries. These are the attacker-favorite
# paths because they bypass installer registration entirely. The candidates
# list above covered them for the uninstaller pass; sweep them again here so
# the binary itself is actually removed (or scheduled-for-removal) even when
# the uninstaller wasn't applicable.
$portableBins = @(
    "C:\AnyDesk.exe",
    "C:\Temp\AnyDesk.exe",
    "C:\Windows\Temp\AnyDesk.exe",
    "$env:APPDATA\AnyDesk.exe",
    "$env:LOCALAPPDATA\AnyDesk.exe"
)
foreach ($bin in $portableBins) {
    if (-not $bin) { continue }
    if (Test-Path -LiteralPath $bin) {
        if (Remove-OrSchedulePendingReboot -Path $bin) {
            $swept += 1
            Write-Output "[falcon-extras] swept portable $bin"
        }
    }
}

$pendingRebootCount = $pendingReboot.Count
Write-Output "[falcon-extras] uninstall-anydesk done service_removed=$serviceRemoved uninstaller_ran=$uninstallerRan swept=$swept pending_reboot=$pendingRebootCount host=$env:COMPUTERNAME"
if ($pendingRebootCount -gt 0) {
    Write-Output "[falcon-extras] pending-reboot paths: $($pendingReboot -join '; ')"
}

# Image File Execution Options (IFEO) hijack removal -- MITRE T1546.012.
#
# Two related attack patterns share this script:
#   1. IFEO Debugger hijack: HKLM\...\Image File Execution Options\<image>\Debugger
#      = "<attacker.exe>". When victim.exe is launched, attacker.exe runs in
#      its place with the original args appended.
#   2. Silent Process Exit monitor: HKLM\...\Image File Execution Options\<image>
#      with GlobalFlag = 0x200 (FLG_MONITOR_SILENT_PROCESS_EXIT) paired with
#      HKLM\...\SilentProcessExit\<image>\MonitorProcess = "<attacker.exe>".
#      When victim.exe exits, MonitorProcess launches.
#
# Strategy:
#   - For the supplied image_name, locate four candidate subkeys:
#       HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>
#       HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<image>
#       HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<image>
#       HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<image>
#   - At each present subkey, capture priors then delete the attack-marker
#     values: Debugger, MonitorProcess, ReportingMode. Delete GlobalFlag
#     ONLY when its value matches the silent-exit trigger (0x200 bit set) --
#     Microsoft sets GlobalFlag legitimately on system processes for other
#     reasons, so wholesale removal is unsafe.
#   - If a subkey is empty after removal, delete the empty subkey too --
#     attacker-created IFEO entries shouldn't linger as forensics noise.
#   - Refuse to touch IFEO entries for known-system binaries (cmd.exe,
#     explorer.exe, etc.). Those exist as a foot-gun guard: an attacker who
#     hijacked cmd.exe needs operator-level review, not a one-click revert,
#     because reverting can lock out a remote-access path mid-IR.

$ErrorActionPreference = 'Stop'
$image = $Params.ImageName

if ([string]::IsNullOrWhiteSpace($image)) {
    Write-Output "image_name is empty"
    exit 1
}

# Foot-gun guard: refuse to revert IFEO on the handful of binaries where a
# bad revert breaks remote response. The operator should remediate these by
# hand after confirming the path back to the host.
$blockedSystem = @('cmd.exe','powershell.exe','pwsh.exe','explorer.exe','svchost.exe','wininit.exe','services.exe','lsass.exe','smss.exe','csrss.exe','winlogon.exe')
foreach ($b in $blockedSystem) {
    if ($image -ieq $b) {
        Write-Output "refusing to auto-revert IFEO on system-critical binary '$image' -- remediate by hand after confirming alternate access path"
        exit 1
    }
}

$bases = @(
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit',
    'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
)
$attackerValues = @('Debugger','MonitorProcess','ReportingMode')
$touchedSubkeys = 0
$removedValues = 0
$removedSubkeys = 0

foreach ($base in $bases) {
    $sub = Join-Path $base $image
    if (-not (Test-Path $sub)) { continue }
    $touchedSubkeys += 1
    Write-Output "[eyas] inspecting $sub"

    $priorValues = Get-ItemProperty -Path $sub -ErrorAction SilentlyContinue
    foreach ($v in $attackerValues) {
        if ($priorValues -and $priorValues.PSObject.Properties.Name -contains $v) {
            $prior = $priorValues.$v
            try {
                Remove-ItemProperty -Path $sub -Name $v -Force -ErrorAction Stop
                Write-Output "[eyas] removed $v (was '$prior') at $sub"
                $removedValues += 1
            } catch {
                Write-Output "[eyas] failed to remove $v at ${sub}: $_"
            }
        }
    }

    # GlobalFlag: only remove when the silent-exit trigger bit (0x200) is set.
    if ($priorValues -and $priorValues.PSObject.Properties.Name -contains 'GlobalFlag') {
        $gf = [int]$priorValues.GlobalFlag
        if (($gf -band 0x200) -ne 0) {
            try {
                Remove-ItemProperty -Path $sub -Name 'GlobalFlag' -Force -ErrorAction Stop
                Write-Output "[eyas] removed GlobalFlag (was 0x$([Convert]::ToString($gf,16)) -- silent-exit trigger) at $sub"
                $removedValues += 1
            } catch {
                Write-Output "[eyas] failed to remove GlobalFlag at ${sub}: $_"
            }
        } else {
            Write-Output "[eyas] leaving GlobalFlag=0x$([Convert]::ToString($gf,16)) at $sub (no silent-exit bit set; likely legitimate)"
        }
    }

    # Sweep the empty subkey.
    $remaining = Get-ItemProperty -Path $sub -ErrorAction SilentlyContinue
    $remainingValueCount = 0
    if ($remaining) {
        $remainingValueCount = ($remaining.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') }).Count
    }
    $remainingChildren = (Get-ChildItem -Path $sub -ErrorAction SilentlyContinue | Measure-Object).Count
    if ($remainingValueCount -eq 0 -and $remainingChildren -eq 0) {
        try {
            Remove-Item -Path $sub -Force -ErrorAction Stop
            Write-Output "[eyas] removed empty subkey $sub"
            $removedSubkeys += 1
        } catch {
            Write-Output "[eyas] failed to remove empty subkey ${sub}: $_"
        }
    }
}

if ($touchedSubkeys -eq 0) {
    Write-Output "[eyas] no IFEO / SilentProcessExit subkey present for image '$image' -- nothing to remediate"
    exit 0
}

Write-Output "[eyas] remove-ifeo-hijack done image='$image' subkeys_inspected=$touchedSubkeys values_removed=$removedValues empty_subkeys_removed=$removedSubkeys host=$env:COMPUTERNAME"

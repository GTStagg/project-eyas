# Nuke Adobe Flash Player. EOL since 2020-12-31; Adobe explicitly directs all
# users to uninstall. There is no "update" path -- the only fix Spotlight will
# accept is removal. Catches all three runtimes (NPAPI / ActiveX / PPAPI) in one
# pass via the registry uninstall keys.
$ErrorActionPreference = "Continue"

$keys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$victims = Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object {
    $name = $_.DisplayName
    if (-not $name) { return $false }
    # Examples seen in the wild:
    #   "Adobe Flash Player 32 NPAPI"
    #   "Adobe Flash Player 32 ActiveX"
    #   "Adobe Flash Player 32 PPAPI"
    #   "Adobe Flash Player ActiveX" (older builds, no major version in name)
    $name -match "^Adobe Flash Player"
}

if (-not $victims) {
    Write-Output "[falcon-extras] no Adobe Flash Player installs found host=$env:COMPUTERNAME"
    # Still sweep the leftover directories in case a prior uninstall left bits behind.
    $swept = 0
    foreach ($dir in @("$env:WINDIR\System32\Macromed\Flash", "$env:WINDIR\SysWOW64\Macromed\Flash")) {
        if (Test-Path $dir) {
            Write-Output "[falcon-extras] removing leftover directory $dir"
            Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
            if (-not (Test-Path $dir)) { $swept++ }
        }
    }
    Write-Output "[falcon-extras] flash-uninstall done (no installs, swept=$swept) host=$env:COMPUTERNAME"
    exit 0
}

Write-Output "[falcon-extras] found $($victims.Count) Adobe Flash Player install(s):"
$victims | ForEach-Object { Write-Output "  - $($_.DisplayName)  [$($_.PSChildName)]" }

$failed = 0
foreach ($v in $victims) {
    $guid = $v.PSChildName
    if ($guid -match "^\{[0-9A-Fa-f\-]+\}$") {
        Write-Output "[falcon-extras] uninstalling $($v.DisplayName) via msiexec /x $guid"
        $proc = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList "/x", $guid, "/qn", "/norestart" `
            -Wait -PassThru -NoNewWindow
        Write-Output "[falcon-extras]   exit=$($proc.ExitCode)"
        if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) { $failed++ }
        continue
    }

    # Non-MSI install -- typically the standalone Adobe installer. Parse the
    # registry UninstallString and append the silent flags. Adobe's installer
    # accepts -uninstall (it ignores unknown args, so passing it on the MSI
    # path would also be safe, but we only get here when it's not MSI).
    $cmd = $v.UninstallString
    if (-not $cmd) {
        Write-Output "[falcon-extras] skipping $($v.DisplayName) -- no UninstallString in registry"
        $failed++
        continue
    }
    # UninstallString examples:
    #   "C:\Windows\SysWOW64\Macromed\Flash\FlashUtil32_32_0_0_465_Plugin.exe" -uninstallUnlock
    #   C:\Windows\System32\Macromed\Flash\FlashUtil64_32_0_0_465_ActiveX.exe -maintain activex
    # We exec it as-is and append -uninstall for safety; the silent switch
    # supported by every Adobe FlashUtil build is the bare -uninstall.
    if ($cmd -match '^\s*"([^"]+)"\s*(.*)$') {
        $exe = $matches[1]
        $args = "$($matches[2]) -uninstall".Trim()
    } else {
        # Unquoted path -- split on first space.
        $parts = $cmd -split ' ', 2
        $exe = $parts[0]
        $args = if ($parts.Length -gt 1) { "$($parts[1]) -uninstall" } else { "-uninstall" }
    }
    if (-not (Test-Path $exe)) {
        Write-Output "[falcon-extras] skipping $($v.DisplayName) -- uninstaller not on disk: $exe"
        $failed++
        continue
    }
    Write-Output "[falcon-extras] uninstalling $($v.DisplayName) via $exe $args"
    $proc = Start-Process -FilePath $exe -ArgumentList $args `
        -Wait -PassThru -NoNewWindow
    Write-Output "[falcon-extras]   exit=$($proc.ExitCode)"
    if ($proc.ExitCode -ne 0) { $failed++ }
}

# Scrub leftover Macromed directories. Adobe uninstallers occasionally leave
# the OCX / DLL / config bits behind, which keeps Spotlight reporting the
# product as installed even after the registry entry is gone.
$swept = 0
foreach ($dir in @("$env:WINDIR\System32\Macromed\Flash", "$env:WINDIR\SysWOW64\Macromed\Flash")) {
    if (Test-Path $dir) {
        Write-Output "[falcon-extras] removing leftover directory $dir"
        Remove-Item -Path $dir -Recurse -Force -ErrorAction SilentlyContinue
        if (-not (Test-Path $dir)) { $swept++ }
        else { Write-Output "[falcon-extras]   WARN: $dir still present after Remove-Item"; $failed++ }
    }
}

Write-Output "[falcon-extras] flash-uninstall done failed=$failed of $($victims.Count) swept=$swept host=$env:COMPUTERNAME"
exit $failed

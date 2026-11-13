# Nuke legacy Oracle JRE 6 / 7 / 8. These are EOL and a perpetual source of
# Spotlight findings. We do NOT touch OpenJDK, Adoptium / Temurin, Azul Zulu,
# or Oracle JDK 11+/17+/21+ -- those are actively maintained and may be
# load-bearing for tooling on the host.
$ErrorActionPreference = "Continue"

$keys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
)

$victims = Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object {
    $name = $_.DisplayName
    $publisher = $_.Publisher
    if (-not $name) { return $false }
    # Match legacy Oracle/Sun JRE only. Examples: "Java 8 Update 281", "Java(TM) 7 Update 80",
    # "J2SE Runtime Environment 5.0 Update 22", "Java SE Development Kit 8 Update 281" (the
    # standalone JRE bundled inside the JDK installer registers separately as "Java 8...").
    ($publisher -match "Oracle|Sun Microsystems") -and (
        $name -match "^Java(\(TM\))?\s+[6-8]\b" -or
        $name -match "^J2SE Runtime Environment" -or
        $name -match "^Java\s+SE\s+Runtime\s+Environment\s+[6-8]"
    )
}

if (-not $victims) {
    Write-Output "[eyas] no legacy Oracle JRE installs found host=$env:COMPUTERNAME"
    exit 0
}

Write-Output "[eyas] found $($victims.Count) legacy JRE install(s):"
$victims | ForEach-Object { Write-Output "  - $($_.DisplayName)  [$($_.PSChildName)]" }

$failed = 0
foreach ($v in $victims) {
    $guid = $v.PSChildName
    if ($guid -notmatch "^\{[0-9A-Fa-f\-]+\}$") {
        Write-Output "[eyas] skipping $($v.DisplayName) -- non-MSI uninstall key ($guid)"
        $failed++
        continue
    }
    Write-Output "[eyas] uninstalling $($v.DisplayName) via msiexec /x $guid"
    $proc = Start-Process -FilePath "msiexec.exe" `
        -ArgumentList "/x", $guid, "/qn", "/norestart" `
        -Wait -PassThru -NoNewWindow
    Write-Output "[eyas]   exit=$($proc.ExitCode)"
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) { $failed++ }
}

Write-Output "[eyas] jre-uninstall done failed=$failed of $($victims.Count) host=$env:COMPUTERNAME"
exit $failed

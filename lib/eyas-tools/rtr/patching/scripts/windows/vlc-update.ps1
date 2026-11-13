# VideoLAN doesn't expose a stable versionless URL for the Windows MSI -- the
# /last/ index lists the current release and we pick the .msi by name. Mirrors
# all serve identical content; using the canonical download host avoids mirror
# selection latency.
$index = "https://download.videolan.org/pub/videolan/vlc/last/win64/"
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
$page = Invoke-WebRequest -Uri $index -UseBasicParsing -ErrorAction Stop
$href = ($page.Links | Where-Object { $_.href -match '^vlc-[\d.]+-win64\.msi$' } | Select-Object -First 1).href
if (-not $href) {
    Write-Error "Could not locate VLC win64 MSI in $index"
    exit 6
}
$url = $index + $href
$result = @(Install-FromUrl -Url $url -ProductName "VLC media player" -Kind "msi")
$result | Where-Object { $_ -isnot [int] }
$exit = Get-InstallExitCode $result
Write-Output "[eyas] vlc-update version=$href exit=$exit host=$env:COMPUTERNAME"
exit $exit

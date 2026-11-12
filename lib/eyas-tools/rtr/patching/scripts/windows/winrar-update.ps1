# WinRAR's stable filename pattern is winrar-x64-<3-digit-version>.exe at
# rarlab.com/rar/. No JSON API; scrape the download page for the current
# en-US x64 link.
$base = "https://www.rarlab.com"
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
$page = Invoke-WebRequest -Uri "$base/download.htm" -UseBasicParsing -ErrorAction Stop
# Match anchors whose href looks like /rar/winrar-x64-740.exe -- pick the first
# (the page lists English builds at the top, then localized builds).
$href = ($page.Links | Where-Object { $_.href -match "^(/rar/)?winrar-x64-\d+\.exe$" } | Select-Object -First 1).href
if (-not $href) {
    Write-Error "Could not locate WinRAR x64 download link on rarlab download page"
    exit 6
}
if ($href -notmatch "^https?://") { $href = $base + ($(if ($href.StartsWith("/")) { "" } else { "/" })) + $href }
# WinRAR's installer accepts /S for silent install (Inno-like).
$exit = Install-FromUrl -Url $href -ProductName "WinRAR" -Kind "exe" -SilentArgs "/S"
Write-Output "[falcon-extras] winrar-update url=$href exit=$exit host=$env:COMPUTERNAME"
exit $exit

# Firefox enterprise MSI. Mozilla's download.mozilla.org redirector with
# product=firefox-msi-latest-ssl is unreliable in practice -- the resolved
# URL frequently 404s and the cross-domain redirect to download-installer
# .cdn.mozilla.net mishandles URL-encoded spaces in the MSI filename. Mozilla's
# documented enterprise pattern is: query product-details for the current
# stable version, then pull the version-pinned MSI from archive.mozilla.org.
# Two HTTP calls but bulletproof.

$ErrorActionPreference = "Stop"

# TLS 1.2 already forced by msi-installer.ps1 preamble; reaffirm here in case
# this script ever runs without the preamble.
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

try {
    $versions = Invoke-RestMethod -UseBasicParsing `
        -Uri "https://product-details.mozilla.org/1.0/firefox_versions.json"
    $version = $versions.LATEST_FIREFOX_VERSION
    if (-not $version) { throw "product-details JSON missing LATEST_FIREFOX_VERSION" }
    Write-Output "[falcon-extras] resolved Firefox stable version: $version"
} catch {
    Write-Output "[falcon-extras] WARN: product-details lookup failed ($($_.Exception.Message)); falling back to redirector"
    $url = "https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en-US"
    $result = @(Install-FromUrl -Url $url -ProductName "Mozilla Firefox" -Kind "msi")
    $result | Where-Object { $_ -isnot [int] }
    $exit = Get-InstallExitCode $result
    Write-Output "[falcon-extras] firefox-update exit=$exit host=$env:COMPUTERNAME"
    exit $exit
}

# Archive layout: https://archive.mozilla.org/pub/firefox/releases/<version>/win64/<lang>/Firefox%20Setup%20<version>.msi
# The MSI filename has a literal space; URL-encode it once and Invoke-WebRequest
# preserves the encoding through the request.
$encodedFile = "Firefox%20Setup%20$version.msi"
$url = "https://archive.mozilla.org/pub/firefox/releases/$version/win64/en-US/$encodedFile"

$result = @(Install-FromUrl -Url $url -ProductName "Mozilla Firefox $version" -Kind "msi")
$result | Where-Object { $_ -isnot [int] }
$exit = Get-InstallExitCode $result
Write-Output "[falcon-extras] firefox-update exit=$exit host=$env:COMPUTERNAME"
exit $exit

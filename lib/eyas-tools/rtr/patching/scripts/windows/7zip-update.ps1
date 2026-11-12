# 7-Zip -- official repo at ip7z/7zip on GitHub publishes MSI installers per
# release. Query the API for the latest x64 MSI and install it.
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "falcon-extras")
$json = $wc.DownloadString("https://api.github.com/repos/ip7z/7zip/releases/latest")
$asset = ($json | ConvertFrom-Json).assets | Where-Object { $_.name -match "^7z[0-9]+-x64\.msi$" } | Select-Object -First 1
if (-not $asset) {
    Write-Error "Could not locate 7-Zip x64 MSI in latest release."
    exit 6
}
$exit = Install-FromUrl -Url $asset.browser_download_url -ProductName "7-Zip" -Kind "msi"
Write-Output "[falcon-extras] 7zip-update version=$($asset.name) exit=$exit host=$env:COMPUTERNAME"
exit $exit

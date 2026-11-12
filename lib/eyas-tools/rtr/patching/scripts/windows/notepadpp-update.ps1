# Notepad++ has no stable "latest" URL -- query GitHub Releases for the most
# recent x64 installer, then download + install silently.
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "falcon-extras")
$json = $wc.DownloadString("https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases/latest")
$asset = ($json | ConvertFrom-Json).assets | Where-Object { $_.name -match "Installer\.x64\.exe$" } | Select-Object -First 1
if (-not $asset) {
    Write-Error "Could not locate Notepad++ x64 installer in latest release."
    exit 6
}
$result = @(Install-FromUrl -Url $asset.browser_download_url -ProductName "Notepad++" -Kind "exe" -SilentArgs "/S")
$result | Where-Object { $_ -isnot [int] }
$exit = Get-InstallExitCode $result
Write-Output "[falcon-extras] notepadpp-update version=$($asset.name) exit=$exit host=$env:COMPUTERNAME"
exit $exit

# Git for Windows ships only as an Inno Setup .exe -- query GitHub Releases
# for the current 64-bit installer. Same pattern as notepadpp-update.
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "falcon-extras")
$json = $wc.DownloadString("https://api.github.com/repos/git-for-windows/git/releases/latest")
$asset = ($json | ConvertFrom-Json).assets | Where-Object { $_.name -match "^Git-.*-64-bit\.exe$" } | Select-Object -First 1
if (-not $asset) {
    Write-Error "Could not locate Git for Windows 64-bit installer in latest release."
    exit 6
}
# Inno Setup silent flags: /VERYSILENT (no UI), /NORESTART (let our reboot policy decide),
# /SUPPRESSMSGBOXES (don't block on prompts), /CLOSEAPPLICATIONS (kill open git.exe so
# files aren't locked). Default install path / components.
$result = @(Install-FromUrl -Url $asset.browser_download_url -ProductName "Git for Windows" -Kind "exe" `
    -SilentArgs "/VERYSILENT /NORESTART /SUPPRESSMSGBOXES /CLOSEAPPLICATIONS")
$result | Where-Object { $_ -isnot [int] }
$exit = Get-InstallExitCode $result
Write-Output "[falcon-extras] git-update version=$($asset.name) exit=$exit host=$env:COMPUTERNAME"
exit $exit

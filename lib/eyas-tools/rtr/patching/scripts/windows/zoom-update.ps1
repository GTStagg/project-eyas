# Zoom IT-admin MSI -- Zoom keeps the URL versionless and always rolls forward
# to the latest GA build. archType=x64 forces the 64-bit installer.
$url = "https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64"
$result = @(Install-FromUrl -Url $url -ProductName "Zoom" -Kind "msi")
$result | Where-Object { $_ -isnot [int] }
$exit = Get-InstallExitCode $result
Write-Output "[falcon-extras] zoom-update exit=$exit host=$env:COMPUTERNAME"
exit $exit

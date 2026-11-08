# Zoom IT-admin MSI -- Zoom keeps the URL versionless and always rolls forward
# to the latest GA build. archType=x64 forces the 64-bit installer.
$url = "https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64"
$exit = Install-FromUrl -Url $url -ProductName "Zoom" -Kind "msi"
Write-Output "[falcon-extras] zoom-update exit=$exit host=$env:COMPUTERNAME"
exit $exit

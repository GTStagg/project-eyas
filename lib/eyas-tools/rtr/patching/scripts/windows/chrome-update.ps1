# Google Chrome enterprise MSI -- stable URL Google maintains for IT admins.
$url = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
$exit = Install-FromUrl -Url $url -ProductName "Google Chrome" -Kind "msi"
Write-Output "[falcon-extras] chrome-update exit=$exit host=$env:COMPUTERNAME"
exit $exit

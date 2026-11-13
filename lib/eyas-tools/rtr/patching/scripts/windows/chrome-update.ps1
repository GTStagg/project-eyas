# Google Chrome enterprise MSI -- stable URL Google maintains for IT admins.
$url = "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
$result = @(Install-FromUrl -Url $url -ProductName "Google Chrome" -Kind "msi")
$result | Where-Object { $_ -isnot [int] }
$exit = Get-InstallExitCode $result
Write-Output "[eyas] chrome-update exit=$exit host=$env:COMPUTERNAME"
exit $exit

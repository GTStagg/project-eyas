# Microsoft Edge for Business -- fwlink redirects to current stable x64 MSI.
# Edge normally auto-updates; an explicit MSI push covers hosts where the
# Edge update service is disabled or stalled.
$url = "https://go.microsoft.com/fwlink/?linkid=2093437"
$exit = Install-FromUrl -Url $url -ProductName "Microsoft Edge" -Kind "msi"
Write-Output "[falcon-extras] edge-update exit=$exit host=$env:COMPUTERNAME"
exit $exit

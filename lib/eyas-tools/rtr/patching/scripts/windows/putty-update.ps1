# Simon Tatham's site keeps a stable "latest" alias for the 64-bit MSI.
$url = "https://the.earth.li/~sgtatham/putty/latest/w64/putty-64bit-installer.msi"
$result = @(Install-FromUrl -Url $url -ProductName "PuTTY" -Kind "msi")
$result | Where-Object { $_ -isnot [int] }
$exit = Get-InstallExitCode $result
Write-Output "[falcon-extras] putty-update exit=$exit host=$env:COMPUTERNAME"
exit $exit

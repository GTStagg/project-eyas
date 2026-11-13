# Adobe maintains a stable "always points at the current GA" URL for the
# Acrobat Reader 64-bit installer at admdownload.adobe.com. The installer is
# the full bundle (~250MB) -- it'll cleanly upgrade an existing install and
# is also a fresh install if Reader isn't present.
$url = "https://admdownload.adobe.com/bin/live/readerdc64_en_a_install.exe"
# /sAll = silent everything, /rs = restart suppress, /msi = pass through to msiexec.
$result = @(Install-FromUrl -Url $url -ProductName "Adobe Acrobat Reader DC" -Kind "exe" `
    -SilentArgs "/sAll /rs /msi /norestart")
$result | Where-Object { $_ -isnot [int] }
$exit = Get-InstallExitCode $result
Write-Output "[eyas] acrobat-reader-update exit=$exit host=$env:COMPUTERNAME"
exit $exit

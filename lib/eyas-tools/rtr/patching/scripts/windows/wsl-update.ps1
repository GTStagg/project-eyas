# Update the WSL kernel + runtime in-place. Only meaningful on hosts where
# WSL is actually installed -- on a stock Server 2019 / older Win10 host
# `wsl.exe` may not exist; we treat that as "nothing to do" rather than fail.
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
    Write-Output "[eyas] wsl.exe not present on this host -- skipping host=$env:COMPUTERNAME"
    exit 0
}

# --web-download bypasses the Microsoft Store update path (disabled in many
# locked-down environments) and pulls the kernel package directly from MS.
Write-Output "[eyas] running wsl --update --web-download"
$proc = Start-Process -FilePath "wsl.exe" -ArgumentList "--update", "--web-download" `
    -Wait -PassThru -NoNewWindow
Write-Output "[eyas] wsl --update exit=$($proc.ExitCode) host=$env:COMPUTERNAME"
exit $proc.ExitCode

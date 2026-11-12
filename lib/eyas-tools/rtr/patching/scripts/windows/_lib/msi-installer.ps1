# Direct vendor-installer download + silent install.
# Designed to run under SYSTEM via RTR runscript, where winget is unreliable.

# Force TLS 1.2 globally for this PowerShell session. SYSTEM context on
# older Win10 builds defaults to TLS 1.0 / 1.1 which most vendor CDNs
# (Mozilla, Microsoft fwlink, Adobe) now reject outright -- manifests as
# "Unable to connect to remote server" rather than a useful HTTP error.
[Net.ServicePointManager]::SecurityProtocol = `
    [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Install-FromUrl parameters:
#   Url         -- vendor download URL
#   ProductName -- friendly name for log lines
#   Kind        -- 'msi' (msiexec /i /qn) or 'exe' (Start-Process with SilentArgs)
#   SilentArgs  -- exe-only; vendor silent-install switches
function Install-FromUrl {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$ProductName,
        [Parameter(Mandatory=$true)][ValidateSet("msi","exe")][string]$Kind,
        [string]$SilentArgs = "",
        [string]$Sha256 = ""
    )

    $ext = if ($Kind -eq "msi") { "msi" } else { "exe" }
    $tmp = Join-Path $env:TEMP "falcon-extras-$([guid]::NewGuid()).$ext"

    try {
        Write-Output "[falcon-extras] downloading $ProductName from $Url"
        # Invoke-WebRequest gives us a real HTTP status on failure (WebClient
        # just throws a generic WebException). UseBasicParsing avoids the IE
        # engine dependency that breaks under SYSTEM. Following redirects is
        # the default; we set MaximumRedirection high for vendor CDN chains.
        try {
            Invoke-WebRequest -Uri $Url -OutFile $tmp -UseBasicParsing `
                -MaximumRedirection 10 -ErrorAction Stop | Out-Null
        } catch [System.Net.WebException] {
            $resp = $_.Exception.Response
            if ($resp) {
                $code = [int]$resp.StatusCode
                $desc = $resp.StatusDescription
                Write-Error "Download failed: HTTP $code $desc (resolved URL: $($resp.ResponseUri))"
            } else {
                Write-Error "Download failed: $($_.Exception.Message)"
            }
            return 4
        } catch {
            Write-Error "Download failed: $($_.Exception.Message)"
            return 4
        }

        if (-not (Test-Path $tmp)) {
            Write-Error "Download claimed success but file not on disk"
            return 4
        }
        $size = (Get-Item $tmp).Length
        Write-Output "[falcon-extras] downloaded $size bytes -> $tmp"
        if ($size -lt 1024) {
            Write-Error "Downloaded file is suspiciously small ($size bytes). Aborting."
            return 5
        }

        # Optional integrity pin. When the caller supplies a SHA-256, verify the
        # downloaded bytes against it BEFORE install and abort on mismatch -- this
        # is the real integrity gate for the generic installer (HTTPS alone proves
        # transport, not that the file is the expected build). Empty pin skips
        # silently so existing callers with stable vendor URLs are unchanged.
        if ($Sha256) {
            $actual = (Get-FileHash -Path $tmp -Algorithm SHA256).Hash
            if ($actual -ine $Sha256) {
                Write-Error "Hash mismatch for $ProductName -- expected $Sha256 got $actual. Aborting before install."
                return 6
            }
            Write-Output "[falcon-extras] $ProductName SHA256 verified: $actual"
        }

        Write-Output "[falcon-extras] installing $ProductName"
        if ($Kind -eq "msi") {
            $proc = Start-Process -FilePath "msiexec.exe" `
                -ArgumentList "/i", "`"$tmp`"", "/qn", "/norestart", "REBOOT=ReallySuppress" `
                -Wait -PassThru -NoNewWindow
        } else {
            $argList = if ($SilentArgs) { $SilentArgs.Split(" ") } else { @() }
            $proc = Start-Process -FilePath $tmp -ArgumentList $argList -Wait -PassThru -NoNewWindow
        }
        $exit = $proc.ExitCode
        Write-Output "[falcon-extras] $ProductName installer exit=$exit"
        # MSI exit codes: 0 = success, 3010 = success-reboot-required.
        if ($Kind -eq "msi" -and $exit -eq 3010) {
            Write-Output "[falcon-extras] note: reboot required to complete $ProductName install"
            return 0
        }
        return $exit
    }
    finally {
        if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
    }
}

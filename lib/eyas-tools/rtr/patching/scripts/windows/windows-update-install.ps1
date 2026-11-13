# Install pending Windows Updates via the Windows Update Agent COM API.
# Built into every Windows host since Vista -- no module bootstrap required,
# which sidesteps PowerShellGet/NuGet version drift across Win10 / Win11 /
# Server 2019 / Server 2022.
#
# Params (set by library.py before this body):
#   $Params.KbFilter  -- comma-separated KB ids (e.g. "KB5034441,KB5040430"), or $null for all
#   $Params.Reboot    -- "never" | "if-required" | "force"

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()

Write-Output "[eyas] searching for pending updates"
$searchResult = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
$candidates = $searchResult.Updates
Write-Output "[eyas] found $($candidates.Count) candidate update(s)"

# Optional KB filter -- intersection of candidates with KbFilter list.
$kbList = $null
if ($Params.KbFilter) {
    $kbList = @($Params.KbFilter -split "," | ForEach-Object { $_.Trim().TrimStart("kK","K","k") })
    Write-Output "[eyas] KB filter active: $($kbList -join ', ')"
}

$selected = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $candidates) {
    if ($kbList) {
        $matches = $false
        foreach ($kb in $u.KBArticleIDs) {
            if ($kbList -contains $kb) { $matches = $true; break }
        }
        if (-not $matches) { continue }
    }
    if ($u.EulaAccepted -eq $false) { $u.AcceptEula() | Out-Null }
    $selected.Add($u) | Out-Null
}

if ($selected.Count -eq 0) {
    Write-Output "[eyas] nothing to install (filter matched 0 of $($candidates.Count) candidates)"
    exit 0
}

Write-Output "[eyas] downloading $($selected.Count) update(s)"
$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $selected
$downloadResult = $downloader.Download()
Write-Output "[eyas] download result code: $($downloadResult.ResultCode)  hresult: 0x$('{0:X}' -f $downloadResult.HResult)"
# ResultCode: 0=NotStarted, 1=InProgress, 2=Succeeded, 3=SucceededWithErrors, 4=Failed, 5=Aborted
if ($downloadResult.ResultCode -ne 2 -and $downloadResult.ResultCode -ne 3) {
    Write-Output "[eyas] download failed; aborting before install"
    exit 7
}

Write-Output "[eyas] installing $($selected.Count) update(s)"
$installer = $session.CreateUpdateInstaller()
$installer.Updates = $selected
$installResult = $installer.Install()
Write-Output "[eyas] install result code: $($installResult.ResultCode)  hresult: 0x$('{0:X}' -f $installResult.HResult)  reboot-required: $($installResult.RebootRequired)"
for ($i = 0; $i -lt $selected.Count; $i++) {
    $u = $selected.Item($i)
    $r = $installResult.GetUpdateResult($i)
    Write-Output "[eyas]   $($u.Title)  ResultCode=$($r.ResultCode)  HResult=0x$('{0:X}' -f $r.HResult)"
}

$rebootNeeded = $installResult.RebootRequired
switch ($Params.Reboot) {
    "force"       { if ($rebootNeeded) { Write-Output "[eyas] scheduling reboot (force)"; shutdown.exe /r /t 60 /c "falcon-extras post-patch reboot" } }
    "if-required" { if ($rebootNeeded) { Write-Output "[eyas] scheduling reboot (if-required)"; shutdown.exe /r /t 60 /c "falcon-extras post-patch reboot" } }
    default       { Write-Output "[eyas] reboot deferred (policy=never, reboot-required=$rebootNeeded)" }
}

Write-Output "[eyas] done $(Get-Date -Format o) host=$env:COMPUTERNAME"
# Map COM ResultCode to a sensible exit code: 2=success, 3=partial, anything else=fail
switch ($installResult.ResultCode) {
    2 { exit 0 }
    3 { exit 1 }
    default { exit 8 }
}

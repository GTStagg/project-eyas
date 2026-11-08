# Install pending .NET Framework updates via Microsoft Update.
#
# Why this is separate from win-update-install: by default the Windows Update
# Agent only fetches Windows-OS updates. .NET Framework cumulative updates
# (the ones Spotlight surfaces as "Update Microsoft .NET Framework to ...")
# only appear in the catalog after the host opts in to Microsoft Update --
# the same toggle as the "Receive updates for other Microsoft products"
# checkbox in the Settings UI. We register the Microsoft Update service
# programmatically, then drive the WUA COM API the same way win-update-install
# does, but with a category filter so we only act on .NET payloads.
#
# Params:
#   $Params.Reboot -- "never" | "if-required" | "force"

$ErrorActionPreference = "Continue"

# Step 1: register Microsoft Update with the WUA service manager. Idempotent
# -- adding an already-registered service is a no-op.
$mu = "7971f918-a847-4430-9279-4a52d1efe18d"  # canonical Microsoft Update service id
try {
    $sm = New-Object -ComObject Microsoft.Update.ServiceManager
    $existing = $sm.Services | Where-Object { $_.ServiceID -eq $mu }
    if (-not $existing) {
        Write-Output "[falcon-extras] enrolling host in Microsoft Update"
        # 7 = AddServiceFlag.AllowPendingRegistration | AllowOnline | RegisterServiceWithAU
        $sm.AddService2($mu, 7, "") | Out-Null
    } else {
        Write-Output "[falcon-extras] Microsoft Update already registered"
    }
} catch {
    Write-Error "Failed to register Microsoft Update service: $($_.Exception.Message)"
    exit 6
}

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
# ServerSelection 3 = ssOthers; pair with ServiceID to point the searcher at MU.
$searcher.ServerSelection = 3
$searcher.ServiceID = $mu

Write-Output "[falcon-extras] searching Microsoft Update for pending .NET Framework updates"
$searchResult = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
$candidates = $searchResult.Updates
Write-Output "[falcon-extras] $($candidates.Count) total candidate(s) returned"

$selected = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $candidates) {
    # .NET Framework updates carry both a "Microsoft .NET Framework" categorization
    # and a title that almost always contains "NET Framework" -- match either to
    # be resilient to category-data drift.
    $isDotNet = $false
    foreach ($c in $u.Categories) {
        if ($c.Name -match "\.NET Framework") { $isDotNet = $true; break }
    }
    if (-not $isDotNet -and $u.Title -match "\.NET Framework") { $isDotNet = $true }
    if (-not $isDotNet) { continue }

    if ($u.EulaAccepted -eq $false) { $u.AcceptEula() | Out-Null }
    $selected.Add($u) | Out-Null
}

if ($selected.Count -eq 0) {
    Write-Output "[falcon-extras] no pending .NET Framework updates host=$env:COMPUTERNAME"
    exit 0
}

Write-Output "[falcon-extras] selected $($selected.Count) .NET Framework update(s):"
for ($i = 0; $i -lt $selected.Count; $i++) {
    Write-Output "  - $($selected.Item($i).Title)"
}

$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $selected
$dl = $downloader.Download()
Write-Output "[falcon-extras] download result code=$($dl.ResultCode) hresult=0x$('{0:X}' -f $dl.HResult)"
if ($dl.ResultCode -ne 2 -and $dl.ResultCode -ne 3) { exit 7 }

$installer = $session.CreateUpdateInstaller()
$installer.Updates = $selected
$ir = $installer.Install()
Write-Output "[falcon-extras] install result code=$($ir.ResultCode) hresult=0x$('{0:X}' -f $ir.HResult) reboot-required=$($ir.RebootRequired)"

$rebootNeeded = $ir.RebootRequired
switch ($Params.Reboot) {
    "force"       { if ($rebootNeeded) { Write-Output "[falcon-extras] scheduling reboot (force)"; shutdown.exe /r /t 60 /c "falcon-extras .NET post-patch reboot" } }
    "if-required" { if ($rebootNeeded) { Write-Output "[falcon-extras] scheduling reboot (if-required)"; shutdown.exe /r /t 60 /c "falcon-extras .NET post-patch reboot" } }
    default       { Write-Output "[falcon-extras] reboot deferred (policy=never, reboot-required=$rebootNeeded)" }
}

switch ($ir.ResultCode) {
    2 { exit 0 }
    3 { exit 1 }
    default { exit 8 }
}

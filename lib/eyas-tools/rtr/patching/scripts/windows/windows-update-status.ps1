# Read-only: report pending Windows Updates without installing.
# Uses the WUA COM API for the same compatibility reasons as the install script.
$ErrorActionPreference = "Stop"

$session = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
$searchResult = $searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")
$pending = $searchResult.Updates

if ($pending.Count -eq 0) {
    Write-Output "[falcon-extras] no pending updates host=$env:COMPUTERNAME"
    exit 0
}

Write-Output "[falcon-extras] $($pending.Count) pending update(s) host=$env:COMPUTERNAME"
foreach ($u in $pending) {
    $kbs = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ","
    if (-not $kbs) { $kbs = "(no-KB)" }
    $sevText = if ($u.MsrcSeverity) { $u.MsrcSeverity } else { "Unspecified" }
    Write-Output "  $kbs  [$sevText]  $($u.Title)"
}

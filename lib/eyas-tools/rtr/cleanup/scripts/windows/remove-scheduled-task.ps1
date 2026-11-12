$ErrorActionPreference = 'Stop'
$full = $Params.TaskPath
$folder = Split-Path -Parent $full
$leaf = Split-Path -Leaf $full
if (-not $folder) { $folder = '\' }
if (-not $folder.EndsWith('\')) { $folder = $folder + '\' }

$task = Get-ScheduledTask -TaskName $leaf -TaskPath $folder -ErrorAction SilentlyContinue
if (-not $task) {
    Write-Output "scheduled task '$full' not found on this host"
    exit 0
}

# Capture for the operator audit trail before removal.
$action = ($task.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join '; '
$principal = $task.Principal.UserId
Write-Output "pre-removal: principal='$principal' action='$action'"

try {
    Unregister-ScheduledTask -TaskName $leaf -TaskPath $folder -Confirm:$false
    Write-Output "scheduled task '$full' removed"
} catch {
    Write-Output "removal failed for '$full': $_"
    exit 1
}

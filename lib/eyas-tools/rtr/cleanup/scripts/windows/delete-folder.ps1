$ErrorActionPreference = 'Stop'
$path = $Params.Path

if ([string]::IsNullOrWhiteSpace($path)) {
    Write-Output "path is empty"
    exit 1
}

$blocked = @(
    'C:\Windows',
    'C:\Program Files',
    'C:\Program Files (x86)',
    'C:\ProgramData\Microsoft',
    'C:\Users',
    'C:\Users\Public',
    'C:\ProgramData'
)
foreach ($b in $blocked) {
    if ($path -ieq $b) {
        Write-Output "refusing to delete protected directory: $b"
        exit 1
    }
}
$inProtectedTree = $false
foreach ($b in @('C:\Windows','C:\Program Files','C:\Program Files (x86)','C:\ProgramData\Microsoft')) {
    if ($path -like ($b + '\*')) { $inProtectedTree = $true; break }
}
if ($inProtectedTree) {
    Write-Output "refusing to delete inside protected directory tree: $path"
    exit 1
}

$trimmed = $path.TrimEnd('\')
$segments = ($trimmed -split '\\').Where({ $_ -ne '' }).Count
if ($segments -lt 3) {
    Write-Output "refusing to delete shallow path '$path' -- minimum depth is 3 segments (e.g. C:\Users\bob\target)"
    exit 1
}

if (-not (Test-Path -LiteralPath $path)) {
    Write-Output "no folder at '$path' on this host"
    exit 0
}

$item = Get-Item -LiteralPath $path -Force
if (-not $item.PSIsContainer) {
    Write-Output "refusing to delete '$path' -- not a directory (use host-delete-file)"
    exit 1
}

# MoveFileEx fallback for locked files. Schedules deletion at next reboot
# (MOVEFILE_DELAY_UNTIL_REBOOT = 0x4). Without this, a single locked file
# (locked JVM jar, in-use sqlite, lock-held log file) makes the whole
# Remove-Item -Recurse fail atomically, leaving the entire folder intact --
# the operator's expectation is "delete what you can, schedule the rest,
# tell me what stayed."
if (-not ('NativeMethods.Kernel32' -as [type])) {
    Add-Type -Namespace 'NativeMethods' -Name 'Kernel32' -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto, SetLastError=true)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
"@ -ErrorAction SilentlyContinue
}

# Pre-count for telemetry.
$children = Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
$preFileCount = ($children | Where-Object { -not $_.PSIsContainer }).Count
$totalBytes = ($children | Where-Object { -not $_.PSIsContainer } | Measure-Object -Property Length -Sum).Sum
if (-not $totalBytes) { $totalBytes = 0 }

# Two-pass deletion: first try the fast atomic path. If it succeeds, we're
# done. If it fails, fall through to the file-by-file walker that handles
# locked files individually.
$atomicSucceeded = $false
try {
    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
    $atomicSucceeded = $true
} catch {
    # Fall through to the resilient walker.
}

if ($atomicSucceeded) {
    Write-Output "deleted folder '$path' (files=$preFileCount, total=$totalBytes bytes)"
    exit 0
}

# Resilient file-by-file walker. Order: deepest-first so directory deletes
# happen after their contents are emptied. Locked files get scheduled for
# pending-reboot deletion via MoveFileEx; the report distinguishes
# `deleted` / `pending_reboot` / `failed`.
$deleted = 0
$pendingReboot = @()
$failed = @()

# Files first, deepest-first.
$allFiles = Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { -not $_.PSIsContainer } |
    Sort-Object -Property { $_.FullName.Length } -Descending
foreach ($f in $allFiles) {
    try {
        Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
        $deleted += 1
    } catch {
        $scheduled = $false
        try {
            $scheduled = [NativeMethods.Kernel32]::MoveFileEx($f.FullName, $null, 4)
        } catch { }
        if ($scheduled) {
            $pendingReboot += $f.FullName
        } else {
            $failed += "$($f.FullName) ($($_.Exception.Message))"
        }
    }
}

# Then directories, deepest-first. A directory whose children are all
# scheduled-for-pending-delete cannot be removed until reboot, so schedule
# the directory itself with MoveFileEx too.
$allDirs = Get-ChildItem -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.PSIsContainer } |
    Sort-Object -Property { $_.FullName.Length } -Descending
foreach ($d in $allDirs) {
    try {
        Remove-Item -LiteralPath $d.FullName -Recurse -Force -ErrorAction Stop
    } catch {
        $scheduled = $false
        try {
            $scheduled = [NativeMethods.Kernel32]::MoveFileEx($d.FullName, $null, 4)
        } catch { }
        if ($scheduled) {
            $pendingReboot += $d.FullName
        } else {
            $failed += "$($d.FullName) ($($_.Exception.Message))"
        }
    }
}

# Finally, the root.
try {
    Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop
} catch {
    $scheduled = $false
    try {
        $scheduled = [NativeMethods.Kernel32]::MoveFileEx($path, $null, 4)
    } catch { }
    if ($scheduled) {
        $pendingReboot += $path
    } else {
        $failed += "$path ($($_.Exception.Message))"
    }
}

$pendingCount = $pendingReboot.Count
$failedCount = $failed.Count
Write-Output "delete-folder '$path' result: deleted=$deleted pending_reboot=$pendingCount failed=$failedCount initial_files=$preFileCount initial_bytes=$totalBytes"
if ($pendingCount -gt 0) {
    Write-Output "  pending-reboot paths (locked, will delete on next boot):"
    foreach ($p in $pendingReboot) { Write-Output "    $p" }
}
if ($failedCount -gt 0) {
    Write-Output "  failed paths (could not delete or schedule -- investigate manually):"
    foreach ($p in $failed) { Write-Output "    $p" }
    exit 1
}
# Pending-reboot is partial success -- exit 0 so the catalog reports it as
# a successful run with attached metadata. Failed items (couldn't even
# schedule) are the only true error state.
exit 0

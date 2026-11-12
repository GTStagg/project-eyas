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
    'C:\ProgramData\Microsoft'
)
foreach ($b in $blocked) {
    if ($path -like ($b + '\*') -or $path -ieq $b) {
        Write-Output "refusing to delete inside protected directory: $b"
        exit 1
    }
}

if (-not (Test-Path -LiteralPath $path)) {
    Write-Output "no file at '$path' on this host"
    exit 0
}

$item = Get-Item -LiteralPath $path -Force
if ($item.PSIsContainer) {
    Write-Output "refusing to delete directory '$path' — script targets files only"
    exit 1
}

$size = $item.Length
$mtime = $item.LastWriteTimeUtc.ToString('o')

try {
    Remove-Item -LiteralPath $path -Force
    Write-Output "deleted '$path' (size=$size bytes, mtime=$mtime)"
} catch {
    Write-Output "delete failed for '$path': $_"
    exit 1
}

$ErrorActionPreference = 'Stop'
$path = $Params.Path
$qroot = 'C:\ProgramData\FalconCleanup\quarantine'

if ([string]::IsNullOrWhiteSpace($path)) {
    Write-Output "path is empty"
    exit 1
}

$blocked = @('C:\Windows','C:\Program Files','C:\Program Files (x86)','C:\ProgramData\Microsoft')
foreach ($b in $blocked) {
    if ($path -like ($b + '\*') -or $path -ieq $b) {
        Write-Output "refusing to quarantine inside protected directory: $b"
        exit 1
    }
}

if (-not (Test-Path -LiteralPath $path)) {
    Write-Output "no file at '$path' on this host"
    exit 0
}

$item = Get-Item -LiteralPath $path -Force
if ($item.PSIsContainer) {
    Write-Output "refusing to quarantine directory '$path' -- script targets files only"
    exit 1
}

if (-not (Test-Path -LiteralPath $qroot)) {
    New-Item -ItemType Directory -Path $qroot -Force | Out-Null
    $acl = Get-Acl -LiteralPath $qroot
    $acl.SetAccessRuleProtection($true, $false)
    $sysRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'NT AUTHORITY\SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $admRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($sysRule)
    $acl.AddAccessRule($admRule)
    Set-Acl -LiteralPath $qroot -AclObject $acl
}

$hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.Substring(0,16)
$stamp = (Get-Date -Format 'yyyyMMdd-HHmmss')
$qname = "$($item.Name).$hash.$stamp.quarantined"
$qpath = Join-Path $qroot $qname

$size = $item.Length
$mtime = $item.LastWriteTimeUtc.ToString('o')

try {
    Move-Item -LiteralPath $path -Destination $qpath -Force
    $manifest = @{
        original_path = $path
        original_size = $size
        original_mtime_utc = $mtime
        sha256_prefix = $hash
        quarantined_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json -Compress
    Set-Content -LiteralPath ($qpath + '.manifest.json') -Value $manifest -Encoding ASCII
    Write-Output "quarantined '$path' -> '$qpath' (size=$size bytes, sha256_prefix=$hash)"
} catch {
    Write-Output "quarantine failed for '$path': $_"
    exit 1
}

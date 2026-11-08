$ErrorActionPreference = 'Continue'
$killed = @()
$failed = @()

if ($Params.Pid) {
    $procId = [int]$Params.Pid
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $proc) {
        Write-Output "no process with pid=$procId on this host"
        exit 0
    }
    try {
        Stop-Process -Id $procId -Force -ErrorAction Stop
        $killed += "$($proc.ProcessName) (pid=$procId)"
    } catch {
        $failed += "pid=$procId : $_"
    }
} elseif ($Params.ImageName) {
    $procs = Get-Process | Where-Object { $_.ProcessName -match [regex]::Escape($Params.ImageName) }
    if (-not $procs) {
        Write-Output "no process matched image_name='$($Params.ImageName)'"
        exit 0
    }
    foreach ($p in $procs) {
        try {
            Stop-Process -Id $p.Id -Force -ErrorAction Stop
            $killed += "$($p.ProcessName) (pid=$($p.Id))"
        } catch {
            $failed += "$($p.ProcessName) (pid=$($p.Id)) : $_"
        }
    }
} else {
    Write-Output "neither pid nor image_name supplied"
    exit 1
}

if ($killed.Count -gt 0) {
    Write-Output ("killed: " + ($killed -join '; '))
}
if ($failed.Count -gt 0) {
    Write-Output ("failed: " + ($failed -join '; '))
    exit 1
}

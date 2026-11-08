$ErrorActionPreference = 'Stop'
$svcName = $Params.ServiceName

if ([string]::IsNullOrWhiteSpace($svcName)) {
    Write-Output "service_name is empty"
    exit 1
}

$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Output "service '$svcName' not found on this host"
    exit 0
}

$priorStatus = $svc.Status
if ($svc.Status -ne 'Stopped') {
    try {
        Stop-Service -Name $svcName -Force -ErrorAction Stop
    } catch {
        Write-Output "stop failed for '$svcName' (status=$priorStatus): $_"
        exit 1
    }
}

$out = & sc.exe delete $svcName 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Output "deleted service '$svcName' (was $priorStatus)"
} else {
    Write-Output "sc.exe delete failed for '$svcName': $out"
    exit 1
}

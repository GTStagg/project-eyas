$ErrorActionPreference = 'Stop'
$svc = Get-Service -Name $Params.ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Output "service '$($Params.ServiceName)' not found on this host"
    exit 0
}
$priorStatus = $svc.Status
$priorStart = (Get-CimInstance Win32_Service -Filter "Name='$($Params.ServiceName)'" -ErrorAction SilentlyContinue).StartMode
try {
    if ($svc.Status -ne 'Stopped') {
        Stop-Service -Name $Params.ServiceName -Force
    }
    Set-Service -Name $Params.ServiceName -StartupType Disabled
    Write-Output "service '$($Params.ServiceName)' stopped and disabled (was $priorStatus / $priorStart)"
} catch {
    Write-Output "stop/disable failed for '$($Params.ServiceName)': $_"
    exit 1
}

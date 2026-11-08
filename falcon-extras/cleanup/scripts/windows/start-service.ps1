$ErrorActionPreference = 'Stop'
$svc = Get-Service -Name $Params.ServiceName -ErrorAction SilentlyContinue
if (-not $svc) {
    Write-Output "service '$($Params.ServiceName)' not found on this host"
    exit 1
}
$priorStatus = $svc.Status
$priorStart = (Get-CimInstance Win32_Service -Filter "Name='$($Params.ServiceName)'" -ErrorAction SilentlyContinue).StartMode
try {
    Set-Service -Name $Params.ServiceName -StartupType $Params.StartupType
    if ((Get-Service -Name $Params.ServiceName).Status -ne 'Running') {
        Start-Service -Name $Params.ServiceName
    }
    $now = Get-Service -Name $Params.ServiceName
    Write-Output "service '$($Params.ServiceName)' started, startup=$($Params.StartupType) (was $priorStatus / $priorStart, now $($now.Status))"
} catch {
    Write-Output "start failed for '$($Params.ServiceName)': $_"
    exit 1
}

$ErrorActionPreference = 'Stop'
$keymap = @{
    'Run'     = 'Software\Microsoft\Windows\CurrentVersion\Run'
    'RunOnce' = 'Software\Microsoft\Windows\CurrentVersion\RunOnce'
}
$psPath = "$($Params.Hive):\$($keymap[$Params.KeyPath])"
if (-not (Test-Path $psPath)) {
    Write-Output "key '$psPath' not present on this host"
    exit 0
}
$existing = Get-ItemProperty -Path $psPath -Name $Params.ValueName -ErrorAction SilentlyContinue
if (-not $existing) {
    Write-Output "value '$($Params.ValueName)' not present in $psPath"
    exit 0
}
$priorData = $existing.$($Params.ValueName)
Write-Output "pre-removal: $($Params.Hive)\$($keymap[$Params.KeyPath])\$($Params.ValueName) = $priorData"
try {
    Remove-ItemProperty -Path $psPath -Name $Params.ValueName -Force
    Write-Output "removed $($Params.Hive)\$($keymap[$Params.KeyPath])\$($Params.ValueName)"
} catch {
    Write-Output "removal failed: $_"
    exit 1
}

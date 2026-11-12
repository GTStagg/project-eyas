$ErrorActionPreference = 'Stop'
$name = $Params.FilterName
$ns = 'root\subscription'

if ([string]::IsNullOrWhiteSpace($name)) {
    Write-Output "filter_name is empty"
    exit 1
}

$filter = Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq $name }
if (-not $filter) {
    Write-Output "no __EventFilter named '$name' in $ns on this host"
    exit 0
}

$bindings = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
    Where-Object { $_.Filter -like "*Name=`"$name`"*" }

$consumerRefs = @()
foreach ($b in $bindings) {
    if ($b.Consumer -match 'Name="([^"]+)"') {
        $consumerRefs += [pscustomobject]@{
            class = ($b.Consumer -split ':')[0]
            name = $matches[1]
        }
    }
}

$removedBindings = 0
foreach ($b in $bindings) {
    try { Remove-CimInstance -InputObject $b; $removedBindings++ } catch {
        Write-Output "binding remove failed: $_"
    }
}

$removedConsumers = 0
foreach ($cref in $consumerRefs | Sort-Object -Property name -Unique) {
    foreach ($cls in @('CommandLineEventConsumer','ActiveScriptEventConsumer','LogFileEventConsumer','NTEventLogEventConsumer','SMTPEventConsumer')) {
        $c = Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $cref.name }
        foreach ($ci in $c) {
            try { Remove-CimInstance -InputObject $ci; $removedConsumers++ } catch {
                Write-Output "consumer remove failed for $($cref.name): $_"
            }
        }
    }
}

try {
    Remove-CimInstance -InputObject $filter
    Write-Output "removed WMI persistence chain for filter '$name' (bindings=$removedBindings, consumers=$removedConsumers)"
} catch {
    Write-Output "filter remove failed for '$name': $_"
    exit 1
}

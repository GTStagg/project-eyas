$ErrorActionPreference = 'Stop'
$ns = 'root\subscription'

# Known-benign Microsoft-shipped filter/consumer names. Present on most
# Windows installs; should not be flagged as suspicious by default.
$BenignFilterNames = @('SCM Event Log Filter')
$BenignConsumerNames = @('SCM Event Log Consumer','BVTConsumer','BVTFilter')

function Test-Suspicious {
    param([string]$kind, [hashtable]$obj)
    $reasons = New-Object System.Collections.Generic.List[string]
    if ($kind -eq 'filter') {
        $q = [string]$obj.Query
        if ($q -match '__InstanceModificationEvent\s+WITHIN\s+\d+') {
            $reasons.Add('polling __InstanceModificationEvent timer (classic T1546.003 trigger)')
        }
        if ($q -match 'Win32_LocalTime|Win32_Process|Win32_LogonSession|__InstanceCreationEvent') {
            $reasons.Add("query references attacker-favored class")
        }
        if ($obj.Name -match '^[A-Za-z0-9]{16,}$') {
            $reasons.Add('filter name looks random/guid-like')
        }
        if ($BenignFilterNames -contains $obj.Name) { return @() }
    } elseif ($kind -eq 'consumer') {
        $cls = [string]$obj.__Class
        if ($cls -eq 'CommandLineEventConsumer') {
            $cmd = [string]$obj.CommandLineTemplate
            if ($cmd) {
                $cmdLower = $cmd.ToLower()
                if ($cmdLower -match 'powershell|pwsh\.exe|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin') {
                    $reasons.Add('CommandLineTemplate invokes interpreter / lolbin')
                }
                if ($cmdLower -match '-enc(odedcommand)?\s|frombase64string|downloadstring|iex\s|invoke-expression') {
                    $reasons.Add('CommandLineTemplate has encoded / download-and-exec pattern')
                }
                if ($cmdLower -match '\\appdata\\|\\temp\\|\\programdata\\|\\users\\public\\') {
                    $reasons.Add('CommandLineTemplate references user-writable path')
                }
            }
        } elseif ($cls -eq 'ActiveScriptEventConsumer') {
            $reasons.Add('ActiveScriptEventConsumer (rare; most modern attacker WMI uses this)')
        }
        if ($BenignConsumerNames -contains $obj.Name) { return @() }
    }
    return $reasons.ToArray()
}

# Enumerate all three classes in root\subscription.
$filters = @()
foreach ($f in (Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction SilentlyContinue)) {
    $reasons = Test-Suspicious 'filter' @{ Name = $f.Name; Query = $f.Query }
    $filters += [pscustomobject]@{
        name = $f.Name
        query_language = $f.QueryLanguage
        query = $f.Query
        event_namespace = $f.EventNamespace
        suspicious = ($reasons.Count -gt 0)
        reasons = $reasons
    }
}

$bindings = @()
foreach ($b in (Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)) {
    $filterName = $null
    if ($b.Filter -match 'Name="([^"]+)"') { $filterName = $matches[1] }
    $consumerClass = $null
    $consumerName = $null
    if ($b.Consumer -match '^(?:[^:]+:)?([^.]+)\.Name="([^"]+)"') {
        $consumerClass = $matches[1]
        $consumerName = $matches[2]
    } elseif ($b.Consumer -match '([A-Za-z]+EventConsumer).*Name="([^"]+)"') {
        $consumerClass = $matches[1]
        $consumerName = $matches[2]
    }
    $bindings += [pscustomobject]@{
        filter_name = $filterName
        consumer_class = $consumerClass
        consumer_name = $consumerName
        filter_ref = [string]$b.Filter
        consumer_ref = [string]$b.Consumer
    }
}

$consumers = @()
foreach ($cls in @('CommandLineEventConsumer','ActiveScriptEventConsumer','LogFileEventConsumer','NTEventLogEventConsumer','SMTPEventConsumer')) {
    foreach ($c in (Get-CimInstance -Namespace $ns -ClassName $cls -ErrorAction SilentlyContinue)) {
        $obj = @{
            __Class = $cls
            Name = $c.Name
            CommandLineTemplate = if ($cls -eq 'CommandLineEventConsumer') { $c.CommandLineTemplate } else { $null }
            ScriptingEngine = if ($cls -eq 'ActiveScriptEventConsumer') { $c.ScriptingEngine } else { $null }
            ScriptText = if ($cls -eq 'ActiveScriptEventConsumer') { $c.ScriptText } else { $null }
            ExecutablePath = if ($cls -eq 'CommandLineEventConsumer') { $c.ExecutablePath } else { $null }
            WorkingDirectory = if ($cls -eq 'CommandLineEventConsumer') { $c.WorkingDirectory } else { $null }
        }
        $reasons = Test-Suspicious 'consumer' $obj
        $consumers += [pscustomobject]@{
            class = $cls
            name = $c.Name
            command_line_template = $obj.CommandLineTemplate
            executable_path = $obj.ExecutablePath
            working_directory = $obj.WorkingDirectory
            scripting_engine = $obj.ScriptingEngine
            script_text_excerpt = if ($obj.ScriptText) { $obj.ScriptText.Substring(0, [Math]::Min(400, $obj.ScriptText.Length)) } else { $null }
            suspicious = ($reasons.Count -gt 0)
            reasons = $reasons
        }
    }
}

# Cross-link: for each filter, find its bindings + the consumers referenced.
$chains = @()
foreach ($f in $filters) {
    $linkedBindings = $bindings | Where-Object { $_.filter_name -eq $f.name }
    $linkedConsumers = @()
    foreach ($lb in $linkedBindings) {
        $match = $consumers | Where-Object { $_.class -eq $lb.consumer_class -and $_.name -eq $lb.consumer_name }
        if ($match) { $linkedConsumers += $match }
    }
    $consumerSuspicious = $false
    $allReasons = @($f.reasons)
    foreach ($lc in $linkedConsumers) {
        if ($lc.suspicious) { $consumerSuspicious = $true }
        $allReasons += $lc.reasons
    }
    $chains += [pscustomobject]@{
        filter_name = $f.name
        filter_query = $f.query
        consumers = @($linkedConsumers | ForEach-Object {
            [pscustomobject]@{
                class = $_.class
                name = $_.name
                command_line_template = $_.command_line_template
                scripting_engine = $_.scripting_engine
            }
        })
        suspicious = ($f.suspicious -or $consumerSuspicious)
        reasons = ($allReasons | Sort-Object -Unique)
    }
}

$result = [pscustomobject]@{
    filter_count = $filters.Count
    binding_count = $bindings.Count
    consumer_count = $consumers.Count
    chains = $chains
    orphan_consumers = @($consumers | Where-Object { $c = $_; -not ($bindings | Where-Object { $_.consumer_class -eq $c.class -and $_.consumer_name -eq $c.name }) })
    orphan_bindings = @($bindings | Where-Object { $b = $_; -not ($filters | Where-Object { $_.name -eq $b.filter_name }) })
    suspicious_filter_names = @($chains | Where-Object { $_.suspicious } | ForEach-Object { $_.filter_name })
}

# Marker-wrapped JSON so the caller can extract cleanly even if PowerShell
# emits incidental output (warnings, etc.) before/after.
Write-Output '<<<WMI_PERSISTENCE_JSON>>>'
$result | ConvertTo-Json -Depth 8 -Compress
Write-Output '<<<END_WMI_PERSISTENCE_JSON>>>'

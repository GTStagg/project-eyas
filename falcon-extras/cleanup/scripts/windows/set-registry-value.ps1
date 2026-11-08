# Generic registry-hardening primitive. One script, slot-driven catalog.
#
# The agent / operator picks a slot (enum validated by manifest); the slot
# encodes hive + key path + value name + type + the hardened "green" default
# + an allowed-values whitelist. If $Params.Value is omitted, the green
# default is written -- that's the "revert to safe state" mode. If $Params.Value
# is supplied, it must appear in the slot's allowed list.
#
# Adding a new finding = adding a row to $catalog. No new script, no new
# manifest entry beyond extending the slot enum.
#
# Slots are restricted to security-hardening keys with well-understood green
# defaults. Operators who need to write arbitrary registry values to arbitrary
# paths should still build a finding-specific cleanup script -- this primitive
# is intentionally not a free-form registry editor.

$ErrorActionPreference = 'Stop'
$slot = $Params.Slot
$value = $Params.Value

# Sentinel for slots whose green default is "delete the value entirely"
# (e.g. AutoAdminLogon's DefaultPassword should not exist).
$DELETE = '__delete__'

$catalog = @{
    'wdigest-uselogoncredential' = @{
        Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest';
        Name='UseLogonCredential'; Type='DWord'; Green=0; Allowed=@(0,1);
        Why='WDigest plaintext-credential cache. Mimikatz sekurlsa::wdigest reads this. Green=0 (modern Windows default).'
    }
    'lsa-runasppl' = @{
        Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';
        Name='RunAsPPL'; Type='DWord'; Green=1; Allowed=@(0,1,2);
        Why='LSA Protected Process Light. Blocks unsigned drivers and non-PPL processes from injecting LSASS. Green=1 (or 2 with UEFI lock). Reboot required.'
    }
    'lsa-nolmhash' = @{
        Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';
        Name='NoLMHash'; Type='DWord'; Green=1; Allowed=@(0,1);
        Why='Disables storage of LM hashes (trivially crackable). Green=1.'
    }
    'lsa-lmcompatibilitylevel' = @{
        Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';
        Name='LmCompatibilityLevel'; Type='DWord'; Green=5; Allowed=@(3,4,5);
        Why='LM/NTLM auth level. 5 = NTLMv2 only, refuse LM and NTLMv1. Green=5.'
    }
    'lsa-disablerestrictedadmin' = @{
        Hive='HKLM'; Path='SYSTEM\CurrentControlSet\Control\Lsa';
        Name='DisableRestrictedAdmin'; Type='DWord'; Green=1; Allowed=@(0,1);
        Why='Blocks RDP RestrictedAdmin mode (pass-the-hash via RDP). Green=1.'
    }
    'winlogon-autoadminlogon' = @{
        Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';
        Name='AutoAdminLogon'; Type='String'; Green='0'; Allowed=@('0','1');
        Why='Automatic logon at boot using stored credentials. Green=0.'
    }
    'winlogon-defaultpassword' = @{
        Hive='HKLM'; Path='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon';
        Name='DefaultPassword'; Type='String'; Green=$DELETE; Allowed=@($DELETE);
        Why='Cleartext password used by AutoAdminLogon. Green = value absent. Always revert by deleting.'
    }
    'printnightmare-noelevation' = @{
        Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint';
        Name='NoWarningNoElevationOnInstall'; Type='DWord'; Green=0; Allowed=@(0,1);
        Why='Point-and-Print elevation bypass (CVE-2021-34527 PrintNightmare). Green=0.'
    }
    'printnightmare-updatepromptsettings' = @{
        Hive='HKLM'; Path='SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint';
        Name='UpdatePromptSettings'; Type='DWord'; Green=0; Allowed=@(0,1,2);
        Why='Point-and-Print update-prompt suppression. Green=0 (warn).'
    }
}

if (-not $catalog.ContainsKey($slot)) {
    Write-Output "unknown slot '$slot'. Known: $($catalog.Keys -join ', ')"
    exit 1
}
$entry = $catalog[$slot]

# Resolve target value.
if ([string]::IsNullOrWhiteSpace($value)) {
    $resolved = $entry.Green
    $mode = 'revert-to-green'
} else {
    if ($entry.Type -eq 'DWord') {
        try { $candidate = [int]$value } catch {
            Write-Output "value '$value' is not a valid DWord for slot '$slot'"
            exit 1
        }
    } else {
        $candidate = [string]$value
    }
    if ($entry.Allowed -notcontains $candidate) {
        Write-Output "value '$value' not in allowed list ($($entry.Allowed -join ',')) for slot '$slot'"
        exit 1
    }
    $resolved = $candidate
    $mode = 'explicit-set'
}

$rkey = "$($entry.Hive):\$($entry.Path)"
$ref  = "$($entry.Hive)\$($entry.Path)\$($entry.Name)"

# Capture prior state for the audit trail.
$priorRepr = '(absent)'
if (Test-Path $rkey) {
    $existing = Get-ItemProperty -Path $rkey -Name $entry.Name -ErrorAction SilentlyContinue
    if ($existing) {
        $priorRepr = "'$($existing.$($entry.Name))'"
    }
}

if ($resolved -eq $DELETE) {
    if ($priorRepr -eq '(absent)') {
        Write-Output "[falcon-extras] $slot already absent at $ref ($mode)"
        exit 0
    }
    try {
        Remove-ItemProperty -Path $rkey -Name $entry.Name -Force
        Write-Output "[falcon-extras] $slot deleted at $ref (was $priorRepr, $mode)"
        exit 0
    } catch {
        Write-Output "[falcon-extras] delete failed at ${ref}: $_"
        exit 1
    }
}

try {
    if (-not (Test-Path $rkey)) {
        New-Item -Path $rkey -Force | Out-Null
    }
    Set-ItemProperty -Path $rkey -Name $entry.Name -Value $resolved -Type $entry.Type
    Write-Output "[falcon-extras] $slot set to '$resolved' at $ref (was $priorRepr, $mode)"
} catch {
    Write-Output "[falcon-extras] set failed at ${ref}: $_"
    exit 1
}

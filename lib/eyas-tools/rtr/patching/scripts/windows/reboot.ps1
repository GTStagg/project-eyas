# Force-reboot the host. Used by the agent when an operator explicitly asks
# to reboot one or more hosts (e.g. to finalize a patch that returned 3010,
# DISM Disable-Feature, or a .NET Framework install). Not auto-routed by
# Spotlight remediation matching.
$ErrorActionPreference = "Continue"

Write-Output "[eyas] rebooting host=$env:COMPUTERNAME"
Restart-Computer -Force

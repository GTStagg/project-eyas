# Force-reboot the host. IR-context cleanup primitive.
#
# Used to finalize Phase 2 cleanup actions that returned `pending_reboot`
# paths (locked files scheduled via MoveFileEx for next-boot delete) and
# whenever the operator explicitly requests a reboot post-IR. Mirror of
# the patching catalog's win-reboot script -- duplicated here so the IR
# agent doesn't have to reach across catalogs (the cleanup catalog is
# what the IR playbook works from).
#
# Falcon RTR queues commands and the host receives them on the next sensor
# poll, so the agent's connection to the host is severed by Restart-Computer
# but the command itself completes successfully on the host side.
$ErrorActionPreference = "Continue"

Write-Output "[falcon-extras] rebooting host=$env:COMPUTERNAME"
Restart-Computer -Force

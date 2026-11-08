#!/bin/bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    echo "[falcon-extras] error: must run as root (RTR runscript runs as root by default)" >&2
    exit 2
fi
echo "[falcon-extras] start $(date -u +%FT%TZ) host=$(hostname)"

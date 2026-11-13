#!/bin/bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
    echo "[eyas] error: must run as root (RTR runscript runs as root by default)" >&2
    exit 2
fi
echo "[eyas] start $(date -u +%FT%TZ) host=$(hostname)"

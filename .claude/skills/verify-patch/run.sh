#!/usr/bin/env bash
# Smoke-test one or more patching catalog entries: render with representative
# params, check the output is pure ASCII, probe the Spotlight pattern.
# Usage: run.sh <script_id> [<script_id> ...]
set -euo pipefail
cd "$(dirname "$0")/../../.."

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <script_id> [<script_id> ...]" >&2
    exit 2
fi

exec node scripts/rtr-library-cli.mjs verify "$@"

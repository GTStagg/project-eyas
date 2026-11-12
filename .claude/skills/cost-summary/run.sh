#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
exec node node_modules/tsx/dist/cli.mjs .claude/skills/cost-summary/summarize.mjs "$@"

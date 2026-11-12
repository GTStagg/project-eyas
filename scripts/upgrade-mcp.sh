#!/usr/bin/env bash
# Refresh the dev MCP server.
#
# The MCP server (eyas-mcp) is pinned by git commit in versions.json, and dev
# spawns it with `uvx --from git+<repo>@<ref>` (lib/mcp/falcon-client.ts), so
# bumping the pin is the upgrade. This script re-resolves that pinned spec from
# a clean uv cache (useful after a pin bump, or when a cached build is
# suspect). It never resolves the server by bare package name.
#
# Standalone bundles do NOT use this script — they install pinned wheels from
# vendor/ at start.sh time.
set -euo pipefail

GREEN='\033[0;32m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
step() { echo -e "  ${BOLD}$*${RESET}"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"

if command -v uv >/dev/null 2>&1; then
  PKG=$(node -e "process.stdout.write(require('./versions.json')['mcp-server-package'])")
  SPEC=$(node -e "const v=require('./versions.json');process.stdout.write('git+'+v['mcp-server-git']+'@'+v['mcp-server-ref'])")
  step "Refreshing uv cache for ${PKG}…"
  uv cache clean "$PKG" >/dev/null 2>&1 || true
  ok "uv cache cleared"
  step "Resolving pinned ${PKG}…"
  RESOLVED=$(uvx --quiet --from "$SPEC" "$PKG" --version 2>/dev/null | head -1 || echo "(version not reported)")
  ok "${RESOLVED}"
else
  echo "  WARN: uv not installed — skipping MCP server refresh." >&2
  echo "        brew install uv  (or)  curl -LsSf https://astral.sh/uv/install.sh | sh" >&2
fi

echo ""
echo -e "  ${GREEN}${BOLD}Done.${RESET}"
echo "  Restart 'npm run dev' so the next MCP spawn picks up the new version."

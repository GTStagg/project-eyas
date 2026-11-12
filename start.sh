#!/usr/bin/env bash
# Launches the falcon-mcp frontend as a standalone macOS app.
# Run: ./start.sh
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
err()   { echo -e "${RED}${BOLD}  ERROR:${RESET} $*" >&2; }
info()  { echo -e "  $*"; }
ok()    { echo -e "  ${GREEN}✓${RESET} $*"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── macOS Gatekeeper: strip com.apple.quarantine on first run ────────────────
# Downloaded zips inherit com.apple.quarantine on every file. Gatekeeper then
# refuses to load unsigned native .node bindings (better-sqlite3, sharp) with
# the "could not verify … free of malware" dialog. We don't have an Apple
# Developer ID to notarize with, so strip the attribute at launch. Scoped to
# the bundle tree, idempotent, no-op once the bit is gone.
if [[ "${OSTYPE:-}" == "darwin"* ]] && command -v xattr >/dev/null 2>&1; then
  if xattr "$SCRIPT_DIR" 2>/dev/null | grep -q '^com\.apple\.quarantine$'; then
    xattr -dr com.apple.quarantine "$SCRIPT_DIR" 2>/dev/null || true
    ok "stripped macOS quarantine attribute from bundle"
  fi
fi

# ─── Prereq: Node.js ──────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  echo ""
  err "Node.js is not installed."
  info "Install the LTS from https://nodejs.org or via:  brew install node"
  echo ""
  exit 1
fi
NODE_MAJOR=$(node -e "process.stdout.write(process.version.replace('v','').split('.')[0])")
# Minimum is v22 — this bundle ships better-sqlite3 native prebuilds only for
# Node 22 (ABI 127), Node 24 (ABI 137), and Node 26 (ABI 147). v20 (ABI 115)
# reached end-of-life in 2026 and is not staged, so it would pass an older
# "≥20" gate and then hard-fail at the prebuild selector below. Keep this
# floor in sync with BSQLITE_ABIS in make-dist.sh.
if [ "$NODE_MAJOR" -lt 22 ]; then
  echo ""
  err "Node.js v22 or newer is required (LTS v22, v24, or v26). Found: $(node --version)"
  info "Upgrade via:  brew upgrade node    (or download from https://nodejs.org)"
  echo ""
  exit 1
fi
ok "Node.js $(node --version)"

# ─── macOS: select the better-sqlite3 prebuild matching the running Node ABI ─
# Native bindings are compiled against a specific NODE_MODULE_VERSION; loading
# the wrong one fails with "compiled against a different Node.js version".
# The bundle ships one prebuild per supported ABI under
# vendor/better-sqlite3-prebuilds/<target>-<abi>/. Copy the matching one over
# the path Next.js standalone expects. Linux uses whatever the build host
# compiled — Linux recipients are dev-internal and run matching Node.
if [[ "${OSTYPE:-}" == "darwin"* ]]; then
  BSQLITE_ABI=$(node -e "process.stdout.write(String(process.versions.modules))")
  BSQLITE_ARCH="darwin-$(uname -m | sed 's/^x86_64$/x64/' )"
  BSQLITE_PREBUILD="${SCRIPT_DIR}/vendor/better-sqlite3-prebuilds/${BSQLITE_ARCH}-${BSQLITE_ABI}/better_sqlite3.node"
  BSQLITE_DEST="${SCRIPT_DIR}/node_modules/better-sqlite3/build/Release/better_sqlite3.node"
  if [ -f "$BSQLITE_PREBUILD" ]; then
    if ! cmp -s "$BSQLITE_PREBUILD" "$BSQLITE_DEST" 2>/dev/null; then
      cp "$BSQLITE_PREBUILD" "$BSQLITE_DEST"
      ok "better-sqlite3 prebuild matched to Node ABI ${BSQLITE_ABI} (${BSQLITE_ARCH})"
    fi
  else
    echo ""
    err "No better-sqlite3 prebuild for Node ABI ${BSQLITE_ABI} (${BSQLITE_ARCH}) in this bundle."
    info "This bundle ships prebuilds for: $(ls "${SCRIPT_DIR}/vendor/better-sqlite3-prebuilds" 2>/dev/null | tr '\n' ' ')"
    info "Switch to a supported Node.js version, or request a rebuild that includes ABI ${BSQLITE_ABI}."
    echo ""
    exit 1
  fi
fi

# ─── Prereq: uv OR (offline path) python3 ────────────────────────────────────
# When the bundle ships pre-downloaded wheels (vendor/falcon-mcp-wheels/), we
# install offline into a sibling venv using system python3 — uv is not required.
# When wheels aren't bundled, we fall back to `uvx falcon-mcp` (needs network).
WHEELS_DIR="${SCRIPT_DIR}/vendor/falcon-mcp-wheels"
VENV_DIR="${SCRIPT_DIR}/vendor/falcon-mcp-venv"
# Package/command name of the bundled MCP server, recorded by make-dist.sh.
MCP_PKG=""
if [ -f "$SCRIPT_DIR/build-info.json" ]; then
  MCP_PKG=$(node -e "try{const j=require(process.argv[1]);process.stdout.write((j.mcpServer||{}).package||'')}catch(e){}" "$SCRIPT_DIR/build-info.json" 2>/dev/null || echo "")
fi
MCP_PKG="${MCP_PKG:-eyas-mcp}"
OFFLINE_BIN="${VENV_DIR}/bin/${MCP_PKG}"

if [ -d "$WHEELS_DIR" ] && [ "$(ls -A "$WHEELS_DIR" 2>/dev/null)" ]; then
  # Honor explicit PYTHON3 override (e.g. PYTHON3=python3.12). Otherwise pick
  # the first python3.X on PATH that's >=3.10, falling back to plain python3.
  PY_BIN=""
  if [ -n "${PYTHON3:-}" ] && command -v "$PYTHON3" &>/dev/null; then
    PY_BIN="$PYTHON3"
  else
    # Prefer the exact Python the bundled wheels were built for. The offline
    # `pip --no-index` install needs version-matched binary wheels (pydantic
    # -core, FalconPy deps): selecting a newer Python — e.g. brew-default 3.13
    # when the wheels are cp312 — hard-fails on first launch even when the
    # right version is also installed. build-info.json records the wheel
    # target; read it with node (guaranteed present from the check above —
    # python is the thing we're still hunting for). Fall back to a 3.12-first
    # probe order so we still avoid 3.13 if the file is absent (dev checkout).
    WHEEL_PY_VER=""
    if [ -f "$SCRIPT_DIR/build-info.json" ]; then
      WHEEL_PY_VER=$(node -e "try{const j=require(process.argv[1]);process.stdout.write((j.wheelTarget||{}).pythonVersion||'')}catch(e){}" "$SCRIPT_DIR/build-info.json" 2>/dev/null || echo "")
    fi
    for cand in ${WHEEL_PY_VER:+"python${WHEEL_PY_VER}"} python3.12 python3.11 python3.10 python3.13 python3; do
      if command -v "$cand" &>/dev/null; then
        ver=$("$cand" -c 'import sys;print(f"{sys.version_info[0]}.{sys.version_info[1]}")' 2>/dev/null || echo "")
        case "$ver" in
          3.1[0-9]) PY_BIN="$cand"; break ;;
        esac
      fi
    done
  fi
  if [ -z "$PY_BIN" ]; then
    echo ""
    err "No Python ≥3.10 found (needed for offline falcon-mcp install)."
    info "Install via:  brew install python@3.12"
    info "Or set:       PYTHON3=/path/to/python3.12 ./start.sh"
    echo ""
    exit 1
  fi
  ok "python3 $("$PY_BIN" --version 2>&1 | awk '{print $2}') ($PY_BIN)"

  if [ ! -x "$OFFLINE_BIN" ]; then
    info "First-run offline install of falcon-mcp from bundled wheels…"
    rm -rf "$VENV_DIR"
    if ! "$PY_BIN" -m venv "$VENV_DIR" >/dev/null; then
      echo ""
      err "Failed to create venv at $VENV_DIR"
      echo ""
      exit 1
    fi
    if ! "$VENV_DIR/bin/pip" install --quiet --no-index --find-links "$WHEELS_DIR" "$MCP_PKG"; then
      echo ""
      err "Offline install of falcon-mcp failed."
      info "The bundled wheels may not match your python3 version."
      info "Bundled for: python 3.12. Found: $(python3 --version 2>&1)"
      info "Either install python@3.12 or rebuild the bundle for your version."
      echo ""
      exit 1
    fi
    ok "falcon-mcp installed → $OFFLINE_BIN"
  else
    ok "falcon-mcp already installed (offline)"
  fi

  export FALCON_MCP_COMMAND="$OFFLINE_BIN"
  export FALCON_MCP_ARGS="--transport stdio"
  USE_OFFLINE=1
else
  if ! command -v uvx &>/dev/null; then
    echo ""
    err "uv (uvx) is not installed and no bundled wheels found."
    info "Either rebuild the bundle with wheels (uv on build host), or install uv:"
    info "  brew install uv"
    info "  curl -LsSf https://astral.sh/uv/install.sh | sh"
    echo ""
    exit 1
  fi
  ok "uv $(uvx --version 2>/dev/null | head -1)"
  USE_OFFLINE=0
fi

# ─── .env ─────────────────────────────────────────────────────────────────────
# Auto-create an empty .env on first run so AUTH_SESSION_SECRET (below) has a
# place to land. The operator never needs to hand-edit it — Falcon and
# Anthropic credentials are collected by the in-browser /register wizard and
# stored encrypted in data/eyas.db.
if [ ! -f ".env" ]; then
  : > .env
  chmod 600 .env 2>/dev/null || true
  info ".env not found — created an empty one. Credentials are collected in the browser."
fi
set -a
# shellcheck disable=SC1091
source .env
set +a
ok ".env loaded"

# First-launch hint: no DB yet means the operator is about to land at /register.
if [ ! -f "data/eyas.db" ]; then
  info "(First launch — /register will collect Falcon + Anthropic credentials.)"
fi

# An optional standalone gateway lock is baked into the build at make-dist.sh time
# via lib/config/build-flags.ts (compiled into the bundle) when the builder sets ANTHROPIC_GATEWAY_BASE_URL. No runtime
# env knob — that would defeat the unauthorized-redistribution lock. To
# change the locked URL or unlock the wizard, recompile from source.

# ─── AUTH_SESSION_SECRET: auto-generate on first run ──────────────────────────
# Encrypts the iron-session cookie AND is the HKDF root for column encryption
# of credentials in data/eyas.db. Single-user — generated once, persisted to
# .env so sessions survive restarts. Delete the line to rotate (kicks all
# sessions AND invalidates encrypted credentials — operator re-registers).
if [ -z "${AUTH_SESSION_SECRET:-}" ] || [ "${#AUTH_SESSION_SECRET}" -lt 32 ]; then
  if command -v openssl &>/dev/null; then
    NEW_SECRET=$(openssl rand -hex 32)
  else
    NEW_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  fi
  if grep -qE '^[[:space:]]*AUTH_SESSION_SECRET=' .env 2>/dev/null; then
    # Replace existing empty/short value
    if [[ "$OSTYPE" == "darwin"* ]]; then
      sed -i '' -E "s|^[[:space:]]*AUTH_SESSION_SECRET=.*|AUTH_SESSION_SECRET=${NEW_SECRET}|" .env
    else
      sed -i -E "s|^[[:space:]]*AUTH_SESSION_SECRET=.*|AUTH_SESSION_SECRET=${NEW_SECRET}|" .env
    fi
  else
    printf "\n# Auto-generated on first run. Delete to rotate (invalidates all sessions).\nAUTH_SESSION_SECRET=%s\n" "$NEW_SECRET" >> .env
  fi
  export AUTH_SESSION_SECRET="$NEW_SECRET"
  ok "AUTH_SESSION_SECRET generated and saved to .env"
fi

# Enforce 0600 on .env on every launch. It holds AUTH_SESSION_SECRET — the HKDF
# root that decrypts every stored Falcon/Anthropic credential — so the threat
# model (SECURITY.md) treats it as mode 0600, mirroring data/eyas.db. The
# default umask leaves a freshly created file at 0644, and macOS `sed -i ''`
# rewrites the file (resetting perms), so re-assert it here regardless of how
# .env came to exist this run.
chmod 600 .env 2>/dev/null || true

# ─── Standalone build present? ───────────────────────────────────────────────
if [ ! -f "server.js" ]; then
  echo ""
  err "server.js missing — this archive may be corrupt or you're running"
  err "start.sh from a source checkout. For source checkouts, run:"
  info "  npm install && npm run build"
  info "and use ./scripts/dev-start.sh instead."
  echo ""
  exit 1
fi

# ─── Verify falcon-mcp is runnable ────────────────────────────────────────────
if [ "$USE_OFFLINE" -eq 1 ]; then
  if ! "$OFFLINE_BIN" --help >/dev/null 2>&1; then
    echo ""
    err "Bundled falcon-mcp at $OFFLINE_BIN is not runnable."
    echo ""
    exit 1
  fi
  ok "falcon-mcp ready (offline)"
else
  info "Verifying the MCP server is reachable via uvx (first run may download)…"
  # Resolve from the pinned git ref in versions.json, never by bare package name.
  MCP_SPEC=$(node -e "const v=require(process.argv[1]);process.stdout.write('git+'+v['mcp-server-git']+'@'+v['mcp-server-ref']+' '+v['mcp-server-package'])" "$SCRIPT_DIR/versions.json")
  # shellcheck disable=SC2086
  if ! uvx --quiet --from $MCP_SPEC --help >/dev/null 2>&1; then
    echo ""
    err "uvx could not run the MCP server. Check your network and Python install."
    info "Try manually:  uvx --from $MCP_SPEC --help"
    echo ""
    exit 1
  fi
  ok "falcon-mcp ready"
fi

# ─── Launch ───────────────────────────────────────────────────────────────────
PORT="${PORT:-3000}"
# zsh/bash on macOS auto-export $HOSTNAME to the machine's hostname (e.g.
# "ML-LR33RWJ600"), which Node then tries — and fails — to resolve. Honor a
# value from .env if the user explicitly set one there; otherwise force the
# loopback default regardless of what the shell exported.
if grep -qE '^[[:space:]]*HOSTNAME=' .env 2>/dev/null; then
  : # HOSTNAME came from .env — leave it
else
  HOSTNAME="127.0.0.1"
fi
export PORT HOSTNAME

URL="http://${HOSTNAME}:${PORT}"

echo ""
echo -e "  ${BOLD}falcon-mcp frontend${RESET}  ${DIM}→${RESET}  ${BOLD}${URL}${RESET}"
echo ""

# Open browser after a short delay (non-blocking). Skipped under the managed
# launcher (EYAS_MANAGED=1): `eyas start` waits for readiness itself and opens
# the browser then, so start.sh opening it here would race + double-open.
if [ "${EYAS_MANAGED:-}" != "1" ]; then
  ( sleep 2 && open "${URL}" >/dev/null 2>&1 ) &
fi

exec node server.js

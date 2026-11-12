#!/usr/bin/env bash
# Structural + smoke-boot checks for the standalone bundle. Exits non-zero on
# any failure. Run from the repo root.
#
#   bash .claude/skills/validate-bundle/run.sh                # auto-locate latest zip
#   bash .claude/skills/validate-bundle/run.sh path/to/x.zip  # specific bundle
#   SKIP_BOOT=1 bash .claude/skills/validate-bundle/run.sh    # structural only
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'
fail_count=0
pass_count=0
skip_count=0

ok()    { echo -e "  ${GREEN}✓${RESET} $*"; pass_count=$((pass_count+1)); }
fail()  { echo -e "  ${RED}✗ $*${RESET}"; fail_count=$((fail_count+1)); }
skip()  { echo -e "  ${YELLOW}~${RESET} $*"; skip_count=$((skip_count+1)); }
hdr()   { echo -e "\n${BOLD}$*${RESET}"; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT"

# ─── Locate bundle ────────────────────────────────────────────────────────────
if [ "${1:-}" ]; then
  ZIP="$1"
else
  ZIP=$(ls -1t project-eyas-v*.zip 2>/dev/null | head -1)
fi

if [ -z "${ZIP:-}" ] || [ ! -f "$ZIP" ]; then
  echo -e "${RED}${BOLD}No bundle found.${RESET}  Run ./make-dist.sh first."
  exit 1
fi
echo -e "${BOLD}Validating:${RESET} $ZIP  ${DIM}($(du -h "$ZIP" | cut -f1))${RESET}"

BUNDLE_NAME="$(basename "$ZIP" .zip)"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT
LISTING_FILE="$WORK_DIR/paths"
# Extract paths once to a temp file so subsequent greps don't run inside a
# pipeline that pipefail can SIGPIPE-poison when `grep -q` exits early.
unzip -l "$ZIP" | awk 'NR>3 {print $4}' | grep -v '^$' | grep -v '^----' > "$LISTING_FILE"

# ─── Structural checks ────────────────────────────────────────────────────────

hdr "Structural"

# 1. No dev data/ leak
LEAKED_DATA=$(grep -E "^${BUNDLE_NAME}/data/(auth\.json|cost-log\.jsonl|perf-log\.jsonl|dev\.log|config\.json|eyas\.db|eyas\.db-wal|eyas\.db-shm)$" "$LISTING_FILE" || true)
if [ -z "$LEAKED_DATA" ]; then
  ok "no dev data/ leak (auth.json / cost-log / perf-log / dev.log / config.json / eyas.db)"
else
  fail "dev data/ leaked into bundle:\n$(echo "$LEAKED_DATA" | sed 's/^/      /')"
fi

# 2. The retired falcon-extras sidecar is gone: no source, no wheels.
RETIRED=$(grep -E "^${BUNDLE_NAME}/(falcon-extras/|vendor/falcon-extras-wheels/)" "$LISTING_FILE" || true)
if [ -z "$RETIRED" ]; then
  ok "no falcon-extras files or wheels (the add-on is retired)"
else
  fail "retired falcon-extras files in the bundle:\n$(echo "$RETIRED" | head -5 | sed 's/^/      /')"
fi

# 3. No unallowed platform-specific .node native bindings. Allowlist:
#   - sharp: Next.js image-opt binary; Next falls back to JS at runtime so a
#     Linux-built bundle still runs on macOS even though sharp's .node files
#     are Linux ELF.
#   - better-sqlite3: required for the SQLite-backed config/auth store. The
#     dev build host is Linux; make-dist.sh stages macOS-arm64 prebuilds for
#     each supported Node ABI under vendor/better-sqlite3-prebuilds/, and
#     leaves the build/Release/ path with the lowest-ABI prebuild as the
#     default. start.sh picks the matching ABI on launch.
# argon2 was the case we paid for — it broke the bundle on macOS until we
# migrated to scrypt.
NATIVE=$(grep -E "\.node$" "$LISTING_FILE" \
  | grep -vE "/(node_modules/)?@img/sharp[^/]*/" \
  | grep -vE "/(node_modules/)?better-sqlite3/build/Release/better_sqlite3\.node$" \
  | grep -vE "/vendor/better-sqlite3-prebuilds/[^/]+/better_sqlite3\.node$" \
  || true)
if [ -z "$NATIVE" ]; then
  ok "no unexpected native .node bindings (sharp + better-sqlite3 allowlisted)"
else
  fail "unexpected native binding(s) — bundle may be platform-specific:\n$(echo "$NATIVE" | sed 's/^/      /')"
fi

# 5. eyas-mcp wheels staged (offline install on the recipient's host)
MCP_WHEELS=$(grep -cE "^${BUNDLE_NAME}/vendor/falcon-mcp-wheels/.*\.whl$" "$LISTING_FILE" || true)
if [ "$MCP_WHEELS" -gt 0 ]; then
  ok "eyas-mcp wheels staged ($MCP_WHEELS)"
else
  fail "eyas-mcp wheels missing — recipients on offline networks won't be able to install"
fi

# 6. BUILD-INFO present + version match
unzip -q "$ZIP" "${BUNDLE_NAME}/BUILD-INFO.txt" "${BUNDLE_NAME}/build-info.json" -d "$WORK_DIR" 2>/dev/null || true
if [ -f "$WORK_DIR/${BUNDLE_NAME}/BUILD-INFO.txt" ] && [ -f "$WORK_DIR/${BUNDLE_NAME}/build-info.json" ]; then
  PKG_VERSION=$(node -e "process.stdout.write(require('./package.json').version)")
  BUNDLE_VERSION=$(node -e "process.stdout.write(require('$WORK_DIR/${BUNDLE_NAME}/build-info.json').appVersion)")
  if [ "$PKG_VERSION" = "$BUNDLE_VERSION" ]; then
    ok "BUILD-INFO present + version matches package.json ($PKG_VERSION)"
  else
    fail "version drift: package.json=$PKG_VERSION  build-info.json=$BUNDLE_VERSION"
  fi
else
  fail "BUILD-INFO.txt or build-info.json missing"
fi

# 7. server.js at root
if grep -qxF "${BUNDLE_NAME}/server.js" "$LISTING_FILE"; then
  ok "server.js present at bundle root"
else
  fail "server.js missing — bundle won't launch"
fi

# 7b. Gateway deployment lock, when the build asked for one.
# The lock is opt-in: make-dist.sh bakes it only when ANTHROPIC_GATEWAY_BASE_URL
# is set, overwriting build-flags.ts (gatewayOnly=true + forcedGatewayUrl)
# before `npm run build`. A default build is unlocked and accepts a direct
# Anthropic API key or a gateway entered on first run — that passes here.
# Set REQUIRE_GATEWAY_LOCK=1 when you ship gateway-locked bundles and want an
# unlocked one to fail.
#
# When build-info.json claims a lock, the compiled JS is the only place it
# survives — a build that skipped/reverted the bake (or a hand-tampered
# bundle) would carry metadata claiming a lock with no forced URL in the
# compiled chunks. So we assert the forced URL is physically present in the
# compiled output (string literals survive minification).
if [ -f "$WORK_DIR/${BUNDLE_NAME}/build-info.json" ]; then
  LOCK_ON=$(node -e "process.stdout.write(String(require('$WORK_DIR/${BUNDLE_NAME}/build-info.json').deploymentLock?.gatewayOnly === true))" 2>/dev/null || echo "false")
  FORCED_URL=$(node -e "process.stdout.write(String(require('$WORK_DIR/${BUNDLE_NAME}/build-info.json').deploymentLock?.forcedGatewayUrl || ''))" 2>/dev/null || echo "")
  if [ "$LOCK_ON" != "true" ]; then
    if [ -n "$FORCED_URL" ]; then
      fail "build-info.json has forcedGatewayUrl but gatewayOnly is not true — inconsistent deployment lock"
    elif [ "${REQUIRE_GATEWAY_LOCK:-0}" = "1" ]; then
      fail "bundle is NOT gateway-locked (REQUIRE_GATEWAY_LOCK=1) — rebuild with ANTHROPIC_GATEWAY_BASE_URL set"
    else
      ok "no gateway lock (default build; set ANTHROPIC_GATEWAY_BASE_URL to bake one)"
    fi
  elif [ -z "$FORCED_URL" ]; then
    fail "build-info.json deploymentLock.forcedGatewayUrl is empty — gateway lock has no target URL"
  else
    # Extract just the compiled server output and grep for the forced URL.
    # Limit to .next/ + server.js so we're checking COMPILED code, not source.
    unzip -q "$ZIP" "${BUNDLE_NAME}/.next/*" "${BUNDLE_NAME}/server.js" -d "$WORK_DIR/lockcheck" 2>/dev/null || true
    if grep -rqF "$FORCED_URL" "$WORK_DIR/lockcheck" 2>/dev/null; then
      ok "gateway lock baked into compiled bundle (forcedGatewayUrl present in .next/)"
    else
      fail "forcedGatewayUrl ($FORCED_URL) NOT found in compiled .next/ — build-info.json claims a lock the bundle doesn't enforce. The build-flags bake likely didn't take before \`npm run build\`."
    fi
    rm -rf "$WORK_DIR/lockcheck"
  fi
else
  skip "gateway lock check (build-info.json not extracted)"
fi

# 8. start.sh present (executable bit isn't reliably preserved across zip impls;
# we only check presence here — make-dist.sh chmod +x's the staged copy)
if grep -qxF "${BUNDLE_NAME}/start.sh" "$LISTING_FILE"; then
  ok "start.sh present"
else
  fail "start.sh missing"
fi

# ─── Smoke-boot (optional) ────────────────────────────────────────────────────

if [ "${SKIP_BOOT:-0}" = "1" ] || [ "${fail_count}" -gt 0 ]; then
  hdr "Smoke-boot"
  if [ "${SKIP_BOOT:-0}" = "1" ]; then
    skip "skipped (SKIP_BOOT=1)"
  else
    skip "skipped because structural checks already failed"
  fi
else
  hdr "Smoke-boot"

  EXTRACT="$WORK_DIR/extract"
  mkdir -p "$EXTRACT"
  unzip -q "$ZIP" -d "$EXTRACT"
  STAGE="$EXTRACT/$BUNDLE_NAME"

  # Pick a free port — don't collide with the user's dev server on 3000.
  PORT=$(node -e "
const net = require('net');
const s = net.createServer();
s.listen(0, () => { process.stdout.write(String(s.address().port)); s.close(); });
")

  # Minimal .env: only AUTH_SESSION_SECRET. No Falcon / Anthropic creds — the
  # /register wizard handles those. server.js doesn't need them at boot.
  SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  cat > "$STAGE/.env" <<EOF
AUTH_SESSION_SECRET=$SECRET
EOF

  echo "  starting server.js on :$PORT (silent, $WORK_DIR/server.log)…"
  # exec node so SERVER_PID is the node process itself, not the wrapping
  # subshell — otherwise `kill "$SERVER_PID"` SIGTERMs bash and leaves node
  # orphaned, holding the port.
  (cd "$STAGE" && PORT="$PORT" HOSTNAME=127.0.0.1 NODE_ENV=production exec node server.js > "$WORK_DIR/server.log" 2>&1) &
  SERVER_PID=$!

  # Poll /api/healthz — the cheap PUBLIC liveness probe. /api/health is
  # authenticated, so an unauthenticated poll there 302-redirects to /login
  # (which curl -f treats as success) and would mask a server that never
  # actually came up.
  HEALTH_OK=0
  for i in $(seq 1 60); do
    if curl -sSf -o /dev/null --max-time 2 "http://127.0.0.1:$PORT/api/healthz" 2>/dev/null; then
      HEALTH_OK=1
      break
    fi
    sleep 1
  done

  if [ "$HEALTH_OK" -eq 1 ]; then
    ok "/api/healthz responded 200 within 60s"

    # /login redirects to /register on a fresh bundle (no user registered yet),
    # so -L follows. Banner copy was reworded from "For Internal Use Only" to
    # the Unofficial-disclosure language during the 2026-05-04 branding refresh.
    if curl -sSL "http://127.0.0.1:$PORT/login" | grep -qi "not an official crowdstrike product"; then
      ok "/login renders (Unofficial disclosure present)"
    else
      fail "/login did not render or Unofficial disclosure missing — see $WORK_DIR/server.log"
    fi

    if curl -sSL "http://127.0.0.1:$PORT/register" | grep -qi "not an official crowdstrike product"; then
      ok "/register renders (Unofficial disclosure present)"
    else
      fail "/register did not render or Unofficial disclosure missing — see $WORK_DIR/server.log"
    fi
  else
    fail "/api/healthz never responded — see $WORK_DIR/server.log (showing last 30 lines):"
    tail -30 "$WORK_DIR/server.log" | sed 's/^/      /' >&2
  fi

  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" 2>/dev/null || true
fi

# ─── Summary ──────────────────────────────────────────────────────────────────
echo ""
if [ "$fail_count" -eq 0 ]; then
  echo -e "${GREEN}${BOLD}PASS${RESET}  $pass_count checks · $skip_count skipped"
  exit 0
else
  echo -e "${RED}${BOLD}FAIL${RESET}  $fail_count failed · $pass_count passed · $skip_count skipped"
  exit 1
fi

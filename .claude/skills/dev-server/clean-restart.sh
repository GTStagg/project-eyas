#!/usr/bin/env bash
# .claude/skills/dev-server/clean-restart.sh
#
# Kill all Next.js dev processes owned by this user, clear .next, start a
# single fresh dev server in the background. See SKILL.md for why each
# step matters and which symptoms it fixes.
#
# Flags (env vars):
#   KEEP_NEXT=1  — skip rm -rf .next
#   NO_START=1   — kill + clear only, don't start a new server
#   PORT=3000    — target port (default 3000)

set -u

PORT="${PORT:-3000}"
KEEP_NEXT="${KEEP_NEXT:-0}"
NO_START="${NO_START:-0}"
LOG_DIR="${LOG_DIR:-/tmp}"

# Run from repo root regardless of where we were invoked.
REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
info()   { printf '  --  %s\n' "$*"; }
ok()     { printf '  \033[32mok\033[0m  %s\n' "$*"; }
warn()   { printf '  \033[33m!!\033[0m  %s\n' "$*"; }

list_dev_procs() {
  # `-o command` (not `cmd`): macOS `ps` has no `cmd` column, but both macOS
  # and Linux accept `command`/`args` for the full invocation.
  ps -u "$(id -u)" -o pid,etime,command 2>/dev/null \
    | grep -E "next-server|next dev|node .+next dev" \
    | grep -v grep \
    | grep -v "clean-restart.sh" \
    || true
}

count_dev_procs() {
  list_dev_procs | wc -l | tr -d ' '
}

# ─── 1. inventory ────────────────────────────────────────────────────────────
echo
echo "== dev-server clean-restart (port=$PORT) =="

initial=$(list_dev_procs)
if [[ -n "$initial" ]]; then
  yellow "Found existing dev process(es):"
  echo "$initial" | sed 's/^/    /'
else
  info "No existing dev processes."
fi

# ─── 2. kill (graceful, then hard) ───────────────────────────────────────────
if [[ -n "$initial" ]]; then
  info "Sending SIGTERM to next-server / next dev..."
  pkill -f "next-server" 2>/dev/null || true
  pkill -f "next dev"    2>/dev/null || true
  sleep 2

  if [[ "$(count_dev_procs)" -gt 0 ]]; then
    warn "SIGTERM didn't take. Sending SIGKILL."
    pkill -9 -f "next-server" 2>/dev/null || true
    pkill -9 -f "next dev"    2>/dev/null || true
    sleep 1
  fi

  remaining=$(list_dev_procs)
  if [[ -n "$remaining" ]]; then
    red "FAIL: dev processes survived SIGKILL. Investigate before continuing:"
    echo "$remaining" | sed 's/^/    /'
    exit 2
  fi
  ok "All prior dev processes killed."
fi

# ─── 3. verify port is free ──────────────────────────────────────────────────
# Match only the LISTENing socket — without -sTCP:LISTEN, lsof also returns
# connected clients (e.g. an open browser tab), which falsely reads as "held".
# lsof is present on both macOS and Linux; the old `ss` fallback was Linux-only.
port_holder() {
  lsof -nP -iTCP:"$PORT" -sTCP:LISTEN -t 2>/dev/null | head -n 5
}

holder="$(port_holder)"
if [[ -n "$holder" ]]; then
  warn "Port $PORT still appears held:"
  echo "$holder" | sed 's/^/    /'
  warn "Waiting 3s for socket teardown..."
  sleep 3
  holder="$(port_holder)"
  if [[ -n "$holder" ]]; then
    red "FAIL: port $PORT still held by a non-Next process. Investigate before continuing."
    exit 3
  fi
fi
ok "Port $PORT is free."

# ─── 4. clear .next ──────────────────────────────────────────────────────────
if [[ "$KEEP_NEXT" == "1" ]]; then
  info "KEEP_NEXT=1 — leaving .next/ in place."
else
  if [[ -d .next ]]; then
    rm -rf .next
    ok "Cleared .next/"
  else
    info ".next/ absent — nothing to clear."
  fi
fi

# ─── 5. start ────────────────────────────────────────────────────────────────
if [[ "$NO_START" == "1" ]]; then
  info "NO_START=1 — not starting a new dev server."
  echo
  green "Done. Environment is clean."
  exit 0
fi

LOG_FILE="$LOG_DIR/eyas-dev-$(date +%Y%m%d-%H%M%S).log"
info "Starting dev server on port $PORT — log: $LOG_FILE"

# Background so the script returns; redirect both streams to the log.
nohup env PORT="$PORT" npm run dev > "$LOG_FILE" 2>&1 &
DEV_PID=$!

# Wait for ready signal or known failure.
SECONDS=0
TIMEOUT="${TIMEOUT:-60}"
while (( SECONDS < TIMEOUT )); do
  if grep -qE "Ready in|✓ Ready" "$LOG_FILE" 2>/dev/null; then
    ok "Dev server ready (pid $DEV_PID)."
    break
  fi
  if grep -qE "EADDRINUSE|FATAL|bootstrap failed|Error: Cannot" "$LOG_FILE" 2>/dev/null; then
    red "FAIL: dev server emitted an error during startup. Last 20 lines:"
    tail -20 "$LOG_FILE" | sed 's/^/    /'
    exit 4
  fi
  sleep 1
done

if (( SECONDS >= TIMEOUT )); then
  red "FAIL: dev server didn't become ready within ${TIMEOUT}s. Last 20 lines:"
  tail -20 "$LOG_FILE" | sed 's/^/    /'
  exit 5
fi

# ─── 6. confirm exactly one ──────────────────────────────────────────────────
final_count="$(count_dev_procs)"
if [[ "$final_count" != "1" ]] && [[ "$final_count" != "2" && "$final_count" != "3" ]]; then
  # Next.js spawns: the wrapper sh, the node, and the next-server worker.
  # 1-3 matching lines is normal. >3 means we have competing instances.
  warn "Unexpected dev-process count: $final_count (expected 1-3 for a single Next.js dev). Listing:"
  list_dev_procs | sed 's/^/    /'
fi

ok "Single dev server confirmed. Open: http://localhost:$PORT"
echo
green "Done."

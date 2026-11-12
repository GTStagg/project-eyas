#!/usr/bin/env bash
# gen-install.sh — emit the standalone bundle's install.sh (with the embedded
# `eyas` launcher) to stdout. Called from make-dist.sh at build time:
#
#     bash scripts/gen-install.sh > "$STAGE/install.sh"
#
# Design: the whole install.sh is authored below as ONE quoted heredoc, so every
# runtime `$var` / `$(...)` stays literal (no `\$` escaping). Only the handful of
# build-time values (command name, port) are injected by piping
# the template through `sed`, replacing @@TOKEN@@ markers. This is the
# adaptation of ~/.claude/skills/macos-standalone/gen-install.sh — NOT reused
# verbatim, because eyas's launcher wraps its own start.sh (native better-sqlite3
# + baked gateway lock) instead of `node server.js`, and a
# re-install preserves in-place credentials/DB.
set -euo pipefail

CONFIG="${1:-standalone.json}"
_json() { python3 -c "import json;d=json.load(open('$CONFIG'));print(d.get('$1','${2:-}'))"; }

APP_NAME="$(_json appName project-eyas)"
DISPLAY_NAME="$(_json displayName 'Project Eyas')"
COMMAND="$(_json command eyas)"
DEFAULT_PORT="$(_json defaultPort 3000)"
# Env-var override prefix, e.g. project-eyas -> PROJECT_EYAS.
ENV_PREFIX="$(printf '%s' "$APP_NAME" | tr 'a-z-' 'A-Z_')"

# ── The install.sh template. Quoted heredoc → fully literal; @@TOKENS@@ only. ──
# sed uses '|' as the delimiter; none of the injected values contain '|'.
sed \
  -e "s|@@APP_NAME@@|${APP_NAME}|g" \
  -e "s|@@DISPLAY_NAME@@|${DISPLAY_NAME}|g" \
  -e "s|@@COMMAND@@|${COMMAND}|g" \
  -e "s|@@ENV_PREFIX@@|${ENV_PREFIX}|g" \
  -e "s|@@DEFAULT_PORT@@|${DEFAULT_PORT}|g" \
<<'INSTALL_TEMPLATE'
#!/bin/bash
# @@DISPLAY_NAME@@ installer.
# Run from Terminal:   bash install.sh
# To upgrade, run a newer bundle's install.sh — it replaces the installation in
# place and preserves your credentials and data (.env, data/).
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${@@ENV_PREFIX@@_INSTALL_DIR:-$HOME/.local/share/@@APP_NAME@@}"
DATA_DIR="${@@ENV_PREFIX@@_DATA_DIR:-$HOME/.@@APP_NAME@@}"
BIN_DIR="${@@ENV_PREFIX@@_BIN_DIR:-$HOME/.local/bin}"
LAUNCHER="$BIN_DIR/@@COMMAND@@"

# ---- Corporate TLS-inspection CA (Zscaler / Netskope), if present -----------
_setup_ca() {
  for _ca in "$HOME/.zscaler-ca.pem" \
             "/Library/Application Support/Netskope/STAgent/data/nscacert.pem"; do
    if [ -f "$_ca" ]; then export NODE_EXTRA_CA_CERTS="$_ca"; return; fi
  done
}
_setup_ca

# ---- Copy the bundle into the install directory ------------------------------
# --delete keeps the install dir a clean mirror of the new bundle, but .env and
# data/ are excluded so credentials + the database survive a re-install.
echo "==> Installing @@DISPLAY_NAME@@ to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --exclude '.env' --exclude 'data/' "$BUNDLE_DIR/" "$INSTALL_DIR/"
else
  # rsync-less fallback (macOS always has rsync; this is belt-and-suspenders):
  # overwrite code, never touch an existing .env / data/.
  find "$BUNDLE_DIR" -maxdepth 1 -mindepth 1 ! -name .env ! -name data \
    -exec cp -R {} "$INSTALL_DIR/" \;
fi
chmod +x "$INSTALL_DIR/start.sh" 2>/dev/null || true

# ---- Write the @@COMMAND@@ launcher ------------------------------------------
mkdir -p "$BIN_DIR"
cat > "$LAUNCHER" <<'LAUNCHER_EOF'
#!/bin/bash
# @@COMMAND@@ — @@DISPLAY_NAME@@ launcher.
# Usage: @@COMMAND@@ [start|stop|restart|status|logs]   (default: start)
set -uo pipefail

INSTALL_DIR="${@@ENV_PREFIX@@_INSTALL_DIR:-$HOME/.local/share/@@APP_NAME@@}"
DATA_DIR="${@@ENV_PREFIX@@_DATA_DIR:-$HOME/.@@APP_NAME@@}"
BIN_DIR="${@@ENV_PREFIX@@_BIN_DIR:-$HOME/.local/bin}"
LAUNCHER="$BIN_DIR/@@COMMAND@@"
PORT="${PORT:-@@DEFAULT_PORT@@}"
PID_FILE="$DATA_DIR/@@APP_NAME@@.pid"
LOG_FILE="$DATA_DIR/@@APP_NAME@@.log"

_setup_ca() {
  for _ca in "$HOME/.zscaler-ca.pem" \
             "/Library/Application Support/Netskope/STAgent/data/nscacert.pem"; do
    if [ -f "$_ca" ]; then export NODE_EXTRA_CA_CERTS="$_ca"; return; fi
  done
}

_healthz_ok() { curl -fs -o /dev/null "http://127.0.0.1:$PORT/api/healthz" 2>/dev/null; }

_is_running() {
  [ -f "$PID_FILE" ] || return 1
  kill -0 "$(cat "$PID_FILE")" 2>/dev/null
}

_start() {
  if _is_running; then
    echo "@@DISPLAY_NAME@@ is already running (pid $(cat "$PID_FILE"), http://localhost:$PORT)"
    return 0
  fi
  _setup_ca
  mkdir -p "$DATA_DIR"
  echo "Starting @@DISPLAY_NAME@@ on http://localhost:$PORT"
  # Run eyas's own start.sh in the background. EYAS_MANAGED tells start.sh not
  # to open the browser (we do it after readiness). Because start.sh ends in
  # `exec node server.js`, $PID_FILE tracks the real node pid.
  (
    cd "$INSTALL_DIR"
    EYAS_MANAGED=1 \
    PORT="$PORT" \
      nohup bash "$INSTALL_DIR/start.sh" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    disown
  )
  # First launch after a (re-)install rebuilds the Python components from the
  # bundle's wheels, so allow generous time (~180s) before giving up.
  local ok=""
  for _ in $(seq 1 90); do
    sleep 2
    if _healthz_ok; then ok=1; break; fi
    _is_running || break   # start.sh aborted (e.g. wheel rebuild failed)
  done
  if [ -n "$ok" ]; then
    command -v open >/dev/null && open "http://localhost:$PORT" 2>/dev/null || true
    echo "Ready — http://localhost:$PORT  (run '@@COMMAND@@ stop' to stop)"
    return 0
  fi
  echo "@@DISPLAY_NAME@@ did not become ready in time. Run '@@COMMAND@@ logs' to see why."
  return 1
}

_stop() {
  if ! _is_running; then
    echo "@@DISPLAY_NAME@@ is not running."
    rm -f "$PID_FILE"
    return 0
  fi
  local pid; pid="$(cat "$PID_FILE")"
  # Single-pid SIGTERM (never a group kill) so the server's WAL-checkpoint
  # shutdown handler runs and the database is left consistent.
  kill "$pid" 2>/dev/null || true
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    i=$((i+1)); [ "$i" -ge 30 ] && break; sleep 0.5
  done
  kill -0 "$pid" 2>/dev/null && kill -9 "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
  echo "Stopped."
}

_show_status() {
  if _is_running; then
    echo "Running (pid $(cat "$PID_FILE"), http://localhost:$PORT)"
  else
    echo "Not running."
    rm -f "$PID_FILE"
  fi
}

_logs() {
  [ -f "$LOG_FILE" ] || { echo "No log yet ($LOG_FILE)."; return 0; }
  tail -f "$LOG_FILE"
}

case "${1:-start}" in
  start)   _start ;;
  stop)    _stop ;;
  restart) _stop; _start ;;
  status)  _show_status ;;
  logs)    _logs ;;
  *)
    echo "Usage: @@COMMAND@@ [start|stop|restart|status|logs]"
    echo "  start    Start in the background and open the browser (default)"
    echo "  stop     Stop the background server"
    echo "  restart  Stop then start"
    echo "  status   Is it running?"
    echo "  logs     Follow the server log"
    exit 1
    ;;
esac
LAUNCHER_EOF
chmod +x "$LAUNCHER"

# ---- Put ~/.local/bin on PATH so `@@COMMAND@@` resolves ----------------------
_add_to_path() {
  local profile="$1"
  if [ -f "$profile" ] && grep -qF '.local/bin' "$profile"; then return; fi
  printf '\n# Added by @@DISPLAY_NAME@@ installer\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$profile"
  echo "   Added ~/.local/bin to PATH in $profile"
}
if [ -n "${ZSH_VERSION:-}" ] || [ "$(basename "${SHELL:-}")" = "zsh" ]; then
  _add_to_path "$HOME/.zshrc"
else
  _add_to_path "$HOME/.bash_profile"
  [ -f "$HOME/.bashrc" ] && _add_to_path "$HOME/.bashrc"
fi

# ---- Done --------------------------------------------------------------------
echo ""
echo "Installed: @@DISPLAY_NAME@@"
echo ""
echo "   @@COMMAND@@          — start (runs in the background, opens the browser)"
echo "   @@COMMAND@@ stop     — stop it"
echo "   @@COMMAND@@ status   — is it running?"
echo "   @@COMMAND@@ logs     — view the server log"
echo ""
if ! echo "$PATH" | grep -q "$BIN_DIR"; then
  echo "   Open a new Terminal window (or run:  source ~/.zshrc)"
  echo "   so the '@@COMMAND@@' command is available."
  echo ""
fi
INSTALL_TEMPLATE

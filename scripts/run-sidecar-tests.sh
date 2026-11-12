#!/usr/bin/env bash
# Run every falcon-extras pure-function test suite. The add-on registers no
# tools any more, so there are none today; the runner stays until the add-on
# is removed. Run from the project root: `npm run test:sidecar`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

# SIDECAR_PYTHON overrides the interpreter (CI uses a fresh venv).
PY="${SIDECAR_PYTHON:-falcon-extras/.venv/bin/python3}"
if [ ! -x "$PY" ]; then
  echo "ERROR: $PY missing." >&2
  echo "       Run: cd falcon-extras && uv venv && uv pip install -r requirements.txt" >&2
  exit 1
fi

# Every test_*.py under falcon-extras/, so a new suite can't be left out.
SUITES=()
while IFS= read -r f; do SUITES+=("$f"); done < <(find falcon-extras -name 'test_*.py' -not -path '*/.venv/*' | sort)
if [ "${#SUITES[@]}" -eq 0 ]; then
  # Every add-on tool now runs in Eyas; nothing is left to test here.
  echo "No sidecar test suites (the add-on registers no tools)."
  exit 0
fi

PASS=0
FAIL=0
for suite in "${SUITES[@]}"; do
  echo ""
  echo "=== $suite ==="
  if "$PY" "$suite"; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
  fi
done

echo ""
echo "Suites: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]

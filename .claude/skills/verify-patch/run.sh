#!/usr/bin/env bash
# Smoke-test one or more patching catalog entries.
# Usage: run.sh <script_id> [<script_id> ...]
set -euo pipefail
cd "$(dirname "$0")/../../.."

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <script_id> [<script_id> ...]" >&2
    exit 2
fi

python3 - "$@" <<'PY'
import sys, json, pathlib
sys.path.insert(0, "falcon-extras")
from patching import library

ids = sys.argv[1:]
manifest = json.load(open("falcon-extras/patching/manifest.json"))
by_id = {s["id"]: s for s in manifest["scripts"]}

# Defaults to satisfy required params per script id, where the obvious answer exists.
DEFAULT_PARAMS = {
    "win-update-install": {"reboot": "never"},
    "win-dotnet-framework-update": {"reboot": "never"},
    "app-temurin": {"version": "21"},
    "app-office": {"channel": "current"},
    "linux-pkg-upgrade": {"package": "curl"},
    # Generic installer: url + product are required (no defaults -- that's the
    # security boundary). kind defaults to msi; sha256/silent_args are optional.
    # Omitting sha256 here deliberately exercises the louder UNVERIFIED banner.
    "win-app-install": {"url": "https://example.com/app.msi", "product": "Example App"},
}

failed = 0
for sid in ids:
    spec = by_id.get(sid)
    if not spec:
        print(f"[FAIL] {sid}: not in manifest")
        failed += 1
        continue
    params = DEFAULT_PARAMS.get(sid, {})
    try:
        plan = library.resolve_plan(sid, params)
    except Exception as e:
        print(f"[FAIL] {sid}: resolve_plan -> {type(e).__name__}: {e}")
        failed += 1
        continue
    body = plan.rendered
    nonascii = sum(1 for c in body if ord(c) > 127)
    status = "OK" if nonascii == 0 else "FAIL"
    if nonascii > 0:
        failed += 1
    print(
        f"[{status}] {sid}: {len(body)}B, runtime={plan.expected_runtime_minutes}m, "
        f"reboot={plan.reboot_risk}, non-ascii={nonascii}"
    )

    # Spotlight regression: the entry's own pattern should still resolve back to itself.
    sm = spec.get("spotlight_match")
    if sm:
        # Build a representative (vendor, product) pair from the patterns by stripping
        # regex anchors / alternations to a literal probe. Doesn't cover every case,
        # but catches the first-declared-wins ordering trap.
        import re
        def first_alt(pat):
            if not pat: return ""
            inner = re.sub(r"^\^|\$$", "", pat)
            inner = re.sub(r"\\\.", ".", inner)
            # split on top-level alternation
            parts = re.split(r"\|", inner, maxsplit=1)
            probe = parts[0]
            # strip parenthesized optional groups like "( Corporation)?" -> ""
            probe = re.sub(r"\([^)]*\)\?", "", probe)
            # strip remaining unmatched parens
            probe = probe.replace("(", "").replace(")", "")
            return probe
        v_probe = first_alt(sm.get("vendor_pattern", ""))
        p_probe = first_alt(sm.get("product_pattern", ""))
        match = library.match_remediation(v_probe, p_probe, spec["os"])
        match_id = match["id"] if match else None
        ok = match_id == sid
        # Probe is best-effort -- complex patterns (nested groups, deep alternation)
        # produce probe strings that don't roundtrip. Treat probe mismatches as
        # informational; real shadowing shows up in /audit-remediations against
        # live data. Render + non-ASCII checks still fail-on-wrong.
        note = "(OK)" if ok else "(probe didn't roundtrip; verify with real Spotlight strings)"
        print(
            f"      spotlight probe vendor={v_probe!r} product={p_probe!r} "
            f"-> {match_id} {note}"
        )

print()
if failed:
    print(f"FAILED: {failed} issue(s)")
    sys.exit(1)
print("All passed.")
PY

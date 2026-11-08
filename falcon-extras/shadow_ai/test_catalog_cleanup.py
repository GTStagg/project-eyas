"""Unit tests for deterministic Shadow-AI cleanup routing.

Regression guard for the ban-and-clean improvement that moved MSIX-vs-Squirrel
uninstaller selection out of a "MANDATORY" playbook prompt instruction (which
agents skip) and into deterministic code (catalog.cleanup_plan). The scan now
hands each app entry a ready-to-fire cleanup[] so the agent never guesses the
installer form from paths.

catalog.py is stdlib-only, so this imports it directly (no venv / FalconPy).

Run:
    python3 falcon-extras/shadow_ai/test_catalog_cleanup.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from catalog import cleanup_plan, classify_distribution_form  # noqa: E402

APPX = "host-uninstall-appx-package"


def _check(name: str, got, want) -> None:
    assert got == want, f"{name}: got {got!r}, want {want!r}"
    print(f"  ok  {name}")


def test_squirrel_curated() -> None:
    # Cursor per-user Squirrel install -> curated uninstaller, no appx.
    paths = [r"C:\Users\jdoe\AppData\Local\Programs\cursor\Cursor.exe"]
    form, ms, plan = cleanup_plan("cursor", paths)
    _check("squirrel.form", form, "squirrel")
    _check("squirrel.ms", ms, False)
    _check("squirrel.plan", plan, [{"script_id": "host-uninstall-cursor", "params": {}}])


def test_msix_claude() -> None:
    # Claude Desktop MSIX -> appx uninstaller with the derived package pattern,
    # NOT the curated Squirrel script.
    paths = [r"C:\Program Files\WindowsApps\Claude_1.2.3_x64__8x0abc\Claude.exe"]
    form, ms, plan = cleanup_plan("claude_desktop", paths)
    _check("msix.form", form, "msix")
    _check("msix.ms", ms, False)
    _check(
        "msix.plan",
        plan,
        [{"script_id": APPX, "params": {"package_name_pattern": "Claude"}}],
    )


def test_microsoft_copilot_stop() -> None:
    # Microsoft-published Store package -> microsoft_managed, empty plan (STOP).
    paths = [
        r"C:\Program Files\WindowsApps\Microsoft.Copilot_1.0_x64__8wekyb3d8bbwe\Copilot.exe"
    ]
    form, ms, plan = cleanup_plan("copilot_cli", paths)
    _check("copilot.form", form, "msix")
    _check("copilot.ms", ms, True)
    _check("copilot.plan", plan, [])


def test_both_forms() -> None:
    # Same product installed both ways (rare) -> fire both, appx first.
    paths = [
        r"C:\Program Files\WindowsApps\Cursor_1.0_x64__abc\Cursor.exe",
        r"C:\Users\jdoe\AppData\Local\Programs\cursor\Cursor.exe",
    ]
    form, ms, plan = cleanup_plan("cursor", paths)
    _check("both.form", form, "both")
    _check("both.ms", ms, False)
    _check(
        "both.plan",
        plan,
        [
            {"script_id": APPX, "params": {"package_name_pattern": "Cursor"}},
            {"script_id": "host-uninstall-cursor", "params": {}},
        ],
    )


def test_unknown_form_curated_default() -> None:
    # Traditional Program Files install (not WindowsApps, not AppData\Local):
    # form unknown, curated script is still the sensible default.
    paths = [r"C:\Program Files\Ollama\ollama.exe"]
    form, ms, plan = cleanup_plan("ollama", paths)
    _check("unknown.form", form, "unknown")
    _check("unknown.plan", plan, [{"script_id": "host-uninstall-ollama", "params": {}}])


def test_no_curated_no_plan() -> None:
    # A cataloged family with no curated uninstaller + unknown form -> empty
    # plan (caller falls back to kill+delete).
    paths = [r"C:\Program Files\Jan\Jan.exe"]
    form, ms, plan = cleanup_plan("jan", paths)
    _check("nocurated.form", form, "unknown")
    _check("nocurated.plan", plan, [])


def test_msix_packages_state_only() -> None:
    # Per-user Packages state path but no WindowsApps exe -> detected as MSIX,
    # but no derivable package pattern, so the appx entry is omitted rather than
    # firing with a bad pattern. No crash.
    paths = [r"C:\Users\jdoe\AppData\Local\Packages\AnthropicClaude_abc\LocalCache\x.exe"]
    form, ms, plan = cleanup_plan("claude_desktop", paths)
    _check("stateonly.form", form, "msix")
    _check("stateonly.plan", plan, [])


def test_empty_paths() -> None:
    _check("empty.form", classify_distribution_form([]), "unknown")
    form, ms, plan = cleanup_plan("cursor", [])
    _check("empty.plan", plan, [{"script_id": "host-uninstall-cursor", "params": {}}])


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"running {len(tests)} cleanup-routing tests")
    for t in tests:
        t()
    print(f"\nALL {len(tests)} PASSED")

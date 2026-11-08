"""Unit tests for override-aware host-group id resolution.

Covers falcon_helpers.resolve_group_id + set_runtime_group_id — the fix for
the same-turn staleness foot-gun: the sidecar runs ONE process per chat turn
with a frozen os.environ, so a group created/adopted mid-turn must be visible
to sibling tools (diagnose / provision / playbook) via a process-local
override, not only the next-spawn env var.

Precedence under test: explicit arg > runtime override > spawn-time env > None.

Run:
    falcon-extras/.venv/bin/python3 falcon-extras/test_group_id_resolution.py
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import falcon_helpers as fh

QENV = "FALCON_QUARANTINE_GROUP_ID"
SENV = "FALCON_SHADOW_AI_BANNED_GROUP_ID"


def _reset():
    """Clear both the runtime overrides and the env vars under test."""
    fh._RUNTIME_GROUP_OVERRIDES.clear()
    for var in (QENV, SENV):
        os.environ.pop(var, None)


def test_none_when_nothing_set():
    _reset()
    assert fh.resolve_group_id("quarantine") is None
    assert fh.resolve_group_id("shadow_ai_banned") is None


def test_env_is_used_when_no_override():
    _reset()
    os.environ[QENV] = "env-q-id"
    assert fh.resolve_group_id("quarantine") == "env-q-id"


def test_override_beats_env():
    """The core fix: a mid-turn adopt/create sets an override that must win
    over the (stale) spawn-time env var."""
    _reset()
    os.environ[QENV] = "stale-env-id"
    fh.set_runtime_group_id("quarantine", "fresh-adopted-id")
    assert fh.resolve_group_id("quarantine") == "fresh-adopted-id"


def test_override_satisfies_when_env_empty():
    """Reproduces the reported bug shape: env unset at spawn, group adopted
    this turn — resolve must now return the adopted id, not None."""
    _reset()
    assert fh.resolve_group_id("quarantine") is None  # pre-adopt
    fh.set_runtime_group_id("quarantine", "adopted-mid-turn")
    assert fh.resolve_group_id("quarantine") == "adopted-mid-turn"


def test_explicit_arg_beats_everything():
    _reset()
    os.environ[QENV] = "env-id"
    fh.set_runtime_group_id("quarantine", "override-id")
    assert fh.resolve_group_id("quarantine", "explicit-id") == "explicit-id"


def test_blank_explicit_falls_through_to_override():
    _reset()
    fh.set_runtime_group_id("quarantine", "override-id")
    assert fh.resolve_group_id("quarantine", "   ") == "override-id"
    assert fh.resolve_group_id("quarantine", None) == "override-id"


def test_kinds_are_isolated():
    """Setting the quarantine override must not bleed into shadow_ai_banned."""
    _reset()
    fh.set_runtime_group_id("quarantine", "q-id")
    assert fh.resolve_group_id("quarantine") == "q-id"
    assert fh.resolve_group_id("shadow_ai_banned") is None


def test_values_are_stripped():
    _reset()
    os.environ[SENV] = "  padded-env  "
    assert fh.resolve_group_id("shadow_ai_banned") == "padded-env"
    fh.set_runtime_group_id("shadow_ai_banned", "  padded-override  ")
    assert fh.resolve_group_id("shadow_ai_banned") == "padded-override"


def test_set_ignores_blank_and_none():
    _reset()
    fh.set_runtime_group_id("quarantine", "")
    fh.set_runtime_group_id("quarantine", "   ")
    fh.set_runtime_group_id("quarantine", None)
    assert "quarantine" not in fh._RUNTIME_GROUP_OVERRIDES
    assert fh.resolve_group_id("quarantine") is None


def test_unknown_kind_raises():
    _reset()
    for op in (lambda: fh.resolve_group_id("bogus"),
               lambda: fh.set_runtime_group_id("bogus", "x")):
        try:
            op()
        except ValueError:
            continue
        raise AssertionError("expected ValueError on unknown kind")


def main() -> int:
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  ok   {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    _reset()
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

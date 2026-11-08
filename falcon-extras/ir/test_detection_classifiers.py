"""Unit tests for the IR detection classifiers.

These two pure functions decide which post-Phase-1 detections are NEW threats
vs artifacts of the workflow itself or retrospective IOC backfill. A
regression here would either over-FP-close real new detections (silent) or
trigger HOLD on a clean run (loud — but burns a re-run). Both classifiers
are conservative by design: any uncertainty falls back to "real."

Run:
    falcon-extras/.venv/bin/python3 falcon-extras/ir/test_detection_classifiers.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ir.detection_classifiers import (  # noqa: E402
    _detection_is_retrospective_backfill,
    _detection_is_retrospective_ioc_match,
    _detection_is_shadow_ai_ioc_audit,
    _detection_is_workflow_self_triggered,
    _RTR_PREAMBLE_BASE64,
)


# RTR preamble snippet operators see in real cmdlines. Wrapping it so the
# test fixtures match what the production sensor reports.
_PREAMBLE_CMDLINE = (
    'powershell.exe -Version 5.1 -s -NoLogo -NoProfile -EncodedCommand '
    + _RTR_PREAMBLE_BASE64
    + ' -File C:\\some\\cleanup.ps1'
)


# ===========================================================================
# _detection_is_workflow_self_triggered
# ===========================================================================


def test_self_triggered_via_top_level_cmdline():
    rec = {"cmdline": _PREAMBLE_CMDLINE}
    assert _detection_is_workflow_self_triggered(rec) is True


def test_self_triggered_via_parent_cmdline():
    # Detection's own process is a child; parent_details carries the RTR
    # preamble. This is the most common shape — IR cleanup spawns a child
    # that fires PShellMimikatz.
    rec = {
        "cmdline": "C:\\Windows\\System32\\whoami.exe",
        "parent_details": {"cmdline": _PREAMBLE_CMDLINE},
    }
    assert _detection_is_workflow_self_triggered(rec) is True


def test_self_triggered_via_behaviors_cmdline():
    rec = {
        "cmdline": "x.exe",
        "behaviors": [{"cmdline": _PREAMBLE_CMDLINE}],
    }
    assert _detection_is_workflow_self_triggered(rec) is True


def test_not_self_triggered_when_no_preamble_anywhere():
    rec = {
        "cmdline": "powershell.exe -EncodedCommand AAA",  # different base64
        "parent_details": {"cmdline": "explorer.exe"},
        "behaviors": [{"cmdline": "cmd.exe /c whoami"}],
    }
    assert _detection_is_workflow_self_triggered(rec) is False


def test_not_self_triggered_when_record_is_empty():
    assert _detection_is_workflow_self_triggered({}) is False


def test_not_self_triggered_with_non_string_cmdline():
    # Defensive: cmdline can be None, missing, or a non-string. Must not
    # crash; must not falsely classify.
    rec = {
        "cmdline": None,
        "parent_details": {"cmdline": 12345},  # non-string
        "behaviors": [
            {"cmdline": ["a", "b"]},  # list, not string
            {"cmdline": _PREAMBLE_CMDLINE},  # this one IS the match
        ],
    }
    # Last behavior matches → True
    assert _detection_is_workflow_self_triggered(rec) is True


def test_self_triggered_partial_base64_does_not_match():
    # A near-miss with a truncated preamble must NOT classify as self.
    truncated = _PREAMBLE_CMDLINE.replace(_RTR_PREAMBLE_BASE64, _RTR_PREAMBLE_BASE64[:-4])
    rec = {"cmdline": truncated}
    assert _detection_is_workflow_self_triggered(rec) is False


# ===========================================================================
# _detection_is_retrospective_ioc_match
# ===========================================================================


# Phase 1 quarantine point used by every retrospective test. Far enough in
# the past that we can write tests against it without flake.
SINCE_TS = 1_700_000_000.0  # 2023-11-14 22:13:20 UTC


def test_retrospective_when_all_underlying_ts_predate_quarantine():
    rec = {
        "network_accesses": [
            {"access_timestamp": str(int(SINCE_TS - 86400))},  # 1d before
        ],
        "behaviors": [
            {"timestamp": "2023-11-13T00:00:00Z"},  # also before SINCE_TS
        ],
    }
    is_retro, reason = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    assert is_retro is True
    assert reason and "predate" in reason


def test_not_retrospective_when_any_underlying_ts_is_after_quarantine():
    rec = {
        "network_accesses": [
            {"access_timestamp": str(int(SINCE_TS - 60))},
            {"access_timestamp": str(int(SINCE_TS + 60))},  # post-quarantine
        ],
    }
    is_retro, reason = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    assert is_retro is False
    assert reason is None


def test_not_retrospective_when_no_underlying_ts_present():
    # No network_accesses, no behaviors[].timestamp — can't classify.
    # Conservative: return False, let the agent decide.
    rec = {"behaviors": [{"description": "no ts here"}]}
    is_retro, _ = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    assert is_retro is False


def test_retrospective_via_iso_8601_behaviors_timestamp():
    # ISO-8601 with Z must parse via datetime.fromisoformat after Z→+00:00.
    rec = {
        "behaviors": [
            {"behavior_timestamp": "2023-11-13T01:23:45Z"},
        ],
    }
    is_retro, _ = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    assert is_retro is True


def test_retrospective_handles_first_behavior_field():
    # behaviors[].first_behavior is a third accepted ISO field on the
    # detection envelope; must be read alongside timestamp + behavior_timestamp.
    rec = {
        "behaviors": [{"first_behavior": "2023-11-13T00:00:00Z"}],
    }
    is_retro, _ = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    assert is_retro is True


def test_retrospective_via_context_timestamp():
    # context_timestamp on the detection root is also valid as an underlying
    # event signal.
    rec = {"context_timestamp": "2023-11-13T00:00:00Z"}
    is_retro, _ = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    assert is_retro is True


def test_retrospective_handles_numeric_epoch_timestamps():
    # Falcon sometimes returns epoch as int/float instead of string. Both
    # must be accepted.
    rec = {
        "network_accesses": [
            {"access_timestamp": SINCE_TS - 3600},  # float
        ],
    }
    is_retro, _ = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    assert is_retro is True


def test_retrospective_skips_unparseable_timestamp_strings():
    # Garbage strings shouldn't crash and shouldn't count as evidence.
    rec = {
        "network_accesses": [
            {"access_timestamp": "not-a-date"},
        ],
    }
    is_retro, _ = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    # No parseable underlying ts → False (conservative).
    assert is_retro is False


def test_retrospective_mixed_epoch_and_iso():
    # Mixed shapes within a single detection — both predate, so still True.
    rec = {
        "network_accesses": [
            {"access_timestamp": str(int(SINCE_TS - 86400))},
        ],
        "behaviors": [
            {"timestamp": "2023-11-13T00:00:00Z"},
            {"first_behavior": SINCE_TS - 3600},  # numeric
        ],
    }
    is_retro, _ = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    assert is_retro is True


def test_retrospective_boundary_timestamp_at_since_ts_classifies_as_real():
    # Exactly at SINCE_TS counts as post-quarantine (>= comparison) — real.
    rec = {
        "network_accesses": [{"access_timestamp": SINCE_TS}],
    }
    is_retro, _ = _detection_is_retrospective_ioc_match(rec, SINCE_TS)
    assert is_retro is False


# ===========================================================================
# _detection_is_shadow_ai_ioc_audit
# ===========================================================================


def test_shadow_ai_audit_claude_ai():
    rec = {
        "behaviors": [
            {"ioc_type": "domain", "ioc_value": "claude.ai"},
        ],
    }
    is_audit, matched = _detection_is_shadow_ai_ioc_audit(rec)
    assert is_audit is True
    assert matched == "claude.ai"


def test_shadow_ai_audit_api_anthropic():
    rec = {
        "behaviors": [
            {"ioc_type": "domain", "ioc_value": "api.anthropic.com"},
        ],
    }
    is_audit, matched = _detection_is_shadow_ai_ioc_audit(rec)
    assert is_audit is True
    assert matched == "api.anthropic.com"


def test_shadow_ai_audit_case_insensitive():
    rec = {
        "behaviors": [
            {"ioc_type": "DOMAIN", "ioc_value": "CHATGPT.COM"},
        ],
    }
    is_audit, matched = _detection_is_shadow_ai_ioc_audit(rec)
    assert is_audit is True
    assert matched == "chatgpt.com"


def test_shadow_ai_audit_ignores_non_catalog_domain():
    rec = {
        "behaviors": [
            {"ioc_type": "domain", "ioc_value": "evil.example.com"},
        ],
    }
    is_audit, matched = _detection_is_shadow_ai_ioc_audit(rec)
    assert is_audit is False
    assert matched is None


def test_shadow_ai_audit_ignores_non_domain_ioc():
    # An IOC fire on a hash that happens to be named like a catalog domain
    # shouldn't match — ioc_type must be "domain".
    rec = {
        "behaviors": [
            {
                "ioc_type": "sha256",
                "ioc_value": "deadbeef" * 8,
            },
        ],
    }
    is_audit, matched = _detection_is_shadow_ai_ioc_audit(rec)
    assert is_audit is False
    assert matched is None


def test_shadow_ai_audit_no_behaviors():
    rec = {"cmdline": "whatever.exe"}
    is_audit, matched = _detection_is_shadow_ai_ioc_audit(rec)
    assert is_audit is False
    assert matched is None


def test_shadow_ai_audit_partial_subdomain_does_not_match():
    # Anchored full-match in the catalog: a subdomain string like
    # "claude.ai.evil.com" must NOT match the "claude.ai" pattern.
    rec = {
        "behaviors": [
            {"ioc_type": "domain", "ioc_value": "claude.ai.evil.com"},
        ],
    }
    is_audit, matched = _detection_is_shadow_ai_ioc_audit(rec)
    assert is_audit is False
    assert matched is None


def test_shadow_ai_audit_mixed_behaviors_picks_match():
    # First behavior is unrelated; second is a Shadow-AI catalog hit. Must
    # return True with the matched value from the right behavior.
    rec = {
        "behaviors": [
            {"ioc_type": "ipv4", "ioc_value": "1.2.3.4"},
            {"ioc_type": "domain", "ioc_value": "api.openai.com"},
        ],
    }
    is_audit, matched = _detection_is_shadow_ai_ioc_audit(rec)
    assert is_audit is True
    assert matched == "api.openai.com"


# ===========================================================================
# _detection_is_retrospective_backfill (Phase 0 workflow-entry variant)
#
# Regression guard for the critical bug where Phase 0 compared underlying
# events against `now` — making EVERY recent real detection look retrospective
# (its events are always older than now) and FP-closing real malware. The
# correct signal is the GAP between the fresh created_timestamp and the old
# underlying events.
# ===========================================================================


def test_backfill_recent_real_malware_is_actionable():
    # THE critical regression: a real detection scored ~5 min after its
    # behavior fired. Tiny created-vs-event gap → NOT retrospective, must stay
    # actionable so the workflow quarantines + cleans.
    rec = {
        "created_timestamp": "2026-06-06T12:05:00Z",
        "behaviors": [{"timestamp": "2026-06-06T12:00:00Z"}],
        "network_accesses": [{"access_timestamp": "1749211200"}],  # 12:00:00Z
    }
    is_retro, reason = _detection_is_retrospective_backfill(rec)
    assert is_retro is False, reason
    assert reason is None


def test_backfill_old_events_fresh_envelope_is_retrospective():
    # True Falcon IOC backfill: events from a month ago, envelope scored now.
    # Wide gap → retrospective, safe to FP-close.
    rec = {
        "created_timestamp": "2026-06-06T12:00:00Z",
        "behaviors": [{"timestamp": "2026-05-01T09:00:00Z"}],
    }
    is_retro, reason = _detection_is_retrospective_backfill(rec)
    assert is_retro is True
    assert reason and "backfill" in reason


def test_backfill_no_underlying_events_is_actionable():
    # No underlying timestamps to reason about → can't classify → actionable.
    rec = {"created_timestamp": "2026-06-06T12:00:00Z", "cmdline": "evil.exe"}
    is_retro, reason = _detection_is_retrospective_backfill(rec)
    assert is_retro is False
    assert reason is None


def test_backfill_no_created_timestamp_is_actionable():
    # Underlying events present but no created_timestamp → can't compute the
    # gap → stay actionable (conservative).
    rec = {"behaviors": [{"timestamp": "2026-05-01T09:00:00Z"}]}
    is_retro, reason = _detection_is_retrospective_backfill(rec)
    assert is_retro is False
    assert reason is None


def test_backfill_mixed_one_recent_event_is_not_retrospective():
    # One ancient event plus one recent event. newest underlying is recent →
    # small gap to created → real new activity, do NOT auto-close.
    rec = {
        "created_timestamp": "2026-06-06T12:10:00Z",
        "behaviors": [
            {"timestamp": "2026-05-01T09:00:00Z"},
            {"timestamp": "2026-06-06T12:00:00Z"},
        ],
    }
    is_retro, reason = _detection_is_retrospective_backfill(rec)
    assert is_retro is False, reason


def test_backfill_epoch_string_network_timestamp():
    # network_accesses[].access_timestamp arrives as epoch-seconds strings;
    # created_timestamp as ISO. Old epoch event + fresh ISO envelope → retro.
    rec = {
        "created_timestamp": "2026-06-06T12:00:00Z",
        "network_accesses": [{"access_timestamp": "1746090000"}],  # 2025-05-01
    }
    is_retro, reason = _detection_is_retrospective_backfill(rec)
    assert is_retro is True


def test_backfill_gap_just_under_threshold_is_actionable():
    # 23h gap (< 24h default floor) → not yet retrospective. Guards the
    # boundary so a same-day real detection isn't swept up.
    rec = {
        "created_timestamp": "2026-06-06T23:00:00Z",
        "behaviors": [{"timestamp": "2026-06-06T00:00:00Z"}],
    }
    is_retro, _ = _detection_is_retrospective_backfill(rec)
    assert is_retro is False


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
        except Exception as e:
            failed += 1
            print(f"  ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

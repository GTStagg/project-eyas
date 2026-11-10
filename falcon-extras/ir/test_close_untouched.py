"""Unit tests for the post-IR "close untouched originals" step.

After the ledger close (extras_ir_close_remediated), the Phase 0 detections no
remediation touched stay open and Eyas's release gate refuses to release the
host. On the operator's say-so, extras_ir_close_untouched_originals closes
every endpoint detection that is still open AND was created before the Phase 1
quarantine time. These tests pin that cutoff: anything that fired during the
engagement (workflow-self, retrospective, a real new detection) stays open,
and a detection with no readable creation time is never closed on a guess.

``close_remediated`` imports ``falcon_helpers`` (→ falconpy) at module load;
it's stubbed here with a fake alerts client, so nothing touches the network.

Run:
    python3 falcon-extras/ir/test_close_untouched.py
"""

from __future__ import annotations

import sys
import types
from datetime import datetime, timezone
from pathlib import Path


class _FakeAlerts:
    """Minimal v2/v3 Alerts client: one page of ids, hydration, and a recorder."""

    def __init__(self, records):
        self.records = {r["composite_id"]: r for r in records}
        self.updates = []

    def query_alerts_v2(self, **kwargs):
        offset = kwargs.get("offset", 0)
        ids = list(self.records)[offset : offset + kwargs.get("limit", 200)]
        return {"status_code": 200, "body": {"resources": ids}}

    def get_alerts_v2(self, body):
        return {
            "status_code": 200,
            "body": {"resources": [self.records[c] for c in body["composite_ids"]]},
        }

    def update_alerts_v3(self, body):
        self.updates.append(body)
        return {"status_code": 200, "body": {}}


_client_holder: dict = {}

_fake = types.ModuleType("falcon_helpers")
_fake._check_response = lambda *a, **k: None
_fake._get_alerts_client = lambda: _client_holder["client"]
_fake._is_permission_error = lambda r: False
_fake._scope_denied_payload = lambda r, s: {"ok": True, "scope_pending": True}
_fake._upstream_error = lambda r: None
_fake._VALID_DETECTION_VERDICTS = {"true_positive", "false_positive"}
_fake._VERDICT_TAG = {"true_positive": "true_positive", "false_positive": "false_positive"}
_fake.reject_unsafe_device_id = lambda d: None
_fake.swallow_exc = lambda e: {"ok": False, "error": str(e)}
sys.modules["falcon_helpers"] = _fake

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # falcon-extras/
from ir.close_remediated import (  # noqa: E402
    close_untouched_originals,
    select_untouched_originals,
)

AID = "a" * 32
CUTOFF_ISO = "2026-05-01T12:00:00Z"
CUTOFF = datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc)


def _rec(cid, created, status="new"):
    return {"composite_id": cid, "status": status, "created_timestamp": created}


def test_only_detections_from_before_the_cutoff_are_selected():
    alerts = [
        _rec("old-1", "2026-04-30T08:00:00Z"),
        _rec("old-2", "2026-05-01T11:59:59.123Z"),
        _rec("during", "2026-05-01T12:00:00Z"),  # at the cutoff: not prior
        _rec("after", "2026-05-01T12:30:00Z"),
    ]
    assert select_untouched_originals(alerts, CUTOFF) == ["old-1", "old-2"]


def test_missing_or_bad_creation_time_is_never_closed():
    alerts = [
        {"composite_id": "no-time", "status": "new"},
        _rec("bad-time", "yesterday"),
        _rec("ok", "2026-04-01T00:00:00Z"),
    ]
    assert select_untouched_originals(alerts, CUTOFF) == ["ok"]


def test_close_runs_one_batch_with_tag_and_comment():
    fake = _FakeAlerts(
        [
            _rec("old-1", "2026-04-30T08:00:00Z"),
            _rec("old-2", "2026-04-29T08:00:00Z", status="in_progress"),
            _rec("closed-already", "2026-04-29T08:00:00Z", status="closed"),
            _rec("during", "2026-05-01T12:05:00Z"),
        ]
    )
    _client_holder["client"] = fake
    out = close_untouched_originals(AID, CUTOFF_ISO, "false_positive", "reviewed by operator")
    assert out["ok"] is True, out
    assert out["scope_count"] == 2 and out["updated"] == 2
    assert out["composite_ids"] == ["old-1", "old-2"]
    assert out["left_open_after_cutoff"] == 1
    assert len(fake.updates) == 1
    actions = {a["name"]: a["value"] for a in fake.updates[0]["action_parameters"]}
    assert actions == {
        "update_status": "closed",
        "add_tag": "false_positive",
        "append_comment": "reviewed by operator",
    }


def test_nothing_prior_closes_nothing():
    fake = _FakeAlerts([_rec("during", "2026-05-01T12:05:00Z")])
    _client_holder["client"] = fake
    out = close_untouched_originals(AID, CUTOFF_ISO, "true_positive")
    assert out["ok"] is True and out["updated"] == 0 and not fake.updates


def test_bad_inputs_are_refused_before_any_call():
    _client_holder["client"] = None  # would raise if used
    assert close_untouched_originals(AID, "not-a-time", "true_positive")["ok"] is False
    assert close_untouched_originals(AID, CUTOFF_ISO, "maybe")["ok"] is False


def test_ledger_close_puts_counts_before_the_long_lists():
    # The agent reads this through a ~12 KB cap; on a busy host the closed /
    # unmatched lists would push the decision counts past it.
    from ir.close_remediated import close_remediated

    fake = _FakeAlerts(
        [_rec(f"old-{i}", "2026-04-30T08:00:00Z") for i in range(30)]
        + [_rec("during", "2026-05-01T12:05:00Z")]
    )
    _client_holder["client"] = fake
    out = close_remediated(AID, [], "true_positive", before_iso=CUTOFF_ISO)
    keys = list(out)
    assert out["unmatched_prior_count"] == 30, out.get("unmatched_prior_count")
    for k in ("unmatched_count", "unmatched_prior_count", "unmatched_prior_sample"):
        assert keys.index(k) < keys.index("unmatched"), keys
    assert keys[-2:] == ["closed", "unmatched"], keys


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

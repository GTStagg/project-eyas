"""Unit tests for the IR Phase-3 prior-open classifier.

``_classify_prior_open`` is the deterministic teeth behind the F2b release
gate's prior-open re-check: the gate refuses to lift containment / remove the
host from quarantine while any of the EXACT Phase-0 original detections
(re-hydrated by composite_id, no time filter) still carries an open status.
The gate biases to UNDER-release — an id the store no longer returns at all is
treated as not-open (absent = no longer an open detection on the host), and any
hydration error fails the whole gate closed upstream in ``phase3.py``.

These tests pin "open status ⇒ reported open, closed/purged ⇒ not open" and
the canonical open-status set, so a silent change to what the gate considers
"still open" trips a test instead of quietly waving a release through.

``phase3.py`` imports ``falcon_helpers`` (→ falconpy) at module load; the SDK
isn't present in the test/CI env, so we stub ``falcon_helpers`` in
``sys.modules`` before importing — the classifier itself is pure (no network).

Run:
    python3 falcon-extras/ir/test_phase3.py
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

# Stub falcon_helpers so phase3's top-level `from falcon_helpers import …`
# doesn't drag in falconpy. The classifier under test touches none of it.
_fake = types.ModuleType("falcon_helpers")
for _name in ("_check_response", "_get_alerts_client", "reject_unsafe_device_id", "swallow_exc"):
    setattr(_fake, _name, lambda *a, **k: None)
sys.modules.setdefault("falcon_helpers", _fake)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # falcon-extras/
from ir.phase3 import _OPEN_STATUSES, _classify_prior_open  # noqa: E402


def _rec(cid="cid-1", status="new", **extra):
    return {"composite_id": cid, "status": status, **extra}


# ---------------------------------------------------------------------------
# Open statuses ⇒ reported open
# ---------------------------------------------------------------------------


def test_new_status_is_open():
    checked, open_ids = _classify_prior_open([_rec(status="new")])
    assert checked == 1 and open_ids == ["cid-1"]


def test_reopened_and_in_progress_are_open():
    recs = [_rec(cid="a", status="reopened"), _rec(cid="b", status="in_progress")]
    checked, open_ids = _classify_prior_open(recs)
    assert checked == 2 and open_ids == ["a", "b"]


def test_open_status_is_case_insensitive():
    # phase3 lowercases the status before the set test; "NEW" must still count.
    checked, open_ids = _classify_prior_open([_rec(status="NEW")])
    assert checked == 1 and open_ids == ["cid-1"]


# ---------------------------------------------------------------------------
# Closed / resolved ⇒ checked-but-not-open
# ---------------------------------------------------------------------------


def test_closed_status_not_open():
    checked, open_ids = _classify_prior_open([_rec(status="closed")])
    assert checked == 1 and open_ids == []


def test_resolved_status_not_open():
    # Any status outside the canonical open set is not-open (the gate only
    # treats new/reopened/in_progress as "still open").
    checked, open_ids = _classify_prior_open([_rec(status="resolved")])
    assert checked == 1 and open_ids == []


def test_mixed_batch_only_open_reported():
    # The realistic shape: a hydrated chunk with a remediated-closed original,
    # a still-open original, an absent-id placeholder is simply not present.
    recs = [
        _rec(cid="closed-1", status="closed"),
        _rec(cid="open-1", status="new"),
        _rec(cid="closed-2", status="resolved"),
        _rec(cid="open-2", status="reopened"),
    ]
    checked, open_ids = _classify_prior_open(recs)
    assert checked == 4
    assert open_ids == ["open-1", "open-2"]


# ---------------------------------------------------------------------------
# Purged / absent ids ⇒ never reach the classifier (not-open)
# ---------------------------------------------------------------------------


def test_absent_id_not_reported_open():
    # An id the store no longer returns isn't in `recs` at all. Only the
    # surviving record is classified; the purged id contributes nothing.
    checked, open_ids = _classify_prior_open([_rec(cid="survivor", status="new")])
    assert checked == 1 and open_ids == ["survivor"]
    assert "purged-and-gone" not in open_ids


def test_empty_recs_zero_open():
    checked, open_ids = _classify_prior_open([])
    assert checked == 0 and open_ids == []


# ---------------------------------------------------------------------------
# Record-shape robustness (mirrors the inline loop phase3 used to run)
# ---------------------------------------------------------------------------


def test_falls_back_to_id_when_no_composite_id():
    checked, open_ids = _classify_prior_open([{"id": "legacy-id", "status": "new"}])
    assert checked == 1 and open_ids == ["legacy-id"]


def test_non_dict_records_skipped_not_counted():
    checked, open_ids = _classify_prior_open(["nope", None, 42, _rec(status="new")])
    assert checked == 1 and open_ids == ["cid-1"]


def test_open_status_without_cid_counted_but_not_reported():
    # Matches phase3's `if cid and status in …`: a record with an open status
    # but no id is inspected (checked) yet can't be reported as an open id.
    checked, open_ids = _classify_prior_open([{"status": "new"}])
    assert checked == 1 and open_ids == []


def test_missing_status_not_open():
    checked, open_ids = _classify_prior_open([{"composite_id": "x"}])
    assert checked == 1 and open_ids == []


# ---------------------------------------------------------------------------
# Caller-supplied status set + the canonical default
# ---------------------------------------------------------------------------


def test_custom_open_statuses_override():
    recs = [_rec(cid="a", status="new"), _rec(cid="b", status="quarantined")]
    checked, open_ids = _classify_prior_open(recs, open_statuses={"quarantined"})
    assert checked == 2 and open_ids == ["b"]


def test_canonical_open_status_set_pinned():
    # Pin the gate's notion of "still open". Changing this set silently would
    # change which detections block a release — make that change loud.
    assert _OPEN_STATUSES == {"new", "reopened", "in_progress"}


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
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

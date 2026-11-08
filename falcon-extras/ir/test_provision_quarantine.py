"""Unit tests for _ensure_readiness_exclusion's pre-warm behavior.

The function is FalconPy-touching; we stub the IOA exclusions client +
the create_ioa_exclusion impl + the pattern-id resolver to test the
decision logic without network. Three branches that matter:

1. Exclusion already exists for the group → don't write, return present.
2. Exclusion missing, pattern_id resolvable → call create, return created.
3. Exclusion missing, pattern_id NOT resolvable → return degraded with a
   warning; do NOT fail provisioning.
4. Exclusion missing, create returns duplicate → translate to present.

Run:
    falcon-extras/.venv/bin/python3 falcon-extras/ir/test_provision_quarantine.py
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# Build minimal FalconPy-shaped response payloads.
def _query_resp(ids):
    return {"status_code": 200, "body": {"resources": list(ids)}}


def _get_resp(records):
    return {"status_code": 200, "body": {"resources": list(records)}}


class _FakeIoaClient:
    def __init__(self, exclusion_records):
        self._records = exclusion_records

    def query_exclusions(self, parameters=None):
        return _query_resp([r["id"] for r in self._records])

    def get_exclusions(self, ids):
        recs = [r for r in self._records if r["id"] in ids]
        return _get_resp(recs)


def _patch_ioa(records):
    """Patch the IOA client constructor in the module under test."""
    return patch(
        "ir.provision_quarantine._get_ioa_exclusions_client",
        return_value=_FakeIoaClient(records),
    )


# ===========================================================================
# Tests
# ===========================================================================


def test_existing_exclusion_returns_present_without_writing():
    from ir.detection_classifiers import _RTR_PREAMBLE_BASE64
    existing = [
        {
            "id": "exc-001",
            "groups": [{"id": "qgroup-1"}],
            "cl_regex": "anchor " + _RTR_PREAMBLE_BASE64 + " tail",
        },
    ]
    with _patch_ioa(existing):
        from ir.provision_quarantine import _ensure_readiness_exclusion
        r = _ensure_readiness_exclusion("qgroup-1")
    assert r["ok"] is True
    assert r["present"] is True
    assert r["id"] == "exc-001"
    assert r.get("created") is False


def test_existing_exclusion_for_other_group_does_not_match():
    """Exclusion exists but is scoped to a DIFFERENT host group — we
    must NOT treat that as 'present' for our quarantine group."""
    from ir.detection_classifiers import _RTR_PREAMBLE_BASE64
    other_group = [
        {
            "id": "exc-001",
            "groups": [{"id": "some-other-group"}],
            "cl_regex": _RTR_PREAMBLE_BASE64,
        },
    ]
    with _patch_ioa(other_group), patch(
        "ir.provision_quarantine._candidate_pattern_id", return_value=None
    ):
        from ir.provision_quarantine import _ensure_readiness_exclusion
        r = _ensure_readiness_exclusion("qgroup-1")
    # Falls through to the not-present branch. Pattern unresolved so we
    # land in the degraded warning state.
    assert r["ok"] is True
    assert r["present"] is False
    assert r["pattern_id_unresolved"] is True


def test_missing_exclusion_creates_when_pattern_id_resolvable():
    """The happy path: provisioning eagerly installs the exclusion."""
    with _patch_ioa([]), patch(
        "ir.provision_quarantine._candidate_pattern_id", return_value="pattern-xyz"
    ), patch(
        "exclusions.create_ioa_exclusion",
        return_value={"ok": True, "id": "exc-new-001"},
    ) as mock_create:
        from ir.provision_quarantine import _ensure_readiness_exclusion
        r = _ensure_readiness_exclusion("qgroup-1")
    assert r["ok"] is True
    assert r["present"] is True
    assert r["created"] is True
    assert r["id"] == "exc-new-001"
    assert r["pattern_id"] == "pattern-xyz"
    # Verify the create call carried the right pieces.
    assert mock_create.called
    kw = mock_create.call_args.kwargs
    assert kw["pattern_id"] == "pattern-xyz"
    assert kw["group_ids"] == ["qgroup-1"]
    assert "RTR runscript preamble" in kw["name"]


def test_missing_exclusion_warns_when_pattern_id_unresolvable():
    """Fresh tenant with no PShellMimikatz history. Provisioning still
    succeeds but warns the operator about JIT install + propagation race
    on first IR engagement."""
    with _patch_ioa([]), patch(
        "ir.provision_quarantine._candidate_pattern_id", return_value=None
    ):
        from ir.provision_quarantine import _ensure_readiness_exclusion
        r = _ensure_readiness_exclusion("qgroup-1")
    assert r["ok"] is True
    assert r["present"] is False
    assert r["created"] is False
    assert r["pattern_id_unresolved"] is True
    assert "warning" in r
    assert "JIT" in r["warning"]


def test_missing_exclusion_translates_duplicate_to_present():
    """If create_ioa_exclusion's server-side duplicate guard fires (the
    cl_regex marker was absent from the existing record so Step 1 didn't
    match, but pattern_id+ifn_regex did match server-side), translate to
    present rather than failing."""
    with _patch_ioa([]), patch(
        "ir.provision_quarantine._candidate_pattern_id", return_value="pattern-xyz"
    ), patch(
        "exclusions.create_ioa_exclusion",
        return_value={
            "ok": False,
            "duplicate": True,
            "existing_ids": ["exc-existing-007"],
        },
    ):
        from ir.provision_quarantine import _ensure_readiness_exclusion
        r = _ensure_readiness_exclusion("qgroup-1")
    assert r["ok"] is True
    assert r["present"] is True
    assert r["was_duplicate"] is True
    assert r["id"] == "exc-existing-007"
    assert r["created"] is False


def test_missing_exclusion_surfaces_unexpected_create_failure():
    """Anything other than duplicate that returns ok=false must surface
    as a provisioning failure — don't paper over real errors."""
    with _patch_ioa([]), patch(
        "ir.provision_quarantine._candidate_pattern_id", return_value="pattern-xyz"
    ), patch(
        "exclusions.create_ioa_exclusion",
        return_value={"ok": False, "error": "FalconPy 500"},
    ):
        from ir.provision_quarantine import _ensure_readiness_exclusion
        r = _ensure_readiness_exclusion("qgroup-1")
    assert r["ok"] is False
    assert r["present"] is False
    assert "FalconPy 500" in r["error"]


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

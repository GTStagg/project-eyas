"""Unit tests for the platform-aware Shadow-AI prevention probes.

Regression guard for the audit finding that `shadow_ai_check_prevention_binding`
and `shadow_ai_prevention_status` only matched the Windows rule group, so a
correctly-bound macOS or Linux prevention policy reported as broken.

Both functions are FalconPy-touching; we stub the Custom IOA client, the
Prevention Policies client, and the group-id resolver to exercise the pure
binding/readiness decision without network.

Run:
    falcon-extras/.venv/bin/python3 falcon-extras/shadow_ai/test_prevention_binding.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shadow_ai.ioa_rules import SHADOW_AI_RULE_GROUP_NAMES  # noqa: E402

BANNED = "a" * 32
WIN_RG = SHADOW_AI_RULE_GROUP_NAMES["windows"]
MAC_RG = SHADOW_AI_RULE_GROUP_NAMES["mac"]
LINUX_RG = SHADOW_AI_RULE_GROUP_NAMES["linux"]


def _ok(resources):
    return {"status_code": 200, "body": {"resources": list(resources)}}


class _FakeIoaClient:
    """Returns rule-group records keyed by name. `groups` maps rule-group
    name -> record dict (with id/name/enabled). Absent names look missing."""

    def __init__(self, groups):
        self._by_name = {g["name"]: g for g in groups}

    def query_rule_groupsMixin0(self, filter=None, limit=10):  # noqa: A002
        m = re.search(r"name:'([^']*)'", filter or "")
        name = m.group(1) if m else None
        rec = self._by_name.get(name)
        return _ok([rec["id"]] if rec else [])

    def get_rule_groupsMixin0(self, ids):
        out = [g for g in self._by_name.values() if g["id"] in ids]
        return _ok(out)


class _FakePreventionClient:
    def __init__(self, policies):
        self._policies = policies

    def query_combined_policies(self, parameters=None):
        return _ok(self._policies)


def _rg(name, *, enabled=True, exists=True):
    return {"name": name, "id": f"rgid::{name}", "enabled": enabled} if exists else None


def _policy(name, platform, *, enabled=True, bound_rg_name=None, on_banned=True):
    return {
        "id": f"pol::{name}",
        "name": name,
        "platform_name": platform,
        "enabled": enabled,
        "groups": [{"id": BANNED}] if on_banned else [{"id": "other"}],
        "ioa_rule_groups": [{"name": bound_rg_name, "id": f"rgid::{bound_rg_name}"}]
        if bound_rg_name
        else [],
    }


def _run_binding(rule_groups, policies, banned=BANNED):
    present = [g for g in rule_groups if g]
    with patch("shadow_ai.tools.resolve_group_id", return_value=banned), patch(
        "shadow_ai.tools._get_custom_ioa_client", return_value=_FakeIoaClient(present)
    ), patch(
        "shadow_ai.tools._get_prevention_client",
        return_value=_FakePreventionClient(policies),
    ):
        from shadow_ai.tools import shadow_ai_check_prevention_binding

        return shadow_ai_check_prevention_binding()


def _attached(res, policy_name):
    return next(p for p in res["attached_policies"] if p["name"] == policy_name)


# ===========================================================================
# Tests
# ===========================================================================

CHECKS = []


def check(label, cond, detail=""):
    CHECKS.append((label, bool(cond), detail))


def test_mac_policy_bound_is_not_falsely_broken():
    """THE regression: a macOS policy bound to the macOS rule group must
    read as bound (the old Windows-only match reported it unbound)."""
    res = _run_binding(
        rule_groups=[_rg(WIN_RG), _rg(MAC_RG), _rg(LINUX_RG, exists=False)],
        policies=[
            _policy("Win Policy", "Windows", bound_rg_name=WIN_RG),
            _policy("Mac Policy", "Mac", bound_rg_name=MAC_RG),
        ],
    )
    mac = _attached(res, "Mac Policy")
    check("mac policy reports bound", mac["rule_group_bound"] is True)
    check("mac entry carries mac rule-group name", mac["rule_group_name"] == MAC_RG)
    win = _attached(res, "Win Policy")
    check("win policy reports bound", win["rule_group_bound"] is True)
    check("ready True when win+mac correctly bound", res["ready"] is True)
    check("no missing steps when fully enforcing", res["missing_steps"] == [])


def test_cross_platform_bind_does_not_count():
    """A macOS policy that somehow carries the Windows group is NOT enforcing
    (Falcon rejects cross-platform binds; the probe must not be fooled)."""
    res = _run_binding(
        rule_groups=[_rg(WIN_RG), _rg(MAC_RG)],
        policies=[_policy("Mac Policy", "Mac", bound_rg_name=WIN_RG)],
    )
    mac = _attached(res, "Mac Policy")
    check("cross-platform bind not counted", mac["rule_group_bound"] is False)
    check("ready False on cross-platform bind", res["ready"] is False)
    check(
        "missing step is platform-tagged [mac]",
        any(s.startswith("[mac]") for s in res["missing_steps"]),
    )


def test_linux_rule_group_missing_blocks_ready():
    res = _run_binding(
        rule_groups=[_rg(WIN_RG), _rg(LINUX_RG, exists=False)],
        policies=[
            _policy("Win Policy", "Windows", bound_rg_name=WIN_RG),
            _policy("Linux Policy", "Linux", bound_rg_name=None),
        ],
    )
    check("ready False when a linux policy is unbound", res["ready"] is False)
    check(
        "linux missing step recommends adopt(platform=linux)",
        any('[linux]' in s and 'platform="linux"' in s for s in res["missing_steps"]),
    )


def test_windows_only_still_ready_backward_compat():
    res = _run_binding(
        rule_groups=[_rg(WIN_RG)],
        policies=[_policy("Win Policy", "Windows", bound_rg_name=WIN_RG)],
    )
    check("windows-only setup still ready", res["ready"] is True)
    check("top-level rule_group_name is windows", res["rule_group_name"] == WIN_RG)
    check("top-level rule_group_exists True", res["rule_group_exists"] is True)


def test_disabled_policy_with_bind_surfaced_not_ready():
    res = _run_binding(
        rule_groups=[_rg(WIN_RG)],
        policies=[_policy("Win Policy", "Windows", enabled=False, bound_rg_name=WIN_RG)],
    )
    check("disabled bound policy → not ready", res["ready"] is False)
    check(
        "disabled policy surfaced in missing steps",
        any("disabled" in s.lower() for s in res["missing_steps"]),
    )


def test_no_policy_attached():
    res = _run_binding(
        rule_groups=[_rg(WIN_RG), _rg(MAC_RG)],
        policies=[_policy("Other", "Windows", bound_rg_name=WIN_RG, on_banned=False)],
    )
    check("ready False with no attached policy", res["ready"] is False)
    check("attached list empty", res["attached_policies"] == [])
    check(
        "missing step references the banned group",
        any(BANNED in s for s in res["missing_steps"]),
    )


def test_prevention_status_reports_all_platforms():
    present = [_rg(WIN_RG), _rg(MAC_RG)]  # linux absent
    with patch(
        "shadow_ai.tools._get_custom_ioa_client",
        return_value=_FakeIoaClient(present),
    ):
        from shadow_ai.tools import shadow_ai_prevention_status

        res = shadow_ai_prevention_status()
    plats = {p["platform"] for p in res["platforms"]}
    check("status lists all three platforms", plats == {"windows", "mac", "linux"})
    linux = next(p for p in res["platforms"] if p["platform"] == "linux")
    check("absent linux rule group flagged not-exists", linux["rule_group_exists"] is False)
    check("top-level hoists windows exists", res["rule_group_exists"] is True)
    check("any_rule_group_exists True", res["any_rule_group_exists"] is True)


def main():
    for fn in [
        test_mac_policy_bound_is_not_falsely_broken,
        test_cross_platform_bind_does_not_count,
        test_linux_rule_group_missing_blocks_ready,
        test_windows_only_still_ready_backward_compat,
        test_disabled_policy_with_bind_surfaced_not_ready,
        test_no_policy_attached,
        test_prevention_status_reports_all_platforms,
    ]:
        fn()

    failed = 0
    for label, ok, detail in CHECKS:
        if ok:
            print(f"  ok  {label}")
        else:
            print(f"  FAIL {label}{(' — ' + detail) if detail else ''}")
            failed += 1
    print(f"\n{len(CHECKS) - failed}/{len(CHECKS)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

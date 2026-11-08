"""Project Eyas tenant teardown.

Wipes all canonical Project Eyas-managed objects from a Falcon tenant so a
fresh provisioning run starts clean. Used during demo cycles and dev
resets.

DESTRUCTIVE — the @mcp.tool() wrappers in server.py are approval-gated.
Dry-run mode returns a structured plan without making any changes.

Discovery surface:
  - Host groups named "Project Eyas - IR Quarantine" / "Project Eyas -
    Shadow-AI Banned" PLUS whatever the active env currently has stored
    as irQuarantineGroupId / shadowAiBannedGroupId (catches non-canonical
    adoptions like "Agentic - Quarantine").
  - Prevention policies starting with "Project Eyas - " across all
    platforms.
  - Custom IOA rule groups starting with "Project Eyas - Shadow-AI Block".
  - IOA exclusions whose comment contains "IR-readiness" (the canonical
    RTR-preamble exclusion).

Execute order is Falcon-enforced:
  1. Detach matched prevention policies from matched host groups
  2. Disable matched prevention policies (Falcon refuses delete on enabled)
  3. Delete matched prevention policies
  4. Delete matched rule groups (binding gone once their policies are deleted)
  5. Delete matched IOA exclusions
  6. Delete matched host groups (must have no attached policies)

The active env's saved group-id fields are NOT cleared automatically —
the operator does that via the /config UI Clear button or by
re-provisioning fresh groups (which auto-saves the new id).
"""

from __future__ import annotations

from typing import Any

from falcon_helpers import (
    _check_response,
    _falcon_kwargs,
    _get_host_group_client,
    _get_ioa_exclusions_client,
    _get_prevention_client,
    resolve_group_id,
)
from falcon_helpers import swallow_exc
from falconpy import CustomIOA


# Canonical name markers. Match what provision_quarantine.py +
# provision_banned.py + ioa_rules.py create.
CANONICAL_HG_NAMES = {
    "Project Eyas - IR Quarantine",
    "Project Eyas - Shadow-AI Banned",
}
CANONICAL_PP_PREFIX = "Project Eyas - "  # IR + Shadow-AI Banned policies share this
CANONICAL_RG_PREFIX = "Project Eyas - Shadow-AI Block"  # Windows + (mac) + (linux)
IR_READINESS_EXCLUSION_HINT = "IR-readiness"  # substring of the exclusion comment


def _get_custom_ioa_client() -> CustomIOA:
    return CustomIOA(**_falcon_kwargs())


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def discover_canonical_objects() -> dict[str, Any]:
    """Read-only scan of the tenant. Returns the discovery shape used by
    both the dry-run and execute paths."""
    result: dict[str, Any] = {
        "host_groups": [],
        "prevention_policies": [],
        "rule_groups": [],
        "ioa_exclusions": [],
        "active_env_hints": {},
        "discovery_errors": [],
    }

    ir_id = resolve_group_id("quarantine") or ""
    sa_id = resolve_group_id("shadow_ai_banned") or ""
    if ir_id:
        result["active_env_hints"]["ir_quarantine_group_id"] = ir_id
    if sa_id:
        result["active_env_hints"]["shadow_ai_banned_group_id"] = sa_id

    # Host groups: canonical-named OR matching an active-env saved id.
    try:
        hg = _get_host_group_client()
        resp = hg.query_combined_host_groups(parameters={"limit": 500})
        guard = _check_response(resp, "HostGroup")
        if guard:
            result["discovery_errors"].append({"step": "host_groups", **guard})
        else:
            for g in ((resp or {}).get("body") or {}).get("resources") or []:
                gid = g.get("id")
                gname = g.get("name") or ""
                canonical = gname in CANONICAL_HG_NAMES
                from_env = gid in (ir_id, sa_id) if gid else False
                if canonical or from_env:
                    result["host_groups"].append({
                        "id": gid,
                        "name": gname,
                        "group_type": g.get("group_type"),
                        "match_reason": "canonical_name" if canonical else "active_env_id",
                    })
    except Exception as exc:  # noqa: BLE001
        result["discovery_errors"].append({"step": "host_groups", "error": f"{type(exc).__name__}: {exc}"})

    # Prevention policies: canonical-prefixed, fanned across platforms.
    try:
        prev = _get_prevention_client()
        for platform in ("Windows", "Mac", "Linux"):
            resp = prev.query_combined_policies(
                parameters={"filter": f"platform_name:'{platform}'", "limit": 500}
            )
            guard = _check_response(resp, "Prevention Policies")
            if guard:
                result["discovery_errors"].append(
                    {"step": f"prevention_policies_{platform.lower()}", **guard}
                )
                continue
            for p in ((resp or {}).get("body") or {}).get("resources") or []:
                pname = p.get("name") or ""
                if pname.startswith(CANONICAL_PP_PREFIX):
                    result["prevention_policies"].append({
                        "id": p.get("id"),
                        "name": pname,
                        "platform_name": p.get("platform_name"),
                        "enabled": bool(p.get("enabled", True)),
                        "attached_group_ids": [
                            g.get("id") for g in (p.get("groups") or []) if g.get("id")
                        ],
                    })
    except Exception as exc:  # noqa: BLE001
        result["discovery_errors"].append(
            {"step": "prevention_policies", "error": f"{type(exc).__name__}: {exc}"}
        )

    # Custom IOA rule groups.
    try:
        ioa = _get_custom_ioa_client()
        resp = ioa.query_rule_groups_full(parameters={"limit": 500})
        guard = _check_response(resp, "CustomIOA")
        if guard:
            result["discovery_errors"].append({"step": "rule_groups", **guard})
        else:
            for rg in ((resp or {}).get("body") or {}).get("resources") or []:
                rname = rg.get("name") or ""
                if rname.startswith(CANONICAL_RG_PREFIX):
                    result["rule_groups"].append({
                        "id": rg.get("id"),
                        "name": rname,
                        "platform": rg.get("platform"),
                        "enabled": bool(rg.get("enabled", True)),
                    })
    except Exception as exc:  # noqa: BLE001
        result["discovery_errors"].append(
            {"step": "rule_groups", "error": f"{type(exc).__name__}: {exc}"}
        )

    # IOA exclusions: match the IR-readiness comment.
    try:
        excl = _get_ioa_exclusions_client()
        resp = excl.query_exclusions(parameters={"limit": 500})
        guard = _check_response(resp, "IOAExclusions")
        if guard:
            result["discovery_errors"].append({"step": "ioa_exclusions_query", **guard})
        else:
            ids = ((resp or {}).get("body") or {}).get("resources") or []
            if ids:
                resp2 = excl.get_exclusions(ids=ids)
                guard2 = _check_response(resp2, "IOAExclusions")
                if guard2:
                    result["discovery_errors"].append({"step": "ioa_exclusions_get", **guard2})
                else:
                    for e in ((resp2 or {}).get("body") or {}).get("resources") or []:
                        comment = e.get("comment") or e.get("description") or ""
                        if IR_READINESS_EXCLUSION_HINT in comment:
                            result["ioa_exclusions"].append({
                                "id": e.get("id"),
                                "name": e.get("name"),
                                "comment": comment[:140],
                                "applied_globally": e.get("applied_globally", False),
                            })
    except Exception as exc:  # noqa: BLE001
        result["discovery_errors"].append(
            {"step": "ioa_exclusions", "error": f"{type(exc).__name__}: {exc}"}
        )

    return result


# ---------------------------------------------------------------------------
# Teardown driver
# ---------------------------------------------------------------------------


def _summarize(plan: dict[str, Any]) -> dict[str, int]:
    return {
        "host_groups_count": len(plan["host_groups"]),
        "prevention_policies_count": len(plan["prevention_policies"]),
        "rule_groups_count": len(plan["rule_groups"]),
        "ioa_exclusions_count": len(plan["ioa_exclusions"]),
        "discovery_errors_count": len(plan["discovery_errors"]),
    }


def teardown_project_eyas_managed(dry_run: bool = True) -> dict[str, Any]:
    """Discover and (optionally) tear down canonical Project Eyas objects.

    dry_run=True returns a structured plan only. dry_run=False executes
    in dependency order. Returns per-step results. The active env's saved
    group-id fields are NOT cleared — operator does that via /config
    Clear button or by re-provisioning fresh."""
    plan = discover_canonical_objects()
    summary = _summarize(plan)
    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "summary": summary,
            "plan": plan,
            "note": (
                "Re-run with dry_run=False to execute. Order: detach policies "
                "from groups → disable policies → delete policies → delete rule "
                "groups → delete IOA exclusions → delete host groups. The active "
                "env's group-id fields are NOT cleared automatically; use the "
                "/config Clear button after teardown completes."
            ),
        }
    return _execute_teardown(plan, summary)


def _execute_teardown(plan: dict[str, Any], summary: dict[str, int]) -> dict[str, Any]:
    steps: list[dict[str, Any]] = []
    hg = _get_host_group_client()
    prev = _get_prevention_client()
    ioa = _get_custom_ioa_client()
    excl = _get_ioa_exclusions_client()

    # 1. Detach prevention policies from their host groups.
    for policy in plan["prevention_policies"]:
        for gid in policy.get("attached_group_ids") or []:
            if not gid:
                continue
            try:
                resp = prev.perform_policies_action(
                    action_name="remove-host-group",
                    ids=policy["id"],
                    group_id=gid,
                )
                guard = _check_response(resp, "Prevention Policies")
                steps.append({
                    "step": "detach_policy_from_group",
                    "policy_id": policy["id"],
                    "policy_name": policy["name"],
                    "host_group_id": gid,
                    "ok": guard is None,
                    **(guard or {}),
                })
            except Exception as exc:  # noqa: BLE001
                steps.append({
                    "step": "detach_policy_from_group",
                    "policy_id": policy["id"],
                    "host_group_id": gid,
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                })

    # 2. Disable enabled policies (delete refuses on enabled).
    for policy in plan["prevention_policies"]:
        if not policy.get("enabled"):
            continue
        try:
            resp = prev.perform_policies_action(action_name="disable", ids=policy["id"])
            guard = _check_response(resp, "Prevention Policies")
            steps.append({
                "step": "disable_policy",
                "policy_id": policy["id"],
                "policy_name": policy["name"],
                "ok": guard is None,
                **(guard or {}),
            })
        except Exception as exc:  # noqa: BLE001
            steps.append({
                "step": "disable_policy",
                "policy_id": policy["id"],
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            })

    # 3. Delete prevention policies.
    for policy in plan["prevention_policies"]:
        try:
            resp = prev.delete_policies(ids=policy["id"])
            guard = _check_response(resp, "Prevention Policies")
            steps.append({
                "step": "delete_prevention_policy",
                "policy_id": policy["id"],
                "policy_name": policy["name"],
                "ok": guard is None,
                **(guard or {}),
            })
        except Exception as exc:  # noqa: BLE001
            steps.append({
                "step": "delete_prevention_policy",
                "policy_id": policy["id"],
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            })

    # 4. Delete Custom IOA rule groups (orphan once their policies are gone).
    for rg in plan["rule_groups"]:
        try:
            resp = ioa.delete_rule_groups(
                ids=rg["id"],
                comment="Project Eyas teardown",
            )
            guard = _check_response(resp, "CustomIOA")
            steps.append({
                "step": "delete_rule_group",
                "rule_group_id": rg["id"],
                "rule_group_name": rg["name"],
                "ok": guard is None,
                **(guard or {}),
            })
        except Exception as exc:  # noqa: BLE001
            steps.append({
                "step": "delete_rule_group",
                "rule_group_id": rg["id"],
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            })

    # 5. Delete IOA exclusions.
    for ex in plan["ioa_exclusions"]:
        try:
            resp = excl.delete_exclusions(ids=ex["id"])
            guard = _check_response(resp, "IOAExclusions")
            steps.append({
                "step": "delete_ioa_exclusion",
                "exclusion_id": ex["id"],
                "ok": guard is None,
                **(guard or {}),
            })
        except Exception as exc:  # noqa: BLE001
            steps.append({
                "step": "delete_ioa_exclusion",
                "exclusion_id": ex["id"],
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            })

    # 6. Delete host groups.
    for h in plan["host_groups"]:
        try:
            resp = hg.delete_host_groups(ids=h["id"])
            guard = _check_response(resp, "HostGroup")
            steps.append({
                "step": "delete_host_group",
                "host_group_id": h["id"],
                "host_group_name": h["name"],
                "ok": guard is None,
                **(guard or {}),
            })
        except Exception as exc:  # noqa: BLE001
            steps.append({
                "step": "delete_host_group",
                "host_group_id": h["id"],
                "ok": False,
                "error": f"{type(exc).__name__}: {exc}",
            })

    ok_count = sum(1 for s in steps if s.get("ok"))
    fail_count = len(steps) - ok_count
    return {
        "ok": fail_count == 0,
        "dry_run": False,
        "summary": {
            **summary,
            "executed_steps": len(steps),
            "succeeded": ok_count,
            "failed": fail_count,
        },
        "steps": steps,
        "discovery_errors": plan["discovery_errors"],
        "next_step": (
            "Clear irQuarantineGroupId + shadowAiBannedGroupId on the active "
            "environment via /config Clear button, then re-provision via the "
            "setup cards to start fresh."
        ),
    }


# ---------------------------------------------------------------------------
# Low-level primitives — also useful on their own.
# ---------------------------------------------------------------------------


def delete_prevention_policy(prevention_policy_id: str) -> dict[str, Any]:
    """Delete a single prevention policy. Caller MUST have detached it
    from all host groups first; Falcon refuses delete on a still-attached
    policy. We disable here as a courtesy (Falcon also refuses delete on
    enabled policies)."""
    if not prevention_policy_id or not isinstance(prevention_policy_id, str):
        return {"ok": False, "error": "prevention_policy_id is required"}
    try:
        prev = _get_prevention_client()
        # Best-effort disable. Errors here (e.g. already disabled) are
        # intentionally swallowed; the real verdict comes from delete.
        prev.perform_policies_action(action_name="disable", ids=prevention_policy_id)
        resp = prev.delete_policies(ids=prevention_policy_id)
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return {"ok": False, "prevention_policy_id": prevention_policy_id, **guard}
        return {"ok": True, "id": prevention_policy_id, "deleted": True}
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


def delete_ioa_rule_group(
    rule_group_id: str,
    comment: str = "Project Eyas teardown",
) -> dict[str, Any]:
    """Delete a single IOA rule group. Falcon refuses if the rule group
    is still bound to any prevention policy — detach via policy update,
    OR delete the binding policies before calling this."""
    if not rule_group_id or not isinstance(rule_group_id, str):
        return {"ok": False, "error": "rule_group_id is required"}
    try:
        ioa = _get_custom_ioa_client()
        resp = ioa.delete_rule_groups(ids=rule_group_id, comment=comment)
        guard = _check_response(resp, "CustomIOA")
        if guard:
            return {"ok": False, "rule_group_id": rule_group_id, **guard}
        return {"ok": True, "id": rule_group_id, "deleted": True}
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

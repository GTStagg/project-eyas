"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

from typing import Any
from falcon_helpers import (
    _get_host_group_client,
    _is_permission_error,
    _scope_denied_payload,
    _upstream_error,
    reject_unsafe_device_id,
)
from falcon_helpers import swallow_exc



def _host_group_action(
    action: str, group_id: str, device_ids: list[str]
) -> dict[str, Any]:
    if not group_id or not isinstance(group_id, str):
        return {"ok": False, "error": "group_id required"}
    if not device_ids:
        return {"ok": False, "error": "device_ids must be a non-empty list"}
    if len(device_ids) > 500:
        return {"ok": False, "error": "max 500 device_ids per call"}
    # Every AID is interpolated into a single-quoted FQL literal at line ~75
    # (device_id:['<id>',...]). Reject-don't-escape each element before it
    # reaches that string — a value carrying ' or \ is a typo or an injection
    # attempt, never a real Agent ID. Same posture as the IR scope walkers.
    for d in device_ids:
        bad = reject_unsafe_device_id(d)
        if bad is not None:
            return bad
    try:
        client = _get_host_group_client()
        # Pre-flight: fetch the group and refuse on dynamic. Saves the agent a
        # token-expensive interpretation cycle on a generic FalconPy 4xx that
        # doesn't say "this group is dynamic" in plain English.
        g = client.get_host_groups(ids=[group_id])
        if _is_permission_error(g):
            return _scope_denied_payload(g, "Host Groups")
        gerr = _upstream_error(g)
        if gerr:
            return {"ok": False, "error": gerr}
        gbody = g.get("body", {}) if isinstance(g, dict) else {}
        groups = gbody.get("resources") or []
        if not groups:
            return {"ok": False, "error": f"group_id not found: {group_id}"}
        gtype = (groups[0] or {}).get("group_type")
        # Falcon has two static flavors: 'static' (added-by-name) and
        # 'staticByID' (added-by-AID). Both accept perform_group_action with
        # add-hosts / remove-hosts. Only 'dynamic' (assignment_rule FQL) is
        # rejected — that's the case where membership is computed, not set.
        if gtype not in ("static", "staticByID"):
            return {
                "ok": False,
                "error": (
                    f"group '{groups[0].get('name')}' is {gtype!r}; add/remove "
                    "is only valid on static or staticByID groups. Dynamic "
                    "group membership is determined by the assignment_rule "
                    "FQL — edit that via update_host_groups instead."
                ),
                "group_type": gtype,
            }
        # FalconPy filter for device membership: comma-joined AIDs in a list.
        filter_value = "(device_id:[" + ",".join(f"'{d}'" for d in device_ids) + "])"
        body = {
            "action_parameters": [{"name": "filter", "value": filter_value}],
            "ids": [group_id],
        }
        r = client.perform_group_action(action_name=action, body=body)
        if _is_permission_error(r):
            return _scope_denied_payload(r, "Host Groups")
        err = _upstream_error(r)
        if err:
            return {"ok": False, "error": err}
        body_out = r.get("body", {}) if isinstance(r, dict) else {}
        return {
            "ok": True,
            "action": action,
            "group_id": group_id,
            "device_ids": device_ids,
            "resources": body_out.get("resources") or [],
        }
    except Exception as exc:
        return swallow_exc(exc)


def host_group_add_members(
    group_id: str, device_ids: list[str]
) -> dict[str, Any]:
    """Add one or more hosts to a static Falcon Host Group. WRITE ACTION —
    requires explicit user approval in the UI before execution.

    Accepts both 'static' (added-by-name) and 'staticByID' (added-by-AID)
    group flavors. Dynamic groups (group_type='dynamic') determine membership
    via their assignment_rule FQL — the pre-flight check rejects those.

    Args:
        group_id: The host group id (must be static or staticByID). From
            falcon_search_host_groups.
        device_ids: List of Falcon device (AID) IDs to add. Cap 500 per call.
    """
    return _host_group_action("add-hosts", group_id, device_ids)


def host_group_remove_members(
    group_id: str, device_ids: list[str]
) -> dict[str, Any]:
    """Remove one or more hosts from a static Falcon Host Group. WRITE
    ACTION — requires explicit user approval in the UI before execution.

    Accepts both 'static' and 'staticByID' group flavors.

    Args:
        group_id: The host group id (must be static or staticByID).
        device_ids: List of Falcon device (AID) IDs to remove. Cap 500 per call.
    """
    return _host_group_action("remove-hosts", group_id, device_ids)


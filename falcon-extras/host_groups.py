"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

from typing import Any
from falcon_helpers import (
    _check_response,
    _get_host_group_client,
    _is_permission_error,
    _scope_denied_payload,
    _upstream_error,
    reject_unsafe_device_id,
)
from falcon_helpers import swallow_exc



def _project_host_group(g: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": g.get("id"),
        "name": g.get("name"),
        "description": g.get("description"),
        "group_type": g.get("group_type"),
        "assignment_rule": g.get("assignment_rule"),
        "created_by": g.get("created_by"),
        "created_timestamp": g.get("created_timestamp"),
        "modified_by": g.get("modified_by"),
        "modified_timestamp": g.get("modified_timestamp"),
    }


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


def host_group_list(
    filter: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """List Falcon Host Groups in the tenant. Read-only.

    Returns each group's id, name, description, group_type (static |
    dynamic), assignment_rule (FQL filter that defines membership for
    dynamic groups), created/modified timestamps + actors. Member counts
    are NOT included here — call extras_host_group_members per group when
    you need them.

    Args:
        filter: Optional FQL filter on group fields (name, group_type,
            created_by, modified_timestamp).
        limit: Max groups to return (1-5000). Default 50.
    """
    try:
        client = _get_host_group_client()
        capped = min(max(limit, 1), 5000)
        # Combined endpoint uses '.' separator on sort, NOT '|' — distinct
        # from FalconPy's docstring which references the pipe form. The
        # FQL-style endpoints use pipe; the combined endpoints use dot.
        # See trace: query_combined_host_groups rejects 'modified_timestamp|desc'
        # with 400 but accepts 'modified_timestamp.desc'.
        params: dict[str, Any] = {"limit": capped, "sort": "modified_timestamp.desc"}
        if filter:
            params["filter"] = filter
        r = client.query_combined_host_groups(parameters=params)
        if _is_permission_error(r):
            return _scope_denied_payload(r, "Host Groups")
        err = _upstream_error(r)
        if err:
            return {"ok": False, "error": err}
        body = r.get("body", {}) if isinstance(r, dict) else {}
        raw = body.get("resources") or []
        items = [_project_host_group(g) for g in raw]
        meta = body.get("meta") or {}
        total = (meta.get("pagination") or {}).get("total")
        return {
            "ok": True,
            "items": items,
            "count": len(items),
            "total": total if total is not None else len(items),
        }
    except Exception as exc:
        return swallow_exc(exc)


def host_group_members(group_id: str, limit: int = 50) -> dict[str, Any]:
    """List the hosts that are members of a Falcon Host Group. Read-only.

    Returns hostname, platform, OS version, last-seen, AID for up to `limit`
    members. Use this to size a group ahead of a staged rollout.

    Args:
        group_id: The host group id (returned by extras_host_group_list).
        limit: Max members to return (1-5000). Default 50.
    """
    try:
        if not group_id or not isinstance(group_id, str):
            return {"ok": False, "error": "group_id required"}
        client = _get_host_group_client()
        capped = min(max(limit, 1), 5000)
        # Combined endpoint quirk: dot separator on sort, not pipe. See
        # extras_host_group_list for the discovery trace.
        r = client.query_combined_group_members(
            parameters={"id": group_id, "limit": capped, "sort": "hostname.asc"}
        )
        if _is_permission_error(r):
            return _scope_denied_payload(r, "Host Groups")
        err = _upstream_error(r)
        if err:
            return {"ok": False, "error": err}
        body = r.get("body", {}) if isinstance(r, dict) else {}
        raw = body.get("resources") or []
        items = [
            {
                "device_id": h.get("device_id"),
                "hostname": h.get("hostname"),
                "platform_name": h.get("platform_name"),
                "os_version": h.get("os_version"),
                "last_seen": h.get("last_seen"),
                "tags": h.get("tags"),
            }
            for h in raw
        ]
        return {"ok": True, "group_id": group_id, "items": items, "count": len(items)}
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
            extras_host_group_list.
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


"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
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

# Concurrency width for the per-group membership fan-out in
# host_group_membership_for_device. Tuned to collapse the 1-probe-per-group
# walk well under the MCP transport's 60s ceiling on realistic (<100-group)
# tenants without pushing Falcon's combined-endpoint rate limit toward 429s.
_MEMBERSHIP_PROBE_WORKERS = 8


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


def host_group_membership_for_device(device_id: str) -> dict[str, Any]:
    """Resolve the full Host Group membership for a single device. Read-only.

    The `groups` array returned by falcon_search_hosts and Falcon's device
    entity endpoints is unreliable: dynamic-group memberships (assignment_rule
    FQL) and sometimes static-group memberships are omitted depending on API
    projection and timing. This tool walks every host group in the tenant and
    returns those that actually contain the given AID.

    Use this in IR workflows where you must capture original membership before
    moving a host (so you can restore it accurately later). The walk is one
    membership probe per group, but probes run concurrently across a thread
    pool, so wall time stays bounded (~10s for a typical <100-group tenant)
    even though the call count is still 1 + N.

    Args:
        device_id: Falcon AID to resolve membership for.

    Returns:
        ok, device_id, items (list of {id, name, group_type, assignment_rule
        if dynamic}), count.
    """
    if not device_id or not isinstance(device_id, str):
        return {"ok": False, "error": "device_id required"}
    # device_id is interpolated into the per-group membership FQL filter below
    # (device_id:'<id>'). Reject-don't-escape before it reaches that literal —
    # this list is read as authoritative by IR Phase 4 release logic, so a
    # crafted id must never widen or skew the membership probe.
    bad = reject_unsafe_device_id(device_id)
    if bad is not None:
        return bad
    try:
        # One shared, pre-authenticated client for every probe. The list call
        # below mints the token; the per-group probes are independent GETs that
        # only READ that token (no refresh fires inside this short window), so a
        # single client is safe to fan out across threads — and avoids the N
        # extra token mints a client-per-worker would incur. The 30s per-request
        # timeout bounds a single hung connection.
        client = _get_host_group_client(timeout=30)
        # Pull the full group list. Cap at 500 — tenants with more groups
        # need pagination, which we accept as a known limitation.
        r = client.query_combined_host_groups(parameters={"limit": 500})
        if _is_permission_error(r):
            return _scope_denied_payload(r, "Host Groups")
        err = _upstream_error(r)
        if err:
            return {"ok": False, "error": err}
        body = r.get("body", {}) if isinstance(r, dict) else {}
        groups = [g for g in (body.get("resources") or []) if g.get("id")]

        # Per-group "is this AID a member?" probe. Returns (group_meta, None) on
        # a hit, (None, None) on a clean miss, or (None, failure) on a permission
        # / upstream / transport error. A failure is surfaced loudly rather than
        # collapsed into "not a member": this list is read as authoritative by IR
        # Phase 4 release logic, and a silently-dropped group (false negative)
        # leaves a host un-restored — strictly worse than a loud failure.
        def _probe(
            g: dict[str, Any],
        ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
            gid = g["id"]
            try:
                mr = client.query_combined_group_members(
                    parameters={
                        "id": gid,
                        "filter": f"device_id:'{device_id}'",
                        "limit": 1,
                    }
                )
            except Exception as exc:
                return None, {"kind": "upstream", "error": str(exc)}
            if _is_permission_error(mr):
                return None, {"kind": "permission", "resp": mr}
            merr = _upstream_error(mr)
            if merr:
                return None, {"kind": "upstream", "error": merr}
            mbody = mr.get("body", {}) if isinstance(mr, dict) else {}
            if mbody.get("resources") or []:
                return (
                    {
                        "id": gid,
                        "name": g.get("name"),
                        "group_type": g.get("group_type"),
                        "assignment_rule": g.get("assignment_rule")
                        if g.get("group_type") == "dynamic"
                        else None,
                    },
                    None,
                )
            return None, None

        member_of: list[dict[str, Any]] = []
        permission_fail: dict[str, Any] | None = None
        upstream_fail: str | None = None
        # 8 workers collapses the walk from N*latency to ~ceil(N/8)*latency
        # while staying under Falcon's combined-endpoint rate ceiling (a higher
        # fan-out risks 429s, which _upstream_error would surface as a loud
        # failure anyway). Results are aggregated after the pool drains; we
        # don't short-circuit on the first error because a mid-walk permission
        # error is a near-impossibility (the list call shares the same scope)
        # and the fan-out makes "probe all N" cheap regardless.
        with ThreadPoolExecutor(max_workers=_MEMBERSHIP_PROBE_WORKERS) as ex:
            for meta, failure in ex.map(_probe, groups):
                if failure is not None:
                    if failure["kind"] == "permission" and permission_fail is None:
                        permission_fail = failure["resp"]
                    elif failure["kind"] == "upstream" and upstream_fail is None:
                        upstream_fail = failure["error"]
                    continue
                if meta is not None:
                    member_of.append(meta)

        if permission_fail is not None:
            return _scope_denied_payload(permission_fail, "Host Groups")
        if upstream_fail is not None:
            return {"ok": False, "error": upstream_fail}

        return {
            "ok": True,
            "device_id": device_id,
            "items": member_of,
            "count": len(member_of),
            "groups_scanned": len(groups),
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


"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from falcon_helpers import _check_response, _get_workflows_client
from falcon_helpers import swallow_exc


def _project_execution(e: dict[str, Any]) -> dict[str, Any]:
    """Trim a workflow-execution record down to fields the dashboard / agent
    actually use. The full upstream record is verbose (per-step results,
    trigger payload, internal state) and routinely tips the MCP token cap on
    busy tenants."""
    return {
        "id": e.get("id") or e.get("execution_id"),
        "definition_id": e.get("definition_id"),
        "definition_name": e.get("definition_name") or e.get("name"),
        "status": e.get("status"),
        "started_timestamp": e.get("started_timestamp") or e.get("start_timestamp"),
        "ended_timestamp": e.get("end_timestamp") or e.get("ended_timestamp"),
        "trigger_source": e.get("trigger_source") or e.get("trigger", {}).get("source") if isinstance(e.get("trigger"), dict) else e.get("trigger_source"),
    }

def workflows_list_definitions(
    filter: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """List Fusion SOAR workflow definitions in the tenant. Read-only.

    Returns each definition's id, name, description, status (enabled?),
    trigger type, last modified. Use this to answer "what automation does
    this tenant have" without going to the console.

    Args:
        filter: Optional FQL filter (e.g. status:'enabled', trigger.kind:'detection').
        limit: Max definitions to return (1-500). Default 50.
    """
    try:
        client = _get_workflows_client()
        capped = min(max(limit, 1), 500)
        params: dict[str, Any] = {"limit": capped}
        if filter:
            params["filter"] = filter
        r = client.search_definitions(parameters=params)
        guard = _check_response(r, "Fusion Workflows")
        if guard:
            return guard
        b = r.get("body", {}) if isinstance(r, dict) else {}
        return {
            "ok": True,
            "items": b.get("resources") or [],
            "count": len(b.get("resources") or []),
            "meta": b.get("meta"),
        }
    except Exception as exc:
        return swallow_exc(exc)


def workflows_list_executions(
    filter: str | None = None, limit: int = 50
) -> dict[str, Any]:
    """List recent Fusion SOAR workflow executions. Read-only.

    Returns each execution's id, definition id, status (success / failed /
    in-progress), start/end timestamps, trigger source. Use this to surface
    "which automations fired in the last 24h, which failed, which are
    still in flight."

    Args:
        filter: Optional FQL filter (e.g. status:'failed', started_timestamp:>'<iso>').
        limit: Max executions to return (1-200). Default 50.
    """
    try:
        client = _get_workflows_client()
        # Hard cap at 100. The upstream WorkflowExecutionsCombined endpoint
        # routinely times out past 100 rows on busy tenants (observed against
        # the MCP transport ceiling on a tenant with heavy automation —
        # nominal 7-day filter + limit=100 still hit 60s). Smaller pages
        # come back in 1-3s and the dashboard surface only renders headlines
        # anyway. The agent can paginate via filter offsets if it needs more.
        capped = min(max(limit, 1), 100)
        # Workflows uses dot separator AND the field name is `started_timestamp`
        # (not `start_timestamp`, which the FalconPy docstring suggests).
        params: dict[str, Any] = {"limit": capped, "sort": "started_timestamp.desc"}
        # Default to a 24-hour recency window when the caller doesn't supply
        # one. Without a recency clause the API walks the entire execution
        # ledger; even a 7-day default has been observed timing out. The
        # recency window is operator-overridable — any caller-supplied
        # filter wins and is passed through verbatim.
        applied_default_window = False
        if filter:
            params["filter"] = filter
        else:
            since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds").replace("+00:00", "Z")
            params["filter"] = f"started_timestamp:>'{since}'"
            applied_default_window = True
        r = client.search_executions(parameters=params)
        guard = _check_response(r, "Fusion Workflows")
        if guard:
            return guard
        b = r.get("body", {}) if isinstance(r, dict) else {}
        raw = b.get("resources") or []
        items = [_project_execution(e) for e in raw if isinstance(e, dict)]
        return {
            "ok": True,
            "items": items,
            "count": len(items),
            "meta": b.get("meta"),
            "filter_applied": params["filter"],
            "default_window_applied": applied_default_window,
        }
    except Exception as exc:
        # Distinguish upstream timeout (slow Falcon API) from other failures
        # so the agent can suggest narrowing the window rather than retrying.
        msg = f"{type(exc).__name__}: {exc}"
        if "Timeout" in type(exc).__name__ or "timed out" in str(exc).lower():
            return {
                "ok": False,
                "error": (
                    "Falcon WorkflowExecutionsCombined timed out (upstream API "
                    "slow on this tenant). Retry with a tighter filter — e.g. "
                    "`started_timestamp:>'<6h-ago-iso>'` or "
                    "`status:'failed'+started_timestamp:>'<24h-ago-iso>'` — "
                    "and a smaller limit (10-25)."
                ),
                "timed_out": True,
                "filter_applied": params["filter"],
            }
        return {"ok": False, "error": msg}


def workflows_execute(
    definition_id: str,
    payload: dict[str, Any] | None = None,
    key: str | None = None,
) -> dict[str, Any]:
    """Execute an on-demand Fusion workflow. WRITE ACTION — requires explicit
    user approval in the UI before execution. The approval prompt surfaces
    the full resolved payload so the operator can verify trigger inputs
    before they fire.

    Payload shape is per-workflow: it must match the workflow's expected
    on-demand trigger inputs. Discover available workflows + their schemas
    via extras_workflows_list_definitions; the trigger contract lives on
    each definition. If the workflow has no on-demand trigger, execute will
    fail upstream — list the triggers first via falcon_list_workflow_triggers
    if uncertain.

    The response contains the new execution_id; poll
    extras_workflows_execution_result to retrieve outputs.

    Args:
        definition_id: The workflow definition id (preferred over name; ids
            are unambiguous when multiple workflows share a name).
        payload: On-demand trigger input dict. Defaults to {}.
        key: Optional dedup key. Falcon suppresses duplicate executions sharing
            the same key within its dedup window. Omit for a fresh UUID.
    """
    if not definition_id or not isinstance(definition_id, str):
        return {"ok": False, "error": "definition_id required"}
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "payload must be a JSON object"}
    try:
        client = _get_workflows_client()
        kwargs: dict[str, Any] = {
            "definition_id": definition_id,
            "body": payload,
        }
        if key:
            kwargs["key"] = key
        r = client.execute(**kwargs)
        guard = _check_response(r, "Fusion Workflows")
        if guard:
            return guard
        b = r.get("body", {}) if isinstance(r, dict) else {}
        resources = b.get("resources") or []
        # WorkflowExecute returns the new execution id(s) in resources.
        execution_id = resources[0] if resources else None
        return {
            "ok": True,
            "definition_id": definition_id,
            "execution_id": execution_id,
            "resources": resources,
        }
    except Exception as exc:
        return swallow_exc(exc)


def workflows_execution_result(execution_id: str) -> dict[str, Any]:
    """Fetch the result of a workflow execution. Read-only. Use after
    extras_workflows_execute to confirm completion + retrieve outputs.

    Workflow executions are asynchronous — a freshly-returned execution id
    may not have results yet. If the result set is empty, wait briefly and
    retry; do not interpret an empty result as a failed execution.

    Args:
        execution_id: Execution id returned by extras_workflows_execute.
    """
    if not execution_id or not isinstance(execution_id, str):
        return {"ok": False, "error": "execution_id required"}
    try:
        client = _get_workflows_client()
        r = client.execution_results(ids=[execution_id])
        guard = _check_response(r, "Fusion Workflows")
        if guard:
            return guard
        b = r.get("body", {}) if isinstance(r, dict) else {}
        resources = b.get("resources") or []
        return {
            "ok": True,
            "execution_id": execution_id,
            "items": resources,
            "count": len(resources),
        }
    except Exception as exc:
        return swallow_exc(exc)


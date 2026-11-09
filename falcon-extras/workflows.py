"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

from typing import Any
from falcon_helpers import _check_response, _get_workflows_client
from falcon_helpers import swallow_exc


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
    via falcon_search_workflow_definitions; the trigger contract lives on
    each definition. If the workflow has no on-demand trigger, execute will
    fail upstream — list the triggers first via falcon_list_workflow_triggers
    if uncertain.

    The response contains the new execution_id; read its outputs with
    falcon_get_workflow_execution_results.

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

"""Identity Protection tool implementations.

Extracted from ``server.py``; ``@mcp.tool()`` wrappers there delegate here.
"""

from __future__ import annotations

from typing import Any


def identity_ir_workflow_playbook(
    entity_id: str | None = None, sam_account_name: str | None = None
) -> dict[str, Any]:
    """Return the agentic identity-IR workflow playbook for a specific entity.
    Read-only. Mirrors extras_ir_workflow_playbook (host) but pivots on an
    identity entity rather than an AID.

    The agent calls this when the operator asks for an agentic identity IR
    workflow on a user; the returned text becomes the agent's working
    playbook for the rest of the conversation. The defining shape of
    identity IR is the **endpoint cascade** — Falcon's IDP API surface
    doesn't include account-disable / session-kill / password-reset, so the
    load-bearing remediation is to run the host IR playbook on each
    endpoint the user has been logged into recently.

    Args:
        entity_id: Optional. IDP entity id from the GraphQL API.
        sam_account_name: Optional. AD samAccountName. At least one of
            entity_id or sam_account_name must be provided.
    """
    from identity_ir_playbook import render_identity_ir_playbook

    text, error = render_identity_ir_playbook(entity_id, sam_account_name)
    if error:
        return {"ok": False, "error": error}
    return {"ok": True, "playbook": text}


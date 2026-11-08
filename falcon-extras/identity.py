"""Identity Protection tool implementations.

Extracted from ``server.py``; ``@mcp.tool()`` wrappers there delegate here.
"""

from __future__ import annotations

import os
from typing import Any

from falcon_helpers import (
    _check_response,
    _get_alerts_client,
)
from falcon_helpers import swallow_exc
from identity_ir_playbook import render_identity_ir_playbook


def identity_detections(
    hours: int = 168,
    limit: int = 50,
    include_policy_matches: bool = False,
    include_closed: bool = False,
) -> dict[str, Any]:
    """List recent Identity Protection detections via the Alerts API
    (filter `product:'idp'`). Read-only.

    Returns each alert's composite_id, severity_name, display_name,
    created_timestamp, status, and the user_name / source_account_name /
    destination_account_name fields specific to identity detections
    (Pass-the-Hash, Golden Ticket, Kerberoasting, suspicious LDAP, etc.).

    By default filters to **open** detections (new / in_progress / reopened)
    and **excludes "Policy rule match" enforcement events** — those are
    sensor-side enforcement firings, not attack-pattern detections, and
    drown out real threats in lab tenants. Set the include_* flags to true
    to bring them back.

    Args:
        hours: How far back to search (default 168 = last 7 days).
        limit: Max detections to return (1-500). Default 50.
        include_policy_matches: When True, includes "Policy rule match"
            rows. Default False — filters them by checking that `tactic`
            is non-empty (policy-match rows have no tactic).
        include_closed: When True, includes closed/resolved detections.
            Default False — restricts to status in {new, reopened, in_progress}.
    """
    try:
        from datetime import datetime, timedelta, timezone
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=max(1, hours))
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        capped = min(max(limit, 1), 500)
        client = _get_alerts_client()
        filt = f"product:'idp'+created_timestamp:>'{cutoff}'"
        if not include_closed:
            filt += "+status:['new','reopened','in_progress']"
        q = client.query_alerts_v2(parameters={
            "filter": filt,
            "limit": capped,
            "sort": "created_timestamp|desc",
        })
        guard = _check_response(q, "Alerts")
        if guard:
            return guard
        ids = (q.get("body", {}) if isinstance(q, dict) else {}).get(
            "resources"
        ) or []
        if not ids:
            return {"ok": True, "items": [], "count": 0}
        # Batch detail fetch — Alerts get_alerts_v2 also caps; chunk to 100.
        items: list[dict[str, Any]] = []
        for i in range(0, len(ids), 100):
            chunk = ids[i : i + 100]
            d = client.get_alerts_v2(body={"composite_ids": chunk})
            guard = _check_response(d, "Alerts")
            if guard:
                return guard
            for x in (
                (d.get("body", {}) if isinstance(d, dict) else {}).get(
                    "resources"
                )
                or []
            ):
                # Filter: drop "Policy rule match" enforcement rows unless
                # explicitly requested. These have empty tactic by design
                # (sensor-side enforcement, not attack pattern), which makes
                # tactic-presence a clean signal/noise discriminator.
                tactic = x.get("tactic") or ""
                if not include_policy_matches and not tactic:
                    continue
                # Project just the fields useful for the IDP decision
                # document — full alert records are huge and noisy.
                items.append({
                    "composite_id": x.get("composite_id"),
                    "id": x.get("id"),
                    "severity": x.get("severity"),
                    "severity_name": x.get("severity_name"),
                    "display_name": x.get("display_name"),
                    "description": x.get("description"),
                    "created_timestamp": x.get("created_timestamp"),
                    "status": x.get("status"),
                    "tactic": tactic,
                    "technique": x.get("technique"),
                    "user_name": x.get("user_name"),
                    "source_account_name": x.get("source_account_name"),
                    "source_account_domain": x.get("source_account_domain"),
                    "destination_account_name": x.get("destination_account_name"),
                    "source_endpoint_host_name": x.get("source_endpoint_host_name"),
                    "destination_endpoint_host_name": x.get("destination_endpoint_host_name"),
                    "falcon_host_link": x.get("falcon_host_link"),
                })
        return {"ok": True, "items": items, "count": len(items)}
    except Exception as exc:
        return swallow_exc(exc)


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


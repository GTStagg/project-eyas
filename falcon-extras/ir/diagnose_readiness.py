"""IR readiness diagnostic.

Verifies the prerequisites that have to be true on a tenant before the
agentic IR workflow can run cleanly:

1. ``FALCON_QUARANTINE_GROUP_ID`` env var is set.
2. The configured group exists in Falcon.
3. IOA exclusions scoped to that group are enumerated.
4. The RTR-runscript-preamble exclusion is present (without it, every
   Phase 2 cleanup primitive is killed at the sensor on hosts in the
   quarantine prevention policy).
5. A ``pattern_id`` is auto-discovered from a recent PShellMimikatz
   detection so the create-exclusion call can be composed concretely.

The diagnostic does NOT audit the quarantine prevention policy itself
— attached IOA rule groups, ML levels, response-policy settings — that's
a one-time tenant configuration decision, not a per-IR-run question. The
operator is expected to have configured the Agentic-Quarantine group and
its prevention policy to be IR-permissive (allows the cleanup tooling
the workflow needs) and behaviorally-restrictive (catches further
attacker activity) before turning the workflow on. The workflow's job is
to move the host in, wait for propagation (Phase 1.5), execute, and
release; not to second-guess the operator's tenant configuration.

When prerequisites are missing, the response includes
``remediation.tool_calls[]`` — concrete, ready-to-fire
``extras_create_ioa_exclusion`` invocations the operator can review and
fire. The create itself is approval-gated; this diagnostic does not write.

See ``server.py``'s ``extras_diagnose_ir_readiness`` for the full docstring.
"""

from __future__ import annotations

from typing import Any

from falcon_helpers import (
    _check_response,
    _get_alerts_client,
    _get_host_group_client,
    _get_ioa_exclusions_client,
    resolve_group_id,
)

from .detection_classifiers import _RTR_PREAMBLE_BASE64, _RTR_PREAMBLE_FULL_REGEX


def diagnose_ir_readiness() -> dict[str, Any]:
    # Override-aware: a quarantine group created/adopted earlier in this same
    # turn is honored before the (frozen) spawn-time env var.
    quarantine_group_id = resolve_group_id("quarantine") or ""
    checks: dict[str, Any] = {
        "quarantine_group_configured": bool(quarantine_group_id),
        "quarantine_group_id": quarantine_group_id or None,
        "quarantine_group_exists": False,
        "quarantine_group_name": None,
        "quarantine_group_type": None,
        "ioa_exclusions_scoped_to_quarantine": [],
        "rtr_preamble_exclusion_present": False,
        "rtr_preamble_exclusion_id": None,
        "candidate_pattern_id": None,
        "candidate_pattern_name": None,
        "candidate_pattern_source_composite_id": None,
    }
    missing: list[str] = []
    if not quarantine_group_id:
        missing.append("FALCON_QUARANTINE_GROUP_ID env var is not set on the server")
        return {
            "ok": True,
            "ready": False,
            "checks": checks,
            "missing": missing,
            "remediation": {
                "tool_calls": [],
                "notes": [
                    "Set FALCON_QUARANTINE_GROUP_ID to a static Falcon Host Group with an "
                    "aggressive prevention policy, then re-run this diagnostic.",
                ],
            },
        }

    # 1. Verify the quarantine group exists.
    def _guard_msg(guard: dict[str, Any], what: str) -> str:
        # _check_response returns one of two non-None shapes: a scope-denial
        # payload ({scope_pending: True, note, ...}) or an upstream-error
        # payload ({ok: False, error, ...}). Either way the check did NOT
        # confirm the prerequisite, so it belongs in `missing`.
        if guard.get("scope_pending"):
            return (
                f"{what} could not be verified — the required Falcon API scope "
                "is not granted on this tenant."
            )
        return f"{what} failed: {guard.get('error') or 'upstream error'}"

    try:
        hg_client = _get_host_group_client()
        hg_resp = hg_client.get_host_groups(ids=[quarantine_group_id])
        guard = _check_response(hg_resp, "HostGroup")
        if guard is None:
            records = ((hg_resp or {}).get("body") or {}).get("resources") or []
            if records and isinstance(records[0], dict):
                rec = records[0]
                checks["quarantine_group_exists"] = True
                checks["quarantine_group_name"] = rec.get("name")
                checks["quarantine_group_type"] = rec.get("group_type")
            else:
                missing.append(
                    f"Quarantine group id {quarantine_group_id!r} does not exist in Falcon"
                )
        else:
            # Upstream error / scope denial — group existence is UNVERIFIED, not
            # confirmed. Without this branch a transient 500 leaves `missing`
            # empty and the gate falsely reports ready:true on the IR workflow.
            missing.append(_guard_msg(guard, "Quarantine group lookup"))
    except Exception as exc:  # noqa: BLE001
        missing.append(f"Host group lookup failed: {type(exc).__name__}: {exc}")

    # 2. List IOA exclusions and find any scoped to the quarantine group.
    exclusions_enumerated = False
    try:
        ioa_client = _get_ioa_exclusions_client()
        q = ioa_client.query_exclusions(parameters={"limit": 200})
        guard = _check_response(q, "IOAExclusions")
        if guard is None:
            ids = ((q or {}).get("body") or {}).get("resources") or []
            if ids:
                d = ioa_client.get_exclusions(ids=ids)
                d_guard = _check_response(d, "IOAExclusions")
                if d_guard is None:
                    exclusions_enumerated = True
                    records = ((d or {}).get("body") or {}).get("resources") or []
                    for r in records:
                        if not isinstance(r, dict):
                            continue
                        scope_groups = [
                            g.get("id") for g in (r.get("groups") or []) if isinstance(g, dict)
                        ]
                        if quarantine_group_id not in scope_groups:
                            continue
                        item = {
                            "id": r.get("id"),
                            "name": r.get("name"),
                            "pattern_id": r.get("pattern_id"),
                            "ifn_regex": r.get("ifn_regex"),
                            "cl_regex": r.get("cl_regex"),
                        }
                        checks["ioa_exclusions_scoped_to_quarantine"].append(item)
                        # Heuristic match: cl_regex contains the RTR preamble
                        # base64 substring. Don't require exact equality —
                        # operators may have written it slightly differently.
                        cl = (r.get("cl_regex") or "")
                        if _RTR_PREAMBLE_BASE64 in cl:
                            checks["rtr_preamble_exclusion_present"] = True
                            checks["rtr_preamble_exclusion_id"] = r.get("id")
                else:
                    missing.append(_guard_msg(d_guard, "IOA exclusion detail lookup"))
            else:
                # Query succeeded with zero exclusion ids — enumeration IS
                # complete (the tenant simply has none scoped yet).
                exclusions_enumerated = True
        else:
            missing.append(_guard_msg(guard, "IOA exclusion enumeration"))
    except Exception as exc:  # noqa: BLE001
        missing.append(f"IOA exclusion enumeration failed: {type(exc).__name__}: {exc}")

    # 3. Auto-discover a pattern_id from the most recent PShellMimikatz
    # detection so the create call can be concrete.
    try:
        alerts_client = _get_alerts_client()
        q_alerts = alerts_client.query_alerts_v2(
            filter="product:'epp'+display_name:'PShellMimikatz'",
            limit=1,
            sort="created_timestamp.desc",
        )
        guard = _check_response(q_alerts, "Alerts")
        if guard is None:
            alert_ids = ((q_alerts or {}).get("body") or {}).get("resources") or []
            if alert_ids:
                hyd = alerts_client.get_alerts_v2(body={"composite_ids": alert_ids})
                h_guard = _check_response(hyd, "Alerts")
                if h_guard is None:
                    records = ((hyd or {}).get("body") or {}).get("resources") or []
                    if records and isinstance(records[0], dict):
                        rec = records[0]
                        # Try top-level pattern_id first; fall back to
                        # behaviors[].pattern_id (different falcon-mcp
                        # generations project this differently).
                        pid = rec.get("pattern_id")
                        pname = rec.get("display_name") or rec.get("pattern_disposition")
                        if not pid:
                            for b in rec.get("behaviors") or []:
                                if isinstance(b, dict) and b.get("pattern_id"):
                                    pid = b.get("pattern_id")
                                    pname = b.get("display_name") or pname
                                    break
                        if pid:
                            checks["candidate_pattern_id"] = str(pid)
                            checks["candidate_pattern_name"] = pname
                            checks["candidate_pattern_source_composite_id"] = rec.get(
                                "composite_id"
                            )
    except Exception as exc:  # noqa: BLE001
        # Non-fatal — the operator can supply pattern_id manually.
        checks["candidate_pattern_id_lookup_error"] = (
            f"{type(exc).__name__}: {exc}"
        )

    # 4. Compose remediation if needed.
    remediation_calls: list[dict[str, Any]] = []
    if (
        checks["quarantine_group_configured"]
        and checks["quarantine_group_exists"]
        and exclusions_enumerated
        and not checks["rtr_preamble_exclusion_present"]
    ):
        missing.append(
            "RTR runscript preamble IOA exclusion is NOT scoped to the quarantine "
            "host group. Phase 2 cleanup primitives WILL be blocked by the quarantine "
            "policy until this exclusion is created."
        )
        pattern_id = checks["candidate_pattern_id"]
        if pattern_id:
            remediation_calls.append(
                {
                    "tool": "extras_create_ioa_exclusion",
                    "args": {
                        "name": "Project Eyas IR — RTR runscript preamble",
                        "pattern_id": pattern_id,
                        "ifn_regex": r".*\\powershell\.exe(\W.*)?",
                        "cl_regex": _RTR_PREAMBLE_FULL_REGEX,
                        "comment": (
                            "Suppresses PShellMimikatz / PowerShell-encoded-command "
                            "detections triggered by Project Eyas's IR workflow when "
                            "RTR invokes runscript -CloudFile=<name>. The encoded "
                            "preamble decodes to Set-Location 'C:\\'. Scoped to the "
                            "quarantine host group only — production hosts retain "
                            "full PShellMimikatz coverage."
                        ),
                        "group_ids": [quarantine_group_id],
                    },
                }
            )
        else:
            remediation_calls.append(
                {
                    "tool": "extras_create_ioa_exclusion",
                    "needs_pattern_id_lookup": True,
                    "note": (
                        "No PShellMimikatz detection found on this tenant to "
                        "auto-discover pattern_id. To get one: trigger a test "
                        "detection by running any encoded-command PowerShell on a "
                        "non-production host, then re-run this diagnostic. "
                        "Alternatively, supply pattern_id manually from a sample "
                        "detection's behaviors[].pattern_id field."
                    ),
                    "args_template": {
                        "name": "Project Eyas IR — RTR runscript preamble",
                        "pattern_id": "<lookup required>",
                        "ifn_regex": r".*\\powershell\.exe(\W.*)?",
                        "cl_regex": _RTR_PREAMBLE_FULL_REGEX,
                        "comment": (
                            "Suppresses PShellMimikatz / PowerShell-encoded-command "
                            "detections triggered by Project Eyas's IR workflow when "
                            "RTR invokes runscript -CloudFile=<name>."
                        ),
                        "group_ids": [quarantine_group_id],
                    },
                }
            )

    ready = len(missing) == 0
    return {
        "ok": True,
        "ready": ready,
        "checks": checks,
        "missing": missing,
        "remediation": {
            "tool_calls": remediation_calls,
            "notes": [
                "Each remediation tool_call requires explicit user approval at "
                "execution time (extras_create_ioa_exclusion is in the write-tool "
                "registry).",
                "After applying remediation, re-run extras_diagnose_ir_readiness to "
                "confirm `ready: true` before running the IR workflow on any host.",
            ] if remediation_calls else [
                "All IR prerequisites satisfied — workflow can run cleanly on this "
                "tenant.",
            ],
        },
    }

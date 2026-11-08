"""IR quarantine setup tooling.

Three operations the operator runs at TENANT SETUP time, not at IR run
time. The IR workflow trusts that these have been run; runtime auditing
of the quarantine policy is explicitly out of scope.

  - ``diagnose_quarantine_setup`` — read-only state check. Detects which
    of the three migration cases the tenant is in (A: group with no
    dedicated policy / B: group with a single-attachment dedicated
    policy / C: group whose policy is attached to other groups too) and
    surfaces the right next-step CTA.

  - ``create_quarantine_host_group`` — write. Creates a new static host
    group with the canonical naming. Returns the id so the /config UI
    can save it to settings.json.

  - ``provision_quarantine_policy`` — write. Per platform (Windows /
    macOS / Linux), either:
      * mode="adopt"            — Case A or B: rename the existing
                                  bound-to-only-this-group policy to
                                  canonical (or attach a new one if
                                  none exists), push AGGRESSIVE
                                  prevention sliders, ensure the
                                  IR-readiness IOA exclusion exists.
      * mode="create_dedicated" — Case C: create a brand-new policy per
                                  platform bound only to this group,
                                  push AGGRESSIVE settings, create the
                                  exclusions. Leave the operator's
                                  pre-existing policy alone.

Naming convention used for app-managed artifacts (so they're
identifiable later):

  - Host group: ``Project Eyas - IR Quarantine``
  - Prevention policies (one per platform):
      ``Project Eyas - IR Quarantine (auto, windows)``
      ``Project Eyas - IR Quarantine (auto, mac)``
      ``Project Eyas - IR Quarantine (auto, linux)``

The ``(auto, <platform>)`` suffix is the marker that this app created
the artifact. Diagnostics surface it as a ``managed_by_eyas`` flag.

Slider levels pushed: AGGRESSIVE on ``OnSensorMLSlider`` /
``CloudAntiMalware`` / ``AdwarePUP``. EXTRA_AGGRESSIVE is intentionally
not used — high false-positive rate even outside the cleanup-tool
context. Behavioral toggles are NOT touched by this tool; if the
operator wants per-toggle aggression beyond the sliders, that's a
Falcon Console operator decision.
"""

from __future__ import annotations

from typing import Any

from falcon_helpers import (
    _check_response,
    _get_alerts_client,
    _get_host_group_client,
    _get_ioa_exclusions_client,
    _get_prevention_client,
    resolve_group_id,
    set_runtime_group_id,
)
from falcon_helpers import swallow_exc

from .detection_classifiers import _RTR_PREAMBLE_BASE64, _RTR_PREAMBLE_FULL_REGEX


CANONICAL_GROUP_NAME = "Project Eyas - IR Quarantine"
CANONICAL_POLICY_PREFIX = "Project Eyas - IR Quarantine (auto"  # closed by ", <platform>)"
PLATFORMS = ("windows", "mac", "linux")
SLIDER_IDS = ("OnSensorMLSlider", "CloudAntiMalware", "AdwarePUP")
TARGET_LEVEL = "AGGRESSIVE"


# ---------------------------------------------------------------------------
# Diagnostic
# ---------------------------------------------------------------------------


def diagnose_quarantine_setup(host_group_id: str | None = None) -> dict[str, Any]:
    """Read-only. Detect the migration case (A / B / C / ready / no group)
    and return the right next-step CTA shape for the /config UI.

    ``host_group_id`` defaults to the active environment's quarantine group:
    a group created/adopted earlier in this same turn (process-local override),
    else ``FALCON_QUARANTINE_GROUP_ID`` from the spawn-time env (which the
    spawn-env layer populates from the active environment's
    ``irQuarantineGroupId`` field). The override path is what makes a
    same-turn adopt -> re-diagnose read the freshly-saved id instead of
    stale-reading no_group_id.
    """
    host_group_id = resolve_group_id("quarantine", host_group_id)

    if not host_group_id:
        return {
            "ok": True,
            "case": "no_group_id",
            "host_group_id": None,
            "host_group": None,
            "policies": [],
            "ir_readiness_exclusion_present": False,
            "recommended_action": {
                "tool": "extras_create_quarantine_host_group",
                "args": {"name": CANONICAL_GROUP_NAME},
                "label": "Create the IR quarantine host group",
                "description": (
                    "Creates a new static host group named "
                    f"'{CANONICAL_GROUP_NAME}'. After creation, save the "
                    "returned id as the IR quarantine group on the active "
                    "environment, then re-run this diagnostic to provision "
                    "the prevention policy."
                ),
            },
        }

    # 1. Verify the host group exists.
    try:
        hg = _get_host_group_client()
        hg_resp = hg.get_host_groups(ids=[host_group_id])
        guard = _check_response(hg_resp, "HostGroup")
        if guard:
            # A 404 here means the configured group id doesn't exist —
            # that's the same operator-recoverable case as "0 records
            # returned" below. Reclassify so the card shows the friendly
            # "Create / Adopt" CTA instead of a raw upstream error.
            if isinstance(guard.get("error"), str) and "404" in guard["error"]:
                records = []
            else:
                return guard
        else:
            records = ((hg_resp or {}).get("body") or {}).get("resources") or []
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"host group lookup: {type(exc).__name__}: {exc}"}

    if not records or not isinstance(records[0], dict):
        return {
            "ok": True,
            "case": "group_missing",
            "host_group_id": host_group_id,
            "host_group": None,
            "policies": [],
            "ir_readiness_exclusion_present": False,
            "recommended_action": {
                "tool": "extras_create_quarantine_host_group",
                "args": {"name": CANONICAL_GROUP_NAME},
                "label": "Create the IR quarantine host group",
                "description": (
                    f"The configured group id {host_group_id!r} does not "
                    "exist in this tenant. Create a fresh group and update "
                    "the IR quarantine field with the new id."
                ),
            },
        }

    group_record = records[0]
    group_summary = {
        "id": group_record.get("id"),
        "name": group_record.get("name"),
        "group_type": group_record.get("group_type"),
    }

    # 2. Walk prevention policies, find ones attached to this group.
    try:
        prev_client = _get_prevention_client()
        resp = prev_client.query_combined_policies(parameters={"limit": 200})
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return guard
        all_policies = ((resp or {}).get("body") or {}).get("resources") or []
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"policy walk: {type(exc).__name__}: {exc}"}

    policies_on_group: list[dict[str, Any]] = []
    for p in all_policies:
        if not isinstance(p, dict):
            continue
        groups = p.get("groups") or []
        attached_group_ids = [g.get("id") for g in groups if isinstance(g, dict)]
        if host_group_id not in attached_group_ids:
            continue
        managed = isinstance(p.get("name"), str) and p["name"].startswith(CANONICAL_POLICY_PREFIX)
        raw_settings = p.get("prevention_settings") or []
        policies_on_group.append({
            "id": p.get("id"),
            "name": p.get("name"),
            "platform": p.get("platform_name"),
            "enabled": bool(p.get("enabled", True)),
            "attached_group_ids": attached_group_ids,
            "is_dedicated": len(attached_group_ids) == 1,
            "managed_by_eyas": managed,
            "settings_summary": _slider_summary(raw_settings),
            "_raw_settings": raw_settings,  # consumed by _at_target_level below; not surfaced to client
        })

    # 3. IR-readiness IOA exclusion presence.
    exclusion_present = False
    try:
        ioa = _get_ioa_exclusions_client()
        q = ioa.query_exclusions(parameters={"limit": 200})
        guard = _check_response(q, "IOAExclusions")
        if guard is None:
            ids = ((q or {}).get("body") or {}).get("resources") or []
            if ids:
                d = ioa.get_exclusions(ids=ids)
                d_guard = _check_response(d, "IOAExclusions")
                if d_guard is None:
                    exc_records = ((d or {}).get("body") or {}).get("resources") or []
                    for r in exc_records:
                        if not isinstance(r, dict):
                            continue
                        scope_groups = [
                            g.get("id") for g in (r.get("groups") or []) if isinstance(g, dict)
                        ]
                        if host_group_id not in scope_groups:
                            continue
                        if _RTR_PREAMBLE_BASE64 in (r.get("cl_regex") or ""):
                            exclusion_present = True
                            break
    except Exception:  # noqa: BLE001
        # Non-fatal — diagnostic still surfaces what it can.
        pass

    # 4. Classify the case.
    if not policies_on_group:
        case = "A_no_policy"
        recommendation = _recommend_provision(host_group_id, "adopt")
    else:
        any_shared = any(not p["is_dedicated"] for p in policies_on_group)
        all_provisioned = (
            all(p["managed_by_eyas"] for p in policies_on_group)
            and all(_at_target_level(p["_raw_settings"]) for p in policies_on_group)
            and exclusion_present
        )
        if all_provisioned:
            case = "ready"
            recommendation = None
        elif any_shared:
            case = "C_shared_policy"
            recommendation = _recommend_provision(host_group_id, "create_dedicated")
        else:
            case = "B_dedicated_single_group"
            recommendation = _recommend_provision(host_group_id, "adopt")

    # Strip the verbose internal-only _raw_settings field from each
    # policy entry before returning — it was only needed for the
    # at-target-level walk above.
    sanitized_policies = [
        {k: v for k, v in p.items() if k != "_raw_settings"}
        for p in policies_on_group
    ]

    return {
        "ok": True,
        "case": case,
        "host_group_id": host_group_id,
        "host_group": group_summary,
        "policies": sanitized_policies,
        "ir_readiness_exclusion_present": exclusion_present,
        "recommended_action": recommendation,
    }


def _slider_summary(settings: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick out the canonical Windows sliders for display purposes only.
    NOT used for the at-target-level check — that's now schema-tolerant
    (see _at_target_level). Kept for the diagnostic response shape so
    callers can still inspect the named sliders verbatim.
    """
    flat: list[dict[str, Any]] = []
    for s in settings:
        if not isinstance(s, dict):
            continue
        inner = s.get("settings")
        if isinstance(inner, list):
            flat.extend(x for x in inner if isinstance(x, dict))
        else:
            flat.append(s)
    out: dict[str, Any] = {}
    for s in flat:
        sid = s.get("id")
        if sid not in SLIDER_IDS:
            continue
        v = s.get("value") or {}
        out[sid] = {
            "detection": v.get("detection"),
            "prevention": v.get("prevention"),
        }
    return out


def _at_target_level(prevention_settings: list[dict[str, Any]]) -> bool:
    """Return True iff EVERY slider on the policy (any setting whose value
    is a {detection, prevention} pair) is at TARGET_LEVEL or above on
    both knobs. Schema-tolerant — operates on shape, not on a hardcoded
    slider-id list, so macOS / Linux policies (which expose different
    slider IDs from Windows) classify correctly.

    Mirrors the push logic in _push_max_protective_settings: any setting
    with `{detection, prevention}` is a "slider"; any setting with
    `{enabled: bool}` is a "toggle". Toggles are not validated here
    because there's no ordinal "level" — they're either on or off, and
    enforcement intent varies per toggle. The push step enables every
    toggle by design; if the operator subsequently disabled some, the
    policy's still considered "ready" from a level-of-aggression
    perspective.
    """
    rank = {"DISABLED": 0, "CAUTIOUS": 1, "MODERATE": 2, "AGGRESSIVE": 3, "EXTRA_AGGRESSIVE": 4}
    target = rank[TARGET_LEVEL]

    # Flatten grouped + flat shapes the same way _push_max_protective_settings does.
    flat: list[dict[str, Any]] = []
    for s in prevention_settings or []:
        if not isinstance(s, dict):
            continue
        inner = s.get("settings")
        if isinstance(inner, list):
            flat.extend(x for x in inner if isinstance(x, dict))
        else:
            flat.append(s)

    for s in flat:
        v = s.get("value")
        if not isinstance(v, dict):
            continue
        d = v.get("detection")
        # Validate detection only. Prevention is informational because
        # Falcon caps it independently per-slider — e.g.
        # CloudBasedAnomalousProcessExecution is detection-up-to-AGGRESSIVE
        # but prevention=DISABLED is the only value Falcon will store
        # regardless of what the API tries to write. Detection-at-target
        # is the load-bearing signal that the operator (or our push)
        # escalated aggression on this slider; prevention follows
        # whatever Falcon allows.
        if not isinstance(d, str):
            continue
        d_rank = rank.get(d.upper(), -1)
        # Unrecognized vocabulary (e.g., platform-specific values
        # like "ENABLED" / "DISABLED" on some macOS/Linux sliders
        # that don't use the canonical aggression scale). Skip
        # rather than mis-classify as not-at-target.
        if d_rank < 0:
            continue
        if d_rank < target:
            return False

    # If the platform exposes no recognizable detection sliders at all,
    # trust the policy. Some platforms have only behavioral toggles or
    # platform-specific value vocabularies that we can't ordinally rank.
    return True


def _recommend_provision(host_group_id: str, mode: str) -> dict[str, Any]:
    if mode == "adopt":
        label = "Provision the IR quarantine prevention policy (adopt + standardize)"
        description = (
            "Adopts the policy currently bound to this group (or attaches a "
            "fresh one if none exists), renames it to the canonical "
            f"'{CANONICAL_POLICY_PREFIX}, <platform>)' format, pushes "
            f"{TARGET_LEVEL} prevention sliders, and creates the IR-readiness "
            "IOA exclusion. Per platform: Windows, macOS, Linux."
        )
    else:  # create_dedicated
        label = "Create dedicated prevention policies for IR quarantine"
        description = (
            "Your existing policy is attached to other host groups, so pushing "
            f"{TARGET_LEVEL} settings to it would change posture on those "
            "groups too. This action creates a new dedicated prevention "
            "policy per platform bound ONLY to your IR quarantine group, "
            "leaves the existing policy alone, and creates the IR-readiness "
            "IOA exclusion."
        )
    return {
        "tool": "extras_provision_quarantine_policy",
        "args": {"host_group_id": host_group_id, "mode": mode},
        "label": label,
        "description": description,
    }


# ---------------------------------------------------------------------------
# Create host group
# ---------------------------------------------------------------------------


def create_quarantine_host_group(
    name: str = CANONICAL_GROUP_NAME,
    description: str | None = None,
) -> dict[str, Any]:
    """Write. Creates a new STATIC host group. Returns the new id."""
    if not name or not isinstance(name, str):
        return {"ok": False, "error": "name is required"}
    desc = description or (
        "App-managed: hosts placed here during incident response. Three "
        "platform-specific prevention policies (Windows / macOS / Linux) "
        "should be attached, all set to AGGRESSIVE."
    )
    try:
        hg = _get_host_group_client()
        body = {
            "resources": [
                {
                    "name": name,
                    "description": desc,
                    "group_type": "static",
                }
            ]
        }
        resp = hg.create_host_groups(body=body)
        guard = _check_response(resp, "HostGroup")
        if guard:
            return guard
        records = ((resp or {}).get("body") or {}).get("resources") or []
        if not records or not isinstance(records[0], dict):
            return {"ok": False, "error": "create_host_groups returned no record"}
        rec = records[0]
        # Make the new id visible to sibling tools in THIS same turn (the
        # parent persists it to the DB after we return, but our env is frozen).
        set_runtime_group_id("quarantine", rec.get("id"))
        return {
            "ok": True,
            "id": rec.get("id"),
            "name": rec.get("name"),
            "group_type": rec.get("group_type"),
            "next_step": (
                "The new group id is saved to the active environment "
                "automatically — no manual step is needed. Proceed directly to "
                "extras_provision_quarantine_policy with this host_group_id."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


def adopt_quarantine_host_group(
    name: str = CANONICAL_GROUP_NAME,
) -> dict[str, Any]:
    """Find an existing host group by exact name and return its id so the
    chat auto-save hook can persist it as the active env's IR quarantine
    group. Read against Falcon, but the result write to settings is the
    reason this is approval-gated."""
    if not name or not isinstance(name, str):
        return {"ok": False, "error": "name is required"}
    try:
        hg = _get_host_group_client()
        # Walk all groups + match client-side. The FQL `name:'...'` filter on
        # query_combined_host_groups is unreliable for canonical names with
        # spaces+hyphens (agent has observed it returning 0 results for a
        # group that demonstrably exists). Walking is cheap — tenants rarely
        # have >500 host groups — and removes the FQL-escaping foot-gun.
        resp = hg.query_combined_host_groups(parameters={"limit": 500})
        guard = _check_response(resp, "HostGroup")
        if guard:
            return guard
        records = ((resp or {}).get("body") or {}).get("resources") or []
        exact = [r for r in records if isinstance(r, dict) and r.get("name") == name]
        if not exact:
            return {
                "ok": False,
                "error": f"no host group named '{name}' found in this tenant",
                "hint": "use extras_create_quarantine_host_group to create it",
            }
        if len(exact) > 1:
            return {
                "ok": False,
                "error": f"multiple host groups named '{name}' — refusing to guess",
                "candidates": [{"id": r.get("id"), "group_type": r.get("group_type")} for r in exact],
            }
        rec = exact[0]
        # Make the adopted id visible to sibling tools in THIS same turn (the
        # parent persists it to the DB after we return, but our env is frozen).
        set_runtime_group_id("quarantine", rec.get("id"))
        return {
            "ok": True,
            "id": rec.get("id"),
            "name": rec.get("name"),
            "group_type": rec.get("group_type"),
            "next_step": "Saved as the active environment's IR quarantine group.",
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


# ---------------------------------------------------------------------------
# Provision prevention policy (per platform) + exclusion
# ---------------------------------------------------------------------------


def provision_quarantine_policy(
    host_group_id: str,
    mode: str = "adopt",
) -> dict[str, Any]:
    """Write. Provision per-platform prevention policies bound to the
    quarantine host group, push AGGRESSIVE sliders, and create the
    IR-readiness IOA exclusion.

    ``mode``:
      - "adopt": adopt the existing single-group policy if any (rename
        it canonical), or attach a fresh canonical policy if none.
      - "create_dedicated": always create a brand-new policy bound only
        to this group; leave any existing policy alone.
    """
    if not host_group_id or not isinstance(host_group_id, str):
        return {"ok": False, "error": "host_group_id is required"}
    if mode not in ("adopt", "create_dedicated"):
        return {"ok": False, "error": f"unknown mode {mode!r}"}

    # Walk all policies once; bucket per platform.
    try:
        prev = _get_prevention_client()
        resp = prev.query_combined_policies(parameters={"limit": 200})
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return guard
        all_policies = ((resp or {}).get("body") or {}).get("resources") or []
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"policy walk: {type(exc).__name__}: {exc}"}

    per_platform_existing: dict[str, list[dict[str, Any]]] = {p: [] for p in PLATFORMS}
    for p in all_policies:
        if not isinstance(p, dict):
            continue
        platform = (p.get("platform_name") or "").lower()
        if platform not in per_platform_existing:
            continue
        groups = p.get("groups") or []
        attached_ids = [g.get("id") for g in groups if isinstance(g, dict)]
        if host_group_id not in attached_ids:
            continue
        per_platform_existing[platform].append({
            "policy": p,
            "attached_ids": attached_ids,
        })

    actions: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    # Track the IR policy id per platform so we can push them to the top
    # of the per-platform precedence list after all per-platform provisioning
    # finishes. Precedence is what makes the additive group-membership model
    # work: a host added to the IR quarantine group keeps its other group
    # memberships, but the IR policy wins because it's at the top of the
    # precedence list for that platform.
    ir_policy_ids_by_platform: dict[str, str] = {}

    for platform in PLATFORMS:
        target_name = f"{CANONICAL_POLICY_PREFIX}, {platform})"
        existing = per_platform_existing[platform]

        chosen: dict[str, Any] | None = None
        if mode == "adopt" and existing:
            single = [e for e in existing if len(e["attached_ids"]) == 1]
            chosen = (single or existing)[0]

        if chosen is None:
            # Create a fresh policy and attach it to the group.
            create_result = _create_policy_and_attach(
                prev, target_name, platform, host_group_id
            )
            if not create_result.get("ok"):
                errors.append({"platform": platform, **create_result})
                continue
            policy_id = create_result["policy_id"]
            actions.append({
                "platform": platform,
                "step": "create_and_attach",
                "policy_id": policy_id,
                "policy_name": target_name,
            })
        else:
            policy_id = chosen["policy"].get("id")
            current_name = chosen["policy"].get("name") or ""
            if current_name != target_name:
                rename_result = _rename_policy(prev, policy_id, target_name)
                if not rename_result.get("ok"):
                    errors.append({"platform": platform, **rename_result})
                    continue
                actions.append({
                    "platform": platform,
                    "step": "rename",
                    "policy_id": policy_id,
                    "from": current_name,
                    "to": target_name,
                })

        # Push AGGRESSIVE sliders + enable every behavioral toggle.
        push_result = _push_max_protective_settings(prev, policy_id, platform)
        if not push_result.get("ok"):
            errors.append({"platform": platform, **push_result})
            continue
        actions.append({
            "platform": platform,
            "step": "push_settings",
            "policy_id": policy_id,
            "level": TARGET_LEVEL,
            "sliders_touched": push_result.get("sliders_touched", 0),
            "toggles_touched": push_result.get("toggles_touched", 0),
        })
        ir_policy_ids_by_platform[platform] = policy_id

    # Push the IR policies to the top of their per-platform precedence
    # lists. This is the load-bearing piece that makes the additive
    # group-membership model work — a host added to the IR quarantine
    # group keeps its other group memberships, but the IR policy wins
    # because it's first in the precedence list. Without this call, the
    # IR policy could land anywhere in precedence and a higher-precedence
    # production policy (Workstations, etc.) would override it.
    for platform, policy_id in ir_policy_ids_by_platform.items():
        prec_result = _set_to_highest_precedence(prev, policy_id, platform, all_policies)
        if not prec_result.get("ok"):
            # Don't error the whole provisioning — the policy is still
            # attached and configured. But surface the precedence-set
            # failure prominently so the operator knows the IR policy
            # may not actually win on hosts in the quarantine group.
            errors.append({"platform": platform, "stage": "set_precedence", **prec_result})
            actions.append({
                "platform": platform,
                "step": "set_precedence",
                "policy_id": policy_id,
                "ok": False,
                "warning": (
                    "Precedence not set — the IR policy may not enforce "
                    "if a host is also in another group whose policy has "
                    "higher precedence. Fix in Falcon Console (Endpoint "
                    "security → Prevention policies → reorder)."
                ),
            })
            continue
        actions.append({
            "platform": platform,
            "step": "set_precedence",
            "policy_id": policy_id,
            "rank": "highest",
            "policies_in_order": prec_result.get("policies_in_order"),
        })

    # Create the IR-readiness IOA exclusion if missing.
    exclusion_result = _ensure_readiness_exclusion(host_group_id)
    actions.append({"step": "ir_readiness_exclusion", **exclusion_result})

    return {
        "ok": len(errors) == 0,
        "host_group_id": host_group_id,
        "mode": mode,
        "actions": actions,
        "errors": errors,
    }


def _set_to_highest_precedence(
    prev_client,
    target_policy_id: str,
    platform: str,
    all_policies: list[dict[str, Any]],
) -> dict[str, Any]:
    """Reorder per-platform prevention policies so ``target_policy_id`` is
    first. Falcon's set_policies_precedence requires the FULL ordered list
    of non-default policies for the platform; the default policy is
    implicitly always last and is excluded from the request.

    Falcon stores platform names capitalized ("Windows" / "Mac" / "Linux");
    our internal PLATFORMS tuple uses lowercase. Capitalize on the way out.
    """
    api_platform = {"windows": "Windows", "mac": "Mac", "linux": "Linux"}.get(platform, platform.capitalize())

    # Build the full per-platform non-default policy list, target first.
    others: list[str] = []
    target_seen = False
    for p in all_policies:
        if not isinstance(p, dict):
            continue
        if (p.get("platform_name") or "").lower() != platform:
            continue
        if p.get("name") == "platform_default":
            # Default policy is implicit; the API rejects it in the list.
            continue
        pid = p.get("id")
        if not pid:
            continue
        if pid == target_policy_id:
            target_seen = True
            continue
        others.append(pid)
    if not target_seen:
        # The IR policy was just created and isn't in the cached
        # all_policies snapshot. Prepend it explicitly.
        pass
    ordered = [target_policy_id, *others]

    try:
        resp = prev_client.set_policies_precedence(
            ids=ordered,
            platform_name=api_platform,
        )
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return {"ok": False, **guard}
        return {"ok": True, "policies_in_order": ordered}
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


def _create_policy_and_attach(
    prev_client, name: str, platform: str, host_group_id: str
) -> dict[str, Any]:
    # Falcon's create_policies API rejects lowercase platform names with
    # HTTP 400 "Unsupported value specified for 'platform_name'". The
    # accepted vocabulary is capitalized: Windows / Mac / Linux. Our
    # internal PLATFORMS tuple is lowercase to match query_combined_policies'
    # response shape; we capitalize on the way out.
    api_platform = {"windows": "Windows", "mac": "Mac", "linux": "Linux"}.get(
        platform, platform.capitalize()
    )
    try:
        body = {
            "resources": [
                {
                    "name": name,
                    "description": "App-managed by Project Eyas. AGGRESSIVE prevention sliders for IR quarantine. Do not edit manually.",
                    "platform_name": api_platform,
                }
            ]
        }
        resp = prev_client.create_policies(body=body)
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return {"ok": False, "stage": "create_policies", **guard}
        records = ((resp or {}).get("body") or {}).get("resources") or []
        if not records or not isinstance(records[0], dict):
            return {"ok": False, "stage": "create_policies", "error": "no record returned"}
        policy_id = records[0].get("id")
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "stage": "create_policies", "error": f"{type(exc).__name__}: {exc}"}

    try:
        attach = prev_client.perform_policies_action(
            action_name="add-host-group",
            ids=policy_id,
            group_id=host_group_id,
        )
        guard = _check_response(attach, "Prevention Policies")
        if guard:
            return {"ok": False, "stage": "attach_group", **guard, "policy_id": policy_id}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "stage": "attach_group", "policy_id": policy_id, "error": f"{type(exc).__name__}: {exc}"}

    try:
        enable = prev_client.perform_policies_action(action_name="enable", ids=policy_id)
        guard = _check_response(enable, "Prevention Policies")
        if guard:
            return {"ok": False, "stage": "enable", "policy_id": policy_id, **guard}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "stage": "enable", "policy_id": policy_id, "error": f"{type(exc).__name__}: {exc}"}

    return {"ok": True, "policy_id": policy_id}


def _rename_policy(prev_client, policy_id: str, new_name: str) -> dict[str, Any]:
    try:
        body = {"resources": [{"id": policy_id, "name": new_name}]}
        resp = prev_client.update_policies(body=body)
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return {"ok": False, "stage": "rename", **guard}
        return {"ok": True}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "stage": "rename", "error": f"{type(exc).__name__}: {exc}"}


def _push_max_protective_settings(prev_client, policy_id: str, platform: str) -> dict[str, Any]:
    """Read the current prevention_settings, push BOTH:
      - sliders (value: {detection, prevention}) → AGGRESSIVE on both knobs
      - boolean toggles (value: {enabled: bool}) → enabled=true
      - detection-only sliders (value: {detection}) → AGGRESSIVE
    Then write back. Operates on shape, not on a hard-coded toggle list,
    so the policy schema can evolve without code changes.
    """
    try:
        resp = prev_client.get_policies(ids=policy_id)
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return {"ok": False, "stage": "get_for_update", **guard}
        records = ((resp or {}).get("body") or {}).get("resources") or []
        if not records or not isinstance(records[0], dict):
            return {"ok": False, "stage": "get_for_update", "error": "no record"}
        existing = records[0].get("prevention_settings") or []
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "stage": "get_for_update", "error": f"{type(exc).__name__}: {exc}"}

    sliders_touched = 0
    toggles_touched = 0

    def _maybe_update(entry: dict[str, Any]) -> tuple[bool, bool]:
        # Returns (is_slider_change, is_toggle_change).
        v = entry.get("value")
        if not isinstance(v, dict):
            return (False, False)
        # Slider with detection + prevention pair (the three named SLIDER_IDS
        # always have this shape; some additional sliders may too).
        if "detection" in v and "prevention" in v:
            old_d, old_p = v.get("detection"), v.get("prevention")
            v["detection"] = TARGET_LEVEL
            v["prevention"] = TARGET_LEVEL
            entry["value"] = v
            return (old_d != TARGET_LEVEL or old_p != TARGET_LEVEL, False)
        # Detection-only slider.
        if "detection" in v and "prevention" not in v:
            old_d = v.get("detection")
            v["detection"] = TARGET_LEVEL
            entry["value"] = v
            return (old_d != TARGET_LEVEL, False)
        # Boolean toggle.
        if "enabled" in v and isinstance(v.get("enabled"), bool):
            old = v.get("enabled")
            v["enabled"] = True
            entry["value"] = v
            return (False, old is not True)
        return (False, False)

    # Mutate in place AND collect a flat list of (id, value) settings.
    # Falcon's get_policies returns settings nested under groups[].settings
    # (a {name, settings: [{id, value}, ...]} shape), but update_policies
    # expects a FLAT array of {id, value} pairs at the top level. Sending
    # back the grouped shape returns HTTP 400 "Prevention settings must
    # specify an id" because the API iterates entries expecting {id, value}
    # but receives the {name, settings} group wrappers.
    flat: list[dict[str, Any]] = []
    for s in existing:
        if not isinstance(s, dict):
            continue
        inner = s.get("settings")
        if isinstance(inner, list):
            for sub in inner:
                if not isinstance(sub, dict):
                    continue
                slider_chg, toggle_chg = _maybe_update(sub)
                sliders_touched += int(slider_chg)
                toggles_touched += int(toggle_chg)
                if sub.get("id") is not None:
                    flat.append({"id": sub["id"], "value": sub.get("value")})
        else:
            slider_chg, toggle_chg = _maybe_update(s)
            sliders_touched += int(slider_chg)
            toggles_touched += int(toggle_chg)
            if s.get("id") is not None:
                flat.append({"id": s["id"], "value": s.get("value")})

    if sliders_touched == 0 and toggles_touched == 0:
        return {
            "ok": True,
            "sliders_touched": 0,
            "toggles_touched": 0,
            "note": "policy already at max-protective state",
        }

    try:
        body = {"resources": [{"id": policy_id, "settings": flat}]}
        resp = prev_client.update_policies(body=body)
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return {"ok": False, "stage": "update_settings", **guard}
        return {
            "ok": True,
            "sliders_touched": sliders_touched,
            "toggles_touched": toggles_touched,
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "stage": "update_settings", "error": f"{type(exc).__name__}: {exc}"}


# Backward-compat alias — server.py still calls the old name elsewhere.
_push_aggressive_sliders = _push_max_protective_settings


def _ensure_readiness_exclusion(host_group_id: str) -> dict[str, Any]:
    """Verify the IR-readiness IOA exclusion is scoped to the quarantine
    group, and CREATE it if missing.

    Pre-warming (2026-05-11): provisioning installs the exclusion eagerly
    so it has time to propagate to every sensor in the group BEFORE any
    IR engagement fires. Closes the first-IR-run propagation race that
    used to surface as ``batch_init_sessions: 404`` + 5-min Phase 1.5
    timeout. The operator's single approval for
    ``extras_provision_quarantine_policy`` covers the whole chain
    (policies + precedence + this exclusion).

    Idempotent: if the exclusion is already present, returns
    ``{present: True, id: <existing>}`` without writing. The underlying
    ``create_ioa_exclusion`` impl also runs its own (pattern_id, ifn_regex)
    duplicate guard server-side as a second safety net.

    If we can't resolve a pattern_id for PShellMimikatz on this tenant
    (no prior PShellMimikatz detection ever fired, so we have no concrete
    pattern_id to hang the exclusion on), the function reports
    ``pattern_id_unresolved: True`` and DOES NOT fail provisioning. The
    operator gets a clear warning that first-IR-engagement will incur
    the propagation wait + need a JIT install. Re-running provisioning
    after a PShellMimikatz has fired (once) closes the gap.
    """
    # Step 1: check whether an exclusion scoped to this group already
    # carries the RTR-preamble cl_regex marker.
    try:
        ioa = _get_ioa_exclusions_client()
        q = ioa.query_exclusions(parameters={"limit": 200})
        guard = _check_response(q, "IOAExclusions")
        if guard:
            return {"ok": False, **guard}
        ids = ((q or {}).get("body") or {}).get("resources") or []
        if ids:
            d = ioa.get_exclusions(ids=ids)
            d_guard = _check_response(d, "IOAExclusions")
            if d_guard is None:
                exc_records = ((d or {}).get("body") or {}).get("resources") or []
                for r in exc_records:
                    if not isinstance(r, dict):
                        continue
                    scope = [
                        g.get("id") for g in (r.get("groups") or []) if isinstance(g, dict)
                    ]
                    if host_group_id not in scope:
                        continue
                    if _RTR_PREAMBLE_BASE64 in (r.get("cl_regex") or ""):
                        return {"ok": True, "present": True, "id": r.get("id"), "created": False}
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

    # Step 2: missing. Try to resolve a pattern_id.
    pattern_id = _candidate_pattern_id()
    if not pattern_id:
        # Fresh tenant — no PShellMimikatz has fired yet, so we don't
        # have a concrete pattern_id. Don't fail provisioning; flag for
        # the operator. First IR engagement will need JIT install (the
        # old behavior) until provisioning is re-run.
        return {
            "ok": True,
            "present": False,
            "created": False,
            "pattern_id_unresolved": True,
            "warning": (
                "IR-readiness IOA exclusion could NOT be pre-installed: "
                "no PShellMimikatz detection has ever fired on this tenant, "
                "so the pattern_id can't be resolved. The first IR engagement "
                "after a host is moved into the quarantine group will trigger "
                "the PowerShell-encoded-command detector once (this fires the "
                "PShellMimikatz pattern and surfaces its pattern_id); after "
                "that, re-running /config IR-Quarantine provisioning will "
                "install the exclusion eagerly. Until then, the first IR "
                "engagement on a freshly-quarantined host will need a JIT "
                "IOA exclusion install at Phase 0 + the standard "
                "60-90s propagation wait in Phase 1.5."
            ),
        }

    # Step 3: have a pattern_id — fire the create directly. Idempotent
    # against an existing-by-pattern_id-and-ifn_regex pair via the impl's
    # own duplicate guard.
    from exclusions import create_ioa_exclusion
    create_result = create_ioa_exclusion(
        name="Project Eyas IR — RTR runscript preamble",
        pattern_id=pattern_id,
        # IOA engine rejects zero-width assertions (^, $, \b). Use the
        # \W trailing-context pattern per falcon_ioa_no_zero_width_assertions
        # memory: match the image ending in \powershell.exe with optional
        # non-word + anything trailing. Allows bare "...\powershell.exe"
        # AND "...\powershell.exe arg1" without matching "...\powershell.exe2".
        ifn_regex=r".*\\powershell\.exe(\W.*)?",
        cl_regex=_RTR_PREAMBLE_FULL_REGEX,
        comment=(
            "Suppresses PShellMimikatz / PowerShell-encoded-command "
            "detections triggered by Project Eyas's IR workflow when "
            "RTR invokes runscript -CloudFile=<name>. Pre-installed at "
            "tenant-provisioning time so the exclusion has time to "
            "propagate to all sensors before any IR engagement fires."
        ),
        group_ids=[host_group_id],
    )
    if create_result.get("duplicate"):
        # Race with another provisioning run, or older exclusion that
        # didn't carry the cl_regex marker we look for in Step 1. Treat
        # as success.
        return {
            "ok": True,
            "present": True,
            "id": (create_result.get("existing_ids") or [None])[0],
            "created": False,
            "was_duplicate": True,
        }
    if not create_result.get("ok"):
        return {
            "ok": False,
            "present": False,
            "created": False,
            "error": create_result.get("error", "create_ioa_exclusion failed"),
            "create_result": create_result,
        }
    return {
        "ok": True,
        "present": True,
        "id": create_result.get("id"),
        "created": True,
        "pattern_id": pattern_id,
    }


def _candidate_pattern_id() -> str | None:
    """Try to find a recent PShellMimikatz detection so the create-exclusion
    call can be composed concretely. Non-fatal — operator can supply
    pattern_id manually.
    """
    try:
        client = _get_alerts_client()
        q = client.query_alerts_v2(
            filter="product:'epp'+display_name:'PShellMimikatz'",
            limit=1,
            sort="created_timestamp.desc",
        )
        guard = _check_response(q, "Alerts")
        if guard:
            return None
        ids = ((q or {}).get("body") or {}).get("resources") or []
        if not ids:
            return None
        hyd = client.get_alerts_v2(body={"composite_ids": ids})
        h_guard = _check_response(hyd, "Alerts")
        if h_guard:
            return None
        records = ((hyd or {}).get("body") or {}).get("resources") or []
        if not records or not isinstance(records[0], dict):
            return None
        rec = records[0]
        pid = rec.get("pattern_id")
        if not pid:
            for b in rec.get("behaviors") or []:
                if isinstance(b, dict) and b.get("pattern_id"):
                    return str(b["pattern_id"])
        return str(pid) if pid else None
    except Exception:  # noqa: BLE001
        return None

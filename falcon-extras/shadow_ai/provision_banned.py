"""Shadow-AI Banned setup tooling.

Mirrors the IR quarantine pattern: a host group + per-platform prevention
policies + a Custom IOA rule group, set up once at tenant provisioning
time and trusted at runtime.

The model is **default-allow, opt-in to enforcement**: standard prevention
policies do NOT have the Shadow-AI rule group attached; users CAN install
AI tools by default. The operator only intervenes when a specific user/host
needs to be blocked — they add the host to the
``Project Eyas - Shadow-AI Banned`` group, the banned policy wins by
precedence, and the rule group fires for that host only.

Three operations the operator runs at TENANT SETUP time:

  - ``diagnose_shadow_ai_banned_setup`` — read-only state check. Detects
    the migration case (group exists / no policy attached / shared policy /
    ready) and returns the right next-step CTA.

  - ``create_shadow_ai_banned_host_group`` — write. Creates a new static
    host group with canonical naming. Returns the id so /config can save
    it to settings.json.

  - ``provision_shadow_ai_banned_policy`` — write. Per platform: adopts
    the existing single-group policy (rename to canonical + attach the
    Shadow-AI rule group + push stricter sliders) or creates a brand-new
    dedicated policy. Sets per-platform precedence so the banned policy
    wins over standard policies but loses to IR Quarantine.

Naming convention (so artifacts are identifiable):
  - Host group: ``Project Eyas - Shadow-AI Banned``
  - Prevention policies: ``Project Eyas - Shadow-AI Banned (auto, <platform>)``
  - Rule group: ``Project Eyas - Shadow-AI Block`` (created by
    ``extras_shadow_ai_adopt_prevention`` — the existing tool that
    authors the rule corpus; this provisioning tool calls into it
    after creating each policy).
"""

from __future__ import annotations

from typing import Any

from falcon_helpers import (
    _check_response,
    _get_host_group_client,
    _get_prevention_client,
    resolve_group_id,
    set_runtime_group_id,
)
from falcon_helpers import swallow_exc

from .ioa_rules import (
    SHADOW_AI_RULE_GROUP_NAME,
    SHADOW_AI_RULE_GROUP_NAMES,
    CORPUS_BY_PLATFORM,
)


CANONICAL_GROUP_NAME = "Project Eyas - Shadow-AI Banned"
CANONICAL_POLICY_PREFIX = "Project Eyas - Shadow-AI Banned (auto"  # closed by ", <platform>)"
PLATFORMS = ("windows", "mac", "linux")
SLIDER_IDS = ("OnSensorMLSlider", "CloudAntiMalware", "AdwarePUP")
TARGET_LEVEL = "AGGRESSIVE"


# ---------------------------------------------------------------------------
# Diagnostic
# ---------------------------------------------------------------------------


def diagnose_shadow_ai_banned_setup(host_group_id: str | None = None) -> dict[str, Any]:
    """Read-only. Returns the case + recommended_action for the /config card.

    Resolves the banned group from (in precedence order) an explicit arg, a
    group created/adopted earlier in this same turn (process-local override),
    then the spawn-time ``FALCON_SHADOW_AI_BANNED_GROUP_ID`` env. The override
    path makes a same-turn adopt -> re-diagnose read the freshly-saved id.
    """
    host_group_id = resolve_group_id("shadow_ai_banned", host_group_id)

    if not host_group_id:
        return {
            "ok": True,
            "case": "no_group_id",
            "host_group_id": None,
            "host_group": None,
            "policies": [],
            "rule_group_attached": False,
            "recommended_action": {
                "tool": "extras_create_shadow_ai_banned_host_group",
                "args": {"name": CANONICAL_GROUP_NAME},
                "label": "Create the Shadow-AI Banned host group",
                "description": (
                    f"Creates a new static host group named '{CANONICAL_GROUP_NAME}'. "
                    "After creation, save the returned id as the Shadow-AI banned "
                    "group on the active environment, then run "
                    "extras_provision_shadow_ai_banned_policy to attach the "
                    "prevention policies + Shadow-AI rule group."
                ),
            },
        }

    # 1. Verify host group exists.
    try:
        hg = _get_host_group_client()
        hg_resp = hg.get_host_groups(ids=[host_group_id])
        guard = _check_response(hg_resp, "HostGroup")
        if guard:
            # A 404 here means the configured group id doesn't exist —
            # same operator-recoverable case as "0 records" below.
            # Reclassify so the card shows the friendly CTA instead of
            # a raw upstream error.
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
            "rule_group_attached": False,
            "recommended_action": {
                "tool": "extras_create_shadow_ai_banned_host_group",
                "args": {"name": CANONICAL_GROUP_NAME},
                "label": "Create the Shadow-AI Banned host group",
                "description": (
                    f"The configured group id {host_group_id!r} does not "
                    "exist in this tenant. Create a fresh group and update "
                    "the Shadow-AI banned field with the new id."
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

    # Pre-fetch the per-platform rule groups by name and count the rules
    # in each. The rule-group object embedded inside the prevention
    # policy's `ioa_rule_groups[]` list is a SUMMARY that doesn't carry
    # the full rules array — reading `.rules` off that view always
    # returns 0/empty regardless of actual coverage. Use the Custom IOA
    # client for ground truth.
    from .tools import _find_shadow_ai_rule_group, _get_custom_ioa_client
    rule_group_rule_counts: dict[str, int] = {}
    rule_group_rule_names: dict[str, set[str]] = {}
    try:
        ioa_client = _get_custom_ioa_client()
        for plat in PLATFORMS:
            rg, rg_err = _find_shadow_ai_rule_group(ioa_client, plat)
            if rg_err is not None or rg is None:
                continue
            rg_name = rg.get("name")
            if not rg_name:
                continue
            names = {
                r.get("name") for r in (rg.get("rules") or [])
                if isinstance(r, dict) and r.get("name")
            }
            rule_group_rule_counts[rg_name] = len(names)
            rule_group_rule_names[rg_name] = names
    except Exception:  # noqa: BLE001
        # Non-fatal — leave counts empty; per-policy view will fall back
        # to "unknown" rather than misreport 0.
        pass

    policies_on_group: list[dict[str, Any]] = []
    rule_group_attached_anywhere = False
    for p in all_policies:
        if not isinstance(p, dict):
            continue
        groups = p.get("groups") or []
        attached_group_ids = [g.get("id") for g in groups if isinstance(g, dict)]
        if host_group_id not in attached_group_ids:
            continue
        # Each platform's policy should bind its OWN rule group — Falcon
        # rejects cross-platform binds, so we check the matching name.
        platform_lower = (p.get("platform_name") or "").lower()
        expected_rg_name = SHADOW_AI_RULE_GROUP_NAMES.get(platform_lower)
        ioa_groups = p.get("ioa_rule_groups") or []
        bound_rg = next(
            (rg for rg in ioa_groups
             if isinstance(rg, dict) and rg.get("name") == expected_rg_name),
            None,
        ) if expected_rg_name else None
        rule_group_bound = bound_rg is not None
        # Also verify the bound rule group contains every rule from the
        # per-platform corpus. The previous adoption run might have
        # bound the group but failed to author some rules (regex-engine
        # rejection, name-length, etc.); in that case the binding
        # check passes but enforcement coverage is incomplete.
        # NOTE: rule counts come from the pre-fetched rule_group_rule_names
        # map (populated via _find_shadow_ai_rule_group) — the rule-group
        # object embedded in the policy's ioa_rule_groups[] doesn't carry
        # the full rules array.
        rules_in_group = 0
        rules_expected = len(CORPUS_BY_PLATFORM.get(platform_lower, []))
        rules_missing: list[str] = []
        if bound_rg is not None and expected_rg_name in rule_group_rule_names:
            existing_rule_names = rule_group_rule_names[expected_rg_name]
            rules_in_group = len(existing_rule_names)
            for rule in CORPUS_BY_PLATFORM.get(platform_lower, []):
                if rule.name not in existing_rule_names:
                    rules_missing.append(rule.name)
        if rule_group_bound:
            rule_group_attached_anywhere = True
        managed = isinstance(p.get("name"), str) and p["name"].startswith(CANONICAL_POLICY_PREFIX)
        policies_on_group.append({
            "id": p.get("id"),
            "name": p.get("name"),
            "platform": p.get("platform_name"),
            "enabled": bool(p.get("enabled", True)),
            "attached_group_ids": attached_group_ids,
            "is_dedicated": len(attached_group_ids) == 1,
            "managed_by_eyas": managed,
            "rule_group_bound": rule_group_bound,
            "rules_in_group": rules_in_group,
            "rules_expected": rules_expected,
            "rules_missing": rules_missing,
        })

    # 3. Classify case.
    if not policies_on_group:
        case = "A_no_policy"
        recommendation = _recommend_provision(host_group_id, "adopt")
    else:
        any_shared = any(not p["is_dedicated"] for p in policies_on_group)
        all_dedicated_managed_bound = (
            all(p["managed_by_eyas"] for p in policies_on_group)
            and all(p["rule_group_bound"] for p in policies_on_group)
        )
        any_corpus_drift = any(
            p["rules_missing"] for p in policies_on_group
        )
        if all_dedicated_managed_bound and not any_corpus_drift:
            case = "ready"
            recommendation = None
        elif all_dedicated_managed_bound and any_corpus_drift:
            # Policies + bindings are correct, but the rule corpus has
            # drifted from what's actually in the rule groups (a prior
            # adoption run failed to author some rules). Recommend
            # re-running adopt_prevention per affected platform.
            case = "rules_incomplete"
            recommendation = _recommend_corpus_refresh(policies_on_group)
        elif any_shared:
            case = "C_shared_policy"
            recommendation = _recommend_provision(host_group_id, "create_dedicated")
        else:
            case = "B_dedicated_single_group"
            recommendation = _recommend_provision(host_group_id, "adopt")

    return {
        "ok": True,
        "case": case,
        "host_group_id": host_group_id,
        "host_group": group_summary,
        "policies": policies_on_group,
        "rule_group_attached": rule_group_attached_anywhere,
        "recommended_action": recommendation,
    }


def _recommend_corpus_refresh(policies_on_group: list[dict[str, Any]]) -> dict[str, Any]:
    """When per-platform rule groups exist + are bound but some rules
    from the corpus didn't make it into the group (e.g. a prior adoption
    run hit per-rule errors before completing), the diagnostic surfaces
    a `rules_incomplete` case and this recommendation tells the caller
    which platforms need an `extras_shadow_ai_adopt_prevention` re-run.

    Returns a multi-call shape so the /config UI can render a single
    button that fires N primers (one per affected platform).
    """
    affected = [
        p for p in policies_on_group if p.get("rules_missing")
    ]
    platforms = ", ".join(
        f"{(p.get('platform') or '?').lower()} ({len(p.get('rules_missing') or [])} missing)"
        for p in affected
    )
    follow_up_calls = [
        {
            "tool": "extras_shadow_ai_adopt_prevention",
            "args": {
                "prevention_policy_id": p["id"],
                "comment": (
                    f"Project Eyas - Shadow-AI rule corpus refresh "
                    f"({(p.get('platform') or '?').lower()}) - filling "
                    f"{len(p.get('rules_missing') or [])} rule(s) missing "
                    "from a prior adoption run."
                ),
                "mode": "block",
                "platform": (p.get("platform") or "").lower(),
            },
            "platform": (p.get("platform") or "").lower(),
            "missing_rules": p.get("rules_missing"),
        }
        for p in affected
    ]
    return {
        "tool": "extras_shadow_ai_adopt_prevention",
        "args": {},  # multi-call shape — caller iterates follow_up_calls
        "label": "Refresh Shadow-AI rule corpus (incomplete coverage)",
        "description": (
            "The rule groups are bound, but some rules from the per-platform "
            f"corpus aren't actually in the rule groups: {platforms}. The "
            "previous adoption run authored a partial set; re-running "
            "extras_shadow_ai_adopt_prevention per affected platform fills "
            "in the missing rules (idempotent — already-present rules are "
            "skipped by name)."
        ),
        "follow_up_tool_calls": follow_up_calls,
    }


def _recommend_provision(host_group_id: str, mode: str) -> dict[str, Any]:
    if mode == "adopt":
        label = "Provision the Shadow-AI Banned prevention policy (adopt + standardize)"
        description = (
            "Adopts the policy currently bound to this group (or attaches a "
            "fresh one if none exists), renames it to canonical naming, "
            f"pushes {TARGET_LEVEL} prevention sliders, and attaches the "
            f"'{SHADOW_AI_RULE_GROUP_NAME}' Custom IOA rule group. Sets "
            "per-platform precedence above standard policies but below IR "
            "Quarantine. Per platform: Windows, macOS, Linux."
        )
    else:  # create_dedicated
        label = "Create dedicated prevention policies for Shadow-AI Banned"
        description = (
            "Your existing policy is attached to other host groups, so "
            f"pushing {TARGET_LEVEL} settings + the Shadow-AI rule group "
            "to it would change posture on those groups too. This action "
            "creates a new dedicated prevention policy per platform bound "
            "ONLY to the Shadow-AI Banned group, leaves the existing policy "
            "alone, and attaches the rule group + sets precedence."
        )
    return {
        "tool": "extras_provision_shadow_ai_banned_policy",
        "args": {"host_group_id": host_group_id, "mode": mode},
        "label": label,
        "description": description,
    }


# ---------------------------------------------------------------------------
# Create host group
# ---------------------------------------------------------------------------


def create_shadow_ai_banned_host_group(
    name: str = CANONICAL_GROUP_NAME,
    description: str | None = None,
) -> dict[str, Any]:
    """Write. Creates a new STATIC host group. Returns the new id."""
    if not name or not isinstance(name, str):
        return {"ok": False, "error": "name is required"}
    desc = description or (
        "App-managed: hosts placed here are blocked from installing or "
        "running unsanctioned AI tools (Claude Desktop, Cursor, Ollama, "
        "LM Studio, etc.). The Shadow-AI Custom IOA rule group is attached "
        "to the prevention policy bound to this group; default-allow remains "
        "the tenant baseline."
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
        set_runtime_group_id("shadow_ai_banned", rec.get("id"))
        return {
            "ok": True,
            "id": rec.get("id"),
            "name": rec.get("name"),
            "group_type": rec.get("group_type"),
            "next_step": (
                "The new group id is saved to the active environment "
                "automatically — no manual step is needed. Proceed directly to "
                "extras_provision_shadow_ai_banned_policy with this host_group_id."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


def adopt_shadow_ai_banned_host_group(
    name: str = CANONICAL_GROUP_NAME,
) -> dict[str, Any]:
    """Find an existing host group by exact name and return its id so the
    chat auto-save hook can persist it as the active env's Shadow-AI
    banned group. Read against Falcon, but the result write to settings
    is the reason this is approval-gated."""
    if not name or not isinstance(name, str):
        return {"ok": False, "error": "name is required"}
    try:
        hg = _get_host_group_client()
        # Walk all groups + match client-side. The FQL `name:'...'` filter on
        # query_combined_host_groups is unreliable for canonical names with
        # spaces+hyphens; mirrors the IR-quarantine adopt path.
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
                "hint": "use extras_create_shadow_ai_banned_host_group to create it",
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
        set_runtime_group_id("shadow_ai_banned", rec.get("id"))
        return {
            "ok": True,
            "id": rec.get("id"),
            "name": rec.get("name"),
            "group_type": rec.get("group_type"),
            "next_step": "Saved as the active environment's Shadow-AI banned group.",
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


# ---------------------------------------------------------------------------
# Provision prevention policy + rule-group attachment + precedence
# ---------------------------------------------------------------------------


def provision_shadow_ai_banned_policy(
    host_group_id: str,
    mode: str = "adopt",
) -> dict[str, Any]:
    """Write. Per-platform: provision a prevention policy bound to the
    Shadow-AI Banned group, attach the Shadow-AI rule group, push
    AGGRESSIVE sliders + enabled toggles, set precedence above standard
    but below IR Quarantine.

    The Shadow-AI rule group itself is created/refreshed via
    ``extras_shadow_ai_adopt_prevention`` separately — this tool calls
    that helper for each provisioned policy id, so the operator gets
    one approval for the policy provisioning and one approval per policy
    for the rule-group adoption (the existing rule-group tool's gate).
    """
    # Reuse the IR provisioning helpers — the slider push, policy
    # creation, attach, and precedence-setting code is identical.
    from ir.provision_quarantine import (
        _create_policy_and_attach,
        _rename_policy,
        _push_max_protective_settings,
        _set_to_highest_precedence,
    )

    if not host_group_id or not isinstance(host_group_id, str):
        return {"ok": False, "error": "host_group_id is required"}
    if mode not in ("adopt", "create_dedicated"):
        return {"ok": False, "error": f"unknown mode {mode!r}"}

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
    banned_policy_ids_by_platform: dict[str, str] = {}

    for platform in PLATFORMS:
        target_name = f"{CANONICAL_POLICY_PREFIX}, {platform})"
        existing = per_platform_existing[platform]

        chosen: dict[str, Any] | None = None
        if mode == "adopt" and existing:
            single = [e for e in existing if len(e["attached_ids"]) == 1]
            chosen = (single or existing)[0]

        if chosen is None:
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
        banned_policy_ids_by_platform[platform] = policy_id

    # Precedence: push the Shadow-AI Banned policies above standard, but
    # the IR Quarantine policies (if they exist) should remain higher.
    # Strategy: query existing all_policies, find any IR Quarantine
    # policies per platform, and order [IR..., Banned..., others...] —
    # IR first when present, Banned second, the rest in their original
    # relative order.
    for platform, policy_id in banned_policy_ids_by_platform.items():
        prec_result = _set_banned_precedence(prev, policy_id, platform, all_policies)
        if not prec_result.get("ok"):
            errors.append({"platform": platform, "stage": "set_precedence", **prec_result})
            actions.append({
                "platform": platform,
                "step": "set_precedence",
                "policy_id": policy_id,
                "ok": False,
                "warning": (
                    "Precedence not set — Shadow-AI rules may not enforce "
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
            "rank": "above_standard_below_ir",
            "policies_in_order": prec_result.get("policies_in_order"),
        })

    # Attach the Shadow-AI rule group to each provisioned policy. The
    # rule-group authoring + binding goes through extras_shadow_ai_adopt_prevention
    # (its own approval gate); the operator runs that per-policy after
    # this provisioning step. Surfaced as follow_up_tool_calls in the
    # response so the agent / UI can compose them.
    follow_up_calls: list[dict[str, Any]] = []
    for platform, policy_id in banned_policy_ids_by_platform.items():
        follow_up_calls.append({
            "tool": "extras_shadow_ai_adopt_prevention",
            "args": {
                "prevention_policy_id": policy_id,
                "comment": (
                    f"Project Eyas - Shadow-AI Banned ({platform}) - "
                    "auto-provisioned. Authors / refreshes the "
                    "per-platform rule group and binds to this policy."
                ),
                "mode": "block",
                "platform": platform,
            },
            "platform": platform,
        })

    return {
        "ok": len(errors) == 0,
        "host_group_id": host_group_id,
        "mode": mode,
        "actions": actions,
        "errors": errors,
        "follow_up_tool_calls": follow_up_calls,
    }


def _set_banned_precedence(
    prev_client,
    target_policy_id: str,
    platform: str,
    all_policies: list[dict[str, Any]],
) -> dict[str, Any]:
    """Reorder per-platform prevention policies so IR Quarantine (if any)
    stays first, the Shadow-AI Banned policy slots in second, and the
    rest preserve their relative order.

    Mirrors ir.provision_quarantine._set_to_highest_precedence's shape
    but with a more deliberate ordering.
    """
    api_platform = {"windows": "Windows", "mac": "Mac", "linux": "Linux"}.get(
        platform, platform.capitalize()
    )

    ir_policy_ids: list[str] = []
    others: list[str] = []
    target_seen = False
    for p in all_policies:
        if not isinstance(p, dict):
            continue
        if (p.get("platform_name") or "").lower() != platform:
            continue
        if p.get("name") == "platform_default":
            continue
        pid = p.get("id")
        if not pid:
            continue
        name = p.get("name") or ""
        if pid == target_policy_id:
            target_seen = True
            continue
        if name.startswith("Project Eyas - IR Quarantine (auto"):
            ir_policy_ids.append(pid)
            continue
        others.append(pid)
    if not target_seen:
        # Just-created policy isn't in the cached snapshot — that's fine,
        # we'll prepend it after IR.
        pass
    ordered = [*ir_policy_ids, target_policy_id, *others]

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

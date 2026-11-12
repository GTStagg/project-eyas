"""Shadow-AI prevention adoption tools (the hunting tools run in Eyas,
lib/eyas-tools/shadow-ai/). ``@mcp.tool()`` wrappers in server.py delegate
here.
"""

from __future__ import annotations

import re
import time
from typing import Any

from falcon_helpers import (
    _check_response,
    _falcon_kwargs,
    _get_prevention_client,
    resolve_group_id,
)
from falcon_helpers import swallow_exc
from falconpy import CustomIOA

from shadow_ai import (
    DISPOSITION_BLOCK,
    DISPOSITION_DETECT,
    SHADOW_AI_RULE_CORPUS,
    SHADOW_AI_RULE_GROUP_DESCRIPTION,
)


def _get_custom_ioa_client() -> CustomIOA:
    return CustomIOA(**_falcon_kwargs())


# Rename for use inside this module (prevention helpers below pull from
# falcon_helpers but the prevention-policy client builder lives in
# server.py; we re-import lazily from there inside the binding-check tool
# so we don't pull a circular dep at module import time).


def _resolve_windows_process_creation_ruletype_id(
    client: CustomIOA,
) -> tuple[str | None, dict[str, Any] | None]:
    """Backward-compat alias — resolves the Windows Process Creation
    ruletype id. Use ``_resolve_process_creation_ruletype_id`` for
    per-platform resolution.
    """
    return _resolve_process_creation_ruletype_id(client, "windows")


def _resolve_process_creation_ruletype_id(
    client: CustomIOA,
    platform: str,
) -> tuple[str | None, dict[str, Any] | None]:
    """Find the Custom IOA Process Creation ruletype_id for the named
    platform (windows / mac / linux).

    Rule type IDs are deterministic per Falcon platform deployment but
    not constant across tenants. Discover at adoption time.

    Returns (ruletype_id, error_payload). Exactly one is non-None.
    """
    target_platform = platform.lower()
    q = client.query_rule_types(limit=500)
    guard = _check_response(q, "CustomIOA")
    if guard is not None:
        return None, guard
    ids = ((q or {}).get("body") or {}).get("resources") or []
    if not ids:
        return None, {"ok": False, "error": "no Custom IOA rule types returned"}
    d = client.get_rule_types(ids=ids)
    guard = _check_response(d, "CustomIOA")
    if guard is not None:
        return None, guard
    types = ((d or {}).get("body") or {}).get("resources") or []
    for t in types:
        if not isinstance(t, dict):
            continue
        plat = (t.get("platform") or "").lower()
        name = (t.get("name") or "").lower()
        if plat == target_platform and "process creation" in name:
            return str(t.get("id")), None
    return None, {
        "ok": False,
        "error": f"{target_platform} Process Creation rule type not found in tenant",
        "available_types": [
            f"{tt.get('platform')}: {tt.get('name')}" for tt in types if isinstance(tt, dict)
        ],
    }




def _find_shadow_ai_rule_group(
    client: CustomIOA,
    platform: str = "windows",
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Look up the Shadow-AI rule group by name for the named platform.
    Returns (group_record, error). group_record is None if not found
    and there's no error.
    """
    from .ioa_rules import SHADOW_AI_RULE_GROUP_NAMES
    name = SHADOW_AI_RULE_GROUP_NAMES.get(platform.lower())
    if not name:
        return None, {"ok": False, "error": f"unknown platform {platform!r}"}
    q = client.query_rule_groupsMixin0(filter=f"name:'{name}'", limit=10)
    guard = _check_response(q, "CustomIOA")
    if guard is not None:
        return None, guard
    ids = ((q or {}).get("body") or {}).get("resources") or []
    if not ids:
        return None, None
    d = client.get_rule_groupsMixin0(ids=ids)
    guard = _check_response(d, "CustomIOA")
    if guard is not None:
        return None, guard
    records = ((d or {}).get("body") or {}).get("resources") or []
    for r in records:
        if isinstance(r, dict) and r.get("name") == name:
            return r, None
    return None, None


def _platform_rule_group_status(
    client: CustomIOA, platform: str
) -> dict[str, Any] | tuple[None, dict[str, Any]]:
    """Live rule-group state for ONE platform. Returns the per-platform
    summary dict, or (None, error) if the lookup faulted."""
    from .ioa_rules import SHADOW_AI_RULE_GROUP_NAMES, rule_corpus_summary_for_platform

    corpus = rule_corpus_summary_for_platform(platform)
    corpus_names = [r["name"] for r in corpus]
    rg_name = SHADOW_AI_RULE_GROUP_NAMES[platform]
    group, err = _find_shadow_ai_rule_group(client, platform)
    if err is not None:
        return None, err
    if group is None:
        return {
            "platform": platform,
            "rule_group_exists": False,
            "rule_group_name": rg_name,
            "rule_group_id": None,
            "rule_group_enabled": None,
            "installed_rules": [],
            "installed_rule_count": 0,
            "missing_rules": corpus_names,
            "corpus_count": len(corpus),
            "corpus": corpus,
        }
    rules = group.get("rules") or []
    installed = [r.get("name") for r in rules if isinstance(r, dict)]
    missing = [n for n in corpus_names if n not in installed]
    return {
        "platform": platform,
        "rule_group_exists": True,
        "rule_group_id": group.get("id"),
        "rule_group_name": group.get("name"),
        "rule_group_enabled": group.get("enabled"),
        "rule_group_version": group.get("version"),
        "rule_group_platform": group.get("platform"),
        "installed_rule_count": len(installed),
        "installed_rules": installed,
        "missing_rules": missing,
        "corpus_count": len(corpus),
        "corpus": corpus,
    }


# Keys hoisted to the top level from the Windows platform for backward
# compatibility with app/api/shadow-ai/setup/route.ts (which reads the
# Windows-shaped rule-group summary). Per-platform truth is in platforms[].
_STATUS_HOIST_KEYS = (
    "rule_group_exists",
    "rule_group_id",
    "rule_group_name",
    "rule_group_enabled",
    "installed_rules",
    "installed_rule_count",
    "missing_rules",
    "corpus_count",
    "corpus",
)


def shadow_ai_prevention_status() -> dict[str, Any]:
    """Report Shadow-AI prevention deployment state across ALL platforms
    (Windows / macOS / Linux). READ-ONLY.

    For each platform returns the per-platform corpus the adoption tool
    would author plus the live rule-group state (id, enabled flag,
    installed vs missing rules). `platforms[]` carries every platform;
    top-level keys mirror the Windows platform for backward compatibility
    with the setup card. Does NOT read prevention-policy bindings — see
    `extras_shadow_ai_check_prevention_binding` for that.
    """
    from .ioa_rules import SHADOW_AI_RULE_GROUP_NAMES

    try:
        client = _get_custom_ioa_client()
        platforms_out: list[dict[str, Any]] = []
        for plat in SHADOW_AI_RULE_GROUP_NAMES:  # windows, mac, linux
            result = _platform_rule_group_status(client, plat)
            if isinstance(result, tuple):  # (None, error)
                return result[1]
            platforms_out.append(result)

        win = next(
            (p for p in platforms_out if p["platform"] == "windows"),
            platforms_out[0],
        )
        out: dict[str, Any] = {
            "ok": True,
            "platforms": platforms_out,
            "any_rule_group_exists": any(p["rule_group_exists"] for p in platforms_out),
        }
        for k in _STATUS_HOIST_KEYS:
            out[k] = win.get(k)
        if not win["rule_group_exists"]:
            out["note"] = (
                "No Windows rule group with this name exists yet. Run "
                '`extras_shadow_ai_adopt_prevention` (platform="windows") to '
                "create it. See platforms[] for macOS / Linux state."
            )
        return out
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)




def shadow_ai_check_prevention_binding() -> dict[str, Any]:
    """Diagnose whether the Shadow-AI Custom IOA rule group is actually
    enforcing on hosts moved into the AI-Banned host group. READ-ONLY.

    The Ban+Clean workflow only succeeds end-to-end when:
      1. FALCON_SHADOW_AI_BANNED_GROUP_ID is set on the active env.
      2. The host group exists in Falcon.
      3. At least one Prevention Policy is attached to that host group.
      4. The Shadow-AI rule group ("Project Eyas - Shadow-AI Block") is
         bound to one of those policies AND the policy is enabled.
      5. The rule group itself is enabled.

    Operators routinely miss step 4 — `extras_shadow_ai_adopt_prevention`
    only binds the rule group to ONE prevention policy id passed in by
    the operator; it doesn't verify that policy is the one actually
    attached to the AI-Banned host group. This tool walks the live state
    and reports exactly which step is broken so the operator can fix it
    in console (FalconPy doesn't expose policy-to-host-group attachment
    as a write — that's a console step).

    Platform-aware: Falcon rejects cross-platform IOA binds, so each
    attached policy is checked against ITS OWN platform's rule group
    (`Project Eyas - Shadow-AI Block` / `... (mac)` / `... (linux)`),
    not the Windows group alone. A correctly-bound macOS or Linux policy
    no longer reports as broken.

    Returns:
        ok: bool
        ready: bool — true when at least one platform is fully enforcing
            and no enabled attached policy is left unbound
        banned_group_id: str | None
        rule_groups: list[{platform, name, id, exists, enabled}]
        attached_policies: list[{id, name, platform, enabled,
            rule_group_bound, rule_group_name, rule_group_exists,
            rule_group_enabled}]
        missing_steps: list[str] — operator-facing remediation steps,
            prefixed with the platform they apply to
        (rule_group_name / _id / _exists / _enabled are also hoisted to
        the top level from the Windows platform for backward compat.)
    """
    from .ioa_rules import SHADOW_AI_RULE_GROUP_NAMES

    try:
        # Override-aware: a group adopted/created earlier this turn is honored
        # before the (frozen) spawn-time env var.
        banned_group_id = resolve_group_id("shadow_ai_banned") or ""
        if not banned_group_id:
            return {
                "ok": True,
                "ready": False,
                "banned_group_id": None,
                "missing_steps": [
                    'Set the "Shadow-AI banned host group" field on the active '
                    "environment in /config (Environments manager) — without "
                    "it Ban+Clean has nowhere to move hosts."
                ],
            }

        # Steps 2 + 5: per-platform rule group state. Each platform binds
        # its OWN rule group (Falcon rejects cross-platform binds).
        ioa_client = _get_custom_ioa_client()
        rg_by_platform: dict[str, dict[str, Any]] = {}
        for plat, rg_name in SHADOW_AI_RULE_GROUP_NAMES.items():
            group, err = _find_shadow_ai_rule_group(ioa_client, plat)
            if err is not None:
                return err
            rg_by_platform[plat] = {
                "platform": plat,
                "name": rg_name,
                "id": group.get("id") if group else None,
                "exists": group is not None,
                "enabled": bool(group.get("enabled")) if group else False,
            }

        # Steps 3 + 4: walk every prevention policy, find the ones attached
        # to the banned host group, and check whether each carries ITS
        # platform's rule group.
        prev_client = _get_prevention_client()
        resp = prev_client.query_combined_policies(parameters={"limit": 200})
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return guard
        policies = ((resp or {}).get("body") or {}).get("resources") or []

        attached: list[dict[str, Any]] = []
        for p in policies:
            if not isinstance(p, dict):
                continue
            groups = p.get("groups") or []
            in_banned = any(
                isinstance(g, dict) and g.get("id") == banned_group_id for g in groups
            )
            if not in_banned:
                continue
            plat = (p.get("platform_name") or "").lower()
            rg = rg_by_platform.get(plat)
            expected_rg_name = rg["name"] if rg else SHADOW_AI_RULE_GROUP_NAMES.get(plat)
            expected_rg_id = rg["id"] if rg else None
            ioa_groups = p.get("ioa_rule_groups") or []
            bound = any(
                isinstance(rgi, dict)
                and (
                    (expected_rg_id is not None and rgi.get("id") == expected_rg_id)
                    or (expected_rg_name is not None and rgi.get("name") == expected_rg_name)
                )
                for rgi in ioa_groups
            )
            attached.append(
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "platform": p.get("platform_name"),
                    "enabled": bool(p.get("enabled", True)),
                    "rule_group_bound": bound,
                    "rule_group_name": expected_rg_name,
                    "rule_group_exists": bool(rg["exists"]) if rg else False,
                    "rule_group_enabled": bool(rg["enabled"]) if rg else False,
                }
            )

        missing: list[str] = []
        if not attached:
            missing.append(
                f"No Prevention Policy is attached to host group "
                f"{banned_group_id}. In Falcon Console, edit the AI-Banned "
                "host group's prevention policy assignment to attach a policy "
                "(per platform) whose Custom IOA Rule Groups include the "
                "matching 'Project Eyas - Shadow-AI Block' group."
            )
        else:
            platforms_in_play = sorted(
                {(p["platform"] or "").lower() for p in attached if p["platform"]}
            )
            for plat in platforms_in_play:
                rg = rg_by_platform.get(plat) or {}
                rg_name = rg.get("name") or SHADOW_AI_RULE_GROUP_NAMES.get(plat, plat)
                plat_policies = [p for p in attached if (p["platform"] or "").lower() == plat]
                if not rg.get("exists"):
                    missing.append(
                        f"[{plat}] Run extras_shadow_ai_adopt_prevention("
                        f'platform="{plat}") to create the \'{rg_name}\' rule group.'
                    )
                    continue
                if not rg.get("enabled"):
                    missing.append(
                        f"[{plat}] Enable the '{rg_name}' rule group in Falcon "
                        "Console (Endpoint Security → Custom IOA Rule Groups)."
                    )
                enabled_unbound = [
                    p for p in plat_policies if p["enabled"] and not p["rule_group_bound"]
                ]
                if enabled_unbound:
                    names = ", ".join(p["name"] or p["id"] for p in enabled_unbound)
                    missing.append(
                        f"[{plat}] '{rg_name}' is not bound to the attached {plat} "
                        f"prevention policy ({names}). Re-run "
                        "extras_shadow_ai_adopt_prevention with the prevention_policy_id "
                        f'of that policy and platform="{plat}", or bind it via console.'
                    )
                disabled_with_bind = [
                    p for p in plat_policies if p["rule_group_bound"] and not p["enabled"]
                ]
                if disabled_with_bind:
                    names = ", ".join(p["name"] or p["id"] for p in disabled_with_bind)
                    missing.append(
                        f"[{plat}] Rule group is bound, but the prevention policy "
                        f"carrying it is disabled: {names}."
                    )

        # ready: at least one platform fully enforcing (enabled policy +
        # bound + that platform's rule group enabled), and no enabled
        # attached policy left unbound on any platform.
        enforcing = [
            p
            for p in attached
            if p["enabled"] and p["rule_group_bound"] and p["rule_group_enabled"]
        ]
        enabled_unbound_any = [
            p for p in attached if p["enabled"] and not p["rule_group_bound"]
        ]
        ready = bool(enforcing) and not enabled_unbound_any

        # Backward-compat top-level summary (Windows representative for the
        # legacy single-line audit UI; per-platform truth is in rule_groups[]).
        win_rg = rg_by_platform.get("windows", {})
        return {
            "ok": True,
            "ready": ready,
            "banned_group_id": banned_group_id,
            "rule_groups": list(rg_by_platform.values()),
            "rule_group_name": win_rg.get("name"),
            "rule_group_id": win_rg.get("id"),
            "rule_group_exists": win_rg.get("exists", False),
            "rule_group_enabled": win_rg.get("enabled", False),
            "attached_policies": attached,
            "missing_steps": missing,
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)




def shadow_ai_adopt_prevention(
    prevention_policy_id: str,
    comment: str,
    mode: str = "block",
    dry_run: bool = False,
    platform: str = "windows",
) -> dict[str, Any]:
    """Author the Shadow-AI Custom IOA rule bundle and bind it to a
    Prevention Policy. WRITE ACTION — requires explicit user approval.

    Idempotent: looking up the per-platform rule group by name reuses
    an existing one, and per-rule dedup runs by rule name. Rerunning
    after a corpus change appends only the missing rules; no existing
    rule is modified (operator console edits are preserved).

    Args:
        prevention_policy_id: The Prevention Policy id to bind the rule
            group to. Must match the platform of the rule group —
            Falcon rejects cross-platform binds.
        comment: Required free-text reason. Recorded in Falcon Console's
            change ledger for audit.
        mode: 'block' (disposition_id=30, "Block Execution" — prevents the
            process from running; the default) or 'detect' (disposition_id=
            20, raises a detection only). Rules are created AND enabled
            (Falcon creates Custom IOA rules disabled, so the tool flips
            them on via update_rules). On re-run, existing managed rules
            CONVERGE to the chosen enabled+disposition state — re-running
            with a different mode actually re-dispositions them, and a
            previously-broken (disabled) ruleset is repaired in place.
        dry_run: When true, returns the rendered create_rule payloads
            without making any write calls.
        platform: 'windows' / 'mac' / 'linux'. Selects the per-platform
            rule corpus, ruletype, and rule group name. Default
            'windows' for backward-compat with existing callers.
    """
    from .ioa_rules import (
        CORPUS_BY_PLATFORM,
        SHADOW_AI_RULE_GROUP_NAMES,
    )

    if not prevention_policy_id or not isinstance(prevention_policy_id, str):
        return {"ok": False, "error": "prevention_policy_id is required"}
    if not comment or not isinstance(comment, str):
        return {
            "ok": False,
            "error": "comment is required — recorded in Falcon Console change ledger",
        }
    mode_norm = (mode or "").strip().lower()
    if mode_norm not in ("detect", "block"):
        return {
            "ok": False,
            "error": f"mode must be 'detect' or 'block', got {mode!r}",
        }
    platform_norm = (platform or "").strip().lower()
    if platform_norm not in CORPUS_BY_PLATFORM:
        return {
            "ok": False,
            "error": f"platform must be 'windows' / 'mac' / 'linux', got {platform!r}",
        }
    rule_group_name = SHADOW_AI_RULE_GROUP_NAMES[platform_norm]
    corpus = CORPUS_BY_PLATFORM[platform_norm]
    disposition_id = DISPOSITION_BLOCK if mode_norm == "block" else DISPOSITION_DETECT
    # Falcon's Custom IOA API rejects HTTP 400 on any control character
    # (newline, tab, etc.) inside the `comment` field. Sanitize at the
    # boundary so it can't happen regardless of how the operator's
    # comment got assembled (chat-model formatting, terminal wrapping,
    # primer interpolation across line breaks).
    import re as _re
    comment = _re.sub(r"[\x00-\x1f\x7f]+", " ", comment)
    comment = _re.sub(r"\s+", " ", comment).strip()

    try:
        client = _get_custom_ioa_client()

        ruletype_id, err = _resolve_process_creation_ruletype_id(client, platform_norm)
        if err is not None:
            return err

        rendered_rules = [
            {
                "name": r.name,
                "description": r.description,
                "pattern_severity": r.pattern_severity,
                "ruletype_id": ruletype_id,
                "disposition_id": disposition_id,
                "field_values": r.to_field_values(),
                "comment": f"{comment} [{r.rationale_tag}]",
            }
            for r in corpus
        ]

        # Shared converge predicate: a managed rule is "correct" only when it
        # is BOTH enabled AND at the requested disposition. Falcon creates
        # Custom IOA rules DISABLED, and a prior run may have left them at a
        # different disposition, so adoption must converge both.
        def _needs_converge(live_rule: dict[str, Any]) -> bool:
            return (
                not bool(live_rule.get("enabled"))
                or live_rule.get("disposition_id") != disposition_id
            )

        corpus_names = {r["name"] for r in rendered_rules}

        if dry_run:
            # Read-only: report what a live run WOULD do against current state.
            group, err = _find_shadow_ai_rule_group(client, platform_norm)
            if err is not None:
                return err
            live_rules = (group.get("rules") or []) if group else []
            live_by_name = {
                r.get("name"): r for r in live_rules if isinstance(r, dict)
            }
            would_create = [n for n in corpus_names if n not in live_by_name]
            would_converge = [
                {
                    "name": r.get("name"),
                    "from": {
                        "enabled": bool(r.get("enabled")),
                        "disposition_id": r.get("disposition_id"),
                    },
                    "to": {"enabled": True, "disposition_id": disposition_id},
                }
                for n, r in live_by_name.items()
                if n in corpus_names and _needs_converge(r)
            ]
            already_correct = [
                n
                for n, r in live_by_name.items()
                if n in corpus_names and not _needs_converge(r)
            ]
            return {
                "ok": True,
                "dry_run": True,
                "platform": platform_norm,
                "mode": mode_norm,
                "ruletype_id": ruletype_id,
                "disposition_id": disposition_id,
                "rule_group_name": rule_group_name,
                "rule_group_exists": group is not None,
                "rule_group_enabled": bool(group.get("enabled")) if group else False,
                "rendered_rules": rendered_rules,
                "rendered_count": len(rendered_rules),
                "plan": {
                    "would_create_rules": would_create,
                    "would_enable_or_redisposition": would_converge,
                    "already_correct": already_correct,
                },
                "prevention_policy_id": prevention_policy_id,
                "note": (
                    "dry_run: no write calls were made. A live run would create "
                    "the listed rules, then set enabled=True + "
                    f"disposition_id={disposition_id} on every managed rule not "
                    "already in that state, preserving each rule's live match "
                    "patterns."
                ),
            }

        # 1. Resolve / create the rule group.
        group, err = _find_shadow_ai_rule_group(client, platform_norm)
        if err is not None:
            return err
        created_group = False
        if group is None:
            create = client.create_rule_groupMixin0(
                name=rule_group_name,
                description=SHADOW_AI_RULE_GROUP_DESCRIPTION,
                platform=platform_norm,
                comment=comment,
            )
            guard = _check_response(create, "CustomIOA")
            if guard is not None:
                return guard
            new_records = ((create or {}).get("body") or {}).get("resources") or []
            if not new_records:
                return {
                    "ok": False,
                    "error": "create_rule_group returned no record",
                    "raw": (create or {}).get("body"),
                }
            group = new_records[0]
            created_group = True

        rule_group_id = group.get("id")
        if not rule_group_id:
            return {"ok": False, "error": "rule group missing id", "raw": group}

        # 2. Create any corpus rule that doesn't exist yet (dedup by name).
        # Falcon creates Custom IOA rules DISABLED regardless of group state,
        # so create alone does NOT enforce — the enable happens in step 3 via
        # update_rules. (Skipping that step was the original bug: every rule
        # sat enabled=False forever, so the whole group was inert.)
        existing_names = {
            r.get("name") for r in (group.get("rules") or []) if isinstance(r, dict)
        }
        added: list[str] = []
        rule_errors: list[dict[str, Any]] = []
        for rule in rendered_rules:
            if rule["name"] in existing_names:
                continue
            resp = client.create_rule(
                rulegroup_id=rule_group_id,
                ruletype_id=ruletype_id,
                disposition_id=disposition_id,
                name=rule["name"],
                description=rule["description"],
                pattern_severity=rule["pattern_severity"],
                field_values=rule["field_values"],
                comment=rule["comment"],
            )
            guard = _check_response(resp, "CustomIOA")
            if guard is not None:
                rule_errors.append({"rule": rule["name"], "error": guard})
                continue
            added.append(rule["name"])

        # 3. Refetch the group (so freshly created rules carry instance_ids +
        # Falcon's auto-populated field_values), then CONVERGE every managed
        # rule to enabled=True + the requested disposition. Each rule's LIVE
        # field_values are passed straight back — they are the complete
        # server-validated set (all ruletype fields, unused ones defaulted),
        # so the GET→PATCH round-trips cleanly AND any console pattern edits
        # are preserved.
        latest_group, err = _find_shadow_ai_rule_group(client, platform_norm)
        if err is not None:
            return err
        if latest_group is None:
            return {"ok": False, "error": "rule group disappeared mid-adoption"}
        version = latest_group.get("version")
        live_rules = latest_group.get("rules") or []
        already_correct = [
            r.get("name")
            for r in live_rules
            if isinstance(r, dict)
            and r.get("name") in corpus_names
            and not _needs_converge(r)
        ]
        rule_updates: list[dict[str, Any]] = []
        for r in live_rules:
            if not isinstance(r, dict) or r.get("name") not in corpus_names:
                continue  # leave non-managed rules alone
            if not _needs_converge(r):
                continue  # already enabled at the requested disposition
            rule_updates.append(
                {
                    "instance_id": r.get("instance_id"),
                    "name": r.get("name"),
                    "description": r.get("description") or "",
                    "pattern_severity": r.get("pattern_severity") or "medium",
                    "disposition_id": disposition_id,
                    "enabled": True,
                    "field_values": r.get("field_values") or [],
                    "rulegroup_version": version,
                }
            )

        converged = [u["name"] for u in rule_updates]
        if rule_updates:
            upd_resp = client.update_rules(
                body={
                    "rulegroup_id": rule_group_id,
                    "rulegroup_version": version,
                    "comment": comment,
                    "rule_updates": rule_updates,
                }
            )
            guard = _check_response(upd_resp, "CustomIOA")
            if guard is not None:
                return {
                    "ok": False,
                    "stage": "enable_rules",
                    "rule_group_id": rule_group_id,
                    "rules_added": added,
                    "rules_to_converge": converged,
                    "rule_errors": rule_errors,
                    "error": guard,
                }
            # update_rules bumped the version; refetch for the group-enable.
            latest_group, err = _find_shadow_ai_rule_group(client, platform_norm)
            if err is not None:
                return err
            if latest_group is None:
                return {"ok": False, "error": "rule group disappeared mid-adoption"}
            version = latest_group.get("version")

        # 4. Enable the rule group itself (no-op if already enabled — Falcon
        # accepts the PATCH idempotently).
        enable_resp = client.update_rule_groupMixin0(
            id=rule_group_id,
            name=rule_group_name,
            description=SHADOW_AI_RULE_GROUP_DESCRIPTION,
            enabled=True,
            rulegroup_version=version,
            comment=comment,
        )
        guard = _check_response(enable_resp, "CustomIOA")
        if guard is not None:
            return {
                "ok": False,
                "stage": "enable_rule_group",
                "rule_group_id": rule_group_id,
                "rules_added": added,
                "rules_converged": converged,
                "rule_errors": rule_errors,
                "error": guard,
            }

        # 5. Bind to the prevention policy. add-rule-group is idempotent at
        # Falcon's side — re-attaching an already-attached rule group is a
        # 200 with no change.
        prev_client = _get_prevention_client()
        bind_resp = prev_client.perform_policies_action(
            action_name="add-rule-group",
            ids=[prevention_policy_id],
            action_parameters=[{"name": "rule_group_id", "value": rule_group_id}],
        )
        guard = _check_response(bind_resp, "PreventionPolicy")
        bind_error = guard if guard is not None else None

        action_label = "Block Execution (process kill)" if mode_norm == "block" else "Detect"
        return {
            "ok": True,
            "platform": platform_norm,
            "created_rule_group": created_group,
            "rule_group_id": rule_group_id,
            "rule_group_name": rule_group_name,
            "mode": mode_norm,
            "disposition_id": disposition_id,
            "ruletype_id": ruletype_id,
            "rules_added": added,
            "rules_converged": converged,
            "rules_already_correct": already_correct,
            "rule_errors": rule_errors,
            "prevention_policy_id": prevention_policy_id,
            "policy_bind_error": bind_error,
            "note": (
                (
                    f"Rule group enabled; {len(added)} rule(s) created, "
                    f"{len(converged)} rule(s) set to enabled + {action_label}. "
                    "Bound to the prevention policy; enforces on the next sensor "
                    "heartbeat for hosts whose policy includes this rule group."
                )
                if bind_error is None
                else (
                    "Rules enabled but policy binding failed — attach the rule "
                    "group in Falcon Console or re-run this tool. See "
                    "policy_bind_error."
                )
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)



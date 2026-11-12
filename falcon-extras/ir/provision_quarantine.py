"""Prevention-policy helpers shared by the Shadow-AI banned provisioning.

IR quarantine setup (diagnose / create / adopt / provisioning / readiness /
detach) moved into Eyas: lib/eyas-tools/quarantine.ts and
quarantine-provision.ts. What remains here is the policy plumbing that
``shadow_ai.provision_banned`` still imports — create + attach + enable,
rename, the max-protective settings push (with the grouped -> flat
settings flattening Falcon requires) and the precedence reorder. It goes
when the Shadow-AI provisioning moves.
"""

from __future__ import annotations

from typing import Any

from falcon_helpers import _check_response, swallow_exc


CANONICAL_GROUP_NAME = "Project Eyas - IR Quarantine"
CANONICAL_POLICY_PREFIX = "Project Eyas - IR Quarantine (auto"  # closed by ", <platform>)"
PLATFORMS = ("windows", "mac", "linux")
SLIDER_IDS = ("OnSensorMLSlider", "CloudAntiMalware", "AdwarePUP")
TARGET_LEVEL = "AGGRESSIVE"


# ---------------------------------------------------------------------------
# Diagnostic
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Create host group
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Provision prevention policy (per platform) + exclusion
# ---------------------------------------------------------------------------


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


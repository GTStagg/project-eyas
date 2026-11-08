"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

from typing import Any
from falcon_helpers import _check_response, _get_prevention_client
from falcon_helpers import swallow_exc

# Falcon OnSensorMLSlider / CloudAntiMalware levels treated as "off." Anything
# else (CAUTIOUS / MODERATE / AGGRESSIVE / EXTRA_AGGRESSIVE) means the knob is
# actively detecting or preventing.
_ML_SLIDER_OFF = {"DISABLED", "OFF", ""}


def _is_active(level: Any) -> bool:
    """Mlslider value is non-empty AND not a disabled state."""
    return isinstance(level, str) and level not in _ML_SLIDER_OFF


def _flag_prevention_posture(
    policy: dict[str, Any], picks: dict[str, Any]
) -> list[str]:
    """Compute posture flags for one prevention policy. Order matters — the
    dashboard renders them as chips in this sequence.

    Flag vocabulary:
      - `disabled` — `enabled: false` on the policy itself.
      - `ml_detect_only` — sensor ML is detecting but not preventing
        (OnSensorMLSlider detection active, prevention DISABLED/OFF).
      - `cloud_av_detect_only` — cloud AV is detecting but not preventing
        (CloudAntiMalware detection active, prevention DISABLED/OFF).
    """
    flags: list[str] = []
    if not policy.get("enabled", True):
        flags.append("disabled")
    if _is_active(picks.get("ml_detection")) and not _is_active(
        picks.get("ml_prevention")
    ):
        flags.append("ml_detect_only")
    if _is_active(picks.get("cloud_anti_malware_detection")) and not _is_active(
        picks.get("cloud_anti_malware_prevention")
    ):
        flags.append("cloud_av_detect_only")
    return flags


def _summarize_prevention_settings(settings: list[dict[str, Any]] | None) -> dict[str, Any]:
    """Pick a few load-bearing prevention knobs out of the verbose `settings`
    array each policy carries. The Falcon UI groups dozens of toggles per
    platform; we surface the ones that materially separate "block" from
    "detect-only" posture so the dashboard can flag underprovisioned policies
    without a wall of toggles.

    Real setting IDs (verified via direct FalconPy probe 2026-05-03):
      - OnSensorMLSlider  → ml_*  (sensor-side ML detection/prevention)
      - CloudAntiMalware  → cloud_anti_malware_*
      - AdwarePUP         → adware_*  (per-platform, skip from posture flags)
    """
    if not settings:
        return {}
    picks: dict[str, Any] = {}
    # Exact-id map. Substring matching previously missed `OnSensorMLSlider` because
    # the case ("MLSlider") didn't match the lowered "MlSlider" needle.
    id_map = {
        "OnSensorMLSlider": "ml",
        "CloudAntiMalware": "cloud_anti_malware",
        "AdwarePUP": "adware",
    }
    for s in settings:
        if not isinstance(s, dict):
            continue
        sid = s.get("id") or ""
        prefix = id_map.get(sid)
        if not prefix:
            continue
        value = s.get("value") or {}
        detection = value.get("detection")
        prevention = value.get("prevention")
        if detection is not None:
            picks[f"{prefix}_detection"] = detection
        if prevention is not None:
            picks[f"{prefix}_prevention"] = prevention
    return picks


def prevention_policy_posture(limit: int = 100) -> dict[str, Any]:
    """List prevention policies across every platform with a posture summary
    per policy. Returns:
      - per-policy: id, name, platform, enabled, description, key prevention
        settings (ML detection/prevention, AV detection/prevention, etc.),
        posture flags (disabled / ml_detect_only / cloud_av_detect_only)
      - per-platform breakdown
      - tenant-level flags

    Operator question this answers: "what do we have set to detect-only that
    should be blocking?" — escalates the no-redundant-custom-coverage idea
    from chat-time precheck to dashboard-time review.
    """
    try:
        client = _get_prevention_client()
        # Clamp to a sane range so an agent-supplied value can't 400 or over-fetch
        # (matches the clamp convention used by sibling list tools).
        limit = max(1, min(int(limit), 500))
        # No `sort` param: queryCombinedPreventionPolicies returns HTTP 500 (not
        # 400) when handed a sort field it doesn't accept — including the
        # documented `platform_name`. Sort client-side after fetch instead.
        resp = client.query_combined_policies(parameters={"limit": limit})
        guard = _check_response(resp, "Prevention Policies")
        if guard:
            return guard
        body = resp.get("body") or {}
        resources = body.get("resources") or []
        items: list[dict[str, Any]] = []
        platform_counts: dict[str, int] = {}
        detect_only_count = 0
        disabled_count = 0
        for p in resources:
            if not isinstance(p, dict):
                continue
            settings = p.get("prevention_settings") or []
            # Newer responses nest settings under groups[].settings — flatten.
            flat_settings: list[dict[str, Any]] = []
            for s in settings:
                if isinstance(s, dict):
                    inner = s.get("settings")
                    if isinstance(inner, list):
                        flat_settings.extend(x for x in inner if isinstance(x, dict))
                    else:
                        flat_settings.append(s)
            picks = _summarize_prevention_settings(flat_settings)
            flags = _flag_prevention_posture(p, picks)
            if "disabled" in flags:
                disabled_count += 1
            if any(f.endswith("_detect_only") for f in flags):
                detect_only_count += 1
            platform = p.get("platform_name") or "unknown"
            platform_counts[platform] = platform_counts.get(platform, 0) + 1
            items.append(
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "platform": platform,
                    "enabled": p.get("enabled", True),
                    "description": (p.get("description") or "")[:200],
                    "groups": [
                        {"id": g.get("id"), "name": g.get("name")}
                        for g in (p.get("groups") or [])
                        if isinstance(g, dict) and g.get("id")
                    ],
                    "settings": picks,
                    "flags": flags,
                }
            )
        # Stable client-side sort: platform, then disabled-first (worst posture
        # first within each platform), then name.
        items.sort(key=lambda x: (x["platform"], not x["enabled"], x["name"] or ""))
        return {
            "ok": True,
            "items": items,
            "count": len(items),
            "platform_counts": platform_counts,
            "summary": {
                "total": len(items),
                "disabled": disabled_count,
                "detect_only": detect_only_count,
            },
        }
    except Exception as exc:
        return swallow_exc(exc)


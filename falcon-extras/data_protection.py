"""Data Protection (DLP) configuration writes — content patterns,
classifications, and policies.

falcon-mcp 0.20.0 renamed the module Data Security and added native
generic writes (``falcon_create_data_security_entity`` /
``falcon_update_data_security_entity``), but those take an opaque entity body.
These sidecar tools (FalconPy ``DataProtectionConfiguration``) stay the agent's
create path because they apply monitor-first defaults before the write; the
native writes are suppressed at the bridge (lib/mcp/tool-bridge.ts).

The DLP configuration chain is three layers, built bottom-up:

  1. **Content pattern** — a named bundle of regexes that match sensitive
     strings (e.g. an internal project codename, a PAN format). Self-contained.
  2. **Classification** — references one or more content patterns + file
     types and carries the detection rule (severity, response action,
     monitor-vs-enforce). This is the "what counts as sensitive data" unit.
  3. **Policy** — platform-scoped (win/mac) rule set that binds
     classifications and turns inspection on. This is the enforcement unit
     that lands on hosts, ordered by precedence.

Every tool here is a WRITE ACTION and is approval-gated in
``lib/mcp/write-tools.ts``. Bodies are constructed deterministically with
monitor-first defaults (see ``feedback_deterministic_over_agent_instruction``):
the agent supplies the load-bearing identifiers (name, regexes, pattern/
classification ids) and the heavy ``policy_properties`` object is filled in
here, not by the model. Every response runs through ``_check_response`` so a
missing write scope degrades to ``scope_pending`` and a 400 surfaces cleanly
rather than masquerading as success.
"""

from __future__ import annotations

from typing import Any

from falcon_helpers import _check_response, _get_data_protection_client, swallow_exc

# --- enum allowlists (the ones we're confident about; others pass through) ---
_PROTECTION_MODES = {"monitor", "enforce"}
_PLATFORMS = {"win", "mac"}
_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
_RESPONSE_ACTIONS = {"allow", "block"}
_INSPECTION_DEPTHS = {"shallow", "balanced", "deep"}
_CONFIDENCE_LEVELS = {"low", "medium", "high"}


def _safe_text(s: str | None) -> str | None:
    """Coerce em-dash / en-dash to ASCII hyphen in user-facing text fields.
    Falcon's DLP name/description validator rejects them (regex charset is
    `^[\\w\\p{L}\\p{M}\\- :;,\\.!()&\\[\\]\\n@]*$` — no U+2014/U+2013), and the
    agent reliably writes em-dashes in prose. Same quirk as prevention-policy
    names. Cosmetic-only; surfaces a `-` instead of a confusing HTTP 400."""
    if not isinstance(s, str):
        return s
    return s.replace("—", "-").replace("–", "-")


def _first_id(resp: dict[str, Any] | None) -> str | None:
    """Pull the new object's id out of a FalconPy resources[] response. DLP
    create endpoints return either a list of id strings or a list of dicts
    carrying an `id` — handle both."""
    resources = ((resp or {}).get("body") or {}).get("resources") or []
    if not resources:
        return None
    first = resources[0]
    if isinstance(first, str):
        return first
    if isinstance(first, dict):
        return first.get("id")
    return None


def create_content_pattern(
    name: str,
    regexes: list[str],
    category: str,
    region: str = "ALL",
    min_match_threshold: int = 1,
    description: str | None = None,
    example: str | None = None,
) -> dict[str, Any]:
    """Create a Data Protection content pattern (the regex matcher layer).

    Args:
        name: Display name for the pattern.
        regexes: One or more regexes that match the sensitive string. Falcon's
            DLP regex engine is used at match time.
        category: Pattern category label. Valid on Falcon: "Custom", "PII",
            "PCI DSS", "ITAR", "Secret".
        region: Region scope — "ALL" or an ISO-3166 alpha-3 country code
            (e.g. "USA", "CAN", "AUS"). Default "ALL". NOTE: "global" is
            rejected by Falcon ("region not found") — use "ALL".
        min_match_threshold: How many regex hits are required to count as a
            match. Default 1.
        description: Optional free-text describing what the pattern detects.
        example: Optional sample string demonstrating a match (non-sensitive).
    """
    if not name or not isinstance(name, str):
        return {"ok": False, "error": "name is required and must be a string"}
    if not regexes or not isinstance(regexes, list) or not all(isinstance(r, str) for r in regexes):
        return {"ok": False, "error": "regexes is required and must be a non-empty list of strings"}
    if not category or not isinstance(category, str):
        return {"ok": False, "error": "category is required and must be a string"}
    try:
        body: dict[str, Any] = {
            "name": _safe_text(name),
            "regexes": list(regexes),
            "category": category,
            "region": region,
            "min_match_threshold": int(min_match_threshold),
        }
        if description:
            body["description"] = _safe_text(description)
        if example:
            body["example"] = example
        client = _get_data_protection_client()
        r = client.create_content_pattern(body=body)
        guard = _check_response(r, "DataProtection content pattern")
        if guard is not None:
            return guard
        return {
            "ok": True,
            "id": _first_id(r),
            "name": name,
            "category": category,
            "region": region,
            "regex_count": len(regexes),
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


def create_classification(
    name: str,
    content_patterns: list[str],
    protection_mode: str = "monitor",
    file_types: list[str] | None = None,
    detection_severity: str = "informational",
    response_action: str = "allow",
    notify_end_user: bool = False,
) -> dict[str, Any]:
    """Create a Data Protection classification (binds content patterns + a
    detection rule). Defaults to monitor mode (observe, don't block).

    Args:
        name: Display name for the classification.
        content_patterns: Content pattern ids (from
            extras_create_data_protection_content_pattern or
            falcon_search_data_security_entities entity_type="content_pattern") this
            classification matches on. At least one required.
        protection_mode: "monitor" (detect only) or "enforce" (act on the
            response_action). Default "monitor" — the safe first deployment.
        file_types: Optional list of file-type ids to scope matching to.
            Omit for all file types.
        detection_severity: Severity stamped on generated detections —
            informational / low / medium / high / critical. Default
            "informational".
        response_action: What enforce mode does on a match — "allow" (monitor)
            or "block". Default "allow"; only meaningful when
            protection_mode="enforce".
        notify_end_user: Show the end user a notification on a match. Default
            False.
    """
    if not name or not isinstance(name, str):
        return {"ok": False, "error": "name is required and must be a string"}
    if not content_patterns or not isinstance(content_patterns, list):
        return {"ok": False, "error": "content_patterns is required and must be a non-empty list of pattern ids"}
    if protection_mode not in _PROTECTION_MODES:
        return {"ok": False, "error": f"protection_mode must be one of {sorted(_PROTECTION_MODES)}"}
    if detection_severity not in _SEVERITIES:
        return {"ok": False, "error": f"detection_severity must be one of {sorted(_SEVERITIES)}"}
    if response_action not in _RESPONSE_ACTIONS:
        return {"ok": False, "error": f"response_action must be one of {sorted(_RESPONSE_ACTIONS)}"}
    try:
        rule = {
            "detection_severity": detection_severity,
            "response_action": response_action,
            "user_scope": "all",
            "web_locations_scope": "all",
            "trigger_detection": True,
            "notify_end_user": bool(notify_end_user),
            "enable_web_locations": True,
            "enable_usb_devices": True,
            "enable_printer_egress": True,
        }
        classification_properties = {
            "content_patterns": list(content_patterns),
            "protection_mode": protection_mode,
            "file_types": list(file_types) if file_types else [],
            "evidence_duplication_enabled": True,
            "rules": [rule],
        }
        body = {"resources": [{"name": _safe_text(name), "classification_properties": classification_properties}]}
        client = _get_data_protection_client()
        r = client.create_classification(body=body)
        guard = _check_response(r, "DataProtection classification")
        if guard is not None:
            return guard
        return {
            "ok": True,
            "id": _first_id(r),
            "name": name,
            "protection_mode": protection_mode,
            "content_patterns": list(content_patterns),
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)


def create_policy(
    name: str,
    platform: str,
    classifications: list[str],
    description: str | None = None,
    precedence: int | None = None,
    enable_content_inspection: bool = True,
    enable_context_inspection: bool = True,
    enable_network_inspection: bool = True,
    inspection_depth: str = "balanced",
    min_confidence_level: str = "low",
) -> dict[str, Any]:
    """Create a Data Protection policy (the platform-scoped enforcement rule
    set that binds classifications and lands on hosts).

    Built with monitor-safe defaults: inspection is on, but
    block_all_data_access is False and notifications default to the tenant
    default. Tune to enforce via the Falcon Console or update_policies once the
    monitor run is clean.

    Args:
        name: Display name for the policy.
        platform: Target platform — "win" or "mac" (required; DLP policies are
            platform-scoped).
        classifications: Classification ids (from
            extras_create_data_protection_classification or
            falcon_search_data_security_entities entity_type="classification") this policy
            enforces. At least one required.
        description: Optional free-text description.
        precedence: Optional ordering. Lower precedence evaluates first. Omit
            to let Falcon append at the end.
        enable_content_inspection: Inspect file/clipboard content. Default True.
        enable_context_inspection: Inspect context (source app, destination).
            Default True.
        enable_network_inspection: Inspect network/upload egress. Default True.
        inspection_depth: shallow / balanced / deep. Default "balanced".
        min_confidence_level: Minimum match confidence to act on —
            low / medium / high. Default "low".
    """
    if not name or not isinstance(name, str):
        return {"ok": False, "error": "name is required and must be a string"}
    if platform not in _PLATFORMS:
        return {"ok": False, "error": f"platform must be one of {sorted(_PLATFORMS)}"}
    if not classifications or not isinstance(classifications, list):
        return {"ok": False, "error": "classifications is required and must be a non-empty list of classification ids"}
    if inspection_depth not in _INSPECTION_DEPTHS:
        return {"ok": False, "error": f"inspection_depth must be one of {sorted(_INSPECTION_DEPTHS)}"}
    if min_confidence_level not in _CONFIDENCE_LEVELS:
        return {"ok": False, "error": f"min_confidence_level must be one of {sorted(_CONFIDENCE_LEVELS)}"}
    try:
        policy_properties = {
            "classifications": list(classifications),
            "enable_content_inspection": bool(enable_content_inspection),
            "enable_context_inspection": bool(enable_context_inspection),
            "enable_network_inspection": bool(enable_network_inspection),
            "enable_clipboard_inspection": True,
            "inspection_depth": inspection_depth,
            "min_confidence_level": min_confidence_level,
            "allow_notifications": "default",
            "block_notifications": "default",
            "block_all_data_access": False,
            "browsers_without_active_extension": "allow",
            "unsupported_browsers_action": "allow",
            "similarity_detection": False,
        }
        resource: dict[str, Any] = {"name": _safe_text(name), "policy_properties": policy_properties}
        if description:
            resource["description"] = _safe_text(description)
        if precedence is not None:
            resource["precedence"] = int(precedence)
        body = {"resources": [resource]}
        client = _get_data_protection_client()
        r = client.create_policy(body=body, platform_name=platform)
        guard = _check_response(r, "DataProtection policy")
        if guard is not None:
            return guard
        return {
            "ok": True,
            "id": _first_id(r),
            "name": name,
            "platform": platform,
            "classifications": list(classifications),
        }
    except Exception as exc:  # noqa: BLE001
        return swallow_exc(exc)

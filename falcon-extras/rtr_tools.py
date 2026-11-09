"""Auto-extracted tool implementations.

See ``server.py`` ``@mcp.tool()`` wrappers for the public docstrings;
these are the worker functions they delegate to.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any
from falcon_helpers import _check_response, _falcon_kwargs
from falcon_helpers import swallow_exc
from patching import library as patch_lib
from cleanup import library as cleanup_lib

# Hard guard: any single batch larger than this requires the caller to set
# `confirm_large_batch=True`. Patch / cleanup are per-host work — accidentally
# fanning out a wide rollout in one approval is the bug we want to prevent.
LARGE_BATCH_THRESHOLD = 25


def _dispatch_script(plan: Any, device_ids: list[str]) -> dict[str, Any]:
    """Hand a rendered script back to Eyas to run through eyas-mcp.

    The sidecar no longer talks to RTR for patch / cleanup runs. It validates
    and renders (the Eyas content layer), and the Next.js tool bridge
    (lib/mcp/rtr-dispatch.ts) uploads the bytes as a one-off custom script,
    runs it on the hosts and deletes it, all with eyas-mcp's native RTR tools,
    then replaces this envelope with the per-host results. The envelope never
    reaches the agent, and the agent still never supplies script bytes.
    """
    return {
        "ok": True,
        "dispatch": {
            "kind": "rtr_script",
            "script_body": plan.rendered,
            "platform": plan.os,
            "device_ids": list(device_ids),
        },
    }

# The generic installer is the only patch script that takes a vendor URL +
# optional integrity pin as runtime params (every other script bakes a fixed
# vendor URL). When an operator reviews a dry-run, an absent hash is easy to
# miss in the 40-line preview — the require-admin + msi-installer preambles
# push the script body's UNVERIFIED banner out of view. So we surface an
# explicit boolean alongside the plan; the approval-time decision document can
# then never silently approve an unverified install. No-op for every specific
# app script.
GENERIC_INSTALLER_IDS = {"win-app-install"}


def _integrity_signal(plan: Any) -> dict[str, Any]:
    if plan.script_id not in GENERIC_INSTALLER_IDS:
        return {}
    return {"hash_pinned": bool((plan.params or {}).get("sha256"))}


def rtr_list_patch_scripts(os_filter: str | None = None) -> dict[str, Any]:
    """Return the curated patch-script catalog. Read-only. The agent calls
    this to discover what scripts exist; it cannot supply script content.

    Args:
        os_filter: Optional. Restrict to one OS family ('windows', 'macos',
            'linux'). Omit for everything.
    """
    try:
        return {"ok": True, "scripts": patch_lib.list_scripts(os_filter)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def rtr_resolve_patch_plan(
    spotlight_remediation: dict[str, Any],
    device_ids: list[str],
    params: dict[str, Any] | None = None,
    script_id: str | None = None,
    os_hint: str | None = None,
) -> dict[str, Any]:
    """Build a patch plan for a Spotlight remediation entity. Read-only — does
    NOT execute. Returns the matched script id, resolved params (with defaults
    filled in), target device count, a script preview, and execution metadata.
    Use this to compose the decision document the user reviews before approval.

    Args:
        spotlight_remediation: The Spotlight remediation entity, with at least
            'vendor' and 'product' (and optionally 'version'). The library
            matches the first script whose patterns match.
        device_ids: List of Falcon device IDs (AIDs) the plan targets. Not
            used at resolve time except to compute counts and a sample.
        params: Optional. Per-script parameters. Validated against the
            script's schema; required params with no default raise an error.
        script_id: Optional. Skip remediation matching and resolve a specific
            script id directly (e.g. 'win-update-status' for diagnostics).
    """
    try:
        if script_id:
            spec = patch_lib.find_by_id(script_id)
            if not spec:
                return {"ok": False, "error": f"unknown script id: {script_id}"}
        else:
            vendor = (spotlight_remediation or {}).get("vendor", "")
            product = (spotlight_remediation or {}).get("product", "")
            normalized_os = (os_hint or "").strip().lower() or None
            if normalized_os and normalized_os not in {"windows", "linux", "macos"}:
                return {
                    "ok": False,
                    "error": f"os_hint must be one of windows|linux|macos (got {os_hint!r})",
                }
            spec = patch_lib.match_remediation(vendor, product, normalized_os)
            extracted_params: dict[str, Any] = {}
            if not spec and normalized_os == "linux":
                # Fallback: any single-package Linux remediation routes to
                # the generic linux-pkg-upgrade. The script detects apt /
                # dnf / yum at runtime, so one fallback covers all supported
                # distros (Debian, Ubuntu, RHEL, Rocky, Alma, Fedora,
                # Amazon Linux). Package name is extracted from the
                # remediation product string.
                fallback = patch_lib.linux_pkg_fallback(product)
                if fallback:
                    spec, extracted_params = fallback
            if not spec:
                generic_ok = normalized_os == "windows"
                gap: dict[str, Any] = {
                    "ok": False,
                    "error": "no curated script matches this remediation entity",
                    "vendor": vendor,
                    "product": product,
                    "os_hint": normalized_os,
                    "generic_installer_available": generic_ok,
                }
                if generic_ok:
                    gap["hint"] = (
                        "No app-specific script ships for this Windows product, but the "
                        "generic installer can patch it. Re-resolve with "
                        'script_id="win-app-install" and params {url (vendor HTTPS '
                        "download), kind ('msi'|'exe'), product (friendly name), optional "
                        "sha256 (STRONGLY preferred — host-side verify-or-abort integrity "
                        "pin), optional silent_args (exe-only)}. This is NOT freehand: the "
                        "script bytes are baked, only validated params pass the regex. "
                        "Then dry-run via extras_rtr_run_patch (it reports hash_pinned) "
                        "before executing."
                    )
                return gap
            # User-supplied params override extracted ones (e.g. operator
            # corrects a misparsed package name).
            merged_params = {**extracted_params, **(params or {})}
            params = merged_params
        plan = patch_lib.resolve_plan(spec["id"], params or {})
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:
        return swallow_exc(exc)

    return {
        "ok": True,
        "script_id": plan.script_id,
        "title": plan.title,
        "os": plan.os,
        "params": plan.params,
        "preview": plan.preview,
        "reboot_risk": plan.reboot_risk,
        "expected_runtime_minutes": plan.expected_runtime_minutes,
        "read_only": plan.read_only,
        "target_device_count": len(device_ids or []),
        "target_device_sample": (device_ids or [])[:5],
        **_integrity_signal(plan),
    }


def rtr_run_patch(
    script_id: str,
    device_ids: list[str],
    params: dict[str, Any] | None = None,
    dry_run: bool = True,
    confirm_large_batch: bool = False,
) -> dict[str, Any]:
    """Execute a curated patch script via RTR batch session. WRITE ACTION —
    this tool is approval-gated by the Next.js agent loop. The agent calls it,
    the loop pauses, the operator reviews, and only then is the call dispatched.

    Default is `dry_run=True`, which returns the resolved plan + script preview
    WITHOUT calling the CrowdStrike RTR API. Use this to render a final
    pre-flight summary the operator can review before flipping `dry_run=False`.

    Hard guard: when device_ids has more than 25 entries, the call is rejected
    unless `confirm_large_batch=True` is passed explicitly. This prevents the
    agent from accidentally fanning out a wide rollout in a single approval.

    Args:
        script_id: Must match an id from extras_rtr_list_patch_scripts. The
            script content is resolved server-side; the agent cannot author bytes.
        device_ids: Falcon device IDs (AIDs) to target.
        params: Per-script parameters; validated against the manifest schema.
        dry_run: Default True. When True, returns the resolved plan + preview
            and does not invoke RTR. Set False to execute.
        confirm_large_batch: Required (True) when device_ids count > 25.
    """
    try:
        plan = patch_lib.resolve_plan(script_id, params or {})
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    if not device_ids:
        return {"ok": False, "error": "device_ids must be a non-empty list"}

    if len(device_ids) > LARGE_BATCH_THRESHOLD and not confirm_large_batch:
        return {
            "ok": False,
            "error": (
                f"refusing to execute on {len(device_ids)} hosts without "
                f"confirm_large_batch=True (threshold {LARGE_BATCH_THRESHOLD}). "
                "Re-issue the call with confirm_large_batch=True after a second "
                "operator approval."
            ),
            "host_count": len(device_ids),
            "threshold": LARGE_BATCH_THRESHOLD,
        }

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "script_id": plan.script_id,
            "title": plan.title,
            "params": plan.params,
            "preview": plan.preview,
            "reboot_risk": plan.reboot_risk,
            "expected_runtime_minutes": plan.expected_runtime_minutes,
            "host_count": len(device_ids),
            "device_id_sample": device_ids[:5],
            **_integrity_signal(plan),
        }

    return {
        **_dispatch_script(plan, device_ids),
        "dry_run": False,
        "script_id": plan.script_id,
        "title": plan.title,
        "reboot_risk": plan.reboot_risk,
    }


def rtr_check_patch_status(
    cloud_request_ids: list[str],
) -> dict[str, Any]:
    """Poll in-flight RTR commands. Read-only. Use after extras_rtr_run_patch
    when one or more host results returned `complete: false` and a non-null
    `cloud_request_id` — typical for long-running scripts (Windows Update
    install, etc.) that exceed the synchronous batch_admin_command timeout.

    Args:
        cloud_request_ids: One per still-running host. Typically taken from
            the run_patch response's `results[].cloud_request_id` for any
            entry where `complete` was false.
    """
    # Checked by Eyas through eyas-mcp's falcon_check_rtr_admin_command_status
    # (lib/mcp/rtr-dispatch.ts); the sidecar only validates the input.
    ids = [i for i in (cloud_request_ids or []) if isinstance(i, str) and i.strip()]
    if not ids:
        return {"ok": False, "error": "cloud_request_ids is empty"}
    return {"ok": True, "dispatch": {"kind": "rtr_status", "cloud_request_ids": ids}}


def rtr_list_cleanup_scripts(os_filter: str | None = None) -> dict[str, Any]:
    """Return the curated host-cleanup script catalog. Read-only. Distinct
    from the patching catalog (extras_rtr_list_patch_scripts): cleanup is
    incident-response remediation — stop a service, remove a scheduled task,
    delete an autorun registry value, kill a process. Use after a persistence
    audit or detection-triage finding to pick the right id and validated params.
    """
    try:
        return {"ok": True, "scripts": cleanup_lib.list_scripts(os_filter)}
    except Exception as exc:
        return swallow_exc(exc)


def rtr_resolve_cleanup_plan(
    script_id: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Resolve a cleanup script id + params to a render preview without
    executing. Read-only. Use this to confirm parameter validation passes and
    to show the operator the rendered $Params block before triggering the
    write call. Mirrors extras_rtr_resolve_patch_plan.
    """
    try:
        plan = cleanup_lib.resolve_plan(script_id, params or {})
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return {
        "ok": True,
        "script_id": plan.script_id,
        "title": plan.title,
        "intent": plan.intent,
        "params": plan.params,
        "preview": plan.preview,
    }


def rtr_run_cleanup(
    script_id: str,
    device_ids: list[str],
    params: dict[str, Any] | None = None,
    dry_run: bool = True,
    confirm_large_batch: bool = False,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute a curated cleanup script via RTR batch session. WRITE ACTION —
    approval-gated by the Next.js agent loop. Default `dry_run=True`, which
    returns the resolved plan + script preview without calling the RTR API.

    Hard guard: when device_ids has more than 25 entries, the call is rejected
    unless `confirm_large_batch=True`. Cleanup is per-host work; large fanout
    is almost certainly wrong.

    ``evidence`` opens the detection-vouched path widening: when supplied,
    the validator will use a wider regex (``evidence_pattern``) for the
    listed param keys instead of the strict default. Use only when the path
    came directly out of a true-positive detection's evidence — the
    structure is recorded in the result for audit.

    Expected shape::

        {
            "composite_id": "<detection composite id>",
            "source": "cmdline_artifacts.downloaded_files" |
                      "cmdline_artifacts.extract_targets" |
                      "behaviors[].cmdline" | "behaviors[].ioc_value" | ...,
            "vouched_param_keys": ["path"]  # cleanup-script param names
                                            # whose value came from the
                                            # named source on the named
                                            # detection.
        }

    Args:
        script_id: id from extras_rtr_list_cleanup_scripts.
        device_ids: Falcon AIDs to target. Typically a single host.
        params: Per-script parameters; validated against the manifest schema.
        dry_run: Default True. Set False to execute.
        confirm_large_batch: Required (True) when device_ids count > 25.
        evidence: Optional detection-vouching for path-shaped params.
    """
    vouched_keys: set[str] = set()
    if evidence and isinstance(evidence, dict):
        keys = evidence.get("vouched_param_keys")
        if isinstance(keys, list):
            vouched_keys = {k for k in keys if isinstance(k, str)}

    try:
        plan = cleanup_lib.resolve_plan(
            script_id,
            params or {},
            evidence_vouched_keys=vouched_keys or None,
        )
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    if not device_ids:
        return {"ok": False, "error": "device_ids must be a non-empty list"}

    if len(device_ids) > LARGE_BATCH_THRESHOLD and not confirm_large_batch:
        return {
            "ok": False,
            "error": (
                f"refusing to execute on {len(device_ids)} hosts without "
                f"confirm_large_batch=True (threshold {LARGE_BATCH_THRESHOLD})."
            ),
            "host_count": len(device_ids),
            "threshold": LARGE_BATCH_THRESHOLD,
        }

    if dry_run:
        return {
            "ok": True,
            "dry_run": True,
            "script_id": plan.script_id,
            "title": plan.title,
            "intent": plan.intent,
            "params": plan.params,
            "preview": plan.preview,
            "host_count": len(device_ids),
            "device_id_sample": device_ids[:5],
            **({"evidence": evidence} if evidence else {}),
        }

    return {
        **_dispatch_script(plan, device_ids),
        "dry_run": False,
        "script_id": plan.script_id,
        "title": plan.title,
        **({"evidence": evidence} if evidence else {}),
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def save_patch_profile(
    name: str,
    product: str,
    url: str,
    kind: str,
    sha256: str | None = None,
    silent_args: str | None = None,
) -> dict[str, Any]:
    """Persist a reusable generic-installer param-set as a named patch profile.
    WRITE ACTION — approval-gated by the Next.js agent loop. Saving establishes
    a trusted, reusable install source for this tenant, so it is a conscious
    operator decision (running a profile is separately gated at run_patch).

    This does NOT store script bytes and does NOT create any Falcon-side object.
    It validates the supplied params against the SAME win-app-install manifest
    schema the resolve/run path enforces — the security boundary is reused, so a
    saved profile can never carry params that wouldn't pass at execution time.
    The agent supplies a vendor HTTPS URL it already knows; it never invents one.
    On success the Next.js auto-save hook appends the returned profile to the
    active environment's per-tenant catalog.

    Args:
        name: Operator-facing label for the profile (1-64 chars), e.g.
            "Firefox ESR" or "7-Zip x64".
        product: Friendly product name shown in install logs. Validated against
            the win-app-install 'product' pattern.
        url: Vendor HTTPS download URL. Validated against the 'url' pattern
            (https only; shell metacharacters rejected).
        kind: Required. 'msi' (msiexec /qn) or 'exe' (silent switches via
            silent_args). Choose deliberately — the URL extension is not a
            reliable signal of installer type.
        sha256: Optional integrity pin (64 hex). STRONGLY preferred — host-side
            verify-or-abort before install. Omit only when no published hash
            exists; the install then proceeds on HTTPS trust + approval alone.
        silent_args: Optional exe-only silent switches (ignored for kind=msi).
    """
    label = (name or "").strip()
    if not label:
        return {"ok": False, "error": "name is required"}
    if len(label) > 64:
        return {"ok": False, "error": "name must be 64 characters or fewer"}

    spec = patch_lib.find_by_id("win-app-install")
    if not spec:
        return {"ok": False, "error": "generic installer is not available in this build"}

    supplied: dict[str, Any] = {"url": url, "product": product, "kind": kind}
    if sha256:
        supplied["sha256"] = sha256
    if silent_args:
        supplied["silent_args"] = silent_args

    # Reuse the manifest regex boundary — identical to what resolve_plan enforces.
    try:
        validated = patch_lib._validate_params(spec.get("params", {}), supplied)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    profile: dict[str, Any] = {
        "id": "pp_" + uuid.uuid4().hex[:12],
        "name": label,
        "product": validated["product"],
        "url": validated["url"],
        "kind": validated["kind"],
        "createdAt": _now_iso(),
    }
    if validated.get("sha256"):
        profile["sha256"] = validated["sha256"]
    if validated.get("silent_args"):
        profile["silentArgs"] = validated["silent_args"]

    return {"ok": True, "profile": profile, "hash_pinned": bool(profile.get("sha256"))}


def list_patch_profiles() -> dict[str, Any]:
    """List this tenant's saved patch profiles. Read-only. Each profile is a
    reusable generic-installer param-set the operator previously saved. To use
    one: pick a profile, then call extras_rtr_resolve_patch_plan with
    script_id="win-app-install" and the profile's params, then dry-run via
    extras_rtr_run_patch before executing.

    Note: a profile saved earlier in THIS SAME turn is not yet visible here —
    the save is persisted after the tool returns and this reads the per-tenant
    catalog captured when the session started. Save, let the turn finish, then
    list on a later step.
    """
    raw = os.environ.get("FALCON_PATCH_PROFILES", "")
    if not raw:
        return {"ok": True, "profiles": [], "count": 0}
    try:
        parsed = json.loads(raw)
    except Exception:
        return {"ok": True, "profiles": [], "count": 0, "note": "saved profiles were unreadable"}
    if not isinstance(parsed, list):
        return {"ok": True, "profiles": [], "count": 0}
    return {"ok": True, "profiles": parsed, "count": len(parsed)}


def _normalize_os_label(raw: Any) -> str | None:
    """Map a free-form platform string (Spotlight 'host_info.platform' is
    'Windows' | 'Linux' | 'Mac', but callers vary) to the catalog's OS
    vocabulary. Returns None when unrecognizable so callers fail closed —
    an unknown OS is never treated as Windows for generic-installer eligibility.
    """
    r = str(raw or "").strip().lower()
    if r.startswith("win"):
        return "windows"
    if r.startswith("lin"):
        return "linux"
    if r.startswith("mac") or r in {"darwin", "osx", "os x"}:
        return "macos"
    return None


def classify_patch_coverage(
    remediations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Classify a batch of Spotlight remediation entities against the curated
    patch catalog. Read-only — does NOT resolve, render, or execute anything.
    For each entity it reports whether a curated script (or the Linux generic
    upgrade fallback) covers it, and whether the Windows generic installer
    could close the gap.

    Built for the /vulnerabilities page's server-side coverage enrichment: the
    page batches the distinct (vendor, product, os) triples it renders and
    attaches a capability-gap flag beside each row, so a missing app-specific
    script is discoverable in the table rather than only surfacing mid-chat.

    Args:
        remediations: List of entities, each a dict with 'vendor', 'product',
            and 'os' (platform string — 'Windows' | 'Linux' | 'Mac' or any
            recognizable variant). Order is preserved in the result so callers
            can zip results back to inputs.

    Returns per entity: {vendor, product, os (normalized | null), matched,
    script_id (curated id when matched, else null), generic_installer_eligible
    (true only when os is Windows AND no curated script matched)}.
    """
    if not isinstance(remediations, list):
        return {"ok": False, "error": "remediations must be a list"}
    results: list[dict[str, Any]] = []
    for entry in remediations:
        if not isinstance(entry, dict):
            results.append(
                {
                    "vendor": "",
                    "product": "",
                    "os": None,
                    "matched": False,
                    "script_id": None,
                    "generic_installer_eligible": False,
                }
            )
            continue
        vendor = str(entry.get("vendor", "") or "")
        product = str(entry.get("product", "") or "")
        normalized_os = _normalize_os_label(entry.get("os"))
        spec = patch_lib.match_remediation(vendor, product, normalized_os)
        if not spec and normalized_os == "linux":
            fallback = patch_lib.linux_pkg_fallback(product)
            if fallback:
                spec = fallback[0]
        matched = spec is not None
        results.append(
            {
                "vendor": vendor,
                "product": product,
                "os": normalized_os,
                "matched": matched,
                "script_id": spec["id"] if spec else None,
                "generic_installer_eligible": (normalized_os == "windows") and not matched,
            }
        )
    return {"ok": True, "results": results, "count": len(results)}


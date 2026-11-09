"""FalconPy RTR helpers for the IR readiness probe (ir/wait_for_rtr.py).

Patch and cleanup runs no longer go through here: the sidecar renders the
script and Eyas runs it with eyas-mcp's native RTR tools (upload as a one-off
custom script, `runscript -CloudFile=`, delete) — see lib/mcp/rtr-dispatch.ts.
The probe keeps these helpers until eyas-mcp's session wait can exercise a
real runscript.

Why CloudFile rather than -Raw=: RTR's command parser has its own quoting
rules that don't survive inline scripts containing single quotes (the
$Params block trips it). Uploading the script and referencing it by name
sidesteps every inline-quoting trap and is CrowdStrike's documented path
for non-trivial scripts.
"""

from __future__ import annotations

from typing import Any

from falconpy import RealTimeResponse, RealTimeResponseAdmin

from falcon_helpers import _falcon_kwargs


# Batch session lifecycle (init / refresh / delete) lives on the base
# RealTimeResponse service class. Admin commands (runscript, put) live on
# RealTimeResponseAdmin. Two distinct service classes share the same OAuth.
def _rtr_base() -> RealTimeResponse:
    return RealTimeResponse(**_falcon_kwargs())


def _rtr_admin() -> RealTimeResponseAdmin:
    return RealTimeResponseAdmin(**_falcon_kwargs())


# Falcon's script-library platform field uses "mac" not "macos".
_PLATFORM_MAP = {"windows": "windows", "linux": "linux", "macos": "mac"}
_EXT_MAP = {"windows": "ps1", "linux": "sh", "macos": "sh"}


def _upload_script(admin: RealTimeResponseAdmin, name: str, body: str, platform: str) -> tuple[str | None, dict[str, Any]]:
    """Upload a private one-shot script to the Falcon script library.
    Returns (script_id, error_payload). On success error_payload is empty.

    The Falcon API requires multipart/form-data with the script body in a
    `file` field plus metadata fields. FalconPy plumbs metadata kwargs into
    the multipart form when `files=[...]` is provided.
    """
    fcs_platform = _PLATFORM_MAP.get(platform, "windows")
    ext = _EXT_MAP.get(platform, "ps1")
    upload = [("file", (f"{name}.{ext}", body.encode("utf-8"), "application/script"))]
    resp = admin.RTR_CreateScripts(
        name=name,
        description="falcon-extras one-shot patching dispatch (auto-deleted after run)",
        platform=fcs_platform,
        permission_type="private",
        files=upload,
    )
    body_resp = (resp or {}).get("body", {}) if isinstance(resp, dict) else {}
    status = (resp or {}).get("status_code") if isinstance(resp, dict) else None
    errors = body_resp.get("errors") or []
    if status not in (200, 201) or errors:
        return None, {
            "stage": "RTR_CreateScripts",
            "status_code": status,
            "errors": errors,
        }
    # The create endpoint doesn't return the new script's id; look it up by
    # name so we can reference it in -CloudFile= and clean it up afterward.
    listing = admin.RTR_ListScripts(filter=f"name:'{name}'")
    listing_body = (listing or {}).get("body", {}) if isinstance(listing, dict) else {}
    ids = listing_body.get("resources") or []
    script_id = ids[0] if ids and isinstance(ids[0], str) else None
    if not script_id:
        return None, {
            "stage": "RTR_ListScripts",
            "error": f"uploaded script name={name!r} not findable post-create",
            "body": listing_body,
        }
    return script_id, {}


def _delete_script(admin: RealTimeResponseAdmin, script_id: str) -> None:
    try:
        admin.RTR_DeleteScripts(ids=script_id)
    except Exception:
        # Cleanup is best-effort — leaving a stale private one-shot in the
        # script library is annoying but not dangerous.
        pass

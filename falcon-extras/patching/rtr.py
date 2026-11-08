"""Thin FalconPy RTR wrapper for batched script execution.

Used by extras_rtr_run_patch when dry_run=False. Three-step flow:
  1) RTR_create_script() — upload the rendered body to the Falcon script
     library with a unique name (private permission, scoped to one platform).
  2) batch_init_sessions(device_ids) + batch_admin_command(
       runscript -CloudFile="<name>"
     ) — open one batch session targeting up to 10k hosts and invoke by name.
  3) RTR_delete_scripts(ids=[script_id]) — clean up the temporary upload.

Why CloudFile rather than -Raw=: RTR's command parser has its own quoting
rules that don't survive inline scripts containing single quotes (the
$Params block trips it). Uploading the script and referencing it by name
sidesteps every inline-quoting trap and is CrowdStrike's documented path
for non-trivial scripts.
"""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class HostResult:
    device_id: str
    ok: bool
    stdout: str
    stderr: str
    exit_code: int | None
    error: str | None
    cloud_request_id: str | None = None
    complete: bool = True


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


def run_batch(
    device_ids: list[str],
    script_body: str,
    platform: str = "windows",
    queue_offline: bool = False,
    # Capped well under the MCP request timeout (60s default) so the tool
    # always returns to the agent with cloud_request_ids for any host that
    # didn't finish in-band. Long scripts (Windows Update, etc.) routinely
    # exceed this; the agent polls with extras_rtr_check_patch_status.
    timeout_seconds: int = 40,
) -> dict[str, Any]:
    import uuid

    if not device_ids:
        return {"ok": False, "error": "device_ids is empty"}

    admin = _rtr_admin()
    script_name = f"falcon-extras-{uuid.uuid4().hex[:12]}"
    script_id, upload_err = _upload_script(admin, script_name, script_body, platform)
    if not script_id:
        return {"ok": False, **upload_err}

    try:
        base = _rtr_base()
        init = base.batch_init_sessions(
            host_ids=device_ids,
            queue_offline=queue_offline,
            timeout=timeout_seconds,
        )
        init_body = (init or {}).get("body", {}) if isinstance(init, dict) else {}
        init_status = (init or {}).get("status_code") if isinstance(init, dict) else None
        if not init_body or init_status not in (200, 201):
            return {
                "ok": False,
                "stage": "batch_init_sessions",
                "status_code": init_status,
                "errors": init_body.get("errors") if init_body else None,
            }

        batch_id = init_body.get("batch_id")
        session_resources = init_body.get("resources", {}) or {}
        # Hosts that failed to open a session never get a runscript invocation.
        init_failures: list[HostResult] = []
        for did, sess in session_resources.items():
            if not isinstance(sess, dict):
                continue
            if not sess.get("session_id") or sess.get("errors"):
                init_failures.append(
                    HostResult(
                        device_id=did,
                        ok=False,
                        stdout="",
                        stderr="",
                        exit_code=None,
                        error=str(sess.get("errors") or "session_init_failed"),
                    )
                )

        # Reference the uploaded script by name. Quoting the name handles
        # any future scenario where a name contains spaces; for our
        # uuid-suffixed names it's harmless.
        command_string = f'runscript -CloudFile="{script_name}"'

        cmd = admin.batch_admin_command(
            batch_id=batch_id,
            base_command="runscript",
            command_string=command_string,
            timeout=timeout_seconds,
            # Falcon's per-host execution wait. Anything still running when
            # this expires comes back with complete=false + cloud_request_id.
            host_timeout_duration=f"{max(5, timeout_seconds - 10)}s",
        )
        cmd_body = (cmd or {}).get("body", {}) if isinstance(cmd, dict) else {}
        cmd_status = (cmd or {}).get("status_code") if isinstance(cmd, dict) else None
        if not cmd_body or cmd_status not in (200, 201):
            return {
                "ok": False,
                "stage": "batch_admin_command",
                "status_code": cmd_status,
                "batch_id": batch_id,
                "errors": cmd_body.get("errors") if cmd_body else None,
            }

        per_host: list[HostResult] = []
        combined = cmd_body.get("combined", {}) or {}
        resources = combined.get("resources", {}) or {}
        for did, r in resources.items():
            if not isinstance(r, dict):
                continue
            complete = r.get("complete") is not False
            per_host.append(
                HostResult(
                    device_id=did,
                    ok=not r.get("errors") and complete,
                    stdout=str(r.get("stdout") or ""),
                    stderr=str(r.get("stderr") or ""),
                    exit_code=r.get("exit_code"),
                    error=str(r.get("errors")) if r.get("errors") else None,
                    cloud_request_id=r.get("cloud_request_id"),
                    complete=complete,
                )
            )

        per_host.extend(init_failures)
        ok_count = sum(1 for h in per_host if h.ok)
        return {
            "ok": ok_count > 0,
            "batch_id": batch_id,
            "host_count": len(per_host),
            "ok_count": ok_count,
            "results": [h.__dict__ for h in per_host],
        }
    finally:
        _delete_script(admin, script_id)


def check_status(cloud_request_ids: list[str]) -> dict[str, Any]:
    """Poll one or more in-flight admin commands by cloud_request_id.
    Returns per-id status: complete + stdout/stderr/exit_code when finished."""
    if not cloud_request_ids:
        return {"ok": False, "error": "cloud_request_ids is empty"}
    admin = _rtr_admin()
    out: list[dict[str, Any]] = []
    for cid in cloud_request_ids:
        try:
            resp = admin.check_admin_command_status(
                cloud_request_id=cid, sequence_id=0
            )
            body = (resp or {}).get("body", {}) if isinstance(resp, dict) else {}
            resources = (body.get("resources") or [{}])[0] if body else {}
            out.append(
                {
                    "cloud_request_id": cid,
                    "complete": bool(resources.get("complete")),
                    "stdout": resources.get("stdout") or "",
                    "stderr": resources.get("stderr") or "",
                    "exit_code": resources.get("exit_code"),
                    "errors": resources.get("errors") or [],
                }
            )
        except Exception as exc:
            out.append(
                {
                    "cloud_request_id": cid,
                    "complete": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
    return {
        "ok": True,
        "count": len(out),
        "complete_count": sum(1 for r in out if r.get("complete")),
        "results": out,
    }

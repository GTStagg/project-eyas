"""Block until RTR sessions can actually open + run a runscript on the
target host. Used by the IR playbook between Phase 1 (host moved into the
quarantine group) and Phase 2 (first cleanup primitive) — the period
during which the new prevention policy + IOA exclusion are propagating
from backend to sensor and any cleanup attempt will hit
``batch_init_sessions: 404`` until propagation completes.

The probe MUST exercise the full ``runscript -CloudFile=`` path because
that's what's gated by the preamble IOA exclusion. Falconscript transport
uses a different base command and is NOT a valid proxy. Each probe iteration
uploads a minimal one-shot PowerShell script (`exit 0`), runs it via the
cleanup-style runscript path, and reports whether session init + command
dispatch both succeeded for the target AID. The script is deleted in
``finally`` regardless of outcome.

Returns a structured payload the agent can interpret without re-parsing:

    {
        "ready": bool,
        "waited_s": int,                 # cumulative wall-clock spent waiting
        "iterations": int,               # number of probes fired
        "last_error": dict | None,       # most recent probe failure shape
        "first_ready_iteration": int|None,
        "timed_out": bool,
    }

Tuning:

* ``timeout_s`` default 300 (5 min) covers the documented 60–90s sensor-
  side propagation window with healthy headroom for re-tries on a flaky
  sensor connection. An IR analyst will trade 5 min wall-clock for a
  successful run — that's the explicit ask.
* ``interval_s`` default 15s keeps each probe cycle bounded under the MCP
  60s envelope (each probe ~5–10s of API work + interval). The first
  iteration fires immediately so we don't pay the interval penalty when
  the sensor is already ready.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from patching.rtr import _rtr_admin, _rtr_base, _upload_script, _delete_script


# Smallest valid PowerShell payload — exits cleanly with no behavioral
# signal. The script body itself is irrelevant; what we're testing is the
# transport (session init + runscript -CloudFile= invocation).
_PROBE_BODY = "exit 0\n"


def _probe_once(device_id: str, timeout_seconds: int = 20) -> tuple[bool, dict[str, Any] | None]:
    """One probe iteration. Returns (ready, error_or_none).

    ``ready`` is True iff session init succeeded for the target AID AND
    the batch_admin_command dispatch returned 200/201. We don't wait for
    command completion — the script is `exit 0` and complete-on-init is
    not the failure mode we care about; what we care about is whether the
    transport is open at all.
    """
    admin = _rtr_admin()
    script_name = f"falcon-extras-probe-{uuid.uuid4().hex[:12]}"
    script_id, upload_err = _upload_script(admin, script_name, _PROBE_BODY, "windows")
    if not script_id:
        # Upload failure is its own class of error — not a propagation
        # issue. Surface it so the caller can distinguish from the 404.
        return False, {"stage": "RTR_CreateScripts", **(upload_err or {})}

    try:
        base = _rtr_base()
        init = base.batch_init_sessions(
            host_ids=[device_id],
            queue_offline=False,
            timeout=timeout_seconds,
        )
        init_body = (init or {}).get("body", {}) if isinstance(init, dict) else {}
        init_status = (init or {}).get("status_code") if isinstance(init, dict) else None
        if not init_body or init_status not in (200, 201):
            return False, {
                "stage": "batch_init_sessions",
                "status_code": init_status,
                "errors": init_body.get("errors") if init_body else None,
            }
        batch_id = init_body.get("batch_id")
        session_resources = init_body.get("resources", {}) or {}
        # If THIS host's session init failed (preamble blocked, sensor
        # offline, etc.) we'd see it as a missing session_id or a non-empty
        # errors array on this device's resource entry.
        host_resource = session_resources.get(device_id) or {}
        if not host_resource.get("session_id") or host_resource.get("errors"):
            return False, {
                "stage": "batch_init_sessions",
                "status_code": init_status,
                "device_errors": host_resource.get("errors"),
                "host_resource": host_resource if not host_resource.get("session_id") else None,
            }

        # Session opened; try to dispatch the runscript. This is the
        # actual gated path on the sensor — if the IOA exclusion hasn't
        # propagated, the dispatch will fail (or the per-host result will
        # carry the preamble block).
        command_string = f'runscript -CloudFile="{script_name}"'
        cmd = admin.batch_admin_command(
            batch_id=batch_id,
            base_command="runscript",
            command_string=command_string,
            timeout=timeout_seconds,
            host_timeout_duration=f"{max(5, timeout_seconds - 5)}s",
        )
        cmd_body = (cmd or {}).get("body", {}) if isinstance(cmd, dict) else {}
        cmd_status = (cmd or {}).get("status_code") if isinstance(cmd, dict) else None
        if not cmd_body or cmd_status not in (200, 201):
            return False, {
                "stage": "batch_admin_command",
                "status_code": cmd_status,
                "errors": cmd_body.get("errors") if cmd_body else None,
            }
        # Inspect the per-host result for the preamble-block signal. If
        # the dispatch returned 200 but the host's stderr says the
        # encoded command was blocked, that's still not-ready.
        combined = cmd_body.get("combined", {}) or {}
        resources = combined.get("resources", {}) or {}
        host_result = resources.get(device_id) or {}
        stderr = (host_result.get("stderr") or "").lower()
        if stderr and ("blocked" in stderr or "encoded command" in stderr or "not allowed" in stderr):
            return False, {
                "stage": "runscript_blocked_at_sensor",
                "stderr": host_result.get("stderr"),
            }
        return True, None
    finally:
        _delete_script(admin, script_id)


def wait_until_rtr_ready(
    device_id: str,
    timeout_s: int = 300,
    interval_s: int = 15,
) -> dict[str, Any]:
    """Poll until RTR is ready or ``timeout_s`` elapses. See module docstring."""
    if not isinstance(device_id, str) or not device_id:
        return {"ok": False, "error": "device_id is required"}
    timeout_s = max(30, min(int(timeout_s), 600))
    interval_s = max(5, min(int(interval_s), 60))

    start = time.monotonic()
    iterations = 0
    last_error: dict[str, Any] | None = None
    first_ready_iteration: int | None = None

    while True:
        iterations += 1
        ok, err = _probe_once(device_id)
        elapsed = int(time.monotonic() - start)
        if ok:
            first_ready_iteration = iterations
            return {
                "ok": True,
                "ready": True,
                "waited_s": elapsed,
                "iterations": iterations,
                "first_ready_iteration": first_ready_iteration,
                "last_error": None,
                "timed_out": False,
            }
        last_error = err
        # Decide whether to keep waiting. If we'd cross the timeout on
        # the next iteration, stop now and report timed_out instead of
        # paying for a wasted sleep.
        if elapsed + interval_s >= timeout_s:
            return {
                "ok": True,  # the tool itself ran successfully; "ready" reports the outcome
                "ready": False,
                "waited_s": elapsed,
                "iterations": iterations,
                "first_ready_iteration": None,
                "last_error": last_error,
                "timed_out": True,
            }
        time.sleep(interval_s)

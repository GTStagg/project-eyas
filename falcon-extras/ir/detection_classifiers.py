"""Detection classifiers shared across Phase 3 verification and the IR
readiness diagnostic.

Two distinct false-positive detection shapes fire reliably during an agentic
IR run:

1. **Workflow self-triggered** — RTR's ``runscript -CloudFile=<name>``
   transport invokes PowerShell with a fixed ``-EncodedCommand`` preamble
   that decodes to ``Set-Location 'C:\\'``. Aggressive PowerShell
   behavioral detectors (PShellMimikatz et al.) fire on
   ``-EncodedCommand`` regardless of payload. On hosts in a quarantine
   policy that *prevents* encoded-command PowerShell, every IR cleanup
   invocation is killed at the sensor before it runs. Even on permissive
   policies, the detection still pollutes the queue.

2. **Retrospective IOC match** — when a custom IOC is added to Falcon
   during/after the IR, the matching engine backfills against stored
   historical telemetry and surfaces hits as detections with a fresh
   ``created_timestamp`` even though the underlying network/process events
   occurred days earlier. From the operator's perspective these look like
   new threats but are history rendered. Same triage shape: FP-close.

Both shapes get FP-closed unconditionally during Phase 4. ``real`` is
everything else and drives RELEASE / HOLD.

Pure logic — no FalconPy / MCP dependencies; unit-testable on canned
detection records.
"""

from __future__ import annotations

from typing import Any


# Identifying substring of the RTR runscript preamble cmdline. RTR's
# `runscript -CloudFile=<name>` transport invokes PowerShell with this
# fixed `-EncodedCommand` block as the preamble before sourcing the cloud
# file — it base64-decodes to `Set-Location 'C:\'`.
_RTR_PREAMBLE_BASE64 = "UwBlAHQALQBMAG8AYwBhAHQAaQBvAG4AIAAnAEMAOgBcACcA"

# Full anchored cmdline regex that matches the preamble in IOA exclusions.
_RTR_PREAMBLE_FULL_REGEX = (
    r".*-EncodedCommand " + _RTR_PREAMBLE_BASE64 + r".*"
)


def _detection_is_shadow_ai_ioc_audit(rec: dict[str, Any]) -> tuple[bool, str | None]:
    """Did this detection fire on a Shadow-AI audit-trail IOC (the
    detect-only domain IOCs that Ban+Clean Phase 4 creates for AI-provider
    endpoints)?

    Shadow-AI's Phase 4 step creates `falcon_add_ioc` calls with
    `type="domain"`, `action="detect"`, scoped to the banned host group,
    for every observed AI-provider egress endpoint (claude.ai,
    api.anthropic.com, chatgpt.com, etc.). These IOCs are an audit trail
    of continued AI use after host ban — they are NOT malware indicators
    and should not drive an IR engagement.

    Heuristic: walk ``behaviors[].ioc_type`` + ``behaviors[].ioc_value``.
    If any behavior has ``ioc_type == "domain"`` AND the ``ioc_value``
    matches the Shadow-AI egress catalog (lazy-imported to keep this
    module's dependency surface narrow), the detection is a Shadow-AI
    audit fire.

    Conservative: a single behavior matching is enough (typical case is
    one DNS query per detection). Returns ``(True, matched_domain)`` for
    audit fires; ``(False, None)`` otherwise.
    """
    behaviors = rec.get("behaviors") or []
    if not isinstance(behaviors, list) or not behaviors:
        return False, None

    # Lazy import — keeps this module pure-logic at import time and
    # decouples test infrastructure from the shadow_ai package.
    try:
        from shadow_ai.catalog import _AI_EGRESS_PYRX  # type: ignore[import-not-found]
    except Exception:
        return False, None

    for b in behaviors:
        if not isinstance(b, dict):
            continue
        ioc_type = (b.get("ioc_type") or "").lower()
        if ioc_type != "domain":
            continue
        ioc_value = b.get("ioc_value") or ""
        if not isinstance(ioc_value, str) or not ioc_value:
            continue
        ioc_value_lc = ioc_value.lower().strip()
        for rx, _tool, _posture in _AI_EGRESS_PYRX:
            if rx.match(ioc_value_lc):
                return True, ioc_value_lc
    return False, None


def _detection_is_workflow_self_triggered(rec: dict[str, Any]) -> bool:
    """Heuristic: did this detection fire on the RTR runscript preamble
    (i.e. self-triggered by IR cleanup), not on real attacker activity?

    Walks the cmdline, parent_details.cmdline, and behaviors[].cmdline for
    the literal preamble base64. A single match anywhere = self-triggered.
    Conservative: any miss across all three slots returns False so we never
    silently FP-close a real detection.
    """
    needle = _RTR_PREAMBLE_BASE64
    cl = rec.get("cmdline") or ""
    if isinstance(cl, str) and needle in cl:
        return True
    pd = rec.get("parent_details") or {}
    if isinstance(pd, dict):
        pcl = pd.get("cmdline") or ""
        if isinstance(pcl, str) and needle in pcl:
            return True
    for b in rec.get("behaviors") or []:
        if isinstance(b, dict):
            bcl = b.get("cmdline") or ""
            if isinstance(bcl, str) and needle in bcl:
                return True
    return False


def _parse_timestamp(v: Any) -> float | None:
    """Parse a Falcon timestamp into unix epoch seconds.

    Handles both shapes seen in detection records: epoch seconds (int/float
    or a numeric string, e.g. ``network_accesses[].access_timestamp``) and
    ISO 8601 (e.g. ``behaviors[].timestamp``, ``created_timestamp``). Returns
    None if the value is absent or unparseable.
    """
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        try:
            return float(s)
        except ValueError:
            pass
        try:
            from datetime import datetime
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.timestamp()
        except ValueError:
            return None
    return None


def _underlying_event_timestamps(rec: dict[str, Any]) -> list[float]:
    """Collect the timestamps of the underlying network/behavioral events a
    detection summarizes — NOT ``created_timestamp`` (when the envelope was
    scored). Used to distinguish a fresh detection of fresh activity from a
    fresh envelope rendering old, backfilled history.
    """
    out: list[float] = []

    def _push(v: Any) -> None:
        ts = _parse_timestamp(v)
        if ts is not None:
            out.append(ts)

    for na in rec.get("network_accesses") or []:
        if isinstance(na, dict):
            _push(na.get("access_timestamp"))
    for b in rec.get("behaviors") or []:
        if isinstance(b, dict):
            for k in ("timestamp", "behavior_timestamp", "first_behavior"):
                _push(b.get(k))
    # context_timestamp marks when the underlying activity occurred (vs
    # created_timestamp = when scored).
    _push(rec.get("context_timestamp"))
    return out


def _detection_is_retrospective_ioc_match(
    rec: dict[str, Any], since_ts_s: float
) -> tuple[bool, str | None]:
    """Return ``(is_retrospective, reason)`` relative to a KNOWN cutoff.

    A detection is a retrospective IOC match if it carries underlying event
    timestamps and ALL of those timestamps predate the IR's Phase 1
    quarantine point (``since_ts_s``). Phase 3 uses this — by that point the
    quarantine timestamp exists. For the workflow-ENTRY check where no
    quarantine point exists yet, use ``_detection_is_retrospective_backfill``
    instead — comparing against ``now`` there mis-buckets every recent real
    detection as retrospective.

    Conservative classification:
    - Requires AT LEAST ONE underlying event timestamp present. If the record
      has none, we can't make this call and return False.
    - Every present timestamp must predate ``since_ts_s``. A single event
      at-or-after that point means real new activity (or mixed — still not
      safely auto-close-able).
    - ``created_timestamp`` itself is NOT used in the comparison (it's always
      post-IR by construction; the envelope is fresh, the events are old).
    """
    underlying_ts = _underlying_event_timestamps(rec)
    if not underlying_ts:
        return False, None

    newest = max(underlying_ts)
    if newest >= since_ts_s:
        return False, None

    from datetime import datetime, timezone
    newest_iso = datetime.fromtimestamp(newest, tz=timezone.utc).isoformat()
    return True, (
        f"all underlying event timestamps predate Phase 1 quarantine "
        f"(newest underlying: {newest_iso})"
    )


# A retrospective backfill renders events that predate the fresh detection
# envelope by a wide margin. 24h cleanly separates true backfill (events
# days/weeks old) from a real detection of recent activity (envelope scored
# within minutes-to-hours of the event).
_RETRO_BACKFILL_MIN_GAP_S = 24 * 3600


def _detection_is_retrospective_backfill(
    rec: dict[str, Any], min_gap_seconds: float = _RETRO_BACKFILL_MIN_GAP_S
) -> tuple[bool, str | None]:
    """Workflow-ENTRY retrospective check — used at Phase 0 where there is no
    Phase 1 quarantine point to compare against yet.

    A retrospective IOC backfill has a FRESH ``created_timestamp`` (Falcon
    scored it just now) but underlying events that occurred long before — the
    matching engine surfaced stored history as a new-looking detection. The
    distinguishing signal is the GAP between ``created_timestamp`` and the
    newest underlying event, NOT whether the events are simply "older than
    now" (all events are). Comparing against ``now`` would mis-bucket every
    recent real detection as retrospective and FP-close real malware — the
    error class Phase 0's docstring calls unacceptable.

    Returns ``(True, reason)`` only when ALL hold:
    - at least one underlying event timestamp is present,
    - a parseable ``created_timestamp`` is present,
    - ``created_timestamp - newest_underlying_event >= min_gap_seconds``.

    Any uncertainty (missing timestamps, small gap) → ``(False, None)`` so the
    detection stays actionable and the workflow proceeds. Wasting a quarantine
    cycle on a borderline case is acceptable; FP-closing real malware is not.
    """
    underlying_ts = _underlying_event_timestamps(rec)
    if not underlying_ts:
        return False, None

    created = _parse_timestamp(rec.get("created_timestamp"))
    if created is None:
        return False, None

    newest = max(underlying_ts)
    gap = created - newest
    if gap < min_gap_seconds:
        return False, None

    from datetime import datetime, timezone
    newest_iso = datetime.fromtimestamp(newest, tz=timezone.utc).isoformat()
    hours = gap / 3600.0
    return True, (
        f"fresh detection envelope but newest underlying event is "
        f"{hours:.1f}h older than created_timestamp (newest underlying: "
        f"{newest_iso}) — Falcon IOC backfill, not new activity"
    )

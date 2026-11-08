"""Curated host-cleanup script library.

Mirrors the patching/library.py pattern: agent picks a script id from the
manifest and supplies validated params; the renderer concatenates an
auto-generated $Params block + the script body. No script bytes ever come
from the agent.

Distinct from patching/ in intent:
  - patching/ → vulnerability remediation (Spotlight-driven, version updates)
  - cleanup/  → incident-response remediation (persistence findings, kill
                process, stop service, remove registry value)

Reuses the render-time security primitives from patching.library —
_validate_params, _render_params_block, _ascii_coerce — so both catalogs
get the same regex enforcement, $Params encoding, and ASCII coercion. The
RTR transport (CloudFile upload + runscript) lives in patching.rtr and is
generic; cleanup tools call into it directly without duplication.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from patching.library import (
    _ascii_coerce,
    _render_params_block,
    _validate_params,
)

CLEANUP_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = CLEANUP_DIR / "manifest.json"


@dataclass(frozen=True)
class ResolvedCleanupPlan:
    script_id: str
    title: str
    os: str
    params: dict[str, Any]
    rendered: str
    preview: str
    intent: str


def load_manifest() -> dict[str, Any]:
    with MANIFEST_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def list_scripts(os_filter: str | None = None) -> list[dict[str, Any]]:
    manifest = load_manifest()
    scripts = manifest.get("scripts", [])
    if os_filter:
        scripts = [s for s in scripts if s.get("os") == os_filter]
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "os": s["os"],
            "intent": s.get("intent", ""),
            "params": s.get("params", {}),
        }
        for s in scripts
    ]


def find_by_id(script_id: str) -> dict[str, Any] | None:
    for s in load_manifest().get("scripts", []):
        if s["id"] == script_id:
            return s
    return None


def resolve_plan(
    script_id: str,
    supplied_params: dict[str, Any] | None = None,
    evidence_vouched_keys: set[str] | None = None,
) -> ResolvedCleanupPlan:
    spec = find_by_id(script_id)
    if not spec:
        raise ValueError(f"unknown cleanup script id: {script_id!r}")
    params = _validate_params(
        spec.get("params", {}),
        supplied_params or {},
        evidence_vouched_keys=evidence_vouched_keys,
    )

    parts: list[str] = [
        "# Rendered by falcon-extras cleanup/library.py\n"
        f"# script_id: {spec['id']}\n",
        _render_params_block(params, spec.get("os", "windows")),
    ]
    for preamble_rel in spec.get("preambles", []):
        parts.append((CLEANUP_DIR / preamble_rel).read_text(encoding="utf-8"))
    parts.append((CLEANUP_DIR / spec["script"]).read_text(encoding="utf-8"))
    rendered = _ascii_coerce("\n".join(parts))

    lines = rendered.splitlines()
    preview = "\n".join(lines[:40])
    if len(lines) > 40:
        preview += "\n# ... (truncated for preview)"

    return ResolvedCleanupPlan(
        script_id=spec["id"],
        title=spec["title"],
        os=spec["os"],
        params=params,
        rendered=rendered,
        preview=preview,
        intent=spec.get("intent", ""),
    )

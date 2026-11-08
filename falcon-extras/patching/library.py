"""Curated patch-script library.

Loads manifest.json, validates user-supplied params against per-script schemas,
and renders the final RTR script body by concatenating preambles + a generated
$Params block + the script body.

The agent never authors script bytes. It picks a script id from the catalog
and supplies parameters that are validated here. This is the boundary that
keeps RTR execution defensible: the only path from agent to a host shell is
through an id that resolves to a file on disk.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PATCHING_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = PATCHING_DIR / "manifest.json"


@dataclass(frozen=True)
class ResolvedPlan:
    script_id: str
    title: str
    os: str
    params: dict[str, Any]
    rendered: str
    preview: str
    reboot_risk: str
    expected_runtime_minutes: int
    read_only: bool


def load_manifest() -> dict[str, Any]:
    with MANIFEST_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def list_scripts(os_filter: str | None = None) -> list[dict[str, Any]]:
    manifest = load_manifest()
    scripts = manifest.get("scripts", [])
    if os_filter:
        scripts = [s for s in scripts if s.get("os") == os_filter]
    # Strip the on-disk path; surface only what the agent needs.
    return [
        {
            "id": s["id"],
            "title": s["title"],
            "os": s["os"],
            "params": s.get("params", {}),
            "expected_runtime_minutes": s.get("expected_runtime_minutes"),
            "reboot_risk": s.get("reboot_risk", "unknown"),
            "read_only": bool(s.get("read_only", False)),
            "spotlight_match": s.get("spotlight_match"),
        }
        for s in scripts
    ]


def find_by_id(script_id: str) -> dict[str, Any] | None:
    for s in load_manifest().get("scripts", []):
        if s["id"] == script_id:
            return s
    return None


# Linux package naming (Debian + RPM): lowercase letter or digit start,
# then any of [a-z0-9.+-], length 1..50. Same regex as the linux-pkg-upgrade
# param schema so render-time validation is self-consistent. Covers both
# apt-style ("openssh-server", "libcurl4") and dnf/yum-style ("openssh-server",
# "httpd", "ntfs-3g") names.
_LINUX_PACKAGE_RX = re.compile(r"^[a-z0-9][a-z0-9.+\-]{0,49}$")


def linux_pkg_fallback(product: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """When match_remediation returns no specific Linux script, try to
    extract a valid package name from the Spotlight remediation product
    string and route to the generic linux-pkg-upgrade script. The script
    detects apt / dnf / yum at runtime, so this single fallback covers
    every supported Linux distro.

    Spotlight Linux remediation products usually look like:
      "ntfs-3g 1:2022.10.3-1ubuntu4.4"   (apt)
      "openssh-server 1:9.0p1-1ubuntu8.4" (apt)
      "httpd 2.4.57-5.el9"                (dnf/yum)
    The package name is the first whitespace-separated token. Returns
    (spec, params) or None if no valid package name extractable. The
    package regex is the security boundary — anything with a shell
    metacharacter, quote, or whitespace fails the match and falls
    through to None (no script).
    """
    if not product:
        return None
    candidate = product.strip().split()[0].lower()
    if not _LINUX_PACKAGE_RX.fullmatch(candidate):
        return None
    spec = find_by_id("linux-pkg-upgrade")
    if not spec:
        return None
    return spec, {"package": candidate}


def match_remediation(
    vendor: str, product: str, os_filter: str | None = None
) -> dict[str, Any] | None:
    """Return the first script whose spotlight_match patterns match the
    Spotlight remediation entity's vendor + product. Deterministic — first
    declared match wins. os_filter narrows the catalog to one OS family
    ('windows' | 'linux' | 'macos') so cross-platform vendor matches
    (e.g. Google Chrome on Windows vs macOS) resolve correctly."""
    vendor = (vendor or "").strip()
    product = (product or "").strip()
    for s in load_manifest().get("scripts", []):
        if os_filter and s.get("os") != os_filter:
            continue
        match = s.get("spotlight_match")
        if not match:
            continue
        vp = match.get("vendor_pattern")
        pp = match.get("product_pattern")
        if vp and not re.search(vp, vendor):
            continue
        if pp and not re.search(pp, product):
            continue
        return s
    return None


def _validate_params(
    schema: dict[str, Any],
    supplied: dict[str, Any],
    evidence_vouched_keys: set[str] | None = None,
) -> dict[str, Any]:
    """Validate and fill defaults. Raises ValueError on invalid input.

    ``evidence_vouched_keys``: param names the caller has vouched for via a
    Falcon detection's evidence (the path appears in behaviors[]/cmdline_artifacts/
    etc. of a true-positive detection). For those keys, if the param spec
    defines an ``evidence_pattern``, the validator uses it instead of the
    strict ``pattern``. The evidence-pattern is still bounded — it bans
    Windows-invalid filename chars (``*?<>|"``) which would never appear in
    a legitimate path — but allows characters that attackers DO use in
    artifact names (``+=,;[]{}&#@!'``) and that the conservative default
    pattern rejects to keep the strict regex tight.

    The vouching is declarative on this layer; the audit trail (recorded by
    the caller) carries the operator-readable composite_id + source so the
    "why was the strict regex bypassed" question has a per-call answer.
    """
    resolved: dict[str, Any] = {}
    vouched = evidence_vouched_keys or set()
    for key, spec in schema.items():
        if key in supplied:
            value = supplied[key]
            t = spec.get("type")
            if t == "enum":
                values = spec.get("values", [])
                if value not in values:
                    raise ValueError(
                        f"param {key!r}: {value!r} not in {values}"
                    )
            elif t == "string":
                if not isinstance(value, str):
                    raise ValueError(f"param {key!r}: must be string")
                use_evidence = key in vouched and spec.get("evidence_pattern")
                pattern = spec.get("evidence_pattern") if use_evidence else spec.get("pattern")
                if pattern and not re.fullmatch(pattern, value):
                    raise ValueError(
                        f"param {key!r}: does not match pattern {pattern!r}"
                        + (" (evidence-vouched)" if use_evidence else "")
                    )
            else:
                raise ValueError(f"param {key!r}: unknown type {t!r}")
            resolved[key] = value
        elif "default" in spec:
            resolved[key] = spec["default"]
        elif spec.get("optional"):
            continue
        else:
            raise ValueError(f"param {key!r}: required, not supplied")
    # Reject unknown keys — fail closed.
    extra = set(supplied) - set(schema)
    if extra:
        raise ValueError(f"unknown params: {sorted(extra)}")
    return resolved


def _to_pwsh_literal(value: Any) -> str:
    """Render a Python value as a PowerShell literal. Strings are
    single-quoted with internal single-quotes doubled (PowerShell's escape).
    """
    if value is None:
        return "$null"
    if isinstance(value, bool):
        return "$true" if value else "$false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value).replace("'", "''")
    return f"'{s}'"


def _to_bash_literal(value: Any) -> str:
    """Render a Python value as a single-quoted bash literal. Single quotes
    inside the value are escaped via the standard '"'"' incantation. The
    parameter validation regex in _validate_params is the actual security
    boundary; this function only handles encoding, not sanitization.
    """
    if value is None:
        return "''"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value).replace("'", "'\"'\"'")
    return f"'{s}'"


# RTR's `runscript -Raw=...` does not deliver UTF-8 cleanly to the host's
# PowerShell session under SYSTEM context. Multi-byte characters become
# garbage bytes that break the parser. Backstop: coerce common smart
# punctuation to ASCII equivalents at render time, then drop anything
# remaining that isn't pure 7-bit ASCII.
_ASCII_SUBSTITUTIONS = {
    "—": "--",  # em dash
    "–": "-",   # en dash
    "…": "...", # ellipsis
    "‘": "'",   # left single quote
    "’": "'",   # right single quote
    "“": '"',   # left double quote
    "”": '"',   # right double quote
    " ": " ",   # non-breaking space
}


def _ascii_coerce(text: str) -> str:
    for src, dst in _ASCII_SUBSTITUTIONS.items():
        text = text.replace(src, dst)
    # Anything still non-ASCII gets stripped. We log it so contributors
    # notice; emitting to stderr surfaces it through MCP stdio inheritance.
    return text.encode("ascii", "replace").decode("ascii").replace("?", "")


def _render_params_block(params: dict[str, Any], os: str) -> str:
    """Render the params header in the language native to the target OS.
    Windows scripts get a PowerShell $Params hashtable; linux/macos scripts
    get bash-style UPPERCASE variable assignments (referenced as $PACKAGE,
    $REBOOT, etc. inside the script body).
    """
    if os == "windows":
        if not params:
            return "$Params = @{}\n"
        lines = ["$Params = @{"]
        for k, v in params.items():
            pkey = "".join(part.capitalize() for part in k.split("_"))
            lines.append(f"    {pkey} = {_to_pwsh_literal(v)}")
        lines.append("}\n")
        return "\n".join(lines)
    # bash (linux + macos). UPPERCASE conventional shell var names.
    if not params:
        return "# (no params)\n"
    lines = []
    for k, v in params.items():
        bkey = k.upper().replace("-", "_")
        lines.append(f"{bkey}={_to_bash_literal(v)}")
    return "\n".join(lines) + "\n"


def resolve_plan(
    script_id: str, supplied_params: dict[str, Any] | None = None
) -> ResolvedPlan:
    spec = find_by_id(script_id)
    if not spec:
        raise ValueError(f"unknown script id: {script_id!r}")
    params = _validate_params(spec.get("params", {}), supplied_params or {})

    parts: list[str] = []
    parts.append(
        "# Rendered by falcon-extras patching/library.py\n"
        f"# script_id: {spec['id']}\n"
    )
    parts.append(_render_params_block(params, spec.get("os", "windows")))
    for preamble_rel in spec.get("preambles", []):
        parts.append((PATCHING_DIR / preamble_rel).read_text(encoding="utf-8"))
    parts.append((PATCHING_DIR / spec["script"]).read_text(encoding="utf-8"))
    rendered = _ascii_coerce("\n".join(parts))

    preview_lines = rendered.splitlines()[:40]
    preview = "\n".join(preview_lines)
    if len(rendered.splitlines()) > 40:
        preview += "\n# ... (truncated for preview)"

    return ResolvedPlan(
        script_id=spec["id"],
        title=spec["title"],
        os=spec["os"],
        params=params,
        rendered=rendered,
        preview=preview,
        reboot_risk=spec.get("reboot_risk", "unknown"),
        expected_runtime_minutes=spec.get("expected_runtime_minutes", 0),
        read_only=bool(spec.get("read_only", False)),
    )

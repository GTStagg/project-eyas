"""Verify the falcon-extras sidecar registers every tool the frontend expects.

Reads expected_tools.json (sibling file), imports server.py, walks the FastMCP
registry, and exits non-zero with a clear error if any required tool is
missing — or if a safety-critical tool's pinned parameter contract has drifted.
Used by:
  - make-dist.sh after staging the sidecar into the bundle (catches a partial
    deploy before the bundle ships)
  - GET /api/health (parsed by lib/health.ts to surface missing_tools[] in the
    /status report — the operator-facing deploy verification)

expected_tools.json entries are either a plain string (name-only check) or an
object {"name": ..., "required_params": [...]}. The object form additionally
pins the agent-facing parameter contract for safety-critical write tools: every
listed param must still be REQUIRED in the registered tool's input schema, so a
modular-refactor wrapper-signature drift fails the build instead of NameError-ing
only when the tool fires at runtime. "Required" is asserted specifically — a
param that is merely present but demoted to optional (e.g. `device_ids:
list[str] = None`) is itself a contract regression for a gated write tool (the
agent could omit it), so presence alone is not enough.

Usage:
  python3 falcon-extras/verify_tools.py
  python3 falcon-extras/verify_tools.py --json    # machine-readable output

Exit codes:
  0 — every expected tool registered and every pinned param still required
  1 — a tool missing, a pinned param dropped or demoted to optional, or load failure
"""

from __future__ import annotations

import ast
import asyncio
import importlib
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
EXPECTED_PATH = HERE / "expected_tools.json"
SERVER_PATH = HERE / "server.py"


def _load_expected() -> list[dict[str, Any]]:
    """Normalize expected_tools.json into a list of {name, required_params}.

    Back-compat: a plain-string entry becomes {name, required_params: []}
    (name-only check). An object entry must carry a string `name` and, if
    present, a string-array `required_params`.
    """
    with EXPECTED_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)
    tools = data.get("tools")
    if not isinstance(tools, list):
        raise ValueError("expected_tools.json missing top-level 'tools' array")

    normalized: list[dict[str, Any]] = []
    for entry in tools:
        if isinstance(entry, str):
            normalized.append({"name": entry, "required_params": []})
        elif isinstance(entry, dict):
            name = entry.get("name")
            if not isinstance(name, str):
                raise ValueError(f"tool object entry missing string 'name': {entry!r}")
            params = entry.get("required_params", [])
            if not isinstance(params, list) or not all(
                isinstance(p, str) for p in params
            ):
                raise ValueError(
                    f"'required_params' must be a string array for {name!r}: {params!r}"
                )
            normalized.append({"name": name, "required_params": params})
        else:
            raise ValueError(f"tool entry must be a string or object, got: {entry!r}")
    return normalized


def _signature_params(fn: Any) -> set[str]:
    """Fallback param introspection: the underlying function's named params
    (excluding self/cls and *args/**kwargs)."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return set()
    out: set[str] = set()
    for pname, p in sig.parameters.items():
        if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if pname in ("self", "cls"):
            continue
        out.add(pname)
    return out


def _required_signature_params(fn: Any) -> set[str]:
    """Fallback for the REQUIRED set: named params with no default value
    (excluding self/cls and *args/**kwargs). A param with a default is optional,
    so it does NOT count as required — mirroring how FastMCP derives the schema's
    `required` array from the signature."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return set()
    out: set[str] = set()
    for pname, p in sig.parameters.items():
        if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if pname in ("self", "cls"):
            continue
        if p.default is inspect.Parameter.empty:
            out.add(pname)
    return out


def _params_for(tool: Any, fn: Any) -> set[str]:
    """The set of parameter names the agent sees for a tool. Prefers the
    generated JSON input schema (`required` ∪ `properties`); falls back to
    inspect.signature on the underlying fn for older FastMCP / a Tool with no
    inputSchema."""
    schema = getattr(tool, "inputSchema", None)
    names: set[str] = set()
    if isinstance(schema, dict):
        props = schema.get("properties")
        if isinstance(props, dict):
            names |= set(props.keys())
        req = schema.get("required")
        if isinstance(req, list):
            names |= {r for r in req if isinstance(r, str)}
    if names:
        return names
    if fn is not None:
        return _signature_params(fn)
    return names


def _required_params_for(tool: Any, fn: Any) -> set[str]:
    """The subset of parameters the agent is REQUIRED to supply. Prefers the
    JSON input schema's `required` array; falls back to inspect.signature
    (params with no default) when the schema declares no usable properties.

    The pinned-param drift check keys off THIS set rather than mere presence: a
    safety-critical param that survives in `properties` but vanishes from
    `required` (demoted to optional) is still a contract regression."""
    schema = getattr(tool, "inputSchema", None)
    if isinstance(schema, dict) and isinstance(schema.get("properties"), dict):
        # Schema is authoritative once it declares properties. No `required`
        # key means nothing is required → empty set (any pinned param is drift).
        req = schema.get("required")
        return {r for r in req if isinstance(r, str)} if isinstance(req, list) else set()
    if fn is not None:
        return _required_signature_params(fn)
    return set()


def _lazy_impl_imports() -> list[str]:
    """Root module names imported *inside* server.py's tool bodies.

    Every tool wrapper delegates to a cluster module via a function-body
    import (``from exclusions import list_ml_exclusions
    as _impl``). Those imports don't execute on ``import server`` — only when
    the tool fires — so a missing/flattened cluster package sails past the
    registration check above and only ModuleNotFoundErrors at runtime
    ("sidecar returned non-JSON" on the /config cards). Parse the AST and
    collect the top-level module of every import nested in a function body so
    we can resolve them at build time.
    """
    try:
        tree = ast.parse(SERVER_PATH.read_text(encoding="utf-8"), filename=str(SERVER_PATH))
    except Exception:
        return []
    roots: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for sub in ast.walk(node):
            if isinstance(sub, ast.ImportFrom):
                # level > 0 is a relative import (none expected here); skip.
                if sub.level == 0 and sub.module:
                    roots.add(sub.module.split(".")[0])
            elif isinstance(sub, ast.Import):
                for alias in sub.names:
                    roots.add(alias.name.split(".")[0])
    # Only care about the sidecar's own cluster packages/modules — a dropped
    # third-party dep is a separate failure surface (wheels). Restrict to names
    # that resolve to a file/dir in the sidecar tree.
    local: list[str] = []
    for root in sorted(roots):
        if (HERE / root).is_dir() or (HERE / f"{root}.py").is_file():
            local.append(root)
    return local


def _verify_lazy_imports() -> list[dict[str, str]]:
    """Import every sidecar module a tool body lazily depends on. Returns a
    list of {module, error} for any that fail — empty means all resolved."""
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    failures: list[dict[str, str]] = []
    for mod in _lazy_impl_imports():
        try:
            importlib.import_module(mod)
        except Exception as exc:  # noqa: BLE001
            failures.append({"module": mod, "error": f"{type(exc).__name__}: {exc}"})
    return failures


def _load_registered() -> dict[str, tuple[set[str], set[str]]]:
    """Map every registered tool name to (all_params, required_params)."""
    # Make sure the sidecar's own dir is importable, regardless of cwd.
    if str(HERE) not in sys.path:
        sys.path.insert(0, str(HERE))
    # Avoid double-spawning the FastMCP stdio loop on import — server.py only
    # calls mcp.run() under `if __name__ == "__main__":`, so a plain `import`
    # registers tools without starting the server.
    os.environ.setdefault("FALCON_CLIENT_ID", "verify-only")
    os.environ.setdefault("FALCON_CLIENT_SECRET", "verify-only")
    import server  # noqa: F401

    mcp = server.mcp

    # Build a name -> underlying fn map from the tool manager for the
    # inspect.signature fallback (older FastMCP, or a Tool without inputSchema).
    fn_by_name: dict[str, Any] = {}
    manager = getattr(mcp, "_tool_manager", None)
    if manager is not None and hasattr(manager, "_tools"):
        for name, tool_obj in manager._tools.items():
            fn = getattr(tool_obj, "fn", None)
            if fn is not None:
                fn_by_name[name] = fn

    # FastMCP exposes registered tools via list_tools() (async). Fall back to
    # the tool-manager fn map (older FastMCP) for resilience.
    try:
        tools = asyncio.run(mcp.list_tools())
        return {
            t.name: (
                _params_for(t, fn_by_name.get(t.name)),
                _required_params_for(t, fn_by_name.get(t.name)),
            )
            for t in tools
        }
    except Exception:
        if fn_by_name:
            return {
                name: (_signature_params(fn), _required_signature_params(fn))
                for name, fn in fn_by_name.items()
            }
        raise


def main() -> int:
    json_mode = "--json" in sys.argv
    try:
        expected = _load_expected()
    except Exception as exc:
        msg = f"failed to load {EXPECTED_PATH}: {exc}"
        if json_mode:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    try:
        registered = _load_registered()
    except Exception as exc:
        msg = f"failed to load sidecar tool registry: {exc}"
        if json_mode:
            print(json.dumps({"ok": False, "error": msg}))
        else:
            print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    # Resolve every module a tool body lazily imports. This is the guard that
    # catches a cluster package dropped/flattened by the bundler (e.g. the
    # v0.8.5 BSD-cp trailing-slash regression) — registration alone can't,
    # because these imports only fire when the tool runs.
    lazy_failures = _verify_lazy_imports()

    expected_names = {t["name"] for t in expected}
    missing = [t["name"] for t in expected if t["name"] not in registered]
    extra = sorted(set(registered.keys()) - expected_names)

    # Param-contract drift: for entries that pin required_params, every pinned
    # param must still be REQUIRED in the registered tool's schema. Two failure
    # shapes, reported distinctly: the param vanished entirely (missing), or it
    # survives in the schema but is no longer required (demoted to optional).
    # Only checked for tools that ARE registered (a missing tool is reported
    # above).
    param_drift: list[dict[str, Any]] = []
    for t in expected:
        name = t["name"]
        req_params = t["required_params"]
        if not req_params or name not in registered:
            continue
        all_have, required_have = registered[name]
        missing_params = [p for p in req_params if p not in all_have]
        optional_params = [
            p for p in req_params if p in all_have and p not in required_have
        ]
        if missing_params or optional_params:
            param_drift.append(
                {
                    "name": name,
                    "missing_params": missing_params,
                    "optional_params": optional_params,
                    "schema_params": sorted(all_have),
                }
            )

    ok = not missing and not param_drift and not lazy_failures

    if json_mode:
        print(
            json.dumps(
                {
                    "ok": ok,
                    "expected_count": len(expected),
                    "registered_count": len(registered),
                    "missing": missing,
                    "param_drift": param_drift,
                    "lazy_import_failures": lazy_failures,
                    "extra": extra,
                }
            )
        )
        return 0 if ok else 1

    if missing:
        print("FAIL — expected tools not registered on the sidecar:", file=sys.stderr)
        for name in missing:
            print(f"  - {name}", file=sys.stderr)
        print(
            f"\n{len(missing)} of {len(expected)} expected tools are missing "
            f"(sidecar registers {len(registered)}).",
            file=sys.stderr,
        )

    if param_drift:
        print(
            "FAIL — safety-critical tools dropped or demoted a pinned parameter:",
            file=sys.stderr,
        )
        for d in param_drift:
            parts = []
            if d["missing_params"]:
                parts.append(f"missing {d['missing_params']}")
            if d["optional_params"]:
                parts.append(f"no longer required (now optional) {d['optional_params']}")
            print(
                f"  - {d['name']}: {'; '.join(parts)} "
                f"(schema exposes {d['schema_params']})",
                file=sys.stderr,
            )
        print(
            "\nA pinned param dropped out of the agent-facing schema's required "
            "set — a gated write tool's contract drifted (the agent could now omit "
            "it). Fix the wrapper signature in server.py or update required_params "
            "in expected_tools.json if the change is intentional.",
            file=sys.stderr,
        )

    if lazy_failures:
        print(
            "FAIL — cluster modules a tool body imports are not importable:",
            file=sys.stderr,
        )
        for f in lazy_failures:
            print(f"  - {f['module']}: {f['error']}", file=sys.stderr)
        print(
            "\nA sidecar package/module a tool lazily imports can't be loaded. "
            "In the bundle this is almost always a staging bug that dropped or "
            "flattened the package directory (see the make-dist.sh BSD-cp "
            "trailing-slash note) — the tool would ModuleNotFoundError at call "
            "time and surface as 'sidecar returned non-JSON' on the /config cards.",
            file=sys.stderr,
        )

    if missing or param_drift or lazy_failures:
        return 1

    pinned = sum(1 for t in expected if t["required_params"])
    print(
        f"OK — all {len(expected)} expected tools registered "
        f"({pinned} with pinned param contracts, all intact; "
        f"sidecar registers {len(registered)} total; "
        f"{len(extra)} not in expected_tools.json — these are sidecar-internal "
        f"or newly added)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

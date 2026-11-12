"""falcon-extras: the Python add-on (sidecar) holding the Eyas tools that
have not yet moved into the console.

It plugs into the same agent loop as eyas-mcp, with no protocol-level
differences. It is being retired: Eyas's own tools move into lib/eyas-tools/
one family at a time, and generic Falcon operations belong in eyas-mcp.

Transport: stdio. The Next.js process spawns this as a child and the lifecycle
follows the dev server.
"""

from __future__ import annotations

import json
import os
import sys
from importlib import metadata
from typing import Any

from mcp.server.fastmcp import FastMCP


# All cluster-specific imports (FalconPy clients etc.) live in the per-cluster
# impl modules now. Each @mcp.tool()
# wrapper below pulls what it needs lazily inside the function body.

LARGE_BATCH_THRESHOLD = 25


# Strict input validation for Recon FQL — anything that fails these regexes is
# rejected before being interpolated into a filter string. Recon's filter
# language is FQL; single quotes are the literal delimiter, so a value
# containing one would either error or change query semantics. The patterns
# here only accept characters that are unambiguously safe inside a single-
# quoted FQL literal.


mcp = FastMCP("falcon-extras")


def _pkg_version(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "unknown"


@mcp.resource("falcon-extras://about")
def about() -> str:
    """Runtime metadata about this sidecar — surfaced on the app's /status page
    so operators can see exactly what versions are running without shelling in.
    """
    payload = {
        "name": "falcon-extras",
        "purpose": "Retired: every add-on tool now runs in the console itself. This process registers no tools and is removed in the next release.",
        "python": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "falconpy": _pkg_version("crowdstrike-falconpy"),
        "mcp_sdk": _pkg_version("mcp"),
        "required_falcon_scopes": [
            "Hosts:write",  # containment
            "Real Time Response:read",  # patch-plan resolve (catalog only, no host I/O yet)
            "Real Time Response (Admin):write",  # reserved for run_patch (Phase 2)
            "Host Group:read",  # /host-groups surface listing
            "Host Group:write",  # add/remove members on static groups
            "Workflow:read",  # /workflows surface listing
            "Workflow:write",  # on-demand execute
            "Identity Protection Entities:read",  # /identity surface
            "Identity Protection Detections:read",
            "Identity Protection Timeline:read",
            "NGSIEM Data Connections API:read",  # /ngsiem pipeline-health strip — list_data_connections (third-party connectors only)
            "NGSIEM Lookup Files:read",  # /ngsiem pipeline-health strip — list_lookup_files (search_domain=search-all)
            "NGSIEM Parsers:read",  # /ngsiem pipeline-health strip — list_parsers (repository=search-all)
            "Cloud Security API Detections:read",  # cloud module (falcon-mcp 0.10.0) — IOA/IOM findings
            "Cloud Security API Assets:read",  # cloud module (falcon-mcp 0.10.0) — cloud asset inventory
        ],
        "base_url": os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com"),
        "member_cid_set": bool(os.environ.get("FALCON_MEMBER_CID")),
    }
    return json.dumps(payload)


if __name__ == "__main__":
    try:
        mcp.run()
    except Exception as exc:  # pragma: no cover - surface fatal init errors
        print(f"falcon-extras fatal: {exc}", file=sys.stderr)
        sys.exit(1)

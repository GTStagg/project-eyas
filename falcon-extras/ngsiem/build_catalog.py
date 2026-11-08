"""Scrape LogScale's Query Functions index into a JSON catalog.

LogScale (the engine behind NGSIEM) ships a single index page listing every
documented query function with its signature, category, default argument, and
description: https://library.humio.com/data-analysis/functions.html

This script fetches that page once and produces ``catalog.json`` next to
itself. The catalog is the source of truth for both the CQL linter
(``syntax.py``). The agent-facing function lookup is eyas-mcp's native
``falcon_lookup_cql_function`` (its own shipped catalog).

Run manually after a LogScale doc release:

    python3 falcon-extras/ngsiem/build_catalog.py

Output is committed to the repo so the sidecar works offline (standalone
bundles, air-gapped deployments).
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

SOURCE_URL = "https://library.humio.com/data-analysis/functions.html"
OUTPUT = Path(__file__).parent / "catalog.json"


def _strip_tags(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s)


def _normspace(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


SIG_RX = re.compile(r"([A-Za-z][A-Za-z0-9:]*)\(([^)]*)\)")


def parse_signature(sig: str) -> tuple[str | None, list[dict[str, object]]]:
    """Pull function name + parameter list from a signature like
    ``array:sort(array, [asArray], [order], [type])``.

    Returns (name, params) where each param is
    ``{"name": str, "required": bool}``. Brackets denote optional.
    """
    m = SIG_RX.match(sig.strip())
    if not m:
        return None, []
    name = m.group(1)
    body = m.group(2).strip()
    if not body:
        return name, []
    params: list[dict[str, object]] = []
    # Split on commas, respecting that brackets don't nest in these signatures.
    for raw in body.split(","):
        token = raw.strip()
        if not token:
            continue
        if token.startswith("[") and token.endswith("]"):
            params.append({"name": token[1:-1].strip(), "required": False})
        else:
            params.append({"name": token, "required": True})
    return name, params


class IndexTableParser(HTMLParser):
    """Walk the single ``<table summary="Query Functions">`` and emit one
    record per ``<tr>``."""

    def __init__(self) -> None:
        super().__init__()
        self._in_table = False
        self._in_row = False
        self._cell_html: list[str] = []
        self._cells: list[str] = []
        self._depth_in_cell = 0
        self.records: list[dict[str, object]] = []
        self._table_depth = 0  # nested tables (Note boxes etc.)

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "table":
            if self._in_table:
                self._table_depth += 1
            elif d.get("summary") == "Query Functions":
                self._in_table = True
                self._table_depth = 0
            return
        if not self._in_table or self._table_depth > 0:
            if self._in_table and self._depth_in_cell:
                self._cell_html.append(self._tag_str(tag, attrs))
            return
        if tag == "tr":
            self._in_row = True
            self._cells = []
        elif tag in ("td", "th"):
            self._cell_html = []
            self._depth_in_cell = 1
        elif self._depth_in_cell:
            self._depth_in_cell += 0  # inner tags counted by their own start
            self._cell_html.append(self._tag_str(tag, attrs))

    def handle_endtag(self, tag):
        if tag == "table":
            if self._table_depth > 0:
                self._table_depth -= 1
            elif self._in_table:
                self._in_table = False
            return
        if not self._in_table or self._table_depth > 0:
            return
        if tag in ("td", "th"):
            self._cells.append("".join(self._cell_html))
            self._depth_in_cell = 0
        elif tag == "tr":
            if self._cells and len(self._cells) >= 5:
                self._emit(self._cells)
            self._in_row = False
        elif self._depth_in_cell:
            self._cell_html.append(f"</{tag}>")

    def handle_data(self, data):
        if self._in_table and self._depth_in_cell:
            self._cell_html.append(data)

    @staticmethod
    def _tag_str(tag: str, attrs: list[tuple[str, str | None]]) -> str:
        attr_str = "".join(
            f' {k}="{v}"' if v is not None else f" {k}" for k, v in attrs
        )
        return f"<{tag}{attr_str}>"

    def _emit(self, cells: list[str]) -> None:
        # Cell 0: <a href="functions-X.html"><code class="function">name(params)</code></a>
        sig_match = re.search(r'<code class="function">([^<]+)</code>', cells[0])
        href_match = re.search(r'href="(functions-[^"]+\.html)"', cells[0])
        if not sig_match:
            return
        signature = sig_match.group(1).strip()
        name, params = parse_signature(signature)
        if not name:
            return
        categories = [
            _normspace(_strip_tags(t))
            for t in re.findall(r"<a[^>]*>([^<]+)</a>", cells[1])
        ]
        default_arg = _normspace(_strip_tags(cells[2])) or None
        availability = _normspace(_strip_tags(cells[3])) or None
        description = _normspace(_strip_tags(cells[4]))
        self.records.append(
            {
                "name": name,
                "signature": signature,
                "params": params,
                "categories": categories,
                "default_arg": default_arg,
                "availability": availability,
                "description": description,
                "doc_url": f"https://library.humio.com/data-analysis/{href_match.group(1)}"
                if href_match
                else None,
            }
        )


def main() -> int:
    print(f"fetching {SOURCE_URL}", file=sys.stderr)
    req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "falcon-mcp-catalog-builder/0.1"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        html = resp.read().decode("utf-8", errors="replace")

    parser = IndexTableParser()
    parser.feed(html)
    records = parser.records
    if not records:
        print("ERROR: parsed zero records — index format may have changed", file=sys.stderr)
        return 1

    records.sort(key=lambda r: r["name"])
    catalog = {
        "source": SOURCE_URL,
        "function_count": len(records),
        "functions": records,
    }
    OUTPUT.write_text(json.dumps(catalog, indent=2) + "\n")
    print(
        f"wrote {OUTPUT} — {len(records)} functions ({records[0]['name']} … {records[-1]['name']})",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

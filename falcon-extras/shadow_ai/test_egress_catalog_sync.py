"""The AI-egress catalog is shared with Eyas.

Eyas's IR detection classifiers (lib/eyas-tools/ir/detection-classifiers.ts)
read lib/eyas-tools/ai-egress-catalog.json to recognise Shadow-AI audit IOC
fires; the sidecar's Shadow-AI tools still read AI_EGRESS_CATALOG here. This
test fails when the two drift. Regenerate the JSON after editing the catalog:

    cd falcon-extras && python -c "import json; from shadow_ai.catalog import AI_EGRESS_CATALOG as C; \
open('../lib/eyas-tools/ai-egress-catalog.json','w',newline='\\n').write(json.dumps([{'pattern':a,'tool':t,'posture':p} for a,t,p in C],indent=2,ensure_ascii=False)+'\\n')"

Run:
    falcon-extras/.venv/bin/python3 falcon-extras/shadow_ai/test_egress_catalog_sync.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from shadow_ai.catalog import AI_EGRESS_CATALOG  # noqa: E402

JSON_PATH = HERE.parent.parent / "lib" / "eyas-tools" / "ai-egress-catalog.json"


def test_json_matches_python_catalog():
    rows = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    as_tuples = [(r["pattern"], r["tool"], r["posture"]) for r in rows]
    assert as_tuples == list(AI_EGRESS_CATALOG), (
        "lib/eyas-tools/ai-egress-catalog.json is out of date with "
        "shadow_ai/catalog.py AI_EGRESS_CATALOG; regenerate it (see module docstring)"
    )


if __name__ == "__main__":
    test_json_matches_python_catalog()
    print("1 passed")

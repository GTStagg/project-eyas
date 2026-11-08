---
name: verify-patch
description: Use after writing or editing a falcon-extras patching script + manifest entry. Runs the canonical render + spotlight-match + non-ASCII smoke test for one or more script ids. Trigger phrases: "verify the script", "smoke-test the patch", "does the new manifest entry render", "check spotlight matching".
---

# verify-patch

Smoke-test one or more patching catalog entries end-to-end before considering the work done.

## Inputs

The user (or you, post-edit) supplies a script id (e.g. `app-zoom`) and optionally a list of `(vendor, product)` pairs the entry should resolve to. If no spotlight cases are given, infer two or three plausible Spotlight remediation strings from the script's purpose and check those.

## What to run

From the repo root, invoke the verifier:

```bash
bash .claude/skills/verify-patch/run.sh <script_id> [<script_id> ...]
```

The script renders each plan via `library.resolve_plan`, prints body length / runtime / reboot risk / non-ASCII byte count, and confirms the spotlight pattern matches the demo cases bundled in the script.

## Pass criteria

- `resolve_plan` returns without exception
- `non-ascii=0` on every rendered body (RTR strips non-ASCII bytes — they break the host parser)
- For entries with a `spotlight_match`, the canonical demo `(vendor, product)` pair routes back to the same id (regression-tests first-declared-wins ordering)

## Fail handling

- **`unknown script id`** → manifest entry missing or typo'd; re-check `manifest.json`.
- **`non-ascii > 0`** → `_ascii_coerce` is the backstop, but source files should be clean. `grep -nP '[^\x00-\x7F]' <file>` to find offenders.
- **Wrong id resolved by `match_remediation`** → another manifest entry's pattern is shadowing yours. Move the new entry earlier in the manifest, or tighten the colliding pattern.
- **`TypeError: resolve_plan() takes ...`** → API drifted; re-read `library.py` to find the current call signature.

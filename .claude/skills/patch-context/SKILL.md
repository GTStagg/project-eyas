---
name: patch-context
description: Use when about to add, modify, or audit an entry in Eyas's patching catalog. Loads manifest.json, library.ts, and the Agentic-patching section of CLAUDE.md into context as a single bootstrap so subsequent edits don't need to re-discover the conventions. Trigger phrases: "add a patch script", "new RTR script", "another curated remediation", "patching catalog", "manifest entry".
---

# patch-context

Bootstrap the working set for any change to `lib/eyas-tools/rtr/patching/`.

## What to do

Run these reads in parallel — every catalog edit needs all three:

1. `Read lib/eyas-tools/rtr/patching/manifest.json` (full file)
2. `Read lib/eyas-tools/rtr/library.ts` (full file — `resolvePlan`, `matchRemediation`, `validateParams`, `asciiCoerce` are all load-bearing)
3. `Read CLAUDE.md` and locate the "Agentic patching (the curated RTR script library)" section — read at least that section plus the surrounding context

Then list `lib/eyas-tools/rtr/patching/scripts/windows/`, `scripts/linux/`, `scripts/macos/` to see what's already on disk.

## Conventions worth re-reading every time

- **Manifest order is first-declared-wins** for spotlight remediation matching. Place narrow patterns (e.g. `win-wsl-update`) ahead of broad ones (e.g. `win-update-install`).
- **Scripts must be ASCII.** `asciiCoerce` is a backstop (it drops anything non-ASCII after mapping smart punctuation); source files should be clean. No em-dashes (—), smart quotes, or ellipses (…) in `.ps1` / `.sh` files.
- **Params are validated by `validateParams` against the manifest schema.** Unknown keys are rejected. Enum + regex enforced (fullmatch semantics; a leading `(?i)` becomes the JS `i` flag — JS has no other inline flags, so don't use them).
- **Windows MSI installers go through `_lib/msi-installer.ps1::Install-FromUrl`** — never reinvent the download/install dance. Direct EXE installers pass `-SilentArgs` per-vendor.
- **Windows Update payloads use the WUA COM API** (`Microsoft.Update.Session`), never PSWindowsUpdate. See `windows-update-install.ps1` as the canonical example.
- **RTR transport is CloudFile-only** (eyas-mcp's one-off private script, `lib/mcp/native-dispatch.ts`). Inline `runscript -Raw=` corrupts single-quote bodies.

## After editing

Always run `/verify-patch <script_id>` to confirm the manifest entry resolves, the rendered body is ASCII, and the spotlight pattern matches the intended remediation strings.

If a new entry is broadly user-visible (new OS, new install method, new param), update the patching paragraph in CLAUDE.md so the catalog list stays current.

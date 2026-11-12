---
name: audit-remediations
description: Use when deciding which patching scripts to add next, or auditing whether existing scripts still cover the live tenant. Hits the dev server's /vulnerabilities page, extracts every recommended-remediation string, buckets them by vendor/product, and prints uncovered remediations ranked by host count. Trigger phrases: "what scripts should we add next", "audit remediations", "what's uncovered", "which patches are surfaced".
---

# audit-remediations

Re-pull the live Spotlight remediation surface and diff against the patching catalog.

## Prerequisites

- Dev server up at `http://localhost:3000` (the `/vulnerabilities?mode=newest&limit=2000` route renders the Spotlight fanout).
- Falcon credentials valid in the running process — without them the page renders but every row is a 403.

If the dev server isn't up, ask the user to run `npm run dev` (or `docker compose up -d` for the container path) first. Don't try to start it for them.

## What to run

```bash
bash .claude/skills/audit-remediations/run.sh
```

The script:
1. `curl`s the rendered HTML.
2. Greps every `Update <Vendor> <Product>...` / `Install patch for ...` remediation string.
3. Buckets by leading-vendor token (Mozilla, Microsoft Windows, Microsoft Office family, Notepad++, etc.).
4. For each bucket, looks up whether a manifest entry covers it via `matchRemediation` (`lib/eyas-tools/rtr/library.ts`, called through `scripts/rtr-library-cli.mjs match`) on a representative string.
5. Prints two ranked tables: **covered** (with the script id that handles it, host-count high-to-low) and **uncovered** (host-count high-to-low, candidate for next-batch curation).

## Reading the output

- **High-count uncovered** → strong candidates for the next `/add-patch-script` cycle.
- **Covered but suspicious** → e.g. an `app-firefox` row showing thousands of hits across many version targets is fine; an `app-7zip` row with zero hits means the curated script may have stopped routing (vendor pattern drift) and is worth a manual check via `/verify-patch`.
- **Linux kernel CVE descriptions** (`Update the last_gc value...`, `Remove the xhci_initialize_ring_info()...`) are noise from grepping CVE description text — the script filters obvious cases but expect a few in the uncovered list.

## Note for one-off audits

If the user wants the audit but the dev server isn't reachable (remote work, broken local stack), say so explicitly. There is no offline fallback — Spotlight data is tenant-specific and not in the repo.

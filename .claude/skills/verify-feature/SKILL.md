---
name: verify-feature
description: Use immediately after implementing a change to confirm it actually works end-to-end before declaring the task done. Routes by surface — UI changes run Playwright, API changes run curl/fetch probes, Eyas-tool / MCP changes run the tool's test suite plus a direct probe on eyas-mcp. Trigger phrases: "verify the change", "smoke this end-to-end", "did the wizard work", "test it for real".
---

# verify-feature

Don't trust typecheck + build as proof a feature works. Type errors are necessary, not sufficient. This skill is the discipline of running the actual change before reporting success.

## Step 1 — Identify the surface(s) you touched

Before picking a verification path, read your own diff (`git diff --stat`) and classify each changed file:

| File pattern | Surface | Verification path |
|---|---|---|
| `app/**/page.tsx`, `app/**/form.tsx`, `components/**` | UI | **Playwright** |
| `app/api/**/route.ts`, `app/**/actions.ts` | HTTP / server action | **curl probe** (with auth cookie) |
| `lib/mcp/**`, `lib/llm/**`, `lib/health.ts` | server-side glue | **boot probe** + targeted curl |
| `lib/eyas-tools/**` | Eyas's in-process agent tools | **direct tool probe** against a fake or live eyas-mcp |
| `lib/config/**`, `lib/auth/**`, `middleware.ts` | runtime config / auth | **session probe** + at least one gated route fetch |
| `make-dist.sh`, `start.sh` | bundling / launch | **/validate-bundle** skill (separate) |

A change usually crosses two of these — e.g. the wizard touched UI (`app/register/`) AND server actions (`actions.ts`) AND runtime config (`lib/config/`). Run the verification for **each** affected row, not just the heaviest one.

## Step 2 — UI changes: Playwright

**Prereqs:**
- Dev server is running on `:3000` (don't start it yourself — the user runs `npm run dev` outside Claude shells; ask them to start it if it's down).
- `AUTH_SESSION_SECRET` is exported in your shell so `tests/auth.setup.ts` can seal a valid session cookie. The fastest way:
  ```sh
  set -a; source .env.local; set +a
  ```

**Targeted verification (recommended):**
- If the change has an existing spec or you can write a one-shot one, prefer that over the full smoke. Naming convention: `tests/<feature>.spec.ts` (see `investigate-bl.spec.ts`, `patch-plan-button.spec.ts` for examples).
- Run a single spec: `npx playwright test tests/<feature>.spec.ts --reporter=list`.
- For a brand-new spec on a screen that doesn't have one yet (e.g. the /register wizard), write the spec, run it, and KEEP it — these specs become the living regression suite.

**Spec discipline:** the smoke spec (`tests/smoke.spec.ts`) is intentionally LOOSE — HTTP < 400, no `/login` bounce, AppShell rendered, no console errors. Don't add UI-copy assertions there; they rot every release. Tight assertions belong in per-feature specs where the tightness is the whole point.

**Broad verification:**
- `npm run test:smoke` — 8 pages × 3 viewports + chat round-trip. Slower but catches collateral damage on pages you didn't think you touched.

**Pass criteria:**
- All assertions green.
- Zero filtered console errors (the existing helper `filterDevModeNoise` strips Next dev-mode caret-color noise; anything else is a real bug).

**Common failures:**
- `redirected to /login` → AUTH_SESSION_SECRET in your test shell doesn't match the server's. Re-`source .env.local`.
- `Cannot find module 'iron-session'` from `auth.setup.ts` → you're running playwright without going through the project's tsconfig path resolution. `npx playwright test` (not `playwright test`) picks up the right config.
- Hydration warning that's NOT caret-color → real React 19 mismatch in your code. Read the warning's diff carefully — usually a server/client boundary leaked a date/random value.

## Step 3 — API / server-action changes: curl probe

For server actions and API routes, use a curl probe with the same sealed cookie the smoke tests use. After running `tests/auth.setup.ts` once, the cookie value lives in `tests/.auth/state.json`:

```sh
COOKIE=$(jq -r '.cookies[] | select(.name=="falcon_mcp_session") | .value' tests/.auth/state.json)
curl -sS -b "falcon_mcp_session=$COOKIE" http://127.0.0.1:3000/api/<route> | jq .
```

If `tests/.auth/state.json` doesn't exist yet, prime it:
```sh
npx playwright test tests/auth.setup.ts
```

For a server action (e.g. `registerAction`, `testConnectionAction`), drive it through the page that hosts it via Playwright instead — server actions accept multipart form data and are easier to exercise from a test than via raw curl.

## Step 4 — Eyas tool / MCP changes: direct probe

1. Unit-level: the tool's `scripts/test-*.mjs` suite runs it against a fake eyas-mcp (`callNative` / `searchNative` handlers). Add a case for the change.
2. Live: write a one-shot `node_modules/tsx` script that stubs `server-only`, opens `withFalconMcpClient`, builds `makeEyasToolContext(client)` and calls the tool's impl with a real input (load `.env` first for `AUTH_SESSION_SECRET`, and put `uvx` on PATH). Print the raw native response — don't paraphrase — and print shapes and error text, not tenant records.
3. Delete the probe when done.

Use when:
- You added/changed a tool in `lib/eyas-tools/`.
- You changed the RTR script library (`lib/eyas-tools/rtr/`): run `/verify-patch` and `node scripts/test-rtr-library.mjs` instead.
- You suspect an agent's reported failure is a hallucination.

For an end-to-end check of what the agent sees, open `/agent-toolbox` (or fetch `/api/agent-toolbox-catalog?force=1`).

## Step 5 — Runtime config / auth changes

These cross the auth boundary so the verification has to actually authenticate.

**Wizard / register flow:** Playwright spec that:
1. Deletes `data/auth.json` (or sets `FALCON_DATA_DIR` to a temp dir for isolation).
2. Hits `/register`, fills step 1 + step 2, clicks Test connection, asserts response, submits.
3. Verifies redirect to `/`.
4. Reads `data/config.json` and `data/auth.json` and asserts the expected shape.
5. Cleans up.

**Provenance badge logic:** unit-test-style — call `getConfigStatus()` directly with various env / config.json combos and assert source labels.

**Approval gates / write-tool registry:** drive a chat session via Playwright that triggers a write tool, assert the approval prompt appears, deny it, assert no Falcon write happened.

## Step 6 — Report

In your turn-end summary, name what you ran and what it asserted. Examples:

- ✅ "Ran `npx playwright test tests/wizard.spec.ts` — all 4 assertions green; data/config.json contains expected anthropic.authToken + falcon.clientId entries."
- ❌ "Ran the falconscript validator probe; got `{ok: false, error: '...'}` as expected for missing json_input. Then ran with json_input set; got 200 and the expected stdout JSON."

If you didn't or couldn't verify a surface, **say so explicitly** — "Tests for the IR phase 4 path require a real host AID + Falcon scope; verified static (typecheck + render-time validators) only." Don't claim end-to-end without running it.

## Anti-patterns

- Running `npx tsc --noEmit && npm run build` and calling that "verified". It isn't — those check the code compiles, not that the feature works.
- Running the full `test:smoke` when you changed one page and a single spec would have told you faster.
- Trusting an agent's narrative summary of a failure ("cmdlet not found") without the raw response. Always read stderr / exit_code / errors[] yourself.
- Writing probe scripts that get committed. Probes go in `/tmp` and get deleted at the end of the verification.
- **Asserting on derived metadata instead of user-visible output.** This is the silent-failure trap. The header "vulns · 12 hosts" is computed off the items array; the visible "By patch (N) / By host (N)" tabs and rendered table rows are what the user actually sees. A partial-failure (e.g. remediation enrichment 400s, items have no fix data, the `hasFix` filter drops them at render time) leaves metadata intact while the table goes empty. The Spotlight `id:[...]` 400 shipped past a green spec for exactly this reason — I asserted "12 hosts in the banner" when "By patch (0)" was the bug. Always assert at least one row is visible under the default filter chips, AND that the count tabs / pagination labels are non-zero. Treat upstream tool errors that go to falcon-mcp stderr (not the browser console) as invisible to your spec — your only defense is checking the visible output, not the console-error filter.

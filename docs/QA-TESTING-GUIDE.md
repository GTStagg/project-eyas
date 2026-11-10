# QA / Dev Testing Guide

Manual validation playbook for Eyas. One section per surface — how to trigger it, what the expected behavior is, what "broken" looks like, and where the audit trail lands. Use this as the human regression sweep before tagging a release, or to validate a single surface after touching it.

**Companion automation** (run these first; they catch the cheap regressions):

- `npm run typecheck` — strict TS; runs `next typegen` first via `pretypecheck`.
- `npm run lint` — ESLint flat config.
- `npm run test:sidecar` — Python sidecar pure-function suites (UnionFind, RTR-preamble + retrospective classifiers, ledger matcher, CQL linter).
- `npx playwright test` — Playwright E2E (auth seal happens via `tests/auth.setup.ts`).
- `/audit-write-tools` — every write-shape tool is approval-gated.
- `/audit-remediations` — patching catalog covers live Spotlight remediations.
- `/validate-bundle` — after `./make-dist.sh`, before shipping.

The sections below cover what those don't: end-to-end behavior, copy, agent decision-doc shape, approval-gate UX, and the standalone-only deploy surface.

---

## How to read this guide

Each surface has:

- **Trigger** — the click path or curl that exercises it.
- **Expected** — what a correct run looks like, including agent decision-doc shape and audit-trail landing.
- **Broken signals** — what a failure looks like to the eye (vs what shows up in logs).
- **Audit trail** — files / endpoints where you can verify after the fact.

Run dev with `npm run dev` (port 3000). Standalone notes live in a dedicated section at the end. **Do not run `make-dist.sh` while `next dev` is alive** — the build writes/deletes `.next/` and crashes the dev server.

---

## 1. Auth + first-run register

**Trigger**

1. Delete `data/eyas.db` (dev only).
2. Hit `http://localhost:3000` — should land on `/register`.
3. Create an account, log in, log out, log back in.

**Expected**

- `/register` only renders when `data/eyas.db` is absent; subsequent loads bounce to `/login`.
- `data/eyas.db` is mode `0600` after register.
- Session cookie set; reloads stay logged in for 7 days (rolling).
- `/api/healthz` responds 200 without a session; everything else (including `/api/health`) requires one.

**Broken signals**


- Can register a second account silently (multi-user is not supported).
- `/api/health` answers 200 without cookies.
- Reloads bounce to `/login` immediately after success → cookie not being set or `AUTH_SESSION_SECRET` mismatch between request and response.

**Audit trail**

- `data/eyas.db` — single record, scrypt-hashed.
- `settings_audit` table in `data/eyas.db` — one row per `mutateSettings()` call.

---

## 2. Configuration (`/config`)

**Trigger** — `/config`, walk every panel: Anthropic creds, active environment, add a new environment, switch active env, run "Verify credentials" probes.

**Expected**

- Sensitive fields display as `••••` placeholders; saving an unchanged field doesn't rewrite the on-disk value.
- Switching active environment is **refused with 409** while a chat turn is in flight (`isBusy() === true`). Wait for the bubble to settle, then retry.
- "Verify credentials" deep probe surfaces tenant CID and member CID; mismatched CID surfaces an inline diagnosis, not a stack trace.
- Provisioning panels (IR Quarantine, Shadow-AI Banned) end with a primer hand-off to chat for the approval-gated create steps — they don't write groups silently.
- Every save appends one row to the `settings_audit` table (field shape only, no secret values).

**Broken signals**

- Stack trace or `models.retrieve` / `OAuth2` jargon in any user-facing toast → user-facing copy regression (`feedback_user_facing_copy`).
- Switch succeeds mid-turn → `isBusy()` guard broken.
- Saved API key reappears in cleartext in any browser response → sensitive fields are supposed to be masked before round-tripping; check `EnvironmentView` / `AnthropicConfigCard` GET strip.
- Sidebar nav items appear for modules the active tenant doesn't have scope for → capability gate (`/api/health` `capabilities` map) broken.

**Audit trail**

- `data/eyas.db` (mode 0600).
- `settings_audit` table in `data/eyas.db`.
- `/api/health` response → `capabilities` map drives Sidebar visibility.

---

## 3. Chat (`/`)

**Trigger** — open `/`, fire one of the three starter lines, watch the tool-call bubbles.

**Expected**

- EmptyState is the terminal aesthetic: `$ agent --ready` cap, one declarative paragraph, three `›`-prefixed starter lines, placeholder `Eyas…`. No playbooks button, no module pills, no /queue CTA panel.
- The left conversations rail groups rows by relative day (Today / Yesterday / Earlier) and shows a filter box once there are more than six conversations. History rows expire on a 72h rolling idle TTL.
- A button hand-off (IR / Triage / Reconstruct / Tune / Patch / Case / …) lands as a **confirmation card** above the composer: plain-English title + a "what this does / why" line, **Start / Cancel / Edit as message**, and a collapsible **Instructions** disclosure for the precise prompt. Nothing runs until Start. After Start, the user bubble shows the summary (not raw tool names) with a "Show instructions" toggle. All hand-off copy comes from `components/primer.ts::describePrimer`.
- Tool-call bubbles stream in with names, args (collapsed by default), durations.
- Write-shape tools pause the loop with an approval card — `Allow` / `Deny` buttons, never auto-allowed.
- Reload the page mid-conversation: the session is restored (sessionId in localStorage, server keeps the Map). "Fresh chat" only happens on explicit New Chat.
- Cancelling a streaming turn (close tab / refresh / Stop) aborts the loop within the same tick — `AbortError` is filtered out of the visible error UI.

**Broken signals**

- An approval card appears for a *read-only* tool, or a write tool slips through without one → `REQUIRES_APPROVAL` registry drift or a `runAgentLoop` callsite passing `requiresApproval: () => false` (run `/audit-write-tools`).
- Approval card from another tab resolves your turn → session-binding on approvals broken; pending entries must be bound to the originating sessionId.
- Decision-doc output looks like a ranked list of rows rather than verdict / context / recommended actions → primer leaked tabular instruction or the chat system prompt regressed.
- A hand-off shows raw tool names (`extras_*` / `falcon_*`) or an id-stuffed instruction in the card header or user bubble instead of a plain-English summary → `describePrimer` template drifted from the sender's wording (re-run `npm run test:primer`; add/repair the matcher).
- Marketing copy or "decision document" / "synthesize" / "Typical run: N iterations" phrasing visible to the user → landing-page copy regression.

**Audit trail**

- `cost_log` table in `data/eyas.db` — one record per Anthropic call with surface attribution.
- `data/perf-log.jsonl` (only when `PERF_LOG=true`).
- Tool-call bubbles render the same `tool_use` + `tool_result` events sent over SSE.

---

## 4. Queue (`/queue`)

**Trigger** — `/queue`, scan the campaign clusters and identity-overlap callouts; click a row to pivot.

**Expected**

- Detections cluster into campaigns when they share a non-system process ancestor; unclustered detections fall into a separate list.
- `identity_overlap` chip surfaces when a detection's user maps onto an identity hit; `falcon_intel_dashboard_shapes` normalization is applied (nested `{value}` objects flattened, epoch seconds rendered as dates).
- Tuning chip (`fp_pattern` / `queue_drown`) opens a primer hand-off to chat with a Tune verb, not a new page.
- Investigate chip on a row matches the chip on the same host's row in `/detections`, `/hosts`, `/vulnerabilities`.

**Broken signals**

- A detection on host A clusters with host B's detection through `svchost.exe` → system ancestor filter regressed.
- Empty queue when `/detections` shows fresh rows → the bridge filter is dropping too much (incident/crowd_score filter is intentional; other tool-name drops are not).

---

## 5. Detections (`/detections`)

**Trigger** — `/detections`, sort by created, group by host, click an adversary chip.

**Expected**

- Sort happens client-side (upstream silently ignores `sort=` on the four search tools).
- `has_adversary` + `adversary_ids` resolve to a chip via a single batched `falcon_search_actors` call (no N+1).
- Investigate / IR chips mirror those on `/queue` and `/hosts`.

**Broken signals**

- N adversary chips, N round-trips → adversary batch resolver regressed.

---

## 6. Hosts (`/hosts`)

**Trigger** — `/hosts`, scan At-Risk + Contained panels, run a search, open Groups, click Investigate then IR on the same host.

**Expected**

- Each panel calls its own API on demand (`/api/hosts/at-risk`, `/contained`, `/search`, `/groups/list`, `/groups/members`); slow ones don't block fast ones.
- The IR chip is **always present**, in one of three states (same predicate on `/hosts` and `/queue` — `lib/hosts/ir-eligibility.ts`): **live amber** on an RTR-eligible Windows host when IR is configured; **greyed with a tooltip reason** on an explicit non-Windows / non-enabled host ("…Windows hosts with Real Time Response enabled"); **greyed, linking to /config** when IR isn't configured for the environment ("Set up Incident Response in Config"). Sparse/unknown platform data stays lenient (live), deferring to the workflow's own check.
- Contained panel uses teal, never purple. Lateral-movement chips (when present) use blue.
- Removing a host from the IR Quarantine group self-heals via the dynamic group; don't add it back manually.

**Broken signals**

- Investigate chip missing on a host table → cross-table consistency regression.
- Any purple in the UI → palette regression (`feedback_no_purple`).
- A **live (amber, clickable)** IR chip on a Linux host → eligibility regression (it should be greyed-with-reason). Covered by `npm run test:ir-eligibility`.

---

## 7. Vulnerabilities (`/vulnerabilities`)

**Trigger** — `/vulnerabilities`, sort by ExPRT, filter to KEV, open a CVE drill-down, click a remediation chip.

**Expected**

- ExPRT is the primary sort/filter/group; CVSS is display-only.
- KEV filter drives off `cve.cisa_info.is_cisa_kev` / `cve.exploit_status`, not the Intel CVE→actor edge.
- Per-host fan-out runs against noisy hosts (4 parallel MCP clients) when cap > 0 — Spotlight default order otherwise saturates on a single chatty endpoint.
- Page sizes stay ≤ 2000; totals beyond that render as "2,000+", never as a true count (Spotlight 5000-row queries hit the MCP 60s timeout).
- Remediation chip routes through the patching catalog; first-declared-wins ordering means `win-wsl-update` beats `win-update-install` for WSL-tagged remediations.

**Broken signals**

- Spotlight 500 / "timed out" surfaced as raw error text → `_check_response` not wrapping the call.
- Remediation chip on a tenant remediation that has no matching script → run `/audit-remediations`; a manifest entry is shadowed.

---

## 8. IR workflow (chat-mode) + `/ir-runs`

**Trigger**

1. From `/hosts` or `/queue`, click the IR chip on an RTR-eligible Windows host.
2. Chat opens with a **confirmation card** ("Run guided incident response on `<HOST>`") — plain-English summary, no tool names. The precise instruction sits behind the **Instructions** disclosure. Click **Start**; an IR session begins. (The card is produced by `components/primer.ts::describePrimer` — the single home for hand-off copy; covered by `npm run test:primer`.)
3. Walk all five phases: Discovery → Quarantine → Remediation (dry-run preview → live) → Verification → Release/Hold.
4. After release, open `/ir-runs` and click into the engagement record.

**Expected**

- **Phase 0 prefetch fires server-side before the agent loop runs.** You'll see synthetic `tool_use` + `tool_result` bubbles for `extras_ir_workflow_playbook`, `extras_ir_campaign_scope`, AND `extras_ir_phase0_actionable_check` *before* the first agent turn. The agent doesn't have the option to skip these — `IR_TOOL_FILTER` hides them so it can't even try.
- **Phase 0.5 actionability gate short-circuits clean-room engagements.** If every open detection on the host is noise (RTR preamble self-trigger fires from a prior IR run, Shadow-AI Ban+Clean detect-only audit IOC fires on AI-provider DNS, retrospective IOC backfill), `extras_ir_phase0_actionable_check` returns `should_proceed_with_ir: false` with pre-composed `bulk_close_calls[]`. The agent fires those (one approval per bucket), emits a `## Phase 0.5 — No actionable detections (workflow aborted)` section, and STOPS. **The host is NEVER quarantined in this case.** This is the load-bearing protection against IR-on-its-own-tail engagements (Ban+Clean already cleaned the host; only audit/self-trigger noise remains).
- **Closed detections from a previous engagement on the same host don't reappear.** Phase 0 filters server-side to `{new, reopened, in_progress}`. Verify by closing detections on a host via an IR engagement, then re-entering IR on the same host; the previously-closed detections must not show up in the scope payload.
  - *Expected exception:* if Falcon's retrospective IOC backfill has generated genuinely new detections (new `composite_id`, fresh `created_timestamp`) over old underlying events, those will appear and Phase 3 should tag them `[RETROSPECTIVE]` rather than treating them as workflow misses.
- Phase 0 enrichment surfaces `cmdline_artifacts`, `registry_persistence`, `process_tree_delivery_vector`, WMI persistence enumeration, RAT-install scan — all deterministic, not agent-discovered.
- Every write tool pauses the loop with an approval card. `Deny` returns the user to the agent's next decision; `Allow` proceeds.
- Phase 2 ledger entries accumulate; Phase 4's `extras_ir_close_remediated` closes *only* the matched-via-ledger set. Detections without a Phase 2 entry stay open.
- `contained_at_start` / `agent_contained` flags are inspected at Phase 4: containment is only lifted if the agent applied it during this engagement.
- A row lands in the `ir_runs` + `ir_run_turns` tables of `data/eyas.db` keyed `<aid>-<startedAt>`. `/ir-runs` lists every engagement.

**Broken signals**

- Closed detections from a prior session show up in scope → server-side filter regressed; check `falcon-extras/ir/phase0.py:23,65` + `campaign_scope.py:45,77`.
- The agent "asks" whether to run the playbook → IR primer detection (`detectIrPrimer` in `app/api/chat/route.ts`) regressed or `IR_TOOL_FILTER` not applied.
- Host quarantined despite `should_proceed_with_ir: false` → Phase 0.5 gate regressed (agent ignored the partition result). Check `falcon-extras/ir_playbook.py` Phase 0.5 section is rendering AND the chat route's IR primer is pre-fetching `extras_ir_phase0_actionable_check`.
- Phase 4 closes a detection that was never touched in Phase 2 → ledger matcher / closer regressed (run `npm run test:sidecar`).
- Containment lifted on a host that was already contained at engagement start → `contained_at_start` flag ignored.

**Audit trail**

- `ir_runs` + `ir_run_turns` tables — per-session record with phase transitions, approvals, tool durations, usage.
- `cost_log` table — surface attribution `ir:*` for cost-summary slicing.
- `/ir-runs` page lists everything; click-through renders the record.

**Incident report (`/ir-runs/<key>`)**

- *Trigger* — open any engagement from `/ir-runs`; at the top of the detail page click **Generate report**.
- A layered **incident report** streams in place: an **Executive summary** H2 on top, then technical sections (engagement timeline, affected host, response actions by phase, detections & evidence, human oversight & guardrails, what's still open, recommendations).
- Synthesis-only — **no upstream Falcon calls** (`toolFilter: () => false`). It's written purely from the captured `ir_runs` / `ir_run_turns` record, so it's fast and can't 400. Confirm there are NO Falcon `tool_use` bubbles during generation.
- **Print / PDF** and **Webhook** capture it; **Regenerate** rewrites it. Cost log attributes `incident-report`.
- **Tenant-scoped:** open an engagement whose `env_id` ≠ the active tenant and you get a "switch tenant" note instead of the button — no report is generated cross-tenant.
- Spec: `tests/ir-report.spec.ts` (asserts the visible Executive summary heading + a technical section + the Print button — visible report text, not derived metadata).

*Broken signals*

- Report generation emits Falcon `tool_use` bubbles → synthesis-only loop regressed (`toolFilter` not `() => false` in `app/api/ir-report/route.ts`).
- "Generate report" appears on a cross-tenant engagement → tenant gate regressed (`record.envId` vs `getActiveEnvironmentId()` check).
- Report contains hostnames / CVEs / actions absent from the engagement record → synthesis invented data; the system prompt's "invent nothing" instruction regressed (`lib/ir-report/prompt.ts`).

---

## 9. Shadow-AI (`/shadow-ai`)

**The four action surfaces**

| Action | Where | Scope | Mental model |
|---|---|---|---|
| **Audit enforcement chain** | Panel header chip | Tenant | "If I fire Ban + Clean, will it actually enforce?" Walks banned-group → prevention-policies → IOA rule binding. Read-only diagnostic. |
| **Ask agent** | Per-host chip (orange) | One host | Open-ended chat handoff — agent decides what to do from the posture verdict + apps + MCP + egress. |
| **Ban + Clean (workflow)** | Per-host chip (brand red) | One host | Structured Shadow-AI playbook (`extras_shadow_ai_workflow_playbook`): Scan → Ban → Uninstall → MCP cleanup → Detect-only IOC → Verify. Each write gated. Canonical lane. |
| **Sanction** toggle | Per-tool, on row | Tenant | "This tool is approved here — stop flagging it." Pure config (`settings.json::shadowAiSanctionedTools[]`). No host writes. |

**Trigger** — `/shadow-ai`, scan unsanctioned tool hits, sanction one tool, run Audit enforcement chain, click Ban + Clean (workflow) on a host with findings.

**Expected**

- Sanctioning is per-tool, per-tenant. Sanctioning Claude on tenant A must not sanction it on tenant B.
- Sanctioned-tool detections drop out of the verdict bag immediately; the row carries a Sanction chip.
- **Audit enforcement chain** walks banned-group → prevention-policies → IOA rule group binding via `extras_shadow_ai_check_prevention_binding`. If the binding is missing, the result names what's broken in operator language, not a Python traceback.
- IOA rules cover installer shapes (`Claude-Setup.exe`, Squirrel/NSIS variants) — not just post-install image launches.
- **Ban + Clean MSIX path:** if Phase 0 surfaces a Claude Desktop install at `C:\Program Files\WindowsApps\Claude_<ver>_<arch>__<hash>` (MSIX form), Phase 2 should pick `host-uninstall-appx-package` with `package_name_pattern=Claude` — NOT `host-uninstall-claude-desktop` (Squirrel-only) and NOT `host-delete-folder` (refuses WindowsApps).
- **Ban + Clean Microsoft Copilot path:** if Phase 0 surfaces a Microsoft Copilot signal (egress to `copilot.microsoft.com`, `Microsoft.Copilot` MSIX, Copilot CLI, Copilot-in-Edge), Phase 2 must emit a "Microsoft Copilot (no host action)" subsection with three recommendations (sanction / GPO+Intune / detect-only IOC). It must NOT attempt `host-uninstall-appx-package` (system-blocked anyway) or `host-kill-process` against `msedge.exe` / Office / `Copilot.exe`.

**Broken signals**

- Sanctioning on one tenant leaks to another → per-env scoping broken.
- Audit chip surfaces "FalconPy", "MCP", or a stack trace → user-facing copy regression.
- Phase 2 attempts to host-uninstall a Microsoft Copilot signal, or fires `host-delete-folder` against a WindowsApps Claude MSIX → playbook MSIX/Copilot branches regressed.

---

## 10. Intel + Recon + Pivot

**Trigger** — `/intel` (Hunt + Attribution), `/recon`, `/pivot` (merged lookup + threat-graph).

**Expected**

- Intel Hunt produces a three-tier verdict with tenant evidence attached to the row, not a flat global feed.
- Adversary chip enrichment is batched (one `falcon_search_actors` per page).
- `/pivot` accepts a hash / IP / domain and routes to the right Threat Graph endpoint (combined_summary for entities, combined_ran_on for hashes; uses `value` not `ids` for the hash form).
- Recon results come from a unified corpus; `source_category` filters Telegram / dark web / paste / breach inline.

---

## 11. Status (`/status`) + health

**Trigger** — `/status`; also curl `/api/healthz` (no auth) and `/api/health` (authed; `?force=1` for fresh).

**Expected**

- `/status` shows build kind (`standalone` / `docker`), version (matches `package.json`), Anthropic + Falcon-MCP + extras probe results, and `missing_tools[]` (empty in a healthy build). The extras probe is labelled **"Falcon operations add-on"** (covers containment, IR, patching, provisioning — not just containment).
- The **API scopes** checklist shows a per-environment availability blip on each row: green (granted), red (not granted), grey (core / baseline scope — not probed). Driven by the same `/api/health` `capabilities` map as the nav gate; the legend names the active environment. Core scopes are grey by design (the app assumes them and doesn't probe each one).
- `/api/healthz` is a cheap liveness probe; no upstream calls; safe for orchestrator and uptime monitors.
- `/api/health` cached 30s with in-flight de-dup; `?force=1` skips the cache but still requires auth.
- Anthropic gateway (when configured) returns "ok with note" instead of failing on `/v1/models` 404.
- The **Posture history** card shows the latest capture time, the **snapshots stored** count, and coverage ("All areas captured" or "Partial — some areas unavailable"). Before the first run it reads "No snapshots captured yet".
- `GET /api/posture/snapshots` (session-authed) returns `ok: true` with the stored snapshots and a `trend` object; leaf-metric `delta` values are null until a second snapshot exists, then fill in week-over-week. Spec: `tests/posture-status.spec.ts`.

**Broken signals**

- `missing_tools[]` non-empty after a `make-dist.sh` build → run `verify_tools.py` against the staged sidecar source; update `falcon-extras/expected_tools.json` if a tool was deliberately removed.
- `/api/healthz` answers with full probe data → cheap-probe split regressed (`/healthz` must not call upstream).
- `/api/health` 200 without a session cookie → middleware regression.
- The Posture history card throws or blanks the page → it must degrade silently to a zero-state (the `/status` fetch is try/catch-wrapped); a thrown error here is a regression.

---

## 12. Scorecard (`/scorecard`)

**Trigger** — `/scorecard`; also curl `GET /api/scorecard` (session-authed).

**Expected**

- Three sections render: **Agentic operations** (engagements run, median time to close, detections resolved, actions reviewed = allowed / declined / expired), **Agentic activity** (workflows run, total iterations, per-area breakdown), **Posture movement** (per-metric headlines, emerald when the move favors the tenant, amber when it doesn't).
- Trailing-30-day window, compared with the prior 30 days. Everything is **computed locally** — no AI, no Falcon calls.
- **Tenant-scoped:** counts cover the active environment only; pre-attribution rows (`env_id` NULL, from before the ledger was env-stamped) are excluded, not blended in.
- Fresh install / quiet tenant reads as zeros per section (explicit empty states); posture movement stays blank until at least two snapshots exist.
- Spec: `tests/scorecard.spec.ts`.

**Broken signals**

- Counts blend tenants or don't change when you switch environments → env-scoping regressed (`lib/scorecard/compute.ts` env filter).
- Posture movement shows numbers with only one snapshot stored → trend gate regressed (needs ≥2).
- A surface shows a raw key (e.g. `investigate:fingerprint`) instead of a friendly label → `SURFACE_LABEL` / `humanizeSurface` missing an entry.

---

## 13. Scheduler (`/scheduler`-relevant endpoints)

**Trigger** — set `SCHEDULES=patch-digest,daily-briefing,release-watcher,posture-snapshot` in env (with `SCHEDULER_ENABLED=true`); restart; wait for tick or trigger a job manually.

**Expected**

- Registered jobs run on their cadence; output lands in the relevant data file / log; cost log records `scheduled:<job>` attribution.
- `posture-snapshot` **arms without a webhook** (`requiresWebhook: false`) — it writes a posture row to `data/eyas.db` locally, so it runs even when `OUTBOUND_WEBHOOK_URL` is unset. Delivery jobs (briefing, release-watcher) skip with a soft bootError when no webhook is configured.
- Disabling a job by removing it from `SCHEDULES` removes it from the manifest on next boot.

**Broken signals**

- `posture-snapshot` skipped for want of a webhook → it must arm regardless (it's a local-write job, not a delivery job).

---

## 14. Cost log + observability

**Trigger** — `/cost-summary` (or `/cost-summary --since 7d`).

**Expected**

- Chat surface around 68% of spend (baseline `cost_tuning_levers`); the skill soft-flags drift past that.
- Cache hit % above 60 on chat (1h TTL).
- Per-surface attribution lines up with the surfaces you actually exercised in the QA window.

**Broken signals**

- Chat surface > 75% or < 60% → iteration / caching drift; check `agent-loop.ts` recent changes and the chat system prompt size.
- Cache hit % < 40 → cache-block key shape probably regressed.

---

## 15. Approval gate sanity

**Trigger** — `/audit-write-tools`.

**Expected** — every write-shape tool in `falcon-extras/server.py` appears in `lib/mcp/write-tools.ts::REQUIRES_APPROVAL`; no `runAgentLoop` callsite passes `requiresApproval: () => false`. Sub-agents reject write-shape names at the toolset layer regardless of caller intent.

**Broken signals** — anything the skill flags. This is a release blocker.

---

## 16. Agent toolbox (`/agent-toolbox`)

**Trigger** — `/agent-toolbox`; also curl `GET /api/agent-toolbox-catalog?force=1` (session-authed).

**Expected**

- Hero is labeled **Reference · developer surface**; a stat strip shows non-zero counts (total / eyas-mcp / extension / read-only / approval-gated).
- Real tool **rows** render (not just header counts) — e.g. `falcon_search_detections` (read-only) and `falcon_contain_hosts` (approval-gated) are both present by default.
- The search box and the provider / access filter chips narrow the list; expanding a tool row reveals its JSON input schema.
- The "why are some native writes not shown?" disclosure lists the suppressed native writes (e.g. `falcon_update_detections`) — and those names are **absent** from the catalog rows themselves.
- The catalog is the **exact** post-suppression agent-visible set: it reuses the chat agent's tool bridge (`buildToolBridge`), so the total matches what the agent sees. **Read-only** — there is no invoke / run button.
- Reachable from the sidebar's **Reference** group (always shown — not scope-gated).
- Spec: `tests/agent-toolbox.spec.ts`.

**Broken signals**

- A suppressed native write shows up as a callable row → bridge suppression regressed (the catalog must reuse `buildToolBridge`, never re-derive the list).
- The page throws instead of rendering the calm "connect a Falcon tenant" note when the catalog can't build → graceful-failure path regressed.
- Any "run" / "invoke" affordance on a tool row → the read-only contract regressed (re-introduces write-approval / cost / FQL-injection surfaces).

---

# Standalone bundle — additional checks

Everything above applies to the standalone bundle; the items below are standalone-only.

## S1. Build + validate

**Trigger**

```
./make-dist.sh
/validate-bundle
```

(Make sure `next dev` on port 3000 is stopped before running `make-dist.sh` — re-check the port; don't trust "it wasn't running an hour ago".)

**Expected**

- `data/` is absent from the staged bundle (no dev `auth.json`, `cost-log.jsonl`, `perf-log.jsonl`).
- `BUILD-INFO` matches `package.json` version and has `buildKind: "standalone"`.
- Sidecar files present; `verify_tools.py` clean against `falcon-extras/expected_tools.json`.
- No native `.node` binaries other than `@img/sharp` (the only allowlisted one).
- Smoke-boot reaches `/login`.

**Broken signals**

- `validate-bundle` flags a missing sidecar tool → run the AST sweep after any modular refactor (`feedback_ast_sweep_after_modular_refactor`).
- `data/` shipped → `make-dist.sh` regression; the `rm -rf $STAGE/data` step is load-bearing.


## S2. Gateway lock

**Trigger** — unzip the bundle, edit `data/eyas.db` post-boot to swap the Anthropic endpoint to a public API key, restart.

**Expected** — server-side validator (`lib/config/deployment-policy.ts::validateAnthropicAgainstPolicy`) rejects the override; bundle stays pointed at the build-baked gateway URL. The wizard hides the API-key option entirely.

**Broken signals** — repointed bundle boots and serves chat traffic to a non-gateway endpoint → `BUILD_FLAGS` not baked correctly by `make-dist.sh`.

## S3. Secret warmup

**Trigger** — fresh-boot the standalone bundle; immediately fire a chat turn that uses the sidecar.

**Expected** — first request succeeds; sidecar isn't told `FALCON_CLIENT_ID is missing`. `instrumentation.ts` blocks on `warmSecretCache` so secrets are resolved before any request lands.

**Broken signals** — first request fails with sidecar credential error, subsequent requests succeed → warmup non-blocking regression (`standalone_secret_warmup_blocking`).

## S4. macOS Python

**Trigger** — on a macOS host with only system Python 3.9.6, launch the bundle.

**Expected** — `start.sh` finds Homebrew Python 3.12, or `PYTHON3=/path/to/python3.12` is honored; the sidecar boots. Falls back with a clear operator message if neither is available.

**Broken signals** — sidecar boots against system Python 3.9 and errors on type syntax → `start.sh` Python discovery regressed.

## S5. HOSTNAME quirk

**Trigger** — macOS standalone launched from a zsh shell.

**Expected** — `start.sh` forces `HOSTNAME=127.0.0.1` regardless of zsh's auto-export.

---

# Release gate (run before tagging)

Minimum to call a build shippable:

1. `npm run typecheck` + `npm run lint` + `npm run test:sidecar` clean.
2. `/audit-write-tools` clean.
3. `/audit-remediations` no uncovered remediations with double-digit host counts.
4. Manual sweep of sections 3 (Chat), 8 (IR end-to-end), 11 (Status), plus whichever surfaces changed.
5. `./make-dist.sh` + `/validate-bundle` clean.
6. Standalone smoke-boot to `/login` on at least one macOS host.
7. `/cost-summary --since <last QA window>` — chat % within band, cache hit > 60.

Don't ship without 1, 2, 5. The rest is judgment — a docs-only change doesn't need a full standalone smoke.

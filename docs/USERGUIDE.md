# User guide

Hands-on guide to **Eyas** for the three operator personas it serves: **SOC analyst**, **Falcon administrator**, and **IR analyst**. CrowdStrike Sales Engineers can also use this as a feature-tour reference when demoing — the SE-facing live walkthrough is [`DEMO.md`](./DEMO.md).

Unofficial — not a CrowdStrike product. For the architecture overview see [`README.md`](../README.md). For deployment see [`DEPLOYMENT.md`](./DEPLOYMENT.md) (Docker) or [`STANDALONE.md`](./STANDALONE.md) (bundled zip).

---

## Sidebar at a glance

The left drawer (open it with the hamburger on mobile; it's pinned on desktop) groups every surface by intent:

| Group | What it's for |
|---|---|
| **Triage** | Start of shift — Queue, Chat, Briefing |
| **Pivot** | Drill into one host or one artifact — Investigate, Artifact pivot |
| **Hunt** | Look across the tenant — Intel, NGSIEM, Recon, MalQuery |
| **Posture** | Configuration health — Identity, Prevention, Workflows |
| **Dashboards** | Raw browse — Detections, Hosts, Vulnerabilities |
| **System** | Accountability + ops — IR runs, Scorecard, Cost ledger, health probes |
| **Reference** | Developer reference — the **Agent toolbox** lists every Falcon action the assistant can use, each marked read-only or requiring approval; **Blueprint** is a developer guide that explains how a console like this one is built on eyas-mcp and Claude |

Items hide automatically when the underlying Falcon API scope isn't granted on the tenant.

---

## SOC analyst — start of shift

The intended flow is **Queue → hand-off → Chat**. Don't open Chat first and stare at a blank input.

Every hand-off button (Triage, IR, Reconstruct, Tune, Patch, …) opens Chat with a **confirmation card**, not a wall of text. The card states in plain English what the action will do and why (e.g. *"Run guided incident response on WIN-ACCT-01 — contains the host, hunts persistence, and cleans confirmed threats; every step asks for your approval"*). You review, then click **Start**. If you want to see exactly what the agent is being told, expand **Instructions**; if you'd rather hand-edit it, **Edit as message**. Nothing runs until you Start.

### 1. Open `/queue`

Three buckets, ranked composite-score (severity × recency × per-host concentration × uncontained-critical bonus):

- **Top priorities** — score ≥ 15 and fresh. Work these first.
- **Active queue** — fresh and below the cutoff. Work after top.
- **Stale (>7d)** — collapsed by default, separate review.

Each row shows the detection summary, host (with containment chip), severity, age, and tactic. Endpoint detections (`epp` source) and IDP rows are merged into one queue with a source chip. Identity-overlay enrichment is auto-attached: any top-bucket EPP row whose last-logged-in user has an open IDP detection or HIGH/CRITICAL identity risk score gets a sky / red `IdentityOverlapChip`.

### 2. Read the **Triage Brief** above the queue

5 sections — Executive verdict / 🔥 Top priorities / 🔁 Likely campaigns / 💤 Safe to defer / 🛠 Tuning candidates. Click **Generate triage** to run; takes 30–60s. The agent already saw the same data the table shows, so it won't tell you something the rows can't already prove.

### 3. Read the **Campaigns** card if it appears

Cross-host clustering by SHA-256 / image+technique / lateral-by-user. Each campaign card has a **Reconstruct** button that hands off to chat with the cluster pre-injected — useful when you suspect "is this one thing or many things?"

### 4. Per-row **Triage** button

Hands off to chat with a focused primer that includes the row context (composite_id, AID for endpoint rows, samAccountName for identity rows, and identity overlay for top-bucket rows). The agent claims the detection as `in_progress` server-side first (so multiple analysts don't double-work it), then proceeds.

### 5. Per-row **IR** button

Same hand-off shape, different action — kicks the agentic IR workflow (see IR analyst section). Endpoint rows run host IR; identity rows show **Identity IR** (the user-account workflow with an endpoint cascade). The chip is always present; it's only *live* on a host/user that can actually run it and when IR is configured — otherwise it's greyed with a reason (see the IR analyst section for the three states).

### 6. **Tuning candidates** at the bottom

Two signals:
- **fp_pattern** (strongest) — ≥3 closed records, ≥2 hosts, ≥80% closed-as-FP, 0 TP closures
- **queue_drown** — ≥10 fires, ≥3 hosts, max severity ≤ Medium, 0 closures

Each candidate has a **Tune** button — chat primer asking for an exclusion proposal (ML / IOA / sensor-visibility) with risk analysis. Don't blindly approve; the proposal should land as a recommendation, not a write.

### Other Triage-group surfaces

- **`/briefing`** — One-page send-to-stakeholder report. Print as PDF, post to a webhook, or schedule via the `SCHEDULES` env (`daily-briefing` job runs at the operator's chosen cadence). Not for interactive triage; use `/queue` for that.
- **`/`** Chat — Free-form. The empty state is deliberately bare: a one-line intro and three one-click starter prompts. Use it for cross-module questions and write actions that don't fit a dedicated surface; for start-of-shift triage, open `/queue` first.

---

## Falcon administrator — posture and hygiene

### Vulnerability triage and patching

**`/vulnerabilities`** is the daily focus. Three hero cards at the top:
1. **Drop everything** — exploited + has-fix
2. **ExPRT Critical** — adversary-rated critical regardless of CVSS
3. **Actively exploited** — count of CVEs in the CISA Known Exploited Vulnerabilities catalog (US-CERT confirms in-the-wild exploitation). Tile links to the KEV-filtered patch view.

Each table row carries a `KEV` chip and an `exploit:active` / `exploit:public` chip when the CVE record indicates known exploitation, so the per-row "why is this scary?" reads at a glance without expanding the row.

Toggle `by-patch / flat / by-host` view. Filter chips (CISA KEV / exploited / has-fix / stale).

A small **Run adversary attribution agent →** link sits beneath the hero strip for the optional Falcon Intel × Spotlight cross-reference (`/vulnerabilities/adversary-exposure`). Falcon Intel CVE→actor coverage is sparse — treat that surface as enrichment, not as the primary triage lens.

Per-row **Patch** button proposes an RTR script from the curated catalog and runs it through the patch-plan flow with dry-run preview, host-target validation, and per-host approval gates. The catalog covers 25+ high-impact remediations across Windows, Linux (distro-agnostic apt/dnf/yum), and macOS PKG installs.

### Hosts inventory

**`/hosts`** is search-and-act, not pre-load:
- **Find a host** — debounced hostname search (substring FQL on `hostname`)
- **At-risk** — hosts with open critical/high vulns from the last 72h
- **Network contained** — current containment list
- **Group posture report** — collapsible agentic panel; click **Generate report** to get a posture decision document (group inventory + sample membership + posture flags + recommended actions). Pair with `/vulnerabilities` to plan staged rollouts.
- **Per-group expandable table** — lazy-loads up to 100 members per group on expand

Per-row buttons on host rows: **Investigate** (deep-dive), **Add to IOC** (chat primer), **IR** (when quarantine group configured).

### Prevention policy posture

**`/prevention`** — every prevention policy with a posture flag for anything `disabled` or in `*_detect_only`. Use this to find the gap between "we have detection coverage" and "we're actually preventing the thing." Requires `Prevention Policies (Read)` scope on the API client.

The page shows total/disabled/detect-only summary tiles, a per-platform breakdown, and a row table with ML and Cloud AV detection/prevention values per policy. Detect-only is `detection != DISABLED && prevention == DISABLED`.

### Identity posture

**`/identity`** — risky users, active IDP detections, sensor enforcement modes, policy posture. Click **Generate report** (no longer auto-runs — saves tokens). 5-section decision document:
- 🔥 Risky identities (high risk-score)
- 🚨 Active IDP detections (last 14d, status open, tactic-bearing only — drops "Policy rule match" enforcement noise by default)
- 🛡 Sensor posture (DC enforcement modes, status causes)
- 📋 Policy rule summary
- Recommended actions

Filter overrides exposed if you need to include enforcement events or closed status.

### Fusion workflow posture

**`/workflows`** — Fusion SOAR definition + recent execution audit. Click **Generate report**. Inventory + recent runs + failure flags + recommended actions. Read-only — Fusion edits still go through the Falcon console.

---

## IR analyst — incident response

### The IR workflow lives in chat

There is no dedicated IR page. The **IR** chip on `/queue` and `/hosts` rows hands off to chat. The chip is always visible so you know where IR lives: it's **live (amber)** on a Windows host with Real Time Response when IR is configured; **greyed with a tooltip** on a host that can't run it (non-Windows / RTR disabled); and **greyed, linking to Config** when IR hasn't been set up for the environment. Clicking a live chip opens Chat with a confirmation card ("Run guided incident response on \<name\>"); click **Start** to begin.

Behind the card, the agent receives:

> Run the agentic IR workflow on host \<name\> (AID \<aid\>). Load the playbook with `extras_ir_workflow_playbook` and proceed.

The agent loads the playbook, then walks five phases. **Every write is gated by per-tool approval** — phase boundaries are not gates.

| Phase | Action | Writes? |
|---|---|---|
| **0 — Discovery** | Live RTR introspection: process tree (with delivery-vector classifier verdict), services, autoruns (HKLM Run / RunOnce / Wow6432Node…\Run / Winlogon), scheduled tasks, recent EventLog, plus a thorough RAT-install NGSIEM scan (17-product catalog) catching sibling AnyDesk-class installs the cheap Process script misses | none |
| **1 — Quarantine** | Add host to the quarantine group (operator-configured). Optionally network-contain. | gated |
| **2 — Remediation** | Per-action dry-run preview, then real run. Cleanup primitives (14 today): kill process, delete file, quarantine file (forensics-preserving), delete folder, stop/delete service, remove scheduled task, remove run-key, remove IFEO hijack, remove WMI persistence, set registry value (hardening reverts), disable local user, force logoff, block outbound IP, uninstall AnyDesk. | gated |
| **3 — Verification** | Re-run Phase 0 reads, confirm artifacts gone | none |
| **4 — Release / Hold** | Lift agent-applied containment, remove from quarantine group, restore each *static* original group. Dynamic groups self-restore via assignment_rule FQL. | gated |

**Sacred-state invariants the playbook enforces:**
- `contained_at_start` vs `agent_contained` — Phase 4 only lifts containment the agent itself applied. Operator-applied containment is never touched.
- Dynamic groups never re-added — the API rejects it; assignment_rule FQL re-evaluates within minutes.

### Incident report from an engagement

Every engagement is recorded under **IR runs** (`/ir-runs`) — an audit trail keyed by host and start time. Open one for the technical replay (phase-by-phase tool calls, outcome, guardrails, per-turn breakdown). That view is for the responding analyst; the leadership write-up is one click away.

At the top of any engagement's detail page, click **Generate report**. A layered incident report streams in place:

- a plain-language **executive summary** for leadership on top, then
- full technical detail below — engagement timeline, affected host, response actions by phase, detections & evidence, human oversight & guardrails, what's still open, and recommendations.

The report is written **only from the engagement record this console captured** — no new Falcon calls — so it reflects exactly what happened during the response and can't stall on an upstream query. Capture it with **Print / PDF** or post it to a **webhook**, the same as the daily briefing; **Regenerate** rewrites it. The report is scoped to the active tenant — open an engagement that ran under a different tenant and you'll see a "switch tenant" note instead of the button.

### Identity IR workflow

If the actor is a domain account, the **Identity IR** button on `/queue` IDP rows kicks a parallel workflow that pivots on `samAccountName` instead of AID. Five phases mirror the host workflow but the cascade runs the host IR sub-workflow on each recently-active machine for the user (top 3–5).

Note: Falcon API can't toggle account-enabled — that's AD/IdP, not Falcon. The playbook has an `enabled_at_start` field but it's informational only.

### One-off pivot

**`/pivot`** — paste a hash, IP, domain, or URL. Auto-detects type. Default mode (**Cross-source lookup**) fans out across Falcon Intel + custom IOC list + tenant detections + 30 days of NGSIEM telemetry. For file hashes only, switch to **Execution lineage** mode (Threat Graph — every host that ran it, layered with Intel and detections).

**`/investigate`** — paste a hostname for a deep-dive (recent detections, open vulns, RTR snapshot, identity exposure). Two-round structure: independent reads in parallel, then dependent reads + per-host RTR. Typical ~6 iterations.

---

## Hunt and free-form work

- **`/intel`** — Threat actors with evidence in your tenant. **Generate exposure report** runs a 90-day deterministic enrichment server-side and joins it against Falcon Intel: (1) every detection's `has_adversary` / `adversary_ids` resolves to the canonical actor record (ground truth — same signal the Console uses for actor labels), (2) extracted hashes / domains / IPs reverse-lookup through Falcon Intel indicators (corroboration), (3) detection text is scanned for actor aliases (FANCY BEAR / APT28 / Conti / REvil / etc.) as a heuristic fallback. The agent only synthesizes the bundle; no per-detection LLM fan-out. Each evidence row in the report carries provenance so the operator can tell `falcon-attribution` (ground truth) from `text-mention` (heuristic). The pre-fetched `IntelHuntPanel` above the report shows top recent indicators bucketed as `active_in_tenant` / `covered_by_intel` / `watchlist_only`; per-match **Investigate** buttons hand off to chat.
- **`/ngsiem`** — Natural-language → CQL translation, plus 60+ curated battle-tested playbooks organized by MITRE phase (under "Curated playbooks"). Run a playbook one-click; or type a question and let the agent compose the CQL.
- **`/recon`** — Domain or email exposure across breaches, dark-web posts, paste sites, Telegram. One Recon corpus, faceted by `source_category`.
- **`/malquery`** — Hash lineage across CrowdStrike's malware research corpus. Up to 25 hashes per run.

### Chat starter prompts

The chat empty state offers three one-click starter prompts as a jumping-off point:

- Hosts with an open Critical vulnerability and a recent detection (cross-module synthesis)
- This week's detections by tactic and host (weekly threat picture)
- Run the agentic IR workflow on a host (approval-gated write workflow)

These are just seeds — chat takes any prompt. Lean on it for multi-tool synthesis no dedicated surface composes and for write actions, all gated by approval. For single-surface questions (host deep-dive, hash provenance, identity posture, NGSIEM hunt, persistence cleanup), use the dedicated surface — `/investigate`, `/pivot`, `/identity`, `/ngsiem`, the IR workflow.

---

## Approval gates — write tools

Every write action stops the agent loop until the operator approves or denies. Decision is `allow / deny / timeout` (5-minute timeout is distinct from denial). The approval modal shows the tool name, full input arguments, and a brief description of impact.

Write tools today: containment (apply / lift), host group membership add/remove, custom IOC add, prevention policy edit (gated), firewall rule add/edit, RTR script execution (patching + cleanup catalogs), detection status updates (verdict transitions only — `in_progress` claims bypass the gate intentionally because they're bookkeeping, not verdicts).

Two principles:
1. **Pre-flight validate over surfacing raw upstream errors.** Spend an extra read API call to validate preconditions (group type, host eligibility, IOC pre-existence). Operator tokens cost more than API calls.
2. **No redundant custom coverage.** Don't propose a custom IOC/IOA when Falcon Intel or cloud reputation already covers the behavior. Chat enforces a `falcon_search_indicators` + `falcon_search_iocs` precheck before any `falcon_add_ioc`.

---

## Accountability and reporting

Two surfaces answer the questions leadership asks — *what has this console done for my tenant, and where is my posture heading?*

### Posture history (`/status`)

A daily snapshot of the tenant's posture — detections, vulnerabilities, coverage, identity, prevention, data protection, and cases — is captured automatically and stored. The **Posture history** card on `/status` shows the latest capture time, how many snapshots are stored, and whether the last capture was complete. Trends compare each capture with the one from about a week earlier. Turn the daily capture on through the scheduler (the `posture-snapshot` job); it stores locally, so no webhook is needed.

### Operations scorecard (`/scorecard`)

A read-only readout of what this console has done for the active tenant over the trailing 30 days:

- **Agentic operations** — incident-response engagements run, median time to close, detections resolved, and actions reviewed (allowed / declined / expired), each compared with the prior 30 days.
- **Agentic activity** — total workflows run and a per-area breakdown (chat, briefings, investigations, hunts, …).
- **Posture movement** — how the headline posture numbers moved, colored green when the move was in your favor and amber when it wasn't.

Everything is scoped to the active tenant and computed locally — no AI, no extra Falcon calls — and reads as zeros on a fresh install until there's activity. Posture movement fills in once there are at least two snapshots.

---

## Cost transparency

**`/cost`** — token spend per surface, per model, per day, with monthly projection. The console caches the Anthropic prompt (tools block + system prompts) with a 1h TTL on chat (sessions gap minutes between turns) and 5m default on one-shot agentic surfaces. Output tokens are 12% of total cost; chat is 68% of total spend.

Stop a long-running agent with the **Stop** button — it cancels the SSE stream, aborts the Anthropic message, and logs the partial usage to the cost ledger so aborted runs still show up in spend.

---

## When to use the console vs the Falcon UI

| Task | Use the console | Use Falcon UI |
|---|---|---|
| Triage open detections | ✅ `/queue` (campaigns + identity overlay + agent brief) | |
| Browse raw detection list | | ✅ — Falcon's filters are richer |
| Investigate a single host | ✅ `/investigate` or chat | |
| Manage host groups | ✅ for posture overview / agent-driven membership writes | ✅ for one-off rule edits |
| Patch from Spotlight | ✅ — curated catalog + dry-run | |
| Edit a Fusion workflow | | ✅ — Falcon UI only |
| Adjust a prevention policy | ✅ for posture audit | ✅ for the actual edit |
| NGSIEM ad-hoc query | ✅ — curated playbook library is unique | ✅ for visualization-rich saved searches |
| Identity IR | ✅ — endpoint cascade + agentic workflow | |
| Pull a daily briefing for stakeholders | ✅ — print/email/webhook | |
| Write up an incident for leadership | ✅ `/ir-runs` → Generate incident report | |
| See what the console has done / posture trend | ✅ `/scorecard`, `/status` posture history | |

The console is best at agentic synthesis and write workflows that compose multiple modules. The Falcon UI is best at single-purpose deep dives and rich visualization.

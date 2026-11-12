<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/eyas-logo-dark.svg">
    <img alt="Eyas" src="docs/assets/eyas-logo-light.svg" width="420">
  </picture>
</p>

# Eyas

[![CI](https://github.com/GTStagg/project-eyas/actions/workflows/ci.yml/badge.svg)](https://github.com/GTStagg/project-eyas/actions/workflows/ci.yml)
[![Node 22+](https://img.shields.io/badge/node-22%2B-0a0a0a?logo=nodedotjs&logoColor=ef4444)](package.json)
[![License: MIT](https://img.shields.io/badge/license-MIT-dc2626)](LICENSE)
[![Independent project](https://img.shields.io/badge/independent-not_affiliated_with_CrowdStrike-0a0a0a)](NOTICE.md)

**v0.10.0** · An agentic console for CrowdStrike Falcon. Self-hosted Next.js, driving Falcon through Claude by wrapping [`eyas-mcp`](https://github.com/GTStagg/eyas-mcp) — an independent Falcon MCP server derived from CrowdStrike's MIT-licensed `falcon-mcp` (see [NOTICE](./NOTICE.md)) — and a [FalconPy](https://falconpy.io) sidecar. SOC, IR, and Falcon-administration workflows expressed as one prompt: triage a queue, reconstruct an attack chain, build a patch plan, hunt across Intel + telemetry. Every tool call is gated, traced, and auditable.

**Unofficial.** Eyas is not a CrowdStrike product and not a replacement for the Falcon console. The name *eyas* is the falconry term for a young falcon being trained — fitting for a project raised on the same craft as Falcon, but distinctly its own thing. The point is to show what an agent loop on top of an MCP server for Falcon + FalconPy can do that clicking through the console can't — cross-module synthesis, "find me everything that…" pivots, and one-prompt write actions behind an explicit approval. Useful as: a working reference for teams building on `falcon-mcp` / `eyas-mcp`, a hands-on surface for SOC / IR analysts and Falcon administrators, and a demonstration vehicle for an MCP server + FalconPy + Claude together.

## Getting started

- **Use it (macOS):** no prebuilt bundles are published. Build one from source with `./make-dist.sh` (see [`docs/STANDALONE.md`](./docs/STANDALONE.md#building-the-bundle)), then follow the same guide — unzip, `bash install.sh`, `eyas`. Credentials are entered in the browser on first run. To upgrade, pull, rebuild, and run the new bundle's `install.sh`; your password, credentials, and data are kept.
- **Develop on it:** clone this repository and follow the local dev-server path in [`QUICKSTART.md`](./QUICKSTART.md).
- **Docker:** [`QUICKSTART.md`](./QUICKSTART.md) also covers a Docker Compose bring-up. Compose builds `eyas-mcp` from source at the pinned commit; no container images are published.
- **The MCP server is fetched from [`eyas-mcp`](https://github.com/GTStagg/eyas-mcp) on GitHub** — dev, `make-dist.sh` and Compose all use the commit pinned in `versions.json`.

Then [`docs/USERGUIDE.md`](./docs/USERGUIDE.md) is the hands-on guide organized by analyst persona, and [`docs/DEMO.md`](./docs/DEMO.md) a guided live-demo talk track.

---

## What it does

| Surface | What it is | LLM in the loop? |
|---|---|---|
| **`/home` — Control Center** | Landing dashboard. A compact **Control Center** hero (radar reticle + page icon, animated sweep) over a grid of live capability widgets grouped by domain — each opens an in-page **snack panel** hosting either a deterministic readout (hosts at risk, contained hosts, spend) or a one-shot agentic tool panel whose report you can **continue in chat** without leaving the page. A global **Ask the agent** button (TopBar, every page) and a persistent chat dock ride alongside. | Some widgets (agentic panels) |
| **`/` — Chat** | Free-form agentic chat with full Falcon tool access. Tool-call trace is rendered inline with per-tool duration badges. Write actions hit a confirmation card before executing. Deliberately bare empty state — a one-line intro plus three one-click starter prompts. Optional CrowdStrike AIDR guardrail layer — when configured per-environment on `/config`, every prompt and response is scanned for prompt injection, sensitive data, and policy violations before reaching (or leaving) the model. | Yes (manual agent loop) |
| **`/briefing`** | One-page daily security report. Every completed agentic report renders shared "Print / PDF" + "Send to webhook" actions (the latter when `OUTBOUND_WEBHOOK_URL` is set). | Yes |
| **`/investigate`** | Host deep-dive: detections + vulns + RTR snapshot for a single AID. Same Print / Webhook actions as briefing. | Yes |
| **`/pivot`** | Unified artifact-pivot surface. Paste a hash / IP / domain / URL — the agent fans out across Falcon Intel, custom IOC list, detections, NGSIEM telemetry, and Threat Graph (hash → device aggregation, network → vertex summary), returns a 5-section decision document. | Yes |
| **`/intel`** | Adversary exposure (not a global catalog). Walks 90 days of detections; deterministic three-path attribution — Falcon-native `adversary_ids` (ground truth, same source the Console uses), Intel indicator → adversary (corroboration), and detection-text alias matching (heuristic) — joined server-side and rendered with provenance. Surfaces only adversaries with tenant evidence. | Yes |
| **`/intel-dossier`** | Finished-intelligence dossier on a threat actor, campaign, or keyword. Deterministic server-side fan-out — searches reports + actors, fetches their **full content** (report bodies + full actor profiles via `falcon_get_intel_reports` / `falcon_get_intel_actors`), and scans the Recon underground corpus, **every run** — then synthesizes a decision document (verdict / who they are / activities & tradecraft / victimology / underground presence / assessment / sources). Enrichment never depends on the model choosing a tool. | Yes |
| **`/recon`** | Domain / email exposure across the Falcon Adversary Intelligence Recon corpus — criminal marketplaces, dark-web forums, GitHub paste-leaks, Telegram, social media. Decision doc with channel + top-site breakdown, exposed credentials, existing tenant rule coverage, recommended actions. Backed by FalconPy `Recon` (preview_rule for ad-hoc corpus search; the only path that hits the data lake without a saved rule). | Yes |
| **`/malquery`** | Hash lineage across CrowdStrike's MalQuery malware research corpus. Paste up to 25 MD5/SHA-1/SHA-256 hashes — agent fans out MalQuery metadata + Falcon Intel + tenant detections, renders a verdict-led decision document with prevalence, family attribution, tenant exposure, and quota status. | Yes |
| **`/queue`** | Detection triage queue with deterministic ranking, campaign clustering (cross-host, cross-detection), tuning candidates, and identity overlap. Per-host **Triage** + **IR** chips hand off to chat with a primer. Bulk-claim writes detections as `in_progress` in one API call regardless of group size. | Yes (for hand-off only) |
| **`/prevention`** | Prevention Policy posture surface — sensor-ML slider settings, exclusions, behavioral coverage. Read-only. Built with the staged-build pattern; lights up automatically when Prevention Policy scope is granted. | Yes |
| **`/cases`** | Filed-investigations dashboard — open cases ranked by severity with attached alert + event evidence counts and per-row **Triage** hand-off to chat. Backed by the MCP server's Cases module; ships staged-build (page banners and nav hides until `Cases:read` is granted). Case mutations (create / update / attach evidence / tag) are approval-gated for the agent. | No (dashboard) / Yes (Triage hand-off) |
| **`/quarantine`** | Quarantine review. Deterministic clustering of every file Falcon is holding in quarantine — by host and by hash, with state counts and concentration / spread flags — then an agentic verdict/context/actions decision document. Release and delete are approval-gated and handed off to chat via primer. Backed by the MCP server's Quarantine module; ships staged-build. | No (cluster review) / Yes (assessment) |
| **`/correlation`** | NGSIEM correlation-rule health. Summarizes the tenant's published rules — active vs inactive, severity spread, MITRE ATT&CK coverage, staleness — then an agentic decision document flags coverage gaps, stale rules, and inactive high-severity content. Tune / disable hand off to chat (approval-gated). Backed by the MCP server's Correlation Rules module; ships staged-build. | No (health summary) / Yes (assessment) |
| **`/data-protection`** | Data-exposure posture. Summarizes Data Protection policies (enforce vs monitor, precedence), classifications, and content patterns, then an agentic decision document ties posture to live `product:'data-protection'` detections. Read-only surface (the chat agent can edit existing configuration, approval-gated). Backed by the MCP server's Data Security module; ships staged-build. | No (posture summary) / Yes (assessment) |
| **`/discover`** | Falcon Discover asset / application / account inventory. Deterministic posture summary — managed vs unmanaged endpoints (coverage gaps), platform spread, privileged / local-admin accounts and password hygiene, applications flagged suspicious — then an agentic verdict/context/actions decision document. Read-only. Assets and applications come from the FalconPy sidecar (one record shape across managed / unmanaged); accounts come from the MCP server natively. Ships staged-build. | No (posture summary) / Yes (assessment) |
| **`/workflows`** | Fusion SOAR posture surface. Lists workflow definitions, recent executions, available triggers; flags failures and dormant workflows. On-demand `execute` exposed to the agent as a gated write action — payload is rendered fully resolved in the approval modal before fire. Backed by FalconPy `Workflows`. | Yes |
| **`/identity`** | Identity Protection posture surface. Top-N risky USER entities via the IDP GraphQL API + active policy rules. **Builds and renders cleanly even when the API key lacks the IDP scope** — the staged-build pattern lets the surface light up automatically when scope lands, no code changes. Backed by FalconPy `IdentityProtection`. | Yes |
| **`/ngsiem`** | Natural-language → CQL with 60+ curated playbooks across 9 MITRE categories (incl. Shadow AI + Supply Chain). | Yes (for narrative); deterministic queries |
| **`/detections`, `/hosts`, `/vulnerabilities`** | Deterministic dashboards. Each row has an "Ask agent" deep-link into chat. `/detections` and `/vulnerabilities` carry inline **Agent triage** panels above the tables. `/detections` row drawer renders **process-tree ancestry + delivery-vector verdict** (`phishing_doc`, `c2_agent`, `lateral_winrm`, etc.) — converts "what fired" into "how it arrived." `/hosts` folds in host-groups (formerly its own surface) and exposes per-host **Investigate** + **IR** chips. `/vulnerabilities` is a posture surface — five-tile health row, three-card hero strip (Drop everything / ExPRT Critical / **Actively exploited** = CISA KEV count), per-row `KEV` + `exploit:active`/`exploit:public` chips drawn from the Spotlight CVE record. **Build patch plan** + **Run patch in chat** on every By-patch row. A server-computed **capability-gap badge** marks Windows remediations no curated script covers, with **generic-installer** (install/upgrade from a vendor HTTPS URL) and **save-as-profile** hand-offs so a consumer can close the gap at runtime — no rebuild. | No (dashboards) / Yes (triage panels + patch plan) |
| **`/vulnerabilities/adversary-exposure`** | Optional Spotlight × Falcon Intel enrichment surface, reachable via a small link beneath the hero strip. Walks the top 30 open Critical/High CVEs and joins them against `falcon_search_indicators` + `falcon_search_actors`. Falcon Intel CVE→actor coverage is sparse (live measurement: ~0/30 indicator hits, ~1/10 actor capability hits), so the headline triage signal lives on `/vulnerabilities` itself via CISA KEV; this page is for when the operator specifically wants attribution context. | Yes |
| **`/ir-runs`** | Incident-response engagement audit trail — every agentic IR run this console executed, with phase-by-phase tool-call replay, outcome, and guardrails. Each engagement carries a one-click **Generate incident report**: a layered write-up with a plain-language executive summary on top and full technical detail below (timeline, affected host, response actions by phase, detections & evidence, human oversight, open items, recommendations), synthesized from the frozen engagement record with no upstream calls. Print / PDF + webhook capture. Environment-scoped. | No (audit replay) / Yes (incident report) |
| **`/scorecard`** | What this console has accomplished for the active tenant — IR engagements run (with median/mean close time and detections resolved), gated write actions reviewed / allowed / declined, breadth of agentic work by surface, and posture movement over time. Deterministic local-DB aggregation with a period-over-period read; environment-scoped. | No (deterministic readout) |
| **`/cost`** | Token-spend dashboard. Per-day chart, by-surface and by-model breakdowns, recent turns, daily-budget banner. | No |
| **`/status`** | Diagnostics: ping Anthropic, ping CrowdStrike AIDR (when configured), list discovered Falcon tools, build info. Carries a **Posture history** card — latest capture time, snapshots stored, coverage, and the movement between the two most recent posture captures. | No |
| **`/agent-toolbox`** | Developer reference surface (its own **Reference** nav group). Renders the exact live tool surface the agent can compose — `eyas-mcp` plus the FalconPy extension — each tool marked read-only or approval-gated, with top-level params and a full JSON input-schema disclosure. Search + provider / access filters; a "why are some native writes not shown?" disclosure surfaces the curation story (natives routed to richer curated equivalents). Reuses the chat agent's tool-bridge, so it can't drift from what the agent sees. **Read-only — never invokes a tool.** | No (static catalog) |
| **`/blueprint`** | Developer reference surface (**Reference** nav group, beside Agent toolbox). A "build-your-own agentic SOC" advisor: pick a seeded blueprint or ask your own question and it streams a decision document explaining how to compose `falcon-mcp` + FalconPy + Claude — grounded in this console's own reference architecture (in-process MCP client + tool-use loop, approval-gating, the falcon-mcp↔FalconPy split, deterministic enrichment) — with an **Authoritative sources** panel linking out to developer.crowdstrike.com for the platform primitives. Reasons about architecture; calls no Falcon tools, so it works with only Anthropic configured. | Yes (advisor) |

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Browser (single user)                                    │
└──────────────────────────┬───────────────────────────────┘
                           │ HTTPS
┌──────────────────────────▼───────────────────────────────┐
│  Next.js app (App Router, server-side MCP client)         │
│  - app/api/chat: streaming agent loop                     │
│  - app/api/<surface>: deterministic MCP calls             │
│  - lib/mcp/: tool-bridge, write-tool registry             │
│  - lib/chat/: agent loop, approvals, conversation state   │
└────────────┬───────────────────────────┬─────────────────┘
             │                           │
             │                           │
┌────────────▼──────────┐   ┌───────────▼─────────────────┐
│ Anthropic Messages API │   │ eyas-mcp (stdio child;      │
│ (default Claude        │   │ streamable-http in Docker)  │
│  Sonnet 4.6)           │   │ → CrowdStrike Falcon API    │
└────────────────────────┘   └─────────────────────────────┘
                                         ▲
                                         │ same agent loop
                             ┌───────────┴─────────────────┐
                             │ falcon-extras (stdio child) │
                             │ Python + FalconPy           │
                             │ containment, IR, patching,  │
                             │ provisioning, and more      │
                             └─────────────────────────────┘
```

The defining design choice is an **in-process MCP client** (`@modelcontextprotocol/sdk`) running inside the Next.js server, paired with a manual Anthropic tool-use loop. This keeps Falcon API credentials and calls on the Eyas host (vs. routing tool calls through Anthropic's MCP connector) — though the tool results the agent reads are still sent to the model endpoint; see [where data goes](./SECURITY.md#where-data-goes) — gives us a clean hook for write-action approval gating, and lets us emit a per-tool duration trace into the UI. Trade-off: an agent loop we maintain ourselves (`lib/chat/agent-loop.ts`). The MCP server is pinned by git commit in `versions.json`; a variant that targets CrowdStrike's hosted MCP gateway is planned — see [`docs/HOSTED-MCP-ASSESSMENT.md`](./docs/HOSTED-MCP-ASSESSMENT.md).

The **`falcon-extras/`** Python sidecar (always on) shows the architecture's other half — additional MCP servers can be plugged into the same agent loop with no protocol-level differences. It no longer registers any tools and is removed next. The sidecar is being retired: Eyas's own tools are moving into `lib/eyas-tools/`, served in-process by the tool bridge under the same names (the IR, identity-IR, Shadow-AI and Data Protection playbooks, the patch and cleanup script library, host-group membership writes and the IR quarantine setup, policy provisioning and readiness checks, the tenant teardown, the IR detection scope and closers, the process tree, campaign scope and remote-access-tool scan, the Shadow-AI hunts, setup and prevention, and the exclusions and Data Protection creates have moved). Generic Falcon operations belong in `eyas-mcp`. Tools across these capability families (Discover, Recon, Fusion workflow listings and runs, NGSIEM search and listings, prevention posture, host-group listings and membership, contained-host listings, detection status and verdicts, RTR script runs and readiness checks, Threat Graph, MalQuery, Identity Protection reads and host containment started here and now run in `eyas-mcp`):

- **Agentic patching via curated RTR scripts** — `extras_rtr_list_patch_scripts` / `_resolve_patch_plan` / `_run_patch` / `_check_patch_status`. Plan → execute → verify loop (Eyas renders each script from its library; `eyas-mcp` uploads it as a one-off private script, runs it and deletes it) for Windows Update, browser updates, Office Click-to-Run, 7-Zip, JRE removal, **Adobe Flash Player nuke**, **Internet Explorer disable via DISM**, **Windows reboot**, **distro-agnostic Linux apt/dnf/yum upgrades** (single generic script — Ubuntu, Debian, RHEL, Rocky, Alma, Fedora, Amazon Linux), and macOS PKG installs. A **generic Windows installer** (`win-app-install`) installs/upgrades any app from a vendor HTTPS URL, parameterized at runtime (`url`, optional `sha256`, `kind`, `silent_args`, `product`) — declared last and carrying no `spotlight_match` so it can never shadow a specific app script. Validated parameter-sets save as **per-tenant patch profiles** (`extras_save_patch_profile` / `_list_patch_profiles`, stored as data per-environment — no script bytes), so a consumer of the standalone bundle builds their own catalog at runtime without a rebuild.
- **Host group membership writes** — `extras_host_group_add_members` / `_remove_members` (approval-gated; pre-flight refuses dynamic groups with a clean error). Listing groups and members is native in `eyas-mcp`. Folded into `/hosts` (no longer a separate surface).
- **Identity Protection** — the agentic identity-IR cascade (`extras_identity_ir_workflow_playbook`, quarantine-rule writes); identity detections, risky identities, policy rules, IDP sensors, user → host history and host → identity correlation are native in `eyas-mcp`. Backs `/identity`.
- **Agentic incident response** — `extras_ir_workflow_playbook(device_id)` returns a parameterized 5-phase playbook (Discovery → Quarantine → Remediation → Verification → Release). Phase 2 cleanup catalog (`extras_rtr_run_cleanup` + 14 primitives: kill-process, delete-file, quarantine-file, delete-folder, stop/delete-service, remove-scheduled-task, remove-run-key, remove-ifeo-hijack, remove-wmi-persistence, set-registry-value, disable-local-user, force-logoff, block-outbound-ip, uninstall-anydesk) — every script is rendered server-side from a manifest schema; the agent supplies validated params, never script bytes. Before cleanup, the workflow waits until a harmless probe script actually runs on the quarantined host (`falcon_wait_for_rtr_sessions` with `probe="runscript"`). Phase 4 closes only the detections the remediation ledger matched; if original detections the workflow never touched would block release, the agent stops and asks the operator to close them (one approved step) or hold. Closing every open detection on a host on request is a single approved call too.
- **NGSIEM search with a CQL pre-flight check** — `/ngsiem` runs eyas-mcp's `falcon_search_ngsiem` with its query check, a 100-row cap and a 50-second budget (partial rows instead of a timeout). Connection / parser / lookup-file listings and the CQL function lookup are native in `eyas-mcp`.
- **Prevention Policy posture** — eyas-mcp's `falcon_get_prevention_posture` (read), with Eyas's own detect-only rule (sensor ML and cloud antivirus only) applied on top. Backs `/prevention`.

All read-only paths use a shared `_check_response(resp, surface)` guard that recognizes scope-pending 401/403 (returns a clean "scope pending" payload naming the missing scopes) and surfaces non-2xx upstream errors instead of silently masking them as `count: 0`.

---

## Tech stack

- **Next.js 15** (App Router, server components, standalone build)
- **TypeScript**, **Tailwind CSS**, **Inter Tight** (body) + **JetBrains Mono** (display/numbers/code) self-hosted via `next/font/local`, **lucide-react** icons. Visual direction is "SOC operator console at 2am" — brand-red on near-black, dot grid, atmospheric layers, terminal-grade typography
- **`@anthropic-ai/sdk`** (manual tool-use loop, prompt caching on the system prompt)
- **`@modelcontextprotocol/sdk`** (in-process MCP client; HTTP + stdio transports)
- **`eyas-mcp`** (Python MCP server, pinned by commit) for the native Falcon tool surface
- **`crowdstrike-falconpy`** + **`mcp` (Python)** for the extras sidecar
- **macOS standalone bundle** (`make-dist.sh` → `install.sh` + `eyas` launcher, offline wheels) as the primary deployment; **Docker Compose** as a legacy alternative
- **Playwright** for smoke tests

---

## Status

Surface area: ~217 `eyas-mcp` tools (about 200 reach the agent; the rest are held back where Eyas's own version adds checks, or are used only through Eyas's tools) + 56 extras-sidecar tools across agentic patching, agentic incident response, host-group writes, Workflows execute, identity IR, process-tree reconstruction + RAT-install scan, tenant provisioning, and Shadow-AI hunting. Together they cover detections, hosts and containment, vulnerabilities, Recon, MalQuery, Workflows, Identity Protection, Threat Graph, NGSIEM, prevention posture, Discover, Zero Trust Assessment, Cloud Insights and Guardian AI-agent activity (AIDR). Surfaces split into a **`/home` control center** (live capability widgets that open in-page tool panels + a global agent chat dock reachable from every page), deterministic dashboards (`/detections`, `/hosts`, `/queue`, `/vulnerabilities`, `/prevention`, `/cases`), agentic decision documents (`/`, `/briefing`, `/investigate`, `/pivot`, `/intel`, `/intel-dossier`, `/recon`, `/malquery`, `/workflows`, `/identity`, `/ngsiem`, `/shadow-ai`), operator-accountability surfaces (`/scorecard` for what the console has done for the tenant, `/ir-runs` incident reports, and the `/status` posture-history trend), in-page triage panels, and two developer **Reference** surfaces (`/agent-toolbox`, which renders the exact live tool surface the agent can compose, and `/blueprint`, a build-your-own advisor that explains how to compose `eyas-mcp` + FalconPy + Claude, grounded in this console's architecture). Detection drawer renders the full process-tree ancestry + delivery-vector verdict (`phishing_doc`, `c2_agent`, `lateral_winrm`, etc.) — converts "what fired" into "how the attack arrived."

Release notes in [`CHANGELOG.md`](./CHANGELOG.md). Architectural reference + design gotchas in [`CLAUDE.md`](./CLAUDE.md).


---

## Repository layout

```
app/                Next.js App Router pages + API routes
components/         React components (Chat, AgentRun, dashboards, shell)
lib/
  llm/              Anthropic SDK singleton
  mcp/              MCP clients, tool bridge, write-tool registry
  eyas-tools/       Eyas's own agent tools served in-process (workflow playbooks, RTR script library, IR tools)
    process-tree/   Pure-function ancestry classifier (delivery-vector verdicts)
    rtr/patching/   Curated patch scripts (manifest.json + scripts/{windows,linux,macos})
    rtr/cleanup/    Agentic IR cleanup primitives (manifest.json + scripts/windows)
  chat/             Agent loop, approvals, conversation state
  cost/             Token-spend log + Anthropic pricing table
  db/               SQLite (better-sqlite3) + Drizzle, migrations, column encryption
falcon-extras/      Python MCP sidecar (FalconPy)
  server.py         Sidecar tools entry point
tests/              Playwright smoke tests + reference screenshots
docs/               Operator + deployment guides (USERGUIDE, DEPLOYMENT, STANDALONE, DEMO, IR-SETUP, SHADOW-AI-SETUP, …)
scripts/            Build helpers (install.sh generator), scope probe, pure-function test runners
vendor/             Vendored npm tarballs + native prebuilds for the offline bundle
versions.json       Pinned MCP server (eyas-mcp) commit + Python SDK versions
```


---

## Security posture

- All Falcon and Anthropic credentials are server-only — no `NEXT_PUBLIC_*`, no client-side fetches to provider APIs.
- The MCP server and the extras sidecar run as stdio child processes of the app — no network port. (In the Docker path the MCP server is reachable only on the internal Docker network.) The console binds to `127.0.0.1:3000`.
- Every Falcon write action is gated by an explicit user approval in the UI, with a 5-minute timeout that resolves as `"approval expired"` (distinct from a denial).
- Write tools are enumerated in [`lib/mcp/write-tools.ts`](./lib/mcp/write-tools.ts) — when in doubt, list it there.
- First-run registration sets a single password (Node `crypto.scrypt`-hashed, stored at `data/eyas.db`); every route is gated by an iron-session cookie with a 7-day rolling TTL. Delete `data/eyas.db` to re-arm registration; rotate `AUTH_SESSION_SECRET` to invalidate active sessions.
- Falcon + Anthropic credentials are **AES-256-GCM column-encrypted at rest** in `data/eyas.db` (mode 0600); the key is derived via HKDF-SHA256 from `AUTH_SESSION_SECRET`, so an exfiltrated DB file alone is unreadable. Full posture — threat model, at-rest encryption, approval gating, the optional AIDR guardrail, and npm-audit triage — is in [`SECURITY.md`](./SECURITY.md).

---

## License & status

MIT-licensed (see [`LICENSE`](./LICENSE); attributions and trademarks in [`NOTICE.md`](./NOTICE.md)). Unofficial reference implementation — not a CrowdStrike product and not supported by CrowdStrike. Use the code as a working example of an MCP server + FalconPy + Claude integration; deploy against your own tenant at your own discretion.

# Eyas — Whitepaper

**Unofficial**

Eyas is an agentic web console for CrowdStrike Falcon, built on `eyas-mcp` (an independent Falcon MCP server derived from CrowdStrike's MIT-licensed `falcon-mcp`), the [FalconPy](https://falconpy.io) Python SDK, and the Anthropic Claude API. The name *eyas* is the falconry term for a young falcon being trained — Eyas is raised on the same craft as Falcon but is distinctly its own thing. Not a CrowdStrike product. Intended audiences: SOC analysts, IR analysts, and Falcon administrators evaluating an agent layer for their own tenant; CrowdStrike Sales Engineers using the codebase as a working reference for MCP server + FalconPy + Claude integration.

---

## 1. Problem statement

The Falcon console is a comprehensive but click-driven UI. Common security workflows — "summarize all critical detections from the last 24 hours and group them by host", "find any host that hasn't checked in for a week and show its last detection", "is this hash already covered by Falcon Intel before I add a custom IOC?", "patch every host showing CVE-2024-XXXX", "walk me through containment, cleanup, and release on this host" — span multiple modules and require an operator to context-switch between Detections, Hosts, Spotlight, RTR, IOC management, Identity, and Intel. Each cross-module pivot is manual.

Anthropic's Model Context Protocol (MCP) and an MCP server for Falcon (`eyas-mcp`) expose Falcon's API surface as a typed tool catalog that an LLM can drive directly. **Eyas** is a self-hosted Next.js application that wraps that catalog with a chat surface, deterministic dashboards, and curated agentic decision surfaces — turning natural-language prompts into auditable, gated tool calls against the operator's own tenant.

This is an **unofficial reference implementation**, not a production replacement for the Falcon console. Quality is measured by useful, novel cross-module workflows surfaced — not by feature parity. The codebase doubles as a worked example for teams building their own agent layer on top of an MCP server + FalconPy.

---

## 2. Use case

Single-operator security work, primarily:

- **Triage at start of shift.** `/queue` ranks open detections (severity × recency × per-host concentration × uncontained-critical bonus), clusters them into campaigns (cross-host SHA-256 / image+technique / lateral-by-user), surfaces tuning candidates (FP-pattern + queue-drown signals), and produces a 5-section triage brief. Per-row Triage / IR chips hand off to chat with primer context including identity overlay for top-bucket rows.
- **Artifact pivot.** Paste any hash / IP / domain / URL into `/pivot` → Falcon Intel + custom IOC list + tenant detections + 30 days of NGSIEM telemetry, plus Threat Graph (hash → device aggregation for hashes, network-vertex summary for IP/domain). Returns a 5-section decision document.
- **Host deep-dive.** `/investigate` runs a two-round fan-out for one AID: recent detections, open vulnerabilities (ExPRT-prioritized), live RTR introspection via Falcon-published scripts (Process / Service / RegisteredAV / BitLocker / EventLog), and identity exposure.
- **Threat-actor exposure.** `/intel` walks 90 days of detections and runs deterministic three-path attribution server-side: (1) Falcon-native `adversary_ids` resolved against the Intel actor catalog — ground truth, same signal the Console uses; (2) extracted hashes / domains / IPs joined against Falcon Intel indicators (corroboration); (3) detection-text alias matching against a curated CrowdStrike actor map — heuristic. Provenance rendered per evidence row so the operator can tell ground truth from heuristic. Agent only synthesizes; no per-detection LLM fan-out. Surfaces only actors with tenant evidence — no flat global catalog.
- **Adversary-intel exposure.** `/recon` checks domain or email against the Falcon Adversary Intelligence Recon corpus — criminal marketplaces, dark-web forums, paste sites, Telegram, social media — via the Recon `preview_rule` data-lake search path.
- **Hash lineage.** `/malquery` fans out MalQuery metadata + Falcon Intel + tenant detections across up to 25 hashes per run.
- **Vulnerability posture and patching.** `/vulnerabilities` is a posture surface — three-card hero strip (Drop everything / ExPRT Critical / Actively exploited = CISA KEV count), per-row KEV + exploit-status chips, ExPRT-led grouping. The patching loop closes: the curated RTR script catalog (`falcon-extras/patching/`) covers Chrome, Firefox, Office Click-to-Run, 7-Zip, JRE removal, Windows Update via the WUA COM API, distro-agnostic Linux apt/dnf/yum, and macOS PKG installs. Plan → execute (dry-run, then live) → verify. Eyas renders each script from its library; `eyas-mcp` uploads, runs and deletes it.
- **Agentic incident response.** Five-phase chat-resident workflow (Discovery → Quarantine → Remediation → Verification → Release/Hold) gated by per-tool approval. Phase 0 enrichment surfaces process-tree ancestry + delivery-vector verdict (`phishing_doc`, `c2_agent`, `lateral_winrm`, etc.), cmdline artifacts, registry persistence, and a thorough RAT-install scan. Cleanup catalog covers 14 primitives (kill-process, delete-file, quarantine-file, IFEO removal, AnyDesk uninstall, etc.) — all rendered server-side from a manifest schema; the agent supplies validated params, never script bytes. Before cleanup the workflow waits until a probe script actually runs on the quarantined host; at release it closes only what remediation matched and asks the operator before closing original detections it never touched.
- **Operational autonomy.** Manifest-driven recurring jobs (patch digest, daily briefing, an eyas-mcp update check) deliver agentic markdown reports to a webhook on a configurable cadence.
- **Write actions** (IOC, firewall rule groups, custom IOA, scheduled report launch, host containment, host group membership, Fusion workflow execute, RTR patching + cleanup, detection verdict transitions) — gated behind an explicit per-call approval card with a 5-minute timeout.

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Browser (single user)                                    │
└──────────────────────────┬───────────────────────────────┘
                           │ HTTPS (reverse proxy → :3000)
┌──────────────────────────▼───────────────────────────────┐
│  Next.js app                                              │
│  - Chat surface, dashboards, agentic surfaces             │
│  - app/api/chat: streaming agent loop                     │
│  - lib/mcp/: in-process MCP client + tool bridge          │
│  - lib/chat/: agent loop, write-tool approval gating      │
│  - lib/scheduler/: manifest-driven recurring jobs         │
│  - lib/queue/: ranking + campaign clustering + tuning     │
└────────────┬───────────────────────────┬─────────────────┘
             │                           │
┌────────────▼──────────┐   ┌───────────▼─────────────────┐
│ Anthropic Messages API │   │ eyas-mcp (MCP server)       │
│ Claude Sonnet 4.6      │   │ HTTP :8000 / stdio child    │
└────────────────────────┘   │ → CrowdStrike Falcon API    │
                             └─────────────────────────────┘
                                         ▲
                                         │ optional, opt-in
                             ┌───────────┴─────────────────┐
                             │ falcon-extras (stdio child) │
                             │ Python + FalconPy           │
                             │ containment, patching, IR,  │
                             │ RTR introspection, Recon,   │
                             │ MalQuery, Workflows, IDP,   │
                             │ Threat Graph, NGSIEM ops,   │
                             │ Prevention Policy posture   │
                             └─────────────────────────────┘
```

The defining design choice is an **in-process MCP client** (`@modelcontextprotocol/sdk`) running inside the Next.js server, paired with a **manual Anthropic tool-use loop**. Anthropic's hosted MCP connector was rejected for a security-admin tool because:

- **Data exposure.** Falcon credentials and API calls stay on the Eyas host, and the model only sees the tool results the agent requests. The connector would route every tool call and response through Anthropic's infrastructure. Those tool results still reach the model endpoint either way; see [where data goes](../SECURITY.md#where-data-goes).
- **Network exposure.** The MCP server runs as a stdio child process (or on a private docker network), never internet-facing.
- **Approval gating.** With the in-process loop, the confirm step is a single `if` between `tool_use` and execution — no equivalent hook on the connector path.
- **Audit logging.** Every Falcon API call the agent makes is a function call we own, logged with per-tool duration into the chat trace.

Trade-off: an agent loop we maintain ourselves in `lib/chat/agent-loop.ts`. The optional `falcon-extras/` Python sidecar demonstrates the architecture's other half — additional MCP servers plug into the same loop with no protocol-level differences. It uses [FalconPy](https://falconpy.io) to fill capability gaps the MCP server does not cover (host containment, RTR patching, agentic IR cleanup catalog, RTR introspection, Recon, MalQuery, Host Groups membership write, Workflows execute, Identity Protection, Threat Graph, NGSIEM operational endpoints, Prevention Policy posture, process-tree reconstruction, RAT-install scan).

A shared `_check_response(resp, surface)` guard sits between every wrapped FalconPy call and `body.resources` — it recognizes scope-pending 401/403 envelopes and returns a clean "scope pending" payload (the **staged-build pattern**: surfaces ship before scope is granted and light up automatically when applied), and surfaces non-2xx upstream errors instead of silently masking them as `count: 0`.

---

## 4. Deployment

Two supported paths, both driven by the same code. Full guides:

- **Docker / Linux server** — [`DEPLOYMENT.md`](./DEPLOYMENT.md). Compose builds and launches the Next.js app + `eyas-mcp` on a private bridge network; only `127.0.0.1:3000` is published to the host. The Dockerfile is a multi-stage build: a Node stage compiles the Next.js standalone output, a Python 3.12 alpine stage builds the FalconPy venv, and the runner image carries both — so `falcon-extras` is bundled by default. A reverse proxy terminates TLS and forwards real client IPs (used by per-client login throttling when `EYAS_TRUST_PROXY=true`).
- **Standalone macOS** (no Docker) — [`STANDALONE.md`](./STANDALONE.md). Distributed as a zip from `./make-dist.sh`; `start.sh` spawns `eyas-mcp` as a stdio child rather than over HTTP. First launch lands at a `/register` wizard that collects integration credentials and writes them to `data/eyas.db` (mode 0600) — no `.env` editing required.

Quickstart for either path: [`QUICKSTART.md`](../QUICKSTART.md).

Required credentials at a minimum: `ANTHROPIC_API_KEY` (or `ANTHROPIC_AUTH_TOKEN` + `ANTHROPIC_BASE_URL` for a corporate gateway), and `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` / `FALCON_BASE_URL` for the Falcon API client. Falcon scope coverage shapes which surfaces light up — currently every MCP-server module loads by default and capability-gating in `/api/health` hides sidebar items for surfaces whose backing scope isn't granted, so 403s degrade cleanly (the page renders a scope-pending banner; the nav hides) without operator intervention. `FALCON_MCP_MODULES` remains an `.env`-only escape hatch for power users who want to narrow the tool surface further.

---

## 5. Security model

- **Server-only credentials.** No `NEXT_PUBLIC_*`; the browser never holds Anthropic or Falcon keys, and never talks to provider APIs directly.
- **Network isolation.** The MCP server is reachable only on the internal Docker network in the compose path; in the standalone path it's a stdio child of the Node process.
- **Single-user authentication.** First-run `/register` wizard sets a single console password (Node `crypto.scrypt`-hashed, stored at `data/eyas.db`). Every route is gated by an iron-session cookie with a 7-day rolling TTL. Delete `data/eyas.db` to re-arm registration; rotate `AUTH_SESSION_SECRET` to invalidate active sessions.
- **Per-call approval gating.** Every write tool (IOC, firewall, IOA, scheduled report, containment, host group membership, Fusion workflow execute, RTR run, detection verdict transitions) pauses the agent loop on `tool_use` and surfaces a confirm card showing the highest-stakes fields. The approval has a 5-minute timeout that resolves as `"approval expired"` (distinct from a denial). Write tools are enumerated in `lib/mcp/write-tools.ts`.
- **Render-time security on RTR patching + cleanup.** The agent supplies a script `id` and validated parameters — never script bytes. Bytes live in repo as diffable `.ps1` / `.sh` files. Parameter values pass through enum + regex validation (fail-closed against unknown keys), single-quote-escaping for PowerShell, and an ASCII coercion backstop (RTR's runscript transport doesn't deliver UTF-8 cleanly under SYSTEM).
- **Closed-set patching + cleanup catalog.** The agent can only execute scripts already curated and reviewed in the repo. New scripts require a manifest entry + body + `/audit-remediations` bucket diff against live Spotlight data.
- **Tool-call trace as audit log.** Every tool invocation, its arguments, and its duration are rendered inline in the chat UI. Token spend is logged per turn to the local SQLite database and surfaced on `/cost`.
- **Read-only by default.** Recurring scheduled jobs deliver decision documents to a webhook but never invoke writes. Operators still drive execution from the UI.

---

## 6. Using the console

The browser entry point at `/` is a free-form chat surface with full Falcon tool access. Tool calls and their durations render inline; write actions surface a confirmation card.

Curated agentic surfaces produce **decision documents, not ranked lists**:

- **`/queue`** — detection triage with deterministic ranking, campaign clustering, identity overlay, tuning candidates, and a 5-section triage brief above the table.
- **`/pivot`** — artifact pivot (hash/IP/domain/URL). Cross-source lookup mode fans out across Intel + IOC list + detections + NGSIEM telemetry; for hashes, an Execution lineage mode walks Threat Graph for lateral spread.
- **`/intel`** — actor exposure with tenant evidence (no global catalog).
- **`/recon`** — adversary-intelligence corpus exposure (domain/email) via Recon `preview_rule`.
- **`/malquery`** — hash lineage across CrowdStrike's malware research corpus.
- **`/workflows`** — Fusion SOAR posture; on-demand execute is exposed as a gated write action with the resolved payload rendered in the approval modal.
- **`/identity`** — Identity Protection top-N risky entities + active policy rules; staged-build, scope-pending tolerant. Pairs with the agentic identity-IR cascade for endpoint-driven response.
- **`/prevention`** — Prevention Policy posture (sensor-ML slider, exclusions, behavioral coverage). Read-only, staged-build.
- **`/briefing`** — daily report with Print/PDF + webhook send.
- **`/investigate`** — host deep-dive (detections + vulns + live RTR introspection on Windows hosts + identity exposure).
- **`/vulnerabilities/adversary-exposure`** — optional CVE × adversary enrichment, reachable from `/vulnerabilities`. Headline triage on the parent page uses the CISA KEV flag carried in the Spotlight CVE record itself, since Falcon Intel CVE→actor coverage is sparse on this tenant (~0/30 indicator hits measured).

Deterministic dashboards (`/detections`, `/hosts`, `/vulnerabilities`) carry inline **Agent triage** panels above each table. Every dashboard row exposes deep-links into the chat surface via `?primer=<encoded prompt>` — the user reviews before sending. The `/detections` row drawer renders the full process-tree ancestry + delivery-vector verdict — converting "what fired" into "how it arrived." `/hosts` folds in host-groups inventory and per-host Investigate / IR chips.

The `/vulnerabilities` By-patch view exposes "Build patch plan" (decision document) and "Run patch in chat" (dry-run-first execution sequence) on every patchable bucket. Cross-table pivot chips ("Investigate") are present on every host-bearing row across the app for consistency.

The `/ngsiem` surface ships 60+ curated CQL playbooks across nine MITRE categories (incl. Shadow AI + Supply Chain) plus a save-your-own-question facility, fronted by a deterministic Pipeline Health strip showing data-connection / parser / lookup-file counts.

When `SCHEDULER_ENABLED=true` and `OUTBOUND_WEBHOOK_URL` is configured, the `SCHEDULES` env manifest arms recurring read-only agentic runs that POST their markdown to the webhook — `patch-digest` (top open ExPRT-High+ has-fix bundle), `daily-briefing` (the same one-page report `/briefing` produces), and `release-watcher` (notifies when eyas-mcp, the Falcon MCP server Eyas runs, has commits newer than Eyas's pinned commit). Operators self-hosting pick their own cadence per job.

---

## 7. Limitations and roadmap

- **Single-user only.** No multi-tenant or team-collaboration model.
- **Sticky chat session.** `localStorage` + in-memory server map survives reloads — operators should reset between unrelated scenarios so referents from earlier turns don't leak into write-tool prompts. The approval gate still catches it.
- **Build reproducibility.** The MCP server is pinned by git commit in `versions.json` and the sidecar's Python dependencies are hash-locked; every bundle is built offline-installable from those pins.
- **Scope-shaped coverage.** Surfaces light up only when the API client has the corresponding scope. The staged-build pattern (`/identity`, `/prevention`, CAO Hunting) renders cleanly until scope lands; no code change required when granted.
- **Sidebar capability-gating** hides surfaces whose backing scope isn't granted; the agent's tool surface follows the same gate — tools whose scope isn't granted return a structured scope-pending payload rather than a 403 trace. `FALCON_MCP_MODULES` remains as an `.env`-only escape hatch for narrowing the tool surface further.

The honest quality lever remains: which novel "I couldn't easily do this in the console" workflow earns the next surface? Current answers: agentic incident response (the cleanup loop closes), process-tree delivery-vector reconstruction ("how did this arrive" from "what fired"), agentic patching (the patch loop closes), thorough RAT-install scan (catches sibling AnyDesk-class installs the cheap Process script misses), CISA KEV-led vulnerability triage (correct primary signal vs. sparse Intel CVE→actor coverage), and the manifest-driven scheduler (autonomy without writes).

---

## References

- `eyas-mcp` — https://github.com/GTStagg/eyas-mcp
- CrowdStrike `falcon-mcp`, which eyas-mcp derives from (attribution in `NOTICE.md`) — https://github.com/crowdstrike/falcon-mcp
- Model Context Protocol — https://modelcontextprotocol.io
- FalconPy — https://falconpy.io
- Anthropic Messages API — https://docs.anthropic.com/en/api/messages

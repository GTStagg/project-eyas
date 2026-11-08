# For the AIDR Wizard Himself

A post-demo reference for the technical evaluator who cares less about which alert fired and more about how an agentic MCP-based pattern is being built for a security workflow. Companion to:

- [`../README.md`](../README.md) — capability surface
- [`./WHITEPAPER.md`](./WHITEPAPER.md) — design tenets and tradeoffs
- [`./USERGUIDE.md`](./USERGUIDE.md) — operator perspective
- [`../CLAUDE.md`](../CLAUDE.md) — load-bearing implementation gotchas

This document is the architectural narrative — what we built, why we made each non-default choice, and what we'd want a peer reviewer to push on.

---

## What this is

**Eyas** is a self-hosted Next.js application that drives CrowdStrike Falcon through Claude — wrapping CrowdStrike's official [`falcon-mcp`](https://github.com/crowdstrike/falcon-mcp) Model Context Protocol server and a [FalconPy](https://falconpy.io)-based Python sidecar. The name *eyas* is the falconry term for a young falcon being trained: Eyas is raised on the same craft as Falcon, distinctly its own thing. **Unofficial** and explicitly not a Falcon Console replacement — quality is measured by whether the agentic workflows are useful, not by feature parity. The codebase is intended as a working reference for two audiences: customer security teams (SOC, IR, Falcon administration) evaluating an agent layer for their own tenant, and CrowdStrike Sales Engineers demonstrating what `falcon-mcp` + FalconPy + Claude can do together.

The core thesis: a security console is a particularly good fit for an agentic MCP-based interaction model, because:

1. The data is **already structured and tool-call-friendly** (every Falcon API endpoint is a candidate tool).
2. The work is **decision-document-shaped** — operators want "what happened, what should I do, why" more than they want smarter tables.
3. Many actions are **safe to read but consequential to write** — a per-tool approval model fits naturally.
4. The **provenance distinction matters**: ground-truth API data versus heuristic synthesis is a meaningful split that a UI can surface.

---

## The defining architectural choice

We considered three places to put the Anthropic ↔ Falcon glue:

| Option | Where the agent runs | Where Falcon credentials live | What we lose |
|---|---|---|---|
| **A. Anthropic native MCP connector** | Anthropic's servers | Public HTTPS endpoint Anthropic can reach | Data residency, per-tool approval, ownable audit log, MCP server composition flexibility |
| **B. In-process MCP client + manual tool-use loop** *(this project)* | Your app's Node process | Server-side env / `data/eyas.db` | More code to maintain |
| **C. Bring-your-own-frontend, Anthropic Agents SDK** | Anthropic-managed | Same as A, with more abstraction layers | Same as A plus opaque internals |

We picked B. Concretely that means:

- A custom **agent loop** in `lib/chat/agent-loop.ts` that drives `anthropic.messages.stream(...)` directly, parses `tool_use` content blocks, dispatches to the MCP client(s), feeds results back as `tool_result` blocks, and iterates until `stop_reason: end_turn`.
- The **MCP client is in-process** — `@modelcontextprotocol/sdk`'s `Client` running inside the Next.js Node runtime. Falcon-mcp is reached via `StreamableHTTPClientTransport` over a private bridge with `x-api-key` injected through `requestInit.headers`.
- A **second MCP client** to the local `falcon-extras/` Python sidecar (FalconPy + curated tooling) over stdio. Both client tool lists are merged transparently for the agent — the upstream and the sidecar tools look identical at the protocol level.

Direct consequences this audience will care about:

- **No public-internet ingress on the Falcon side.** falcon-mcp lives on a private Docker bridge or as a stdio child of the standalone bundle. Only the app talks to it.
- **Per-tool approval gates.** A registry in `lib/mcp/write-tools.ts` declares which tools are read versus write; the agent loop pauses on any write call, emits an SSE `approval_required` event, and waits up to 5 minutes for the operator decision before resuming. Default-deny on timeout.
- **Audit log is ours.** Every tool call (name, args, duration, result digest) is appended to the local SQLite database (token usage) and `data/perf-log.jsonl` when `PERF_LOG=true` (timing). No external service holds the trail.
- **Composition is trivial.** Adding a third MCP server (NGSIEM ingest, identity vendor, ticketing) is a transport configuration change, not a protocol or prompt change.

---

## The interaction pattern: deterministic enrichment + agentic synthesis

This is the pattern we'd want an AI/security specialist to recognize, because it falls out of repeated practical experience and runs counter to what an "agent demo" usually shows.

The naive shape — and what a lot of MCP demos fall into — is **agent-as-pipeline-runner**:

```
operator → agent → "call tool A" → "call tool B based on A" → "call tool C based on B" → "write report" → return
```

This works for trivial questions but degrades on real workloads. Three failure modes recurred:

1. **Agents bias toward the tools they recognize.** Even with explicit "REQUIRED" instructions to call a new `extras_*` tool, the model would route around it to a familiar `falcon_*` tool whose result didn't actually answer the question.
2. **Agents are bad at deterministic joins.** Asking the model to walk 200 detections, extract every hash, and look each up was unreliable, slow, and expensive — exactly the workload a `for` loop solves in 12 milliseconds.
3. **Iteration cost compounds.** Each "agent calls tool, gets result, decides next call" round-trip is a full LLM forward pass on the entire transcript. Five rounds is 5x the cost.

Our pattern instead:

```
operator → ROUTE (server-side):
              call tool A, B, C in parallel
              deterministic join / classify / cluster (pure functions)
              build a JSON bundle, attach as system-prompt context
          → AGENT (synthesis only):
              agent renders the report from the bundle
              0-2 corroborating tool calls maximum
              return
```

What this gets us:

- **Provenance is enforceable.** Bundle fields are tagged at construction (`source: "falcon-native" | "intel-indicator" | "text-mention"`); the prompt instructs the model to render those tags verbatim. The operator sees in the report whether the attribution came from Falcon's correlation engine or from a heuristic regex.
- **Cost is bounded.** /intel runs at ~$0.02-$0.05 per report instead of $0.50+ when the agent was driving attribution.
- **Latency is bounded.** The MCP fan-out is `Promise.all(...)` in the route. The agent runs once on the assembled bundle.
- **Quality is testable.** The deterministic functions are pure and unit-testable on canned fixtures. The synthesis step is LLM-judged, but the inputs are fixed.

The clearest worked example is `lib/intel/attribution.ts` (paired with `app/api/intel/route.ts`). It runs three deterministic attribution paths server-side:

- **Path 0 — Falcon-native ground truth.** Detections carry a `has_adversary: true` flag and an `adversary_ids: ["2139"]` array of opaque numeric IDs. Resolving each ID through `falcon_search_actors(filter: "id:2139")` returns the canonical actor record (`name: "FANCY BEAR"`). This is the same signal Falcon Console uses to render actor labels — it does not appear in any text field.
- **Path A — corroboration via Intel indicators.** SHA-256s, domains, and IPv4s extracted from the detection set are reverse-looked-up against `falcon_search_indicators`. Hits often carry `actors[]` and `malware_families[]`.
- **Path B — heuristic text mining.** Detection text (`display_name`, `description`, `behaviors[].cmdline`, `parent_details.cmdline`, etc.) is scanned against a curated CrowdStrike actor alias map (FANCY BEAR ↔ APT28/Sofacy/Strontium, WIZARD SPIDER ↔ Conti/Ryuk, etc.).

The three paths join into an `AttributedActor[]` with confidence tiers driven by which paths fired. The agent's only job is to render the bundle as a five-section markdown report with provenance chips and recommended actions.

The route does ~25-35 deterministic API calls. The agent does **zero** tool calls during synthesis on the typical run.

---

## The MCP composition story

Two MCP servers compose into one logical tool surface for the agent:

### 1. `falcon-mcp` (upstream, ~125 tools in 0.16.0)

CrowdStrike's official MCP server. Read-only; covers Detections, Hosts, Vulnerabilities, Indicators (Intel), Actors (Intel), Recon, MalQuery, Workflows (read-only), Discover, IOCs (read), Sensor Usage, Scheduled Reports, NGSIEM, Threat Graph.

We run it as a Docker sidecar in production, or as a `uvx`-spawned child process in the standalone bundle. Either way the transport is `StreamableHTTPClientTransport` with `x-api-key` injected by us — the credential never leaves the host the app runs on.

### 2. `falcon-extras` (our sidecar, ~96 tools)

A Python MCP server in `falcon-extras/` we wrote on top of FalconPy. Fills the gaps where upstream falcon-mcp is missing pieces or where the agent needs a higher-level primitive than the raw API:

- **Host containment** (read + write) — falcon-mcp's Hosts module is read-only.
- **Agentic patching** (read + write) — Spotlight remediation manifest, RTR script library, CloudFile transport. ~30 patching scripts in a manifest schema with parameter validation.
- **Agentic IR cleanup catalog** (read + write) — companion manifest for incident-response remediation primitives (host-quarantine-file, host-delete-folder, host-kill-process, host-remove-ifeo-hijack, etc.).
- **Process-tree reconstruction** — `extras_host_process_tree` walks NGSIEM `ProcessRollup2` events, builds the ancestry chain via `ParentProcessId`, and runs a deterministic classifier that returns a delivery-vector verdict (`phishing_doc` / `c2_agent` / `lateral_winrm` / `ifeo_hijack` / etc.) with confidence + rationale. Anchor recovery handles behavioral detections whose alert timestamp is hours after the actual process launch.
- **NGSIEM operational depth** — `extras_host_rat_install_scan` (17-product image-name regex catalog), `extras_host_recent_logons`, etc.
- **Identity Protection** — staged-build-pattern surface; tools registered, lights up automatically when `idp:read` scope is granted.
- **Falcon-published RTR scripts** — read-only `falconscript -Name=...` invocation for live host introspection (Process, Service, RegistryKey, EventLog, etc.).

The sidecar follows two conventions worth calling out for a peer reviewer:

- **Render-time security.** For RTR script execution, the agent supplies an `id` plus validated parameters; it never supplies script bytes. `falcon-extras/patching/library.py::_render_params_block` builds the PowerShell parameter hash at render time, with single-quote-doubling escape on every string value and an ASCII coerce backstop. The agent cannot inject script logic.
- **Staged-build pattern for pending scopes.** `_check_response(resp, surface)` recognizes 401/403 envelopes and returns a `scope_pending: true` payload instead of raising. Surfaces ship before scope is granted and light up automatically when applied — useful for shipping demo capability against tenants whose API client is still being scoped.

### 3. The bridge

`lib/mcp/tool-bridge.ts` merges the two tool lists into one for the agent. There are no protocol differences — they look identical to the loop. `lib/mcp/parse.ts::detectFalconError` recognizes upstream falcon-mcp's habit of packaging Falcon API 500s as `{ isError: false, content: [{ text: "{\"error\": ...}" }] }` and surfaces them as real errors instead of letting the agent see "isError: false" and treat the failure as a clean empty result.

---

## Surfaces and what each is solving

The console exposes ~19 surfaces. Three operator categories, plus a developer Reference group:

**1. Deterministic dashboards** — no LLM at all. Just MCP fetchers, projections, and React tables. Examples: `/detections`, `/hosts`, `/vulnerabilities`, `/queue`, `/prevention`. These exist because not everything benefits from an agentic interaction; ranked tables ranked correctly are still the right answer for "show me my current state."

**2. Agentic decision documents** — single agent loop per surface, system prompt enforcing a five-or-six section markdown structure, deterministic enrichment in the route. Examples: `/`, `/briefing`, `/investigate`, `/pivot`, `/intel`, `/intel-dossier`, `/recon`, `/malquery`, `/workflows`, `/identity`, `/ngsiem`. Each produces a verdict + recommended-actions document, not a smarter table. `/intel-dossier` is the clearest illustration of the pattern: the route fans out finished-intel report-content + actor-profile + Recon-corpus tools *server-side on every run*, then the agent synthesizes — so enrichment is guaranteed rather than dependent on the model choosing a tool.

**3. Cross-module agentic workflows** — chat-resident, multi-phase, approval-gated. The killer example is the agentic IR workflow: `extras_ir_workflow_playbook(device_id)` returns a five-phase playbook (Discovery → Quarantine → Remediation → Verification → Release) parameterized for the host. The agent walks each phase, every write tool fires the approval gate, and Phase 0 enrichment includes the process-tree reconstruction, cmdline-artifact extraction, registry-persistence projection, and the 17-product RAT-install scan. This is the surface where "agent has judgment, not just pipeline-running" lands hardest.

**Developer Reference surfaces** — segregated in their own nav group, aimed at engineers evaluating or replicating the architecture (the sanctioned exception to the "no developer hints in user-facing copy" rule). `/agent-toolbox` renders the exact live tool catalog the agent composes (read-only, never invokes). `/blueprint` is a "build-your-own agentic SOC" advisor: it streams a decision document explaining how to compose `falcon-mcp` + FalconPy + Claude — grounded in this repo's own reference architecture — and links out to developer.crowdstrike.com for the platform primitives. It reasons about architecture only and calls no Falcon tools, so it works with only Anthropic configured.

---

## Honest gaps

Things this audience is likely to push on, with our current honest answer:

### Eval / regression testing for agentic outputs

We do not have one. The Playwright suite (`tests/`) covers UI smoke and API auth surfaces; agentic synthesis quality is currently anecdotal. The deterministic enrichment functions (`lib/intel/attribution.ts`, `lib/queue/rank.ts`, `lib/queue/campaigns.ts`, `falcon-extras/process_tree/classifier.py`) are unit-testable, and we run those, but the LLM synthesis layer has no fixture-based eval harness. This is the single most credible engineering gap; a small fixture-driven harness asserting "FANCY BEAR appears in `/intel` output when fixture X is in the bundle" would close it.

### Prompt injection / tool-poisoning defenses

We do not have a dedicated defense layer. The defenses we have in practice:

- **Approval gates on every write tool.** A poisoned tool result that talks the agent into containing a host still hits the modal.
- **Projection layer.** `lib/mcp/projections.ts` bounds tokens and drops unstructured nested fields; the agent never sees the full raw `behaviors[]` blob, for instance.
- **Code in tool results is data, not instructions.** The agent does not execute returned content as code. PowerShell bytes for RTR scripts are constructed render-time from validated params, never accepted from agent input.
- **System prompt > tool result.** The Anthropic API treats `tool_result` content as the role-`user` channel; system-prompt-set instructions outrank it for the model. This is defense by API design, not by us.

What we don't have: explicit detection of injection attempts in tool results, prompt-injection canaries, or a sanitization pass on returned text. Worth being direct about.

### Multi-tenant

Single-user, single-tenant by design. `data/eyas.db` is one user; `data/eyas.db` holds the active Falcon tenant's credentials (multi-environment switcher lives in the same file but is operator-toggled, not concurrent). This is a self-hosted personal/team console, not a SaaS product. If the question is "how would this be productized for a Falcon CSP partner?" the answer is "different architecture; this isn't it."

### Cost ceiling enforcement

We log token spend in the local SQLite database and surface a `DAILY_COST_BUDGET_USD` banner, but we do not hard-stop at the ceiling. A runaway agent loop could in principle blow through the budget. `CHAT_MAX_ITERATIONS` (default 50) and per-route iteration caps are the practical safeguards.

### Cancellation semantics

`ReadableStream.cancel` propagates to an `AbortController` whose signal is checked between agent-loop iterations. In-flight tool calls finish before cancel takes effect — we don't tear down a Falcon API call mid-flight because retry semantics get messy. A "Stop" click on a running chat takes effect at the next iteration boundary.

---

## What we'd want a peer reviewer to push on

For an AI specialist reviewing this for the first time:

1. **Is the deterministic-enrichment-plus-agentic-synthesis pattern generalizable?** We claim it is; we have ~6 surfaces using it. Counter-example would be illuminating.
2. **Where would you draw the line between "tool" and "deterministic helper"?** We exposed process-tree reconstruction as an MCP tool because the operator might invoke it from chat. Some of the smaller helpers (the 17-product RAT regex) are not tools — they're embedded in a tool. The split is judgment, and we're not certain we got it right everywhere.
3. **Should approval gates batch?** Per-tool prompts are clean for occasional writes; for a 12-step IR workflow with 6 distinct write tools, the operator gets six modals. We picked granular over batched on purpose (each is a real consent), but a "phase boundary" batched approval is plausibly better UX. We'd want feedback.
4. **What's the right shape for a security-domain eval?** Generic LLM evals don't help. Agentic-RL-style end-to-end success metrics are over-engineered for our case. We think fixture-driven assertions on bundle structure + a few golden synthesis outputs is the sweet spot, but we haven't built it yet.
5. **Is the "in-process MCP client" insistence right when Anthropic's native connector improves?** We assume the data-residency / approval-gate / audit-log argument keeps holding. The day Anthropic ships a native connector with first-class per-tool approval and ownable audit, the calculus changes. We'd want to know if the reviewer thinks that's near-term or far.

---

## Where to look in the code

For the reviewer who wants to dig in after the demo:

- `lib/chat/agent-loop.ts` — the manual Anthropic tool-use loop, including approval pause, cancellation, SSE event emission, per-tool duration tracking. ~400 lines; the whole loop fits in your head.
- `lib/mcp/tool-bridge.ts` + `lib/mcp/projections.ts` + `lib/mcp/write-tools.ts` — the bridge that merges falcon-mcp + falcon-extras tool lists, the projection layer that bounds tokens per tool, and the write-tool registry that gates approvals.
- `lib/intel/attribution.ts` + `app/api/intel/route.ts` — the deterministic-enrichment-plus-agentic-synthesis pattern at its clearest. ~700 lines combined.
- `falcon-extras/server.py` — the FalconPy sidecar, including `_check_response(resp, surface)` (the response guard that catches scope-denied and upstream errors uniformly), `_run_ngsiem_search` (the canonical NGSIEM helper), and the staged-build-pattern envelope for pending scopes.
- `falcon-extras/patching/library.py` + `falcon-extras/patching/manifest.json` — the render-time-security model for RTR script execution. The agent supplies an id + params; never bytes.
- `falcon-extras/process_tree/classifier.py` — the deterministic delivery-vector classifier. Pure-function, fully unit-testable on canned ancestry lists. Most-specific-anchor-wins.
- `CLAUDE.md` — load-bearing implementation gotchas accumulated from real bugs. Not a marketing doc; an engineering memory.

---

## Versions we ship against

- **eyas-mcp** (the MCP server, continued from `falcon-mcp`): pinned by git commit in `versions.json`; `/status` and the bundle's `BUILD-INFO.txt` show the running pin.
- **FalconPy**: 1.6.2 (sidecar); upgrades require re-checking the NGSIEM uber-class quirk noted in CLAUDE.md.
- **Anthropic SDK**: tracks current stable; default model `claude-sonnet-4-6` for chat surfaces, `claude-opus-4-7` for synthesis-heavy reports where token cost is justified.
- **Next.js**: 15.x (App Router, Server Actions, streaming responses).

---

If you want a different kind of follow-up — a code walkthrough on one of the surfaces, a deeper writeup on one of the gaps, or a pairing session on the eval harness shape — we'd welcome it.

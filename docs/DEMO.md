# Demo flow — talk track

A 15–20 minute live walkthrough for two audiences:

- **CrowdStrike customers** (SOC, IR, Falcon administrators) — show how an agent layer on top of Falcon turns multi-tab investigations and remediation work into one prompt with full audit trace.
- **CrowdStrike Sales Engineers** — show what `falcon-mcp` + FalconPy + Claude can do together, with the codebase itself as a working reference for customers asking "how would we build this?"

Adjust depth per audience. Section headers are the beats; quoted lines are what to say while clicking; *italics* are the points to actually land. Keep the **Unofficial** framing visible — the footer disclaimer carries it on every page.

**Pre-flight (do this before the audience joins):**
- Dev server running, browser at [http://127.0.0.1:3000](http://127.0.0.1:3000).
- `falcon-extras` venv built (`falcon-extras/.venv/bin/python` exists) — the sidecar is always-on, and the containment + patching beats depend on it.
- API client scopes confirmed: `Hosts:write` (containment), `Real Time Response:read` + `Real Time Response (Admin):write` (patching), plus the existing read scopes.
- A second tab open at `/cost` — you'll switch to it near the end.
- A third tab open at `/vulnerabilities?mode=newest&limit=500` — the patching beat starts there.
- `CHAT_MAX_ITERATIONS=50` in `.env.local` — patching flows can chew 6–10 polling iterations on long jobs (Windows Update install).
- One real recent detection in your tenant (the chat path lands harder with live data).
- Optional: `ANTHROPIC_MODEL=claude-haiku-4-5-20251001` in `.env.local` if you're worried about ITPM during the demo. Sonnet looks better; Haiku is more reliable.

---

## Beat 1 — Frame the project (60 seconds)

> "This is **Eyas** — a self-hosted Next.js app that drives CrowdStrike Falcon through Claude, wrapping the official `falcon-mcp` MCP server and a FalconPy sidecar. *Eyas* is the falconry term for a young falcon in training — fitting, because it's raised on the same craft as Falcon but is distinctly its own thing. Unofficial — not a CrowdStrike product, not a replacement for the Falcon console. The question it answers: *what does an analyst's day look like when the agent does the cross-module joins, the deterministic enrichment, and the plan-execute-verify loops, and you just talk to Falcon?*"

*Land:* the agent is the method; Falcon is still the subject. Every tool call is gated, traced, and auditable.

---

## Beat 2 — Chat surface, basic question (2 minutes)

Click into the chat input. Paste:

> **Show me the last 5 critical detections, grouped by host.**

While it runs, narrate:

> "Watch the trace appear inline. Every tool the agent invokes shows up as a collapsible block with the arguments and the duration. *That trace is the demo's main value* — when the agent does something useful, you can see exactly why."

Once it finishes, point at the pill row at the bottom of the run:

> "Two iterations, one tool call, ~3 seconds. We log the token cost of every turn — we'll come back to that."

*Land:* the agent picked the right tool with no hand-holding, and the trace makes it auditable.

---

## Beat 3 — Cross-module question (2 minutes)

This is the core "couldn't easily do this in the console" beat. Paste:

> **Find any host that has both a critical detection in the last 7 days AND an unpatched critical CVE. Show host name, the detection summary, and the CVE.**

While it runs:

> "In the console this is at least three tabs and a spreadsheet. Here, the agent decides to call `falcon_search_detections`, then `falcon_search_vulnerabilities`, then joins on the host AID. Notice the duration badges — these are real Falcon round trips."

If it finishes with a useful answer, *that's the headline moment.* If it finds nothing, that's also fine — narrate that the agent was thorough enough to confirm a clean cross-section.

*Land:* the agent loop is doing the join, not us.

---

## Beat 4 — Architecture aside, in passing (60 seconds)

While the trace from beat 3 is still on screen:

> "Quick architecture note. The agent loop runs *inside* this Next.js process — we discover tools from `falcon-mcp`, hand them to Claude as tool definitions, and dispatch the calls ourselves. We could've used Anthropic's hosted MCP connector with one config field, but then Falcon detection data would traverse Anthropic's infrastructure on every tool call. *In-process keeps our Falcon credentials and API calls on our host — the model only sees what the agent asks for.* It also gives us the hook for the next beat."

*Land:* the in-process design is what enables both privacy and the gating story.

---

## Beat 5 — Approval-gated write action (3 minutes)

Paste:

> **Add the SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` to the IOC list as a critical detect-only indicator with the description "demo IOC — please remove".**

(That hash is the SHA-256 of the empty string — safe to use, won't match any real file.)

When the approval card appears:

> "*This is the gate.* The agent decided to call `falcon_add_ioc`. Because we marked that tool as write-capable, the loop pauses and surfaces a friendly summary card — indicator, type, action — above the raw JSON. Nothing has hit Falcon yet."

> "If I walked away for 5 minutes, this would resolve as `approval expired`, distinct from a denial, so the agent knows the difference."

Click **Deny**. Show the trace's "User denied" line.

> "The agent gets a structured tool result that says *'do not retry without explicit user request'*, so we don't end up in an approval-spam loop."

*Land:* gating is one `if` between `tool_use` and execution. No write surface ships without it.

---

## Beat 6 — Deterministic dashboard, second integration pattern (90 seconds)

Open `/detections` in a new tab.

> "Same MCP client, no LLM. This route calls `falcon_search_detections` directly from the server side and renders a deterministic table. The chat surface and the dashboards share `lib/mcp/` — *two integration patterns in one codebase.*"

Hover over a row's **Ask agent** button:

> "Each row deep-links into chat with a primed prompt — the user reviews and sends. Cross-surface linking without auto-firing tool calls."

Click one. The chat input pre-fills. Don't send.

*Land:* the dashboards are the "fast and predictable" path; chat is the "explore and reason" path. They link into each other.

---

## Beat 7 — Briefing + PDF print (90 seconds)

Open `/briefing`.

> "One-page security briefing for whoever doesn't want to log into Falcon. Generated by the same agent loop with a structured prompt that produces a sectioned markdown report."

Click **Download PDF**.

> "*No PDF library.* It's a print stylesheet that isolates the report node and triggers `window.print()`. Generalises to any agent-generated page."

Close the print dialog.

---

## Beat 8 — NGSIEM playbooks (90 seconds)

Open `/ngsiem`.

> "60+ curated NGSIEM CQL queries grouped by MITRE kill-chain stage, including Shadow AI and Supply Chain categories. Each one is a one-click playbook — pick `Persistence: scheduled task created`, watch the query post against your tenant. *The agent didn't write these — they're hand-curated CQL.* The chat surface uses these as primer prompts when you ask broader hunting questions."

Click any playbook. Let it return results (or empty — both are demo-fine).

---

## Beat 9 — Cost transparency (60 seconds)

Switch to your `/cost` tab.

> "Every agent turn logs token usage to a JSONL file. This dashboard reads it directly — total spend, per-day trend, by-surface, by-model, recent 25 turns with cost per turn. *I built this because nobody trusts an LLM-driven tool until they can see what it's spending.*"

Point at the by-surface breakdown:

> "You can see chat dwarfs the deterministic surfaces because briefing and the dashboards either skip the LLM or use it once."

---

## Beat 10 — `falcon-extras`: extending the tool surface (90 seconds)

Back to the chat tab. Paste:

> **What tools do you have for host containment?**

Let the agent answer. It should mention `extras_host_contain` and `extras_host_lift_containment`.

> "Quick story. Upstream `falcon-mcp` doesn't expose host containment — its Hosts module is read-only. So I wrote a small Python sidecar called `falcon-extras` that uses [FalconPy](https://falconpy.io) — CrowdStrike's official Python SDK — to fill the gap. It's a separate MCP server, spawned over stdio by this Next.js process at startup. The agent loop merges its tools into the same tool list with no protocol-level differences."

> "*This is the headline architectural property.* Any new MCP server I want to plug in — internal one we write, third-party, doesn't matter — slots into the same agent loop and gets the same approval gating for free."

> "And we use the same pattern for the next beat: agentic patching."

---

## Beat 11 — Agentic patching: the loop closes (5 minutes — the headline beat)

Switch to your `/vulnerabilities` tab. Toggle to **By patch** view.

> "Spotlight surfaces the actual remediations — `Update Mozilla Firefox · 150.0` rather than 50 individual CVEs. ExPRT-led prioritization, not CVSS. Click into any patch row that has a fix."

Expand a row with a known-good curated script — Chrome, Firefox, Office, or Notepad++ work well. Two buttons appear: **Build patch plan** and **Run patch in chat**.

Click **Build patch plan**.

> "This is read-only. The agent calls `extras_rtr_resolve_patch_plan` against the script catalog, looks up host details, joins CVE coverage, and produces a six-section decision document — Plan / Curated script / Targets / CVE coverage / Change-window guidance / Rollback / Next step. *No host I/O yet.* This is the kind of artifact a vuln-mgmt lead would hand to ops."

Wait for the document to render (~10s). Skim through it on screen.

> "Notice the script preview. The agent never authors PowerShell — it picks an id from a curated catalog. Bytes live as `.ps1` files in the repo. The agent supplies validated parameters; the server renders preambles, the params block, and the body. That's the security boundary."

Now click **Run patch in chat →**.

> "Deep-link into chat with a primed prompt. The user reviews and sends — no auto-fire."

Send the prompt. The agent will:
1. Call `falcon_search_hosts` to look up host OS (so it knows whether to pass `os_hint='windows'` or `'macos'`)
2. Call `extras_rtr_resolve_patch_plan` to confirm the matched script id
3. Call `extras_rtr_run_patch` with `dry_run=true` — **first approval card appears**

> "Same gate as beat 5. The card shows: script id, mode (dry-run, no host I/O), host count, sample AIDs. Approve."

Click **Approve**. The agent shows the resolved plan + script preview.

> "Dry-run output. We've confirmed the right script will run on the right hosts. Now ask it to execute."

Type:

> **Looks good. Run it.**

The agent calls `extras_rtr_run_patch` again with `dry_run=false` — **second approval card appears**, now reading "EXECUTE on hosts."

> "Two-stage approval. The dry-run was the rehearsal; this is the live take."

Click **Approve**. Underneath, the sidecar uploads the rendered script to the Falcon script library, opens a batch RTR session, runs `runscript -CloudFile=` against every host, then deletes the upload.

For short scripts (Chrome / Firefox / Notepad++), this returns in ~30s with per-host stdout / exit codes. For long scripts (Windows Update install), the call returns at ~30s with `complete: false` + a `cloud_request_id` per laggard, and the agent loops on `extras_rtr_check_patch_status` until done.

> "And then — *this is the part that makes it trustworthy* — the agent re-queries Spotlight to verify the CVEs are actually cleared. Plan, execute, verify. The third beat is what most automation tools skip."

If verification reports the CVE still open: narrate the Spotlight scan-cadence caveat ("Spotlight scans aren't real-time; this catches up overnight"). If it reports cleared: that's the win-condition shot.

*Land:* the loop closes end-to-end. This is the demo's strongest "couldn't do this in the console" moment.

---

## Beat 12 — Wrap (60 seconds)

> "What this isn't: a Falcon-console replacement, or a supported CrowdStrike product. What this is: a working reference for what an agent layer on top of Falcon does — cross-module questions in plain English, gated write actions with a full audit trace, deterministic dashboards for the predictable work, **a closed plan-execute-verify loop for vulnerability remediation**, and a clean extension pattern when upstream is missing a capability. Self-hosts on a single box; the only ongoing cost is Anthropic tokens, visible on the cost dashboard. The whole stack — `falcon-mcp` + FalconPy + Claude — is what you'd reach for to build this against your own tenant."

> "Questions?"

---

## If a beat goes wrong, recovery scripts

| Failure | What to say |
|---|---|
| **Anthropic 429 mid-demo** | "Hit the rate limit on my account tier — the system prompt is 26k tokens and we're chaining iterations. Let me retry in 60 seconds — the prompt cache will hit and the next call is essentially free." |
| **Tool returns empty** | "Quiet tenant today — that's actually a good sign for our security posture. The point of the demo is the agentic flow, which we just saw work end-to-end." |
| **Falcon 403** | "API client doesn't have that scope in this tenant. Easy fix in the console; not interesting to debug live. Let me try a different question." |
| **`falcon-extras` child crashes** | Skip beats 10–11's exec parts, keep the architectural narration. Show extras tools are in the tool list (works without the child being healthy as long as listing succeeded earlier). |
| **Chat hangs > 30s on a beat-3 cross-module query** | "Watching for the activity banner — there it is, it's running `falcon_search_vulnerabilities`, that's a slower endpoint. While we wait..." (pivot to talking about `/cost` or the architecture). |
| **Patch dry-run resolves "no curated script matches"** | Means the chosen vendor/product isn't in the catalog yet. Pivot to a known-good row (Chrome / Firefox / Office). Narrate: "the catalog is curated; matching unknown vendors is the boundary." |
| **Patch execution returns `complete: false` + cloud_request_ids and the polling loop runs out of iterations** | "Long script — Windows Update routinely takes 25 minutes. The cloud_request_ids are durable; in production we'd raise iteration cap or hand off to a scheduled poller. For demo purposes, the architectural point already landed." |
| **Spotlight verification still shows CVEs open after patch** | "Spotlight scans aren't real-time. The patch landed; Spotlight catches up on its next scan, usually overnight. The agent calls this out rather than reporting failure." |

---

## Demo cheat sheet — prompts to keep in a sticky note

```
1. Show me the last 5 critical detections, grouped by host.

2. Find any host that has both a critical detection in the last 7 days
   AND an unpatched critical CVE. Show host name, detection summary, CVE.

3. Add the SHA-256
   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
   to the IOC list as a critical detect-only indicator with the
   description "demo IOC — please remove".

4. What tools do you have for host containment?

5. (Beat 11 -- starts via the /vulnerabilities Build patch plan
    + Run patch in chat buttons; the primer is generated for you.
    The follow-up after dry-run is just:)
   Looks good. Run it.

6. (Verification -- the agent should do this on its own, but if you
    need to nudge it:)
   Re-query Spotlight to confirm the CVEs were cleared.
```

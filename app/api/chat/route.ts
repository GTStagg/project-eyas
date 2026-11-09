import { NextResponse } from "next/server";
import type Anthropic from "@anthropic-ai/sdk";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { buildToolBridge, type FalconResource } from "@/lib/mcp/tool-bridge";
import { parseConcatenatedJson } from "@/lib/mcp/parse";
import {
  loadConversation,
  saveConversation,
  getIrMode,
  setIrMode,
  bumpIrTurnCount,
  setSessionTitle,
  TTL_MS,
} from "@/lib/chat/state";
import { runAgentLoop, maybeFenceToolResult, type Emit, type RunAgentOptions } from "@/lib/chat/agent-loop";
import {
  updateActiveEnvironment,
  getActiveEnvironment,
  getActiveEnvironmentId,
} from "@/lib/config/environments";
import type { PatchProfile } from "@/lib/config/store";
import { getRuntimeConfig } from "@/lib/config/runtime";
import { buildKnowledgeContext } from "@/lib/knowledge/retrieve";
import { invalidateHealthCache } from "@/lib/health";
import { summarizeToolResult } from "@/lib/chat/tool-summaries";
import { streamAgent } from "@/lib/chat/stream-agent";
import { tryEnterSession, exitSession } from "@/lib/chat/in-flight";
import {
  TurnObserver,
  appendTurn,
  createRecord,
  getLastRunForAid,
  recentIrCostProjection,
  recordPathFor,
  type IrRunSummary,
  type ToolCallRecord,
} from "@/lib/chat/ir-run-record";
import { getAnthropicModel } from "@/lib/llm/anthropic";
import {
  CONTAIN_TOOLS,
  LIFT_TOOLS,
  containResultConfirms,
  containTargetsAid,
  extractDeviceIds,
  getContainmentGroundTruth,
  getLatestIrRunIdentity,
  getPhase0Scope,
  isDomainController,
} from "@/lib/chat/ir-ground-truth";
import {
  blockedDetectors,
  isAidrEnabled,
  recordBlock,
  scanInput,
  scanOutput,
  type AidrVerdict,
} from "@/lib/aidr/client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Auto-persist host-group ids the agent just created. The IR Quarantine +
// Shadow-AI Banned setup cards return a new group id; without this hook the
// operator would have to copy/paste it back to /config. The endpoints they
// would otherwise hit refuse during isBusy(); we call updateActiveEnvironment
// directly here while the loop holds the in-flight lock.
const AUTO_SAVE_TOOLS: Record<string, "ir" | "shadow_ai"> = {
  extras_create_quarantine_host_group: "ir",
  extras_adopt_quarantine_host_group: "ir",
  extras_create_shadow_ai_banned_host_group: "shadow_ai",
  extras_adopt_shadow_ai_banned_host_group: "shadow_ai",
};

// `bridge.invoke` returns `content` as a joined STRING (the projected
// text-blocks of the MCP response), not the raw `Array<{type,text}>`
// shape from the SDK. Earlier versions of this function only handled
// the array path — when the agent called extras_adopt_*_host_group via
// chat, the hook silently no-op'd and the group id was never persisted.
// Operators had to re-paste the id into /config by hand. Accept both
// shapes so future callsite changes don't re-break it.
function extractCreatedGroupId(content: unknown): string | null {
  const textCandidates: string[] = [];
  if (typeof content === "string") {
    textCandidates.push(content);
  } else if (Array.isArray(content)) {
    for (const block of content) {
      if (!block || typeof block !== "object") continue;
      const text = (block as { type?: string; text?: string }).text;
      if (typeof text === "string") textCandidates.push(text);
    }
  }
  for (const text of textCandidates) {
    try {
      const parsed = JSON.parse(text) as { ok?: unknown; id?: unknown };
      if (parsed && parsed.ok === true && typeof parsed.id === "string" && parsed.id) {
        return parsed.id;
      }
    } catch {
      /* not JSON; skip */
    }
  }
  return null;
}

async function persistCreatedHostGroupId(event: {
  name: string;
  input: Record<string, unknown>;
  content: unknown;
  isError: boolean;
}): Promise<void> {
  if (event.isError) return;
  const kind = AUTO_SAVE_TOOLS[event.name];
  if (!kind) return;
  const id = extractCreatedGroupId(event.content);
  if (!id) return;
  if (kind === "ir") await updateActiveEnvironment({ irQuarantineGroupId: id });
  else await updateActiveEnvironment({ shadowAiBannedGroupId: id });
  invalidateHealthCache();
}

// Auto-persist a patch profile the agent just saved. extras_save_patch_profile
// returns the validated profile object (NOT script bytes — params re-checked
// against the win-app-install manifest regex in the sidecar) but does not write
// to settings itself; this hook appends it to the active environment's
// per-tenant catalog while the loop holds the in-flight lock (the /config
// endpoints refuse during isBusy()). Append semantics — distinct from the
// host-group hook's single-id replace. Same-turn caveat: the saved profile only
// becomes visible to extras_list_patch_profiles on a LATER turn, since the
// sidecar reads its spawn-time env snapshot.
function extractSavedProfile(content: unknown): PatchProfile | null {
  const textCandidates: string[] = [];
  if (typeof content === "string") {
    textCandidates.push(content);
  } else if (Array.isArray(content)) {
    for (const block of content) {
      if (!block || typeof block !== "object") continue;
      const text = (block as { type?: string; text?: string }).text;
      if (typeof text === "string") textCandidates.push(text);
    }
  }
  for (const text of textCandidates) {
    try {
      const parsed = JSON.parse(text) as { ok?: unknown; profile?: unknown };
      if (parsed && parsed.ok === true && parsed.profile && typeof parsed.profile === "object") {
        const p = parsed.profile as Record<string, unknown>;
        if (
          typeof p.id === "string" &&
          typeof p.name === "string" &&
          typeof p.product === "string" &&
          typeof p.url === "string" &&
          (p.kind === "msi" || p.kind === "exe")
        ) {
          return p as unknown as PatchProfile;
        }
      }
    } catch {
      /* not JSON; skip */
    }
  }
  return null;
}

async function persistSavedPatchProfile(event: {
  name: string;
  content: unknown;
  isError: boolean;
}): Promise<void> {
  if (event.isError) return;
  if (event.name !== "extras_save_patch_profile") return;
  const profile = extractSavedProfile(event.content);
  if (!profile) return;
  const current = getActiveEnvironment().patchProfiles ?? [];
  // Append; applyPatch's prune dedupes by id (last-wins) + caps the list.
  await updateActiveEnvironment({ patchProfiles: [...current, profile] });
}

function buildSystemPrompt(resources: FalconResource[]): string {
  const resourceList = resources
    .map((r) => `- ${r.uri}${r.description ? ` — ${r.description}` : ""}`)
    .join("\n");

  const today = new Date().toISOString().slice(0, 10);

  return [
    "You are a security operations assistant connected to a CrowdStrike Falcon tenant through a falcon-mcp server.",
    "",
    `Today's date is ${today} (UTC). Use this for relative-date queries like "last 24 hours" or "EOL status".`,
    "",
    "When the user asks about their environment, use the falcon_* tools to look up real data — do not answer from training knowledge alone.",
    "",
    "Cross-module synthesis is your superpower: when answering, look across multiple Falcon modules rather than relying on one. Examples:",
    "- For a question about a specific host, also check that host's recent detections, open vulnerabilities, and RTR availability — not just `falcon_get_host_details`.",
    "- For a vulnerability question, find which hosts have it.",
    "- For a threat-actor question, also check whether that actor's known indicators or techniques have shown up in the local environment.",
    "- For a 'is this host compromised' question, fan out: detection history + open vulns + live RTR snapshot + recent intel for matching IoCs.",
    "Stitch the results into one coherent answer rather than dumping each tool's output separately.",
    "",
    "When asked which modules / tools / capabilities are 'available', 'enabled', or 'connected' in this installation, call `falcon_list_enabled_modules` (the modules turned on in *this* server); for a finer-grained inventory of the individual tools this server exposes, call `falcon_list_enabled_tools`.",
    "",
    "For 'how many', 'top N', 'distribution', or 'trend over time' questions — counts of detections/alerts by severity, tactic, host, or status; distinct-host counts; volume over a time window; case-configuration counts; Recon notification / exposed-data-record counts — prefer the aggregation tools (`falcon_aggregate_detections`, `falcon_aggregate_case_*`, `falcon_aggregate_recon_notifications`, `falcon_aggregate_recon_exposed_data_records`). One aggregate call returns the buckets and counts directly; do NOT page a search tool and count records by hand. Use a search tool only when you need the individual records themselves. Example: for 'top 5 tactics this week', call `falcon_aggregate_detections` with a `terms` aggregation on `tactic` (size 5) — a bucket list back in one call, no paging.",
    "",
    "Several tools take a `filter` parameter that uses CrowdStrike's FQL syntax. Before constructing such a filter, call `falcon_read_resource` with the appropriate FQL guide URI listed below. The guides are short and authoritative — read them rather than guessing. NGSIEM search uses a different language (CQL); if you author an NGSIEM query, consult its CQL guide the same way.",
    "",
    "Available syntax guides (FQL for tool `filter` params; CQL for NGSIEM search):",
    resourceList || "(none discovered)",
    "",
    "Style:",
    "- Be concise. Show the salient fields (hostname, severity, status, time) rather than dumping raw JSON.",
    "- Use markdown tables when listing more than 2-3 items with structured fields.",
    "- If a query returns nothing, suggest a relaxation or alternative filter.",
    "- If a tool errors, surface the error to the user briefly and propose a next step.",
    "- This is an ongoing conversation; refer back to earlier turns when relevant rather than repeating yourself.",
    "",
    "Citations (IMPORTANT):",
    "- Tool calls in this response are numbered 1, 2, 3, … in the order you called them.",
    "- When you state a fact derived from a tool call, end the sentence with a citation like [1] referencing the tool call number that produced it. Multiple sources: [1][3].",
    "- Citations are clickable in the UI; users can click [N] to jump to the underlying tool call. This is how trust is built.",
    "- Do not invent citations: only reference tool calls you actually made.",
    "- Do not citation-spam: one or two citations per claim is plenty; not every word needs a marker.",
    "",
    "Custom IOC policy (IMPORTANT — avoid duplicate / unnecessary IOCs):",
    "- Before proposing `falcon_add_ioc` for a hash, IP, or domain, first check whether it is already known. Call `falcon_search_indicators` (Falcon Adversary Intelligence's curated IOC feed) and `falcon_search_iocs` (this tenant's existing custom list).",
    "- If the indicator is in `falcon_search_indicators` with `malicious_confidence: high`, CrowdStrike's cloud reputation is already blocking it tenant-wide — tell the user that and do NOT propose adding a custom IOC.",
    "- If the indicator is already in `falcon_search_iocs`, tell the user it's already on the custom list (with its current action and date) and do NOT propose adding it again.",
    "- Only propose `falcon_add_ioc` when both lookups miss, OR when the user explicitly wants to override (e.g., force `prevent` on a hash Intel rates `medium`).",
    "- IOC `action` is type-restricted at the Falcon API: `prevent` is only valid for hash types (`sha256` / `md5`). For `domain`, `ipv4`, `ipv6` the API rejects `prevent` — propose `detect` instead. Network-layer blocking is a DNS/NGFW concern, not the endpoint sensor's IOC engine.",
    "",
    "Finished-intelligence depth (threat actors, campaigns, reports):",
    "- `falcon_search_actors` and `falcon_search_reports` return only summaries. When the user asks about a named threat actor / campaign or wants depth on a report, follow up: pass the `id`s those searches return to `falcon_get_intel_reports` (the full published report body / analysis) and `falcon_get_intel_actors` (the full actor narrative — aliases, targeting, motivations, objectives, kill chain). Do this BEFORE writing your summary — the finished analysis lives in the full content, not the search metadata.",
    "- For an actor's tactics and techniques, `falcon_get_mitre_report` returns the MITRE ATT&CK mapping.",
    "- Raw dark-web collection items (actual forum / Telegram / paste post text) are NOT retrievable ad hoc. The Recon API only returns raw matched content through notifications generated by a PRE-EXISTING monitoring rule (`falcon_search_recon_notifications`), or aggregate counts (`falcon_preview_recon_rule`). If the user asks for raw items and none exist, say so plainly and offer that a Recon monitoring rule would backfill them going forward — do NOT imply the raw items are otherwise available.",
    "",
    "Custom IOA policy (IMPORTANT — same redundancy principle as IOCs):",
    "- Before proposing a new Custom IOA rule (`falcon_create_ioa_rule`, `falcon_create_ioa_rule_group`, etc.), determine whether CrowdStrike already covers the behavior with a built-in pattern.",
    "- Look at the detection(s) the rule is supposed to catch. If they show `behavior_id` / `pattern_id` / mapped MITRE `tactic` + `technique` populated by CrowdStrike, the behavior is already in the platform's catalog — a custom IOA is redundant.",
    "- A detection firing in *detect-only* prevention mode does NOT mean coverage is missing. It means the platform recognized the behavior but the prevention policy is configured not to block. The right fix is to escalate the prevention policy on the relevant host group (or create one for the affected hosts), NOT to write a custom IOA covering the same behavior.",
    "- Only propose a new Custom IOA when (a) the behavior the user wants to catch has no matching built-in pattern AND no existing custom rule group already covers it (search `falcon_search_ioa_rule_groups` first), or (b) the user explicitly wants a stricter / more specific match than the built-in pattern provides.",
    "- When you decline to propose an IOA on these grounds, say so clearly and recommend the prevention-policy adjustment instead — that's the higher-leverage fix.",
    "",
    "NGSIEM CQL syntax (when calling `falcon_search_ngsiem`):",
    "- String literals use **double quotes** only: `ComputerName=\"WIN10-FIN-07\"`. Single quotes are a CQL parse error.",
    "- Tag fields are prefixed with `#` (e.g. `#event_simpleName=DnsRequest`); regular fields are not.",
    "- Regex matches use `field=/pattern/i` and match **anywhere in the value** unless anchored — `/powershell/i` matches a full `...\\powershell.exe` path. Anchor with `^` / `$` for an exact or suffix match, e.g. `/(^|\\.)example\\.com$/i` for a domain and its subdomains.",
    "- Top-N truncation uses `head(N)`, not `limit(N)` — `limit()` is not a CQL function.",
    "",
    "Live host investigation (Real Time Response):",
    "- For questions about live state on a specific host — running processes, current users, environment variables, file/directory contents, registry values, network connections — use the falcon_*_rtr_* tools. Typical sequence: open a session against the host (`falcon_init_rtr_session`), execute one or more read-only commands (`falcon_execute_rtr_read_only_command` with `base_command` like `ps`, `ls`, `cat`, `env`, `netstat`, `reg query`), then close the session (`falcon_delete_rtr_session`). The `read_only` variant is restricted by CrowdStrike to non-mutating commands; you will not be able to write, modify, or delete anything on the host through it.",
    "- If the user names a host by hostname rather than device_id, search hosts first to resolve the device_id, then pass that to `falcon_init_rtr_session`.",
    "- For multi-host RTR queries (e.g. 'run ps on all my Linux hosts'), use `falcon_run_rtr_read_only_command_on_hosts` with the resolved `device_ids` (up to 100) — one call opens a batch session, runs the same read-only command everywhere, and returns per-host output plus `failed_hosts` for offline ones. Present results in a comparison table — flag anything anomalous (processes appearing on only one host, unusual paths, etc.).",
    "",
    "Agentic patching (curated RTR scripts):",
    "- For Spotlight remediation, the patching pipeline is: `extras_rtr_list_patch_scripts` → `extras_rtr_resolve_patch_plan` → `extras_rtr_run_patch` → `extras_rtr_check_patch_status` (if needed) → re-query Spotlight to verify. The catalog/resolve/status tools are read-only; only run_patch is a gated write.",
    "- The catalog covers Windows, Linux (apt-based: Debian/Ubuntu), and macOS. Cross-platform vendors (Chrome on Windows vs macOS, etc.) have separate scripts. Before resolving, look up host OS via `falcon_search_hosts` (the platform field is `Windows` / `Linux` / `Mac`) and pass `os_hint: 'windows'|'linux'|'macos'` to `extras_rtr_resolve_patch_plan`. If a single batch spans multiple OS families, split the dispatch — one resolve+run per OS group.",
    "- ALWAYS call `extras_rtr_run_patch` with `dry_run: true` first. The dry-run returns the resolved script + targets without invoking RTR; surface that to the operator for review. Only call again with `dry_run: false` after the operator says to proceed.",
    "- Batches over 25 hosts are rejected unless you explicitly pass `confirm_large_batch: true`. Do not pass it on the first attempt; raise the size with the operator first.",
    "- The script catalog is curated server-side. You CANNOT author or supply script content — only an id from the catalog plus validated parameters. Freehand PowerShell is never allowed.",
    "- **Generic Windows installer (capability gap).** When no app-specific script matches a Windows remediation but you know the vendor's HTTPS download URL, resolve `script_id: 'win-app-install'` with params `{ url, kind: 'msi'|'exe', product, sha256?, silent_args? }`. This is NOT freehand: the script bytes are baked server-side; only your parameters pass the manifest regex (any shell metacharacter, quote, or whitespace in the URL fails validation and the call is rejected). `extras_rtr_resolve_patch_plan`'s no-match response sets `generic_installer_available: true` with the exact param hint when this applies.",
    "- **Strongly prefer pinning `sha256`** (the installer's SHA-256). When supplied, the host verifies the download against it and ABORTS before install on mismatch — that is the real integrity gate. The resolve/dry-run result reports `hash_pinned: true|false`. If you omit the hash, the install proceeds on HTTPS + operator approval alone and the host prints an `UNVERIFIED (no hash pin)` banner — say plainly in your dry-run summary that the install is UNVERIFIED so the operator approves consciously.",
    "- The generic installer is Windows-only; `kind: 'msi'` ignores `silent_args` (it always uses safe silent flags), so `silent_args` applies to `kind: 'exe'` only. If a remediation is non-Windows, or you do not have a trustworthy vendor URL, do NOT invent one — say no script matches and stop.",
    "- **Saved patch profiles.** A consumer can persist a working installer parameter-set for reuse: `extras_save_patch_profile(name, product, url, kind, sha256?, silent_args?)` (approval-gated — saving establishes a trusted reusable source) and `extras_list_patch_profiles()` to recall them. Flow: list profiles → pick one → `extras_rtr_resolve_patch_plan(script_id: 'win-app-install', params: <profile fields>)` → `extras_rtr_run_patch` dry-run, then live. A profile saved earlier in the SAME turn is not yet visible to a same-turn list — save, then list on a later step.",
    "- After `run_patch` returns: if any per-host result has `complete: false` and a non-null `cloud_request_id`, call `extras_rtr_check_patch_status` with those ids before reporting. Long scripts (Windows Update install, etc.) routinely exceed the synchronous timeout.",
    "- VERIFY THE FIX. After execution completes successfully, re-run `falcon_search_vulnerabilities` against the same host(s) and the affected CVE(s). Report 'verified — CVE no longer present in Spotlight' if the patched CVEs are gone, or flag if they're still open (the patch may have failed silently, or Spotlight has not re-scanned yet — Spotlight scan cadence can lag patching by hours). The verification step is what makes the loop trustworthy; do not skip it.",
    "",
    "Agentic incident response (multi-phase quarantine + cleanup workflow):",
    "- When the operator arrives via the IR primer, the route pre-fetches `extras_ir_workflow_playbook(device_id)`, `extras_ir_campaign_scope(device_id)`, and `extras_ir_phase0_actionable_check(device_id)` server-side BEFORE invoking you, and the results appear as the first three `tool_result` blocks in the conversation. The playbook text in result #1 is your working instruction set — follow it verbatim. The campaign-scope payload in result #2 is the deterministic Phase 0 scope — render it for the operator and use the per-campaign `delivery_vector` to drive Phase 2 action selection. The actionable-partition payload in result #3 tells you whether the IR engagement is justified at all: if `should_proceed_with_ir` is `false`, every open detection on the host is noise (workflow self-trigger / Shadow-AI audit IOC / retrospective backfill) and you MUST fire the pre-composed `bulk_close_calls[]` to close them, then STOP the workflow without quarantining the host — see the playbook's `Phase 0.5 — Actionability gate` section. Do not call those three tools yourself; they are intentionally not in your toolset for IR runs.",
    "- The playbook covers Phase 0 Discovery → Phase 1 Quarantine (host-group move, optional containment) → Phase 2 Remediation (cleanup primitives, each gated) → Phase 3 Verification → Phase 4 Release / Hold. Every consequential write is approval-gated by the agent loop; the playbook describes when to call which tool.",
    "- DO NOT add meta-confirmation prompts in IR ('Please confirm: shall I execute?', 'Approve to proceed?', etc.). The approval gate on each write tool IS the gate; restating it doubles the wait and stalls the workflow on `end_turn`. After a dry-run preview completes, immediately call the same script with `dry_run=False` — the gate fires there.",
    "- Emit each phase's section to the chat as soon as that phase's tool calls finish, before starting the next phase's calls. The operator is reading the transcript in real time.",
    "- If `extras_ir_workflow_playbook` returns ok=false because the quarantine group id is unset, surface that error to the operator clearly and stop — the workflow can't run without it.",
    "- **Bulk-close all open detections on a host = one tool call.** When the operator says 'close all open detections on host X' / 'the host is clean, drain the queue' / 'IR finished but the queue still shows detections, close them' — call `extras_close_all_open_detections_on_host(device_id, verdict, comment)` ONCE. The tool walks every open detection server-side (paginated to exhaustion, 5000 hard cap), chunks the close calls at 500/batch, and returns the aggregate count. Single approval gate covers the whole bulk close. Don't try to capture composite_ids yourself via falcon_search_detections + multiple update_detection_status calls — that path repeatedly truncates and miscounts (113 detections left open on a clean host post-IR observed 2026-05-07 from exactly this anti-pattern). Default `verdict='true_positive'` for a post-IR cleanup; use `false_positive` only when you can attest the detections are noise (workflow-self-triggered, etc.).",
    "- **Reboot is a callable cleanup primitive, not an out-of-band action.** If the operator asks to reboot a host (during IR, after IR, or any time), call `extras_rtr_run_cleanup` with `script_id=\"host-reboot\"` and `device_ids=[<aid>]` (no params). Same dry-run-first approval flow as any other cleanup script. Do NOT decline reboot with 'requires admin RTR' or 'the read-only RTR endpoint can't restart' — that's a different tool surface. The patching catalog has `win-reboot` (callable via `extras_rtr_run_patch`) and the cleanup catalog has `host-reboot` (callable via `extras_rtr_run_cleanup`); both invoke the same `Restart-Computer -Force`. Pick whichever catalog fits the conversational context — IR / cleanup → `host-reboot`, Spotlight finalize → `win-reboot`.",
    "- **Capability-discovery rule (general).** When asked to do something the read-only RTR tool (`falcon_execute_rtr_read_only_command`) can't do, before declaring the action impossible, check the cleanup + patching catalogs (`extras_rtr_list_cleanup_scripts`, `extras_rtr_list_patch_scripts`). The catalogs include curated scripts for actions the read-only RTR command set excludes by design: reboot, service stop/start, file delete, registry write, RAT uninstall, etc. 'I can't do that' is only correct AFTER both catalogs were searched and returned no match.",
    "",
    "Live host introspection (Falcon-published RTR scripts):",
    "- `falcon_list_falcon_scripts` enumerates CrowdStrike-published read-only scripts (Windows-only catalog: Process, Service, ScheduledTask, RegistryKey, LocalUser, LocalGroup, InstalledProgram, RegisteredAV, BitLocker, EventLog, FileInfo, Prefetch, FirewallRule, NetworkShare, etc.). `falcon_run_falcon_script` invokes one against an AID and returns structured JSON.",
    "- Use during triage to ground verdicts in CURRENT live-host state, not just Falcon-recorded metadata. Examples: `Process` + `Service` after a suspicious-execution detection, `RegisteredAV` + `BitLocker` for posture confirmation, `FileInfo` + `Prefetch` to corroborate a hash hit, `LocalUser` + `LocalGroup` for lateral-movement context.",
    "- Avoid pulling `EventLog` casually — output is large. Only use it with a specific `LogName` + `MaxEvents` in `json_input` when there is a concrete reason. Most scripts (Process, Service, RegisteredAV, BitLocker) take no parameters.",
    "- These scripts are read-only by definition; no approval gate. Output is auto-truncated to the first 50 result items per host; if the agent needs more, narrow the query via `json_input` rather than re-running.",
    "",
    "Detection verdicts (TP/FP):",
    "- The Falcon v3 Alerts API only accepts `new` / `in_progress` / `reopened` / `closed` for the lifecycle status. TP/FP is NOT a status — it is recorded via a verdict tag. Do not call `extras_update_detection_status` with `status='true_positive'` or `status='false_positive'`; the API rejects those values.",
    "- To record a verdict, call `extras_update_detection_status` with `verdict='true_positive'` (or `'false_positive'`) and optionally a one-line `comment` summarizing the reasoning. Status defaults to `closed` when a verdict is supplied, which is the normal case. The tool writes the literal `true_positive` / `false_positive` tag — the same tag the Falcon console writes when an operator sets a verdict.",
    "",
    "Detection exclusions (ML / IOA — long-lived tuning, not per-alert disposition):",
    "- An exclusion is a tenant-wide tuning artifact that suppresses FUTURE detections matching the pattern. It is not the right tool for a one-off FP — for that, close the alert with `extras_update_detection_status(verdict='false_positive')`, which is reversible (you can untag) and keeps the historical signal.",
    "- Use `extras_create_ml_exclusion` when an entire image (binary path) is reliably benign across multiple detections — the agent's job is to suppress ML on-write detection on that path. Pre-flight: ALWAYS call `extras_list_ml_exclusions` with a `value:'<path>'` filter first. The create tool also runs this internally and refuses on duplicate, but surfacing the existing match in your response saves an approval round-trip.",
    "- Use `extras_create_ioa_exclusion` when only ONE specific behavior pattern on an image is benign (the rest of the image's behaviors should still be detected). Required: `pattern_id` from a sample detection's `behaviors[].pattern_id` (do NOT guess — pull a fresh `falcon_search_detections` to get a real one), `ifn_regex` (image-file-name regex, full-match anchored), and a `comment` documenting why this is benign (audit trail).",
    "- Default scope: omit `group_ids` to apply globally only when the operator confirms global is appropriate. Prefer host-group scope when the benign behavior is environment-specific (e.g. only the build farm).",
    "- Both create paths are write-gated. The approval card the operator sees should include: the proposed exclusion type + value/pattern, the evidence (FP rate, fire count, hosts), and the documented `comment` text. Never propose an exclusion on a rule with even one true_positive closure.",
    "",
    "Prevention policy posture (coverage / slider review):",
    "- When the operator asks about prevention policy coverage, posture, or how protected the fleet is, prefer `falcon_get_prevention_posture` (optionally `platform`, `only_flagged=true`) over the raw `falcon_search_policies` read. It resolves every prevention policy's enabled state, attached host groups and each ML slider's detection / prevention level, with flags `disabled`, `no_host_groups` and `detect_only_sliders` (the slider ids that detect without preventing). Lead with the sensor ML (`OnSensorMLSlider`) and cloud antivirus (`CloudAntiMalware`) sliders; a detect-only Adware/PUP slider alone is a minor gap; `falcon_search_policies` returns only list-level policy objects (the slider settings blob is intentionally projected away). Use `falcon_search_policies` / `falcon_search_policy_members` only to look up a policy id, confirm enablement, or list the hosts a specific policy governs — then use `falcon_get_prevention_posture` for the actual posture read.",
    "",
    "Falcon Cases triage (decision-doc shape when the operator primes you with a case id):",
    "- The /cases page hands off a `Triage Falcon case ...` primer carrying the case id. Load the case with `falcon_get_cases` (pass the id; the tool returns the full case record including nested `evidence.alerts.records[]` and `evidence.events.records[]`).",
    "- Render a decision doc, not a record dump. Five sections, H2 each, in this order:",
    "  - **Case context** — one line: severity + status + assignee + age + reference_id.",
    "  - **Evidence** — alerts table (composite_id · severity · name · host · status) capped at 10 rows, then events table (timestamp · type · summary) capped at 10. If either is empty, say so explicitly.",
    "  - **Cross-module enrichment** — for each unique host in the alert evidence, one-shot `falcon_get_host_details` (parallel) and surface platform + RTR status + last-seen. For each unique hash/IOC in alert metadata, one-shot `falcon_search_indicators` (parallel) to surface Intel reputation. Skip silently when nothing is enriched.",
    "  - **Verdict** — one paragraph: is this a true positive, a tuning candidate, or already resolved? Lean on the enrichment, not the case fields alone.",
    "  - **Recommended actions** — concrete next steps. Examples: 'Assign owner: <name>' (when unassigned), 'Run agentic IR on host <X> — primer: `[Run IR](/?primer=Run%20the%20agentic%20IR%20workflow%20on%20host%20%60HOST%60%20%28AID%20%60AID%60%29.%20Load%20the%20playbook%20with%20extras_ir_workflow_playbook%20and%20proceed.)`' (when alert evidence has a containable host), 'Close case as <verdict> with comment <...>' (when evidence is exhausted and verdict is clear). Two or three actions max.",
    "- Do NOT call `falcon_update_case` automatically — close/assign writes are operator-driven; surface the recommendation, wait for confirmation, then call.",
    "- If `falcon_get_cases` returns a scope-denial envelope (a 403 — the text carries 'Permission denied' / 'Required scopes' / 'scope not permitted' / 'access denied'), say once 'Required Falcon API scope (`Cases : read`) is not yet granted on this tenant API client.' and stop.",
    "",
    "Shadow-AI hunting (find unsanctioned generative-AI tooling):",
    "- `extras_fleet_shadow_ai_egress(hours_back, limit)` runs a single fleet-wide DnsRequest scan for AI endpoints (api.openai.com, claude.ai, huggingface.co, smithery.ai, etc.) and groups by AID + tool. Cheap broad signal — the right first call when the operator asks 'which hosts are using AI'.",
    "- `extras_host_shadow_ai_scan(device_id, hours_back)` is the deep per-host scan: ProcessRollup2 image-name match (Cursor / Ollama / LM Studio / Claude Desktop / ComfyUI), ProcessRollup2 cmdline match (MCP servers, agentic frameworks like LangChain / AutoGen / CrewAI), AND DnsRequest catalog match — combined into a single posture verdict (`model_developer` / `mcp_host` / `agentic_developer` / `unsanctioned_saas` / `code_assistant` / `image_video_gen` / `no_signal`). Use when the operator drills into a specific host or wants the complete picture, not just egress.",
    "- Verdict severity (most→least concerning): model_developer > mcp_host > agentic_developer > code_assistant > image_video_gen > unsanctioned_saas. mcp_host means the host runs an MCP server — agent has whatever permissions the server exposes (filesystem, browser, source control, RTR). model_developer means local inference — high data-egress / training-data risk.",
    "- Remediation levers (route by signal layer):",
    "  - Local AI app the operator wants gone → `extras_rtr_run_cleanup` with `host-kill-process` + `host-delete-folder` (approval-gated).",
    "  - MCP server / agent script → kill the parent runtime (node / python / uvx) via `host-kill-process`. Note follow-up: the operator likely needs to remove the persistence (scheduled task / Run key / IDE extension) — those aren't the catalog's job today.",
    "  - SaaS egress only (no local artifact) → recommend FQDN block in NGFW/DNS proxy, and create a custom domain IOC with `action='detect'` (per project rules, prevent is hash-only — domain IOCs cap at detect).",
    "  - Sanctioned tool (Copilot Business / M365 Copilot / Falcon GenAI) → no action; flag for the operator's allow-list.",
    "- Do NOT propose tenant-wide IOCs from a single host's egress without operator confirmation. Build the case from `extras_fleet_shadow_ai_egress` showing the same FQDN on multiple hosts before proposing a custom indicator.",
  ].join("\n");
}

type ChatRequest = { sessionId?: string; input?: string };

// Match the IR primer string built by HostActionButtons / QueueTable / etc.
// Backticks are optional so future primer variants don't silently slip past.
// Capture the AID for the server-side prefetch.
const IR_PRIMER_RX =
  /Run the agentic IR workflow on host\s+`?[^`\s]+`?\s*\(AID\s+`?([A-Fa-f0-9]+)`?\)/;

// Tools intentionally hidden from the agent during an active IR run.
// `extras_ir_workflow_playbook` + `extras_ir_campaign_scope` are pre-fetched
// server-side and injected as tool_results — re-calling them would be
// pointless. `extras_ir_phase0_detection_scope` is the older un-clustered
// alternative; agent muscle memory keeps reaching for it. Take the option
// away by filtering at toolset construction.
const IR_FILTERED_TOOLS = new Set([
  "extras_ir_workflow_playbook",
  "extras_ir_campaign_scope",
  "extras_ir_phase0_actionable_check",
  "extras_ir_phase0_detection_scope",
]);

const IR_TOOL_FILTER = (name: string) => !IR_FILTERED_TOOLS.has(name);

const IR_RECENT_RUN_WINDOW_MS = 60 * 60 * 1000; // 1h

function relativeTime(deltaMs: number): string {
  const sec = Math.round(deltaMs / 1000);
  if (sec < 90) return `${sec}s ago`;
  const min = Math.round(sec / 60);
  if (min < 90) return `${min} min ago`;
  const hr = Math.round(min / 60);
  if (hr < 36) return `${hr}h ago`;
  const days = Math.round(hr / 24);
  return `${days}d ago`;
}

function buildIdempotencyHint(prior: IrRunSummary): string {
  const ago = relativeTime(Date.now() - prior.lastTouched);
  const parts = [
    `**Recent IR run on this host detected.** Last touched ${ago}`,
    `(${prior.turnsCount} turn${prior.turnsCount === 1 ? "" : "s"}, ${prior.totalIterations} iteration${prior.totalIterations === 1 ? "" : "s"}`,
  ];
  if (prior.campaignsCount !== null) {
    parts.push(`, ${prior.campaignsCount} campaign${prior.campaignsCount === 1 ? "" : "s"} scoped`);
  }
  if (prior.hasErrors) parts.push(`, with errors`);
  parts.push(`).`);
  return (
    parts.join("") +
    " Before continuing, surface this to the operator and ask whether the prior run completed cleanly or whether this re-run is intentional. If the prior run was incomplete (denied approval, cancelled, RTR-blocked), continue. Otherwise stop and recommend reviewing the prior run record before re-running."
  );
}

/** Strip markdown/punctuation noise from the first user prompt and truncate
 *  to a left-rail-friendly length. setSessionTitle clamps to the canonical
 *  TITLE_MAX_LEN; this only needs to be roughly readable. */
function deriveSessionTitle(input: string): string {
  const cleaned = input
    .replace(/^[#>\s*-]+/, "")
    .replace(/`+/g, "")
    .replace(/\s+/g, " ")
    .trim();
  // Prefer the first sentence-shaped chunk if it lands within the budget.
  const firstSentence = cleaned.split(/(?<=[.!?])\s/, 1)[0] ?? cleaned;
  return firstSentence.length > 0 ? firstSentence : cleaned;
}

// CrowdStrike's API does not include an operator-facing display string in
// the response. We synthesize one from the fired detectors so the chat
// bubble has something specific to show ("blocked: prompt injection,
// secret leak") rather than a generic "policy violation".
const DETECTOR_LABELS: Record<string, string> = {
  malicious_prompt: "prompt injection",
  confidential_and_pii_entity: "sensitive data",
  malicious_entity: "malicious URL/IP",
  custom_entity: "custom-policy match",
  secret_and_key_entity: "secret/credential",
  competitors: "competitor mention",
  language: "disallowed language",
  topic: "off-policy topic",
  code: "code disclosure",
};

function aidrBlockPayload(verdict: AidrVerdict, phase: "input" | "output") {
  const fired = blockedDetectors(verdict);
  const labels = fired.map((k) => DETECTOR_LABELS[k] ?? k.replace(/_/g, " "));
  const reason =
    labels.length === 0
      ? "policy violation"
      : labels.length === 1
        ? labels[0]
        : `${labels.slice(0, -1).join(", ")} and ${labels[labels.length - 1]}`;
  const display_message =
    phase === "input"
      ? `Your message was blocked by CrowdStrike AIDR for ${reason}.`
      : `The response was blocked by CrowdStrike AIDR for ${reason} before delivery.`;
  return {
    phase,
    display_message,
    policy: verdict.policy ?? null,
    detectors: fired,
  };
}

function detectIrPrimer(input: string): { aid: string } | null {
  const m = input.match(IR_PRIMER_RX);
  if (!m) return null;
  // Normalize the captured aid to canonical lowercase hex at the single point
  // it enters the system. The regex admits uppercase ([A-Fa-f0-9]+); the
  // aid-keyed backstop reader (getLatestIrRunIdentity) lowercases its lookup,
  // and Falcon device_id matching is canonical-hex, so an upper/mixed-case aid
  // must be folded here or the release/lift backstops miss on the fallback path.
  return { aid: m[1].toLowerCase() };
}

/** Server-side invoke of a single MCP tool, returning the joined text content
 *  + isError flag. Mirrors what the agent loop's bridge.invoke() returns but
 *  doesn't require building the full bridge for two calls. */
async function callExtrasTool(
  extras: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<{ content: string; isError: boolean }> {
  try {
    const resp = await extras.callTool({ name, arguments: args });
    const text = (resp.content as Array<{ type: string; text?: string }>)
      .map((c) => (c.type === "text" && typeof c.text === "string" ? c.text : ""))
      .filter(Boolean)
      .join("\n");
    return {
      content: text || "(empty result)",
      isError: Boolean(resp.isError),
    };
  } catch (err) {
    return {
      content: err instanceof Error ? err.message : String(err),
      isError: true,
    };
  }
}

/** Pull the two IR ground-truth host facts from a raw falcon_search_hosts
 *  result. Called server-side via callExtrasTool(mcp, …), so this sees the
 *  FULL device body — product_type_desc survives here, unlike the slim agent
 *  projection (lib/mcp/projections.ts::hostProjection drops it). This is the
 *  code-side capture of what the playbook used to ask the agent to track in
 *  prose (falcon-extras/ir_playbook.py — the "contained_at_start" flag). Both
 *  fields default to null (unknown) on any parse gap rather than guessing. */
function parseHostFacts(rawContent: string): {
  containedAtStart: boolean | null;
  hostRole: string | null;
} {
  const hosts = parseConcatenatedJson<Record<string, unknown>>(rawContent);
  const h = hosts[0];
  if (!h) return { containedAtStart: null, hostRole: null };
  const status = typeof h.status === "string" ? h.status.toLowerCase() : null;
  const containedAtStart =
    status === null ? null : status === "contained" || status === "containment_pending";
  const hostRole = typeof h.product_type_desc === "string" ? h.product_type_desc : null;
  return { containedAtStart, hostRole };
}

/** Pre-fetch playbook + campaign scope, emit synthetic tool_use/tool_result
 *  events for trace UI, and return the synthetic message blocks to inject as
 *  conversation prefix so the agent sees the data as if it had called the
 *  tools itself.
 *
 *  Each prefetch tool resolves independently — the SSE `tool_result` for each
 *  is emitted the instant THAT tool returns, with its real wall-clock duration
 *  and a 1-line receipt summary. Operator sees Phase 0 enrichment land in
 *  stages (playbook ~50ms, actionable_check ~1s, campaign_scope often 5-8s)
 *  rather than three bubbles popping after the slowest completes. */
async function prefetchIrContext(opts: {
  extras: Client;
  emit: Emit;
  aid: string;
  /** Optional operator-visible idempotency hint to prepend to the assistant's
   *  prefix text so the agent sees it inline (and surfaces it to the operator
   *  before Phase 0). */
  priorHint?: string | null;
}): Promise<{
  assistantBlocks: Anthropic.ContentBlockParam[];
  toolResultBlocks: Anthropic.ToolResultBlockParam[];
  syntheticToolCalls: ToolCallRecord[];
  playbook: { content: string; isError: boolean };
  scope: { content: string; isError: boolean };
  actionable: { content: string; isError: boolean };
}> {
  const { extras, emit, aid, priorHint } = opts;

  const playbookId = `ir-prefetch-playbook-${Date.now()}`;
  const scopeId = `ir-prefetch-scope-${Date.now()}`;
  const actionableId = `ir-prefetch-actionable-${Date.now()}`;
  const playbookInput = { device_id: aid };
  const scopeInput = { device_id: aid };
  const actionableInput = { device_id: aid };

  emit("iteration_start", { iteration: 0 });
  emit(
    "text",
    "Loading IR playbook, capturing campaign scope, and partitioning open detections for actionability…\n\n",
  );

  emit("tool_use", {
    id: playbookId,
    name: "extras_ir_workflow_playbook",
    input: playbookInput,
  });
  emit("tool_use", {
    id: scopeId,
    name: "extras_ir_campaign_scope",
    input: scopeInput,
  });
  emit("tool_use", {
    id: actionableId,
    name: "extras_ir_phase0_actionable_check",
    input: actionableInput,
  });

  const startedAt = Date.now();
  const runOne = async (
    id: string,
    name: "extras_ir_workflow_playbook" | "extras_ir_campaign_scope" | "extras_ir_phase0_actionable_check",
    input: Record<string, unknown>,
  ): Promise<{ content: string; isError: boolean; durationMs: number; summary: string | undefined }> => {
    const t0 = Date.now();
    const r = await callExtrasTool(extras, name, input);
    const durationMs = Date.now() - t0;
    const summary = summarizeToolResult(name, r.content, r.isError);
    emit("tool_result", {
      tool_use_id: id,
      content: r.content,
      is_error: r.isError,
      duration_ms: durationMs,
      summary,
    });
    return { content: r.content, isError: r.isError, durationMs, summary };
  };

  const [playbookRes, scopeRes, actionableRes] = await Promise.all([
    runOne(playbookId, "extras_ir_workflow_playbook", playbookInput),
    runOne(scopeId, "extras_ir_campaign_scope", scopeInput),
    runOne(actionableId, "extras_ir_phase0_actionable_check", actionableInput),
  ]);

  const playbook = { content: playbookRes.content, isError: playbookRes.isError };
  const scope = { content: scopeRes.content, isError: scopeRes.isError };
  const actionable = { content: actionableRes.content, isError: actionableRes.isError };
  const playbookDuration = playbookRes.durationMs;
  const scopeDuration = scopeRes.durationMs;
  const actionableDuration = actionableRes.durationMs;

  const assistantBlocks: Anthropic.ContentBlockParam[] = [
    {
      type: "text",
      text: priorHint
        ? `${priorHint}\n\nLoading IR playbook, capturing campaign scope, and partitioning open detections.`
        : "Loading IR playbook, capturing campaign scope, and partitioning open detections.",
    },
    {
      type: "tool_use",
      id: playbookId,
      name: "extras_ir_workflow_playbook",
      input: playbookInput,
    },
    {
      type: "tool_use",
      id: scopeId,
      name: "extras_ir_campaign_scope",
      input: scopeInput,
    },
    {
      type: "tool_use",
      id: actionableId,
      name: "extras_ir_phase0_actionable_check",
      input: actionableInput,
    },
  ];

  const toolResultBlocks: Anthropic.ToolResultBlockParam[] = [
    {
      type: "tool_result",
      tool_use_id: playbookId,
      content: maybeFenceToolResult("extras_ir_workflow_playbook", playbook.content),
      is_error: playbook.isError,
    },
    {
      type: "tool_result",
      tool_use_id: scopeId,
      content: maybeFenceToolResult("extras_ir_campaign_scope", scope.content),
      is_error: scope.isError,
    },
    {
      type: "tool_result",
      tool_use_id: actionableId,
      content: maybeFenceToolResult("extras_ir_phase0_actionable_check", actionable.content),
      is_error: actionable.isError,
    },
  ];

  const syntheticToolCalls: ToolCallRecord[] = [
    {
      id: playbookId,
      name: "extras_ir_workflow_playbook",
      input: playbookInput,
      approval: "none",
      result: {
        isError: playbook.isError,
        contentExcerpt:
          playbook.content.length > 2048
            ? playbook.content.slice(0, 2048) + "\n…[truncated]"
            : playbook.content,
        durationMs: playbookDuration,
      },
      ts: startedAt,
    },
    {
      id: scopeId,
      name: "extras_ir_campaign_scope",
      input: scopeInput,
      approval: "none",
      result: {
        isError: scope.isError,
        contentExcerpt:
          scope.content.length > 2048
            ? scope.content.slice(0, 2048) + "\n…[truncated]"
            : scope.content,
        durationMs: scopeDuration,
      },
      ts: startedAt,
    },
    {
      id: actionableId,
      name: "extras_ir_phase0_actionable_check",
      input: actionableInput,
      approval: "none",
      result: {
        isError: actionable.isError,
        contentExcerpt:
          actionable.content.length > 2048
            ? actionable.content.slice(0, 2048) + "\n…[truncated]"
            : actionable.content,
        durationMs: actionableDuration,
      },
      ts: startedAt,
    },
  ];

  return {
    assistantBlocks,
    toolResultBlocks,
    syntheticToolCalls,
    playbook,
    scope,
    actionable,
  };
}

export async function POST(request: Request) {
  let body: ChatRequest;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid JSON body" }, { status: 400 });
  }

  const sessionId = (body.sessionId ?? "").trim();
  const input = (body.input ?? "").trim();
  if (!sessionId) {
    return NextResponse.json({ ok: false, error: "sessionId required" }, { status: 400 });
  }
  if (!input) {
    return NextResponse.json({ ok: false, error: "input required" }, { status: 400 });
  }

  // Per-session mutex: refuse a second concurrent turn on the same session
  // (double-submit / two tabs resuming the same conversation) rather than let
  // the two runs clobber each other's saveConversation (last-writer-wins) and
  // drift the IR turnCount. Mirrors the env-switch 409. Released when the
  // stream settles (onSettled below) — including on cancel/disconnect/error.
  if (!tryEnterSession(sessionId)) {
    return NextResponse.json(
      { ok: false, error: "A turn is already running for this conversation. Wait for it to finish." },
      { status: 409 },
    );
  }

  return streamAgent(async ({ mcp, extras, emit, signal }) => {
    // AIDR input gate. Runs before any LLM/tool work so a blocked prompt
    // never reaches Anthropic. Per-environment credential — when not set,
    // scanInput returns null and we proceed unguarded (banner in /chat
    // tells the operator AIDR is off for the active env). The pre-loop
    // assistant text + buffered output scan together form the chat
    // surface's guardrail boundary (other surfaces are scoped out for v1).
    if (isAidrEnabled()) {
      try {
        const verdict = await scanInput({
          messages: [{ role: "user", content: input }],
          sessionId,
        });
        if (verdict?.blocked) {
          recordBlock({
            sessionId,
            eventType: "input",
            verdict,
            textPreview: input,
          });
          emit("aidr_block", aidrBlockPayload(verdict, "input"));
          emit("done", {
            stop_reason: "aidr_blocked",
            iterations: 0,
            turn_count: 0,
          });
          emit("session_state", { expiresAt: Date.now() + TTL_MS });
          return;
        }
      } catch (err) {
        // Fail-open on AIDR transport errors. Surface a warning so the
        // operator knows the guardrail didn't run, but don't take chat
        // down because CrowdStrike's edge had a hiccup.
        console.warn("[aidr] scanInput failed:", (err as Error).message);
        emit("aidr_unavailable", {
          phase: "input",
          message: (err as Error).message,
        });
      }
    }

    const bridge = await buildToolBridge(mcp, extras);
    const systemPrompt = buildSystemPrompt(bridge.resources);

    // Title capture: derive once from the first user message in this
    // session. set-once semantics live in setSessionTitle, so a follow-up
    // turn doesn't overwrite an earlier title. Cheap derivation (no LLM)
    // matches what the user actually typed — easy to scan in the left rail.
    if (loadConversation(sessionId).length === 0) {
      setSessionTitle(sessionId, deriveSessionTitle(input));
    }

    // IR primer detection + server-side scope capture. Two motivations:
    //   1. The campaign-scope tool was previously agent-instructed; agents
    //      reach for `extras_ir_phase0_detection_scope` (older, un-clustered)
    //      from training-data muscle memory regardless of how strongly the
    //      playbook says otherwise. Calling scope here takes the option away.
    //   2. The playbook itself is also pre-fetched here so we can drop the
    //      "FIRST call extras_ir_workflow_playbook" instruction from the
    //      system prompt, removing one more guess-able step.
    // Both tool names are filtered from the visible toolset for the duration
    // of the IR session — see IR_TOOL_FILTER above.
    const irPrimer = detectIrPrimer(input);
    const existingIrMode = getIrMode(sessionId);
    const enteringIrMode = !!irPrimer && !existingIrMode;

    const prefix: Anthropic.MessageParam[] = [];
    let syntheticPrefetchCalls: ToolCallRecord[] = [];
    if (enteringIrMode && extras && irPrimer) {
      // Idempotency check: if a prior IR run on this host is recent, surface
      // its summary up front so the operator sees "last run 47 min ago"
      // before Phase 0 starts. The agent gets the same hint inline via the
      // assistant prefix so it can ask whether to continue.
      let priorHint: string | null = null;
      try {
        const prior = await getLastRunForAid(irPrimer.aid);
        if (prior && Date.now() - prior.lastTouched < IR_RECENT_RUN_WINDOW_MS) {
          priorHint = buildIdempotencyHint(prior);
          emit("text", priorHint + "\n\n");
        }
      } catch (err) {
        console.error("[ir-run-record] getLastRunForAid failed", err);
      }

      // Cost projection: before kickoff, set expectation based on recent IRs
      // (any host, last 5 runs). Best-effort — never blocks the run.
      try {
        const projection = await recentIrCostProjection(getAnthropicModel());
        if (projection) {
          const usd =
            projection.averageUsd < 0.01
              ? `$${projection.averageUsd.toFixed(4)}`
              : `$${projection.averageUsd.toFixed(2)}`;
          emit(
            "text",
            `Recent IR runs on this console averaged ${usd} (last ${projection.sampleSize} runs).\n\n`,
          );
        }
      } catch (err) {
        console.error("[ir-run-record] recentIrCostProjection failed", err);
      }

      const prefetch = await prefetchIrContext({
        extras,
        emit,
        aid: irPrimer.aid,
        priorHint,
      });
      // Conversation shape: user primer → assistant tool_uses → user tool_results
      // → real agent loop continues from here.
      prefix.push({ role: "user", content: input });
      prefix.push({ role: "assistant", content: prefetch.assistantBlocks });
      prefix.push({ role: "user", content: prefetch.toolResultBlocks });
      syntheticPrefetchCalls = prefetch.syntheticToolCalls;

      const startedAt = Date.now();
      const recordPath = recordPathFor(irPrimer.aid, startedAt);
      // Capture the two agent-independent host facts (S1) before kickoff:
      // containment status and host role. Reuses the generic callExtrasTool
      // against the falcon `mcp` client (not the bridge), so the full device
      // body — including product_type_desc — is visible. Best-effort: any
      // failure leaves both null (unknown), which the card renders honestly
      // and the lift backstop (F1) does not depend on (it keys off the
      // derivable agent_contained truth instead). aid is regex-constrained to
      // hex by IR_PRIMER_RX, so the FQL literal is injection-safe.
      let containedAtStart: boolean | null = null;
      let hostRole: string | null = null;
      try {
        const facts = await callExtrasTool(mcp, "falcon_search_hosts", {
          filter: `device_id:'${irPrimer.aid}'`,
          limit: 1,
        });
        if (!facts.isError) {
          const parsed = parseHostFacts(facts.content);
          containedAtStart = parsed.containedAtStart;
          hostRole = parsed.hostRole;
        }
      } catch (err) {
        console.error("[ir-run-record] host-facts capture failed", err);
      }
      // Best-effort — failure to write the audit file should not block the
      // IR run itself. The operator-facing workflow still runs; the record
      // is the supporting artifact.
      try {
        await createRecord({
          aid: irPrimer.aid,
          sessionId,
          startedAt,
          campaignScopeText: prefetch.scope.content,
          playbookOk: !prefetch.playbook.isError,
          playbookError: prefetch.playbook.isError
            ? prefetch.playbook.content
            : undefined,
          playbookTextLength: prefetch.playbook.content.length,
          containedAtStart,
          hostRole,
        });
      } catch (err) {
        // Fail-open on the WORKFLOW (the live IR must keep running) but
        // fail-VISIBLE on the AUDIT: tell the operator the engagement record
        // didn't capture, so a silent audit gap can't pass for a clean run.
        // Mirrors the aidr_unavailable pattern. See F6.
        console.error("[ir-run-record] createRecord failed", err);
        emit("ir_audit_unavailable", {
          phase: "kickoff",
          message: (err as Error).message,
        });
      }
      setIrMode(sessionId, {
        aid: irPrimer.aid,
        startedAt,
        recordPath,
        turnCount: 0,
      });
    }

    const initialMessages: Anthropic.MessageParam[] = enteringIrMode
      ? [...loadConversation(sessionId), ...prefix]
      : [...loadConversation(sessionId), { role: "user", content: input }];

    // Apply the IR tool filter on every turn while irMode is active — not
    // just the entering turn — so follow-ups can't backslide to the
    // deprecated scope tool.
    const irModeActive = enteringIrMode || !!existingIrMode;
    const toolFilter = irModeActive ? IR_TOOL_FILTER : undefined;

    // Per-turn audit observer. Wraps emit so it sees every event the agent
    // loop fires (tool_use, approval decisions, tool_result, done/cancelled
    // with usage); the resulting TurnRecord appends to the IR run file
    // after runAgentLoop returns.
    const turnIndex = irModeActive ? bumpIrTurnCount(sessionId) : 0;
    const observer = irModeActive
      ? new TurnObserver(turnIndex, input)
      : null;
    if (observer) {
      // The synthetic prefetch tool calls don't fire SSE events through this
      // turn's observer (they happened in prefetchIrContext above) — record
      // them by hand so the audit reflects every tool that ran this turn.
      for (const call of syntheticPrefetchCalls) {
        observer.recordSyntheticCall(call);
      }
    }
    // AIDR output buffer. We capture every assistant text delta so the
    // post-loop scan has the full final string. The deltas still stream
    // to the operator live — if the scan later flags a block, the saved
    // transcript is dropped and an aidr_block bubble is emitted in its
    // place. Brief mid-stream visibility is a known v1 limitation of
    // post-hoc guardrail scanning; CrowdStrike's AI Guard does not
    // support streaming-token inspection.
    const aidrActive = isAidrEnabled();
    const outputChunks: string[] = [];
    const baseEmit: Emit = observer
      ? (event, data) => {
          observer.observe(event, data);
          emit(event, data);
        }
      : emit;
    const wrappedEmit: Emit = aidrActive
      ? (event, data) => {
          if (event === "text" && typeof data === "string") {
            outputChunks.push(data);
          }
          baseEmit(event, data);
        }
      : baseEmit;

    // Knowledge-base retrieval (deterministic, server-side — same pattern as
    // the other route-level enrichments). Top passages from the active
    // environment's reference documents that match this turn's prompt are
    // injected as an uncached system block. Null when the environment has no
    // docs or nothing matched, so chat is unaffected when the KB is empty.
    // Wrapped defensively: a retrieval hiccup must never take down a turn.
    let knowledgeBlock: string | null = null;
    try {
      knowledgeBlock = buildKnowledgeContext(getActiveEnvironmentId(), input);
    } catch (err) {
      console.warn("[knowledge] retrieval failed:", (err as Error).message);
    }

    // ── IR safety core (F1 + F2b + S4) ───────────────────────────────────
    // The highest-blast-radius IR transitions (lift containment, remove from
    // quarantine) get a deterministic server-side backstop behind the agent's
    // judgment, keyed off server-derived ground truth (ir_runs / ir_run_turns)
    // — never the agent's prose or the playbook's advisory flags. See
    // lib/chat/ir-ground-truth.ts and `feedback_deterministic_over_agent_instruction`.
    //
    // `sessionIdentity` is the engagement THIS chat session is running, if any.
    // It is NOT sufficient on its own: a release (lift / group-remove) can
    // arrive from a DIFFERENT chat session, or after the 72h IR-mode idle TTL
    // evicted this session's IrMode — in both cases sessionIdentity is null (or
    // targets another host) while ir_runs still holds the ground truth keyed by
    // aid and never expires. So the guard and approvalContext below are ALWAYS
    // defined and resolve the target engagement per-call: session fast-path when
    // it matches, else aid-keyed from ir_runs (resolveTargetIrIdentity). Without
    // that fallback the entire backstop was session-scoped and a cross-session
    // release silently bypassed every deterministic gate (approval-only).
    const sessionIdentity = irModeActive ? getIrMode(sessionId) : null;

    // Turn-local containment + group-add observations. getContainmentGroundTruth
    // reads ir_run_turns, which is written POST-turn (appendTurn below), so a
    // contain / group-add applied earlier in THIS SAME turn isn't persisted yet.
    // Track them here so a same-turn contain→lift or add→remove sequence sees the
    // earlier action; the usual cross-turn case (Phase 1 contain/quarantine,
    // Phase 4 lift/remove later) is covered by the DB read. These are valid ONLY
    // on the session fast-path — a cross-session release happened in a different
    // process and the DB read is then complete and authoritative on its own.
    let containedThisTurn = false;
    const addedGroupsThisTurn = new Set<string>();

    // F2b memo: lift + group-remove fire seconds apart at release. Compute the
    // deterministic verification scope once per targeted host. Keyed by aid (not
    // a single per-turn slot) so a turn touching two engagements memoizes each
    // independently. "error" / "scope_uncaptured" = fail-closed. realCount = real
    // detections that fired AFTER kickoff; priorOpenCount = the ORIGINAL Phase-0
    // detections still open (re-checked by composite id, since they predate the
    // post-kickoff scan window).
    type Phase3GateResult =
      | { realCount: number; priorOpenCount: number }
      | "error"
      | "scope_uncaptured";
    const phase3GateByAid = new Map<string, Promise<Phase3GateResult>>();

    // Resolve which IR engagement a release write targets when the live session
    // isn't running it (cross-session release, or post-TTL eviction). Walk the
    // call's device_ids and return the latest ir_runs identity for the first
    // that has IR history; null = the targeted host has no engagement on record
    // (so there is nothing for the deterministic gate to protect — approval
    // still applies).
    const resolveTargetIrIdentity = (
      input: Record<string, unknown>,
    ): { aid: string; startedAt: number } | null => {
      for (const id of extractDeviceIds(input)) {
        const hit = getLatestIrRunIdentity(id);
        if (hit) return hit;
      }
      return null;
    };

    const onToolResult: RunAgentOptions["onToolResult"] = async (event) => {
      if (
        sessionIdentity &&
        !event.isError &&
        containTargetsAid(event.input, sessionIdentity.aid)
      ) {
        if (CONTAIN_TOOLS.has(event.name)) {
          // Only an API-confirmed contain counts (ok:false / partial failure
          // arrive as non-error results) — see containResultConfirms.
          if (containResultConfirms(event.content, sessionIdentity.aid)) containedThisTurn = true;
        } else if (event.name === "extras_host_group_add_members") {
          const gid = (event.input as Record<string, unknown>).group_id;
          if (typeof gid === "string" && gid) addedGroupsThisTurn.add(gid);
        }
      }
      await persistCreatedHostGroupId(event);
      await persistSavedPatchProfile(event);
    };

    const guard: RunAgentOptions["guard"] = async (toolName, input) => {
      const isLift = LIFT_TOOLS.has(toolName);
      const isRemove = toolName === "extras_host_group_remove_members";
      if (!isLift && !isRemove) return null;

      // Resolve the engagement this release targets. Fast path: the live
      // session is running the engagement AND this call targets its host — use
      // that identity (it carries the same-turn contain/add observations).
      // Fallback: resolve aid-keyed from ir_runs so a release from a DIFFERENT
      // session, or after the IR-mode TTL evicted this session's IrMode, still
      // hits the backstop. No IR history for the targeted host → null (approval
      // still applies; nothing for the deterministic gate to protect).
      const fast =
        sessionIdentity && containTargetsAid(input, sessionIdentity.aid)
          ? sessionIdentity
          : null;
      const identity = fast ?? resolveTargetIrIdentity(input);
      if (!identity) return null;
      const sameSession = fast !== null;

      const gt = getContainmentGroundTruth(identity.aid, identity.startedAt);
      const agentContained = gt.agentContained || (sameSession && containedThisTurn);

      // F1: never lift a containment THIS workflow did not apply.
      if (isLift && !agentContained) {
        return {
          block: true,
          reason:
            "Refusing to lift containment this workflow did not apply. The host was contained before this engagement began (or by another actor); lifting it is the operator's decision, not the workflow's. Lift it from the Falcon Console if that's intended.",
        };
      }

      // F1-group: never remove this host from a group THIS workflow did not
      // place it in. Phase 1 quarantine IS a group-add and Phase 4 release
      // removes it, so this is F1 at the group layer — keyed off the set of
      // groups this engagement added the host to (DB-derived + same-turn),
      // never the agent's prose. A remove with a missing group_id, or one we
      // never added the host to, is refused.
      if (isRemove) {
        const addedGroups = new Set<string>([
          ...gt.agentAddedGroupIds,
          ...(sameSession ? addedGroupsThisTurn : []),
        ]);
        const gid = (input as Record<string, unknown>).group_id;
        if (typeof gid !== "string" || !addedGroups.has(gid)) {
          return {
            block: true,
            reason:
              "Refusing to remove this host from a group this workflow didn't place it in. The host's group membership predates this engagement (or was set by another actor); changing it is the operator's decision, not the workflow's. Adjust group membership from the Falcon Console if that's intended.",
          };
        }
      }

      // F2b: deterministic release gate — block release while real detections
      // from this engagement remain open. Uses kickoff time as `since`
      // (conservatively wide) for the post-kickoff scan, AND re-checks the exact
      // Phase-0 originals by composite id (those predate the scan window, so a
      // real_count-only gate would miss an original detection that was never
      // remediated). Fail-closed on any scope error AND when the kickoff scope
      // was never captured (so the prior-originals re-check can't silently
      // degrade to a real_count-only gate). Memoized per aid (lift + remove fire
      // seconds apart, possibly across two engagements in one turn).
      let gatePromise = phase3GateByAid.get(identity.aid);
      if (!gatePromise) {
        gatePromise = (async (): Promise<Phase3GateResult> => {
          try {
            const scope = getPhase0Scope(identity.aid, identity.startedAt);
            // A run exists but its Phase-0 detection scope was never captured
            // (kickoff campaign-scope call failed / was pending). We have no
            // record of what the host's original detections were, so we cannot
            // confirm they're closed — fail closed rather than degrade to the
            // post-kickoff-only real_count gate. (captured===true with an empty
            // id set is a genuine clean kickoff — zero originals — and proceeds.)
            if (!scope.captured) return "scope_uncaptured";
            const args: Record<string, unknown> = {
              device_id: identity.aid,
              since_iso: new Date(identity.startedAt).toISOString(),
            };
            if (scope.ids.length > 0) args.prior_composite_ids = scope.ids;
            const res = await callExtrasTool(
              extras,
              "extras_ir_phase3_verification_scope",
              args,
            );
            if (res.isError) return "error";
            const parsed = JSON.parse(res.content) as {
              real_count?: unknown;
              prior_open_count?: unknown;
            };
            if (typeof parsed.real_count !== "number") return "error";
            // If we sent prior_composite_ids we REQUIRE a numeric
            // prior_open_count back — its absence means an older sidecar that
            // can't re-check the originals, so we can't confirm they're closed:
            // fail closed rather than silently degrade to a real_count-only gate
            // (the version-skew fail-open this read closes). When we sent none
            // (clean kickoff, zero originals) priorOpenCount stays 0 correctly.
            let priorOpenCount = 0;
            if (scope.ids.length > 0) {
              if (typeof parsed.prior_open_count !== "number") return "error";
              priorOpenCount = parsed.prior_open_count;
            }
            return { realCount: parsed.real_count, priorOpenCount };
          } catch {
            return "error";
          }
        })();
        phase3GateByAid.set(identity.aid, gatePromise);
      }
      const gate = await gatePromise;
      if (gate === "scope_uncaptured") {
        return {
          block: true,
          reason:
            "Release blocked: Eyas couldn't capture this host's open detections when the engagement started, so it can't confirm the detections that triggered this response were resolved. The host stays quarantined. Review this host in the Falcon Console and release it there once you've confirmed it's clean.",
        };
      }
      if (gate === "error") {
        return {
          block: true,
          reason:
            "Release blocked: the verification re-scan could not complete, so the host stays quarantined as a precaution. Re-run the verification step, or release from the Falcon Console once you've confirmed the host is clean.",
        };
      }
      if (gate.realCount > 0) {
        return {
          block: true,
          reason: `Release blocked: ${gate.realCount} real detection(s) fired during this engagement and remain open. The host stays quarantined. Verify and remediate those detections, then re-run release.`,
        };
      }
      if (gate.priorOpenCount > 0) {
        const n = gate.priorOpenCount;
        return {
          block: true,
          reason: `Release blocked: ${n} of the detection(s) that started this engagement ${n === 1 ? "is" : "are"} still open and unresolved. The host stays quarantined. Close or remediate ${n === 1 ? "it" : "them"}, then re-run release.`,
        };
      }
      return null;
    };

    // Operator-facing caveat surfaced on the RELEASE approval cards (lift +
    // group-remove). States plainly that Eyas's release check is detection-
    // status-based (not a full artifact re-scan), and that Eyas may decline a
    // release but never releases on its own and never overrides the Console.
    const RELEASE_VERIFICATION_NOTE =
      "Eyas verifies a release by re-checking this host's CrowdStrike detection status — it does not independently re-scan every on-host artifact. Eyas may decline a release it can't verify, but it never releases the host on its own and never overrides the Falcon Console.";

    const approvalContext: RunAgentOptions["approvalContext"] = (
      toolName,
      input,
    ) => {
      // Contain is a Phase-1 action INSIDE the running engagement — its verified
      // facts (containedAtStart / agentContained) describe this session's
      // engagement, so it stays session-scoped. (The guard doesn't gate contain;
      // this card is an informed-approval courtesy, incl. the DC blast-radius
      // warning.) No aid-keyed fallback: a contain from another session isn't
      // part of THIS workflow's Phase 1, and surfacing a prior run's
      // containedAtStart against it would misrepresent.
      if (CONTAIN_TOOLS.has(toolName)) {
        if (!sessionIdentity || !containTargetsAid(input, sessionIdentity.aid)) {
          return undefined;
        }
        const gt = getContainmentGroundTruth(
          sessionIdentity.aid,
          sessionIdentity.startedAt,
        );
        return {
          containedAtStart: gt.containedAtStart,
          agentContained: gt.agentContained || containedThisTurn,
          hostRole: gt.hostRole,
          isDomainController: isDomainController(gt.hostRole),
        };
      }

      // Lift / group-remove are release actions the guard gates aid-keyed — so
      // the verified card must resolve the same way (session fast-path, else
      // aid-keyed from ir_runs), or a cross-session release would show no
      // verified facts while the guard still (correctly) blocks it.
      const isLift = LIFT_TOOLS.has(toolName);
      const isRemove = toolName === "extras_host_group_remove_members";
      if (!isLift && !isRemove) return undefined;

      const fast =
        sessionIdentity && containTargetsAid(input, sessionIdentity.aid)
          ? sessionIdentity
          : null;
      const identity = fast ?? resolveTargetIrIdentity(input);
      if (!identity) return undefined;
      const sameSession = fast !== null;
      const gt = getContainmentGroundTruth(identity.aid, identity.startedAt);

      if (isLift) {
        return {
          containedAtStart: gt.containedAtStart,
          agentContained: gt.agentContained || (sameSession && containedThisTurn),
          hostRole: gt.hostRole,
          isDomainController: isDomainController(gt.hostRole),
          releaseVerificationNote: RELEASE_VERIFICATION_NOTE,
        };
      }

      // isRemove
      const addedGroups = new Set<string>([
        ...gt.agentAddedGroupIds,
        ...(sameSession ? addedGroupsThisTurn : []),
      ]);
      const gid = (input as Record<string, unknown>).group_id;
      return {
        workflowAddedToGroup: typeof gid === "string" && addedGroups.has(gid),
        releaseVerificationNote: RELEASE_VERIFICATION_NOTE,
      };
    };

    const result = await runAgentLoop({
      signal,
      mcp,
      extrasMcp: extras,
      systemPrompt,
      initialMessages,
      emit: wrappedEmit,
      sessionId,
      surface: "chat",
      // Chat is the surface where the agent writes full scripts / playbooks, so
      // give it more room than the 4096 agent-loop default (which truncated long
      // scripts mid-output). Operator-tunable via /config (the Anthropic card);
      // runtime.ts parses + clamps it to a safe range and defaults to 16384. The
      // loop streams, so high caps carry no HTTP-timeout risk.
      maxTokensPerTurn: getRuntimeConfig().anthropic.chatMaxTokens,
      toolFilter,
      onToolResult,
      guard,
      approvalContext,
      contextBlocks: knowledgeBlock ? [knowledgeBlock] : undefined,
    });

    let outputBlocked = false;
    if (result.endedNormally && aidrActive && outputChunks.length) {
      try {
        const text = outputChunks.join("");
        const verdict = await scanOutput({ text, sessionId });
        if (verdict?.blocked) {
          outputBlocked = true;
          recordBlock({
            sessionId,
            eventType: "output",
            verdict,
            textPreview: text,
          });
          emit("aidr_block", aidrBlockPayload(verdict, "output"));
        }
      } catch (err) {
        console.warn("[aidr] scanOutput failed:", (err as Error).message);
        emit("aidr_unavailable", {
          phase: "output",
          message: (err as Error).message,
        });
      }
    }

    // Persist the transcript whenever we have a coherent message list — which
    // INCLUDES a cancelled/disconnected turn (endedNormally=false). The agent
    // loop guarantees finalMessages never ends on a dangling tool_use (every
    // return path lands on a user/tool_result or an assistant end_turn message;
    // awaitApproval resolves to a timeout tool_result rather than escaping), so
    // a partial turn resumes cleanly. This keeps the resumable transcript in
    // sync with the IR audit record (appendTurn below) AND with Falcon state
    // already mutated by executed writes — previously a Stop skipped the save,
    // so those writes vanished from history while persisting to ir_run_turns,
    // and a resume replayed stale messages against already-moved state.
    //
    // The one case we still skip: AIDR blocked the assistant OUTPUT — we must
    // not persist blocked content into the resumable transcript. (outputBlocked
    // is only ever set on an endedNormally turn.)
    if (!outputBlocked) {
      saveConversation(sessionId, result.finalMessages);
      // saveConversation bumped lastTouched, so the freshly-rolled expiry below
      // is accurate. Emit it here (not unconditionally) so a turn we didn't
      // persist doesn't over-promise the header TTL pill. Single source of
      // truth for TTL_MS: lib/chat/state.ts.
      emit("session_state", { expiresAt: Date.now() + TTL_MS });
    }

    if (observer) {
      const irMode = getIrMode(sessionId);
      const recordPath = irMode?.recordPath;
      if (recordPath) {
        try {
          await appendTurn(recordPath, observer.finalize());
        } catch (err) {
          // Fail-visible on the audit gap (see kickoff createRecord above).
          console.error("[ir-run-record] appendTurn failed", err);
          emit("ir_audit_unavailable", {
            phase: "turn",
            message: (err as Error).message,
          });
        }
      }
    }
  }, { onSettled: () => exitSession(sessionId) });
}

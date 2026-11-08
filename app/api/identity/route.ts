import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";
import { nativeSidecarPayload } from "@/lib/mcp/native-payload";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// /identity — Identity Protection decision document. Deterministic-first: the
// four extras_identity_* reads are fetched server-side in parallel and injected
// as a context block (mirrors /discover, /intel), so the agent synthesizes
// without spending iterations on tool calls and a no-scope tenant escapes
// immediately. (Read-only surface; no per-tool [N] citations — the injected
// snapshot is the ground truth the doc references by name.)

function parseToolJson(result: unknown): Record<string, unknown> | null {
  const content = (result as { content?: unknown })?.content;
  const text = (Array.isArray(content) ? content : ([] as Array<{ type: string; text?: string }>))
    .map((c) => (c.type === "text" && c.text ? c.text : ""))
    .join("\n");
  try {
    const j = JSON.parse(text) as unknown;
    return j && typeof j === "object" ? (j as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

type IdentityData = {
  risky: Record<string, unknown> | null;
  detections: Record<string, unknown> | null;
  sensors: Record<string, unknown> | null;
  rules: Record<string, unknown> | null;
};

// Risky identities, IDP sensors and policy rules come from the MCP server's
// native tools (same records as the former sidecar twins, verified live);
// identity detections still come from the sidecar.
async function fetchIdentity(extras: Client, mcp: Client): Promise<IdentityData> {
  const [risky, detections, sensors, rules] = await Promise.all([
    nativeSidecarPayload(mcp, "falcon_search_risky_identities", { limit: 15 }),
    extras.callTool({ name: "extras_identity_detections", arguments: { hours: 168, limit: 50 } }).then(parseToolJson),
    nativeSidecarPayload(mcp, "falcon_search_idp_sensors", { limit: 50 }),
    nativeSidecarPayload(mcp, "falcon_search_idp_policy_rules", { limit: 200 }),
  ]);
  return { risky, detections, sensors, rules };
}

// Scope is per-tenant; risky_entities is the primary IDP read, so its
// scope_pending signal gates the whole surface (all four fail together when the
// client lacks Identity Protection Entities:read).
function identityScopePending(d: IdentityData): boolean {
  return d.risky?.scope_pending === true;
}

function items(p: Record<string, unknown> | null): unknown[] {
  const it = p?.items;
  return Array.isArray(it) ? it : [];
}

function renderIdentityContext(d: IdentityData): string {
  // Policy rules can be up to 200 — summarize by action + enabled state rather
  // than dumping them (the report only ever wants the summary). The other three
  // are already small (15 / ≤50 / ≤50) so pass them through raw.
  const rules = items(d.rules);
  const byAction: Record<string, number> = {};
  let enabled = 0;
  for (const r of rules) {
    const o = (r ?? {}) as Record<string, unknown>;
    const a = String(o.action ?? "UNKNOWN");
    byAction[a] = (byAction[a] ?? 0) + 1;
    if (o.enabled) enabled += 1;
  }
  return [
    "## Identity Protection snapshot (GROUND TRUTH — do NOT call any tools)",
    "",
    "### Risky entities (top 15 by risk score)",
    JSON.stringify(items(d.risky), null, 1),
    "",
    "### Active IDP detections (last 7 days; policy-rule enforcement noise + closed already dropped)",
    JSON.stringify(items(d.detections), null, 1),
    "",
    "### Sensor posture (per-protocol enforcement modes)",
    JSON.stringify(items(d.sensors), null, 1),
    "",
    "### Policy rules (summary)",
    `total=${rules.length}, enabled=${enabled}, disabled=${rules.length - enabled}, byAction=${JSON.stringify(byAction)}`,
  ].join("\n");
}

function buildPrompt(): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    "You are producing an IDENTITY PROTECTION decision document for a CrowdStrike Falcon tenant administrator. The user wants one screen that answers: who are the riskiest identities, what's actively happening on the identity surface, what's our enforcement posture, and what should we do.",
    "",
    `Today is ${today} (UTC).`,
    "",
    "The identity surface has ALREADY been fetched for you and is provided below as a context snapshot — treat it as GROUND TRUTH and do NOT call any tools. It contains four blocks:",
    "- Risky entities: top-15 highest-risk USER entities — primaryDisplayName, riskScore, riskScoreSeverity, riskFactors (STALE_ACCOUNT, EXPOSED_PASSWORD, PRIVILEGED, WATCHED, SHADOW_ADMIN, etc.), AD account info.",
    "- Active IDP detections (last 7 days): Pass-the-Hash, Golden Ticket, Kerberoasting, Suspicious LDAP, Privilege escalation, Credential Scanning, Unusual login, etc. — severity, user_name, source/destination account, source/destination endpoint hostnames. Already filtered (open-status + 'Policy rule match' enforcement noise dropped).",
    "- Sensor posture: IDP sensor inventory + per-protocol modes — kerberos_config / ntlm_config / ldap_config / ldaps_config / smb_to_dc_config / rdp_to_dc_config (enforcement / detection / monitoring / off), status (watch for `status.limited-func` + the status_causes array), directory_auditing.",
    "- Policy rules: a summary line (total, enabled/disabled, counts by action DENY / ALLOW / MFA_REQUIRED / …). Use it directly; do not ask for the full rule list.",
    "",
    "Sections — produce all of them in this exact order. Use H2 (##) for each:",
    "",
    "## Executive verdict",
    "One sentence. Lead with the most-actionable fact: '<N> high/critical risky users, <K> active identity detections in the last 7d, <M> sensors with degraded posture' — or 'Identity surface is clean: 0 high-risk users, 0 active IDP detections, all sensors healthy.' No filler.",
    "",
    "## 🔥 Risky identities",
    "Render a table — top 10 risky USERS, ranked by risk score: Display name | sAMAccountName | Severity | Risk score | Top risk factors. Translate machine labels: STALE_ACCOUNT → 'Stale account', EXPOSED_PASSWORD → 'Exposed password', PRIVILEGED → 'Privileged', SHADOW_ADMIN → 'Shadow admin', WATCHED → 'Watched', WEAK_PASSWORD → 'Weak password'. Cap at 10 even if more exist; mention '+ N more' if truncated. If zero, write 'No risky identities surfaced — clean tenant.'",
    "",
    "## 🚨 Active IDP detections (last 7 days)",
    "ONLY render this section's table if at least one IDP detection exists. Render: Severity | Detection | Source user → Destination | Source host → Dest host | When (relative). Show **all** detections in the snapshot (already filtered — policy-rule enforcement noise + closed detections dropped — so what's there is real). If zero, write the heading then 'No IDP detections in the last 7 days.' For each detection, link the display name to the falcon_host_link if present (markdown link). If the same detection type repeats on multiple hosts, do NOT collapse — each row matters for the analyst.",
    "",
    "## 🛡 Sensor posture",
    "One-paragraph summary covering: total sensor count, enforcement-mode distribution across the four key protocols (Kerberos / NTLM / LDAP / SMB-to-DC) — 'all in enforcement' is best, 'mixed' or 'detection-only' are callouts. Then a Concerns table (only if any concerns exist): Sensor (hostname) | Domain | Concern. A concern is: status starts with 'status.limited-func' (cite the status_causes), OR any of the four key protocols is set to anything other than 'enforcement'. If no concerns: 'All sensors in enforcement; no posture concerns.'",
    "",
    "## 📋 Policy rule summary",
    "DO NOT list rules. Summarize: total rules, enabled vs disabled count, breakdown by action (e.g. 'DENY: 40, MFA_REQUIRED: 80, ALLOW: 42'). One line. Then a one-sentence interpretation: 'Strong enforcement posture' if mostly DENY/MFA_REQUIRED, 'Mostly permissive' if mostly ALLOW, 'Heavy MFA reliance' if MFA_REQUIRED dominates.",
    "",
    "## Recommended actions",
    "Pick by evidence (one or two — be decisive, not exhaustive):",
    "- Active IDP detection on a high-risk user → 'Triage detection [name] for [user] in the Queue (link: /queue) — concurrent risk + active threat is the most urgent signal.'",
    "- High-risk users + posture gap (NTLM in detection-only, etc.) → 'Move <protocol> from detection to enforcement on the affected sensors before the next high-risk user is exploited.'",
    "- Many policy rules but key ones disabled → callout the disabled rules by name.",
    "- Clean tenant → 'No action; posture is healthy. Keep monitoring weekly.'",
    "",
    "Style:",
    "- Markdown only. H2 headings. Tables for structured sections.",
    "- Be terse and decisive — a SOC analyst is reading this between meetings.",
    "- Use the small status emoji on section headers exactly as written; do not sprinkle emoji elsewhere.",
    "- If a section has no data, still include the heading with a one-line note rather than skipping.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Do NOT call any tools — the snapshot above is complete. Write the report in ONE turn.",
    "- The very first text token you emit must be the Executive-verdict H2. No preamble, no 'Here is your report.'",
    "- Reference specific entities / detections / sensors by name from the snapshot so the reader can verify against the on-screen data.",
  ].join("\n");
}

export async function POST() {
  return streamAgent(async ({ mcp, extras, emit, signal }) => {
    const data = await fetchIdentity(extras, mcp);
    if (identityScopePending(data)) {
      emit("scope_pending", {
        note: "The Falcon API client does not carry the Identity Protection (Identity Protection Entities:read) scope.",
      });
      emit("done", { stop_reason: "scope_pending", iterations: 0 });
      return;
    }
    await runAgentLoop({
      signal,
      mcp,
      extrasMcp: extras,
      systemPrompt: buildPrompt(),
      contextBlocks: [renderIdentityContext(data)],
      initialMessages: [
        {
          role: "user",
          content:
            "Render the Identity Protection decision document from the provided snapshot.",
        },
      ],
      emit,
      // Read-only synthesis over injected context. Per feedback_never_disable_approvals
      // do NOT override requiresApproval. maxIterations is low — the data is
      // already provided, so the agent should write the report in one turn.
      maxTokensPerTurn: 8192,
      maxIterations: 4,
      surface: "identity",
    });
  });
}

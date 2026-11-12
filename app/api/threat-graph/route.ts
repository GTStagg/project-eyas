import { NextResponse } from "next/server";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Body = { indicator?: string; indicator_type?: string };

const HASH_RX = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
const DOMAIN_RX = /^[a-z0-9][a-z0-9.\-]{0,253}$/;
const IPV4_RX =
  /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const IPV6_RX = /^[0-9a-fA-F:]{2,45}$/;

const VALID_TYPES = new Set([
  "sha256",
  "sha1",
  "md5",
  "ipv4",
  "ipv6",
  "domain",
]);

function classify(raw: string): { value: string; type: string } | null {
  const v = raw.trim();
  if (!v) return null;
  if (HASH_RX.test(v)) {
    const lower = v.toLowerCase();
    if (lower.length === 32) return { value: lower, type: "md5" };
    if (lower.length === 40) return { value: lower, type: "sha1" };
    if (lower.length === 64) return { value: lower, type: "sha256" };
  }
  if (IPV4_RX.test(v)) return { value: v, type: "ipv4" };
  if (IPV6_RX.test(v) && v.includes(":")) return { value: v, type: "ipv6" };
  const lower = v.toLowerCase();
  if (DOMAIN_RX.test(lower) && lower.includes(".")) {
    return { value: lower, type: "domain" };
  }
  return null;
}

function buildPrompt(indicator: string, type: string): string {
  const today = new Date().toISOString().slice(0, 10);
  const isHash = type === "sha256" || type === "sha1" || type === "md5";

  // Threat Graph's queryable surface is hash-keyed. Domain/IP vertex IDs are
  // NOT raw values — they're constructed identifiers that aren't exposed
  // through the public API. So for hashes we pivot through Threat Graph;
  // for network artifacts we lean entirely on detection search.
  const tgPivotInstruction = isHash
    ? `- \`falcon_get_threatgraph_ran_on\` — pass value=\`${indicator}\`, indicator_type=\`${type}\`, limit=50. Returns one record per device that EXECUTED this hash: \`device_id\`, \`timestamp\`, \`edge_type\`, \`scope\`.`
    : `- (Threat Graph is intentionally NOT called for ${type} indicators — the API only accepts hash-keyed vertex IDs, so domain/IP queries reliably 400. Skip it. Detection search below is the authoritative source for "what hosts touched this ${type}".)`;

  const detectionsInstruction = isHash
    ? `- \`falcon_search_detections\` — filter \`behaviors.${type}:'${indicator}'\`. This is the correct field for hash matching.`
    : `- \`falcon_search_detections\` — for domain / IP indicators do NOT filter on \`behaviors.${type}\`; that field is unreliable for network artifacts. Use the free-text query parameter \`q='${indicator}'\` instead — the indicator typically appears in network_accesses, cmdline, or description, all of which q spans.`;

  return [
    "You are producing a THREAT GRAPH PIVOT report for a CrowdStrike Falcon tenant administrator. The user supplied one indicator (hash / domain / IP) and wants one screen that answers: how widely has Falcon's sensor telemetry seen this, what hosts touched it, and what's the next pivot.",
    "",
    `Today is ${today} (UTC).`,
    `Subject indicator: \`${indicator}\` (type: ${type}).`,
    "",
    "DATA GATHERING — fan these out in parallel up front:",
    tgPivotInstruction,
    `- \`falcon_search_indicators\` — Falcon Adversary Intelligence's curated IOC feed. Filter on the indicator value. Reveals whether CS Intel rates it (malicious_confidence) and what actor/family it's tied to.`,
    detectionsInstruction,
    "",
    "After the initial fan-out, do not loop. Write the report.",
    "",
    "TOOL-FAILURE DISCIPLINE — load-bearing:",
    "- If a Threat Graph call returns `ok: false` with an upstream HTTP error (400, 500, etc.), DO NOT interpret that as 'zero devices observed.' That is a tool failure, not a result. Report it: 'Threat Graph returned <error>; sensor-exposure section is inconclusive, not negative.'",
    "- A `scope_pending: true` response is the only response that legitimately means 'no data, surface is empty.' Everything else (4xx/5xx upstream) means 'we don't know — say we don't know.'",
    "- Tenant detections (falcon_search_detections) are authoritative for confirming exposure. If detections show hits but Threat Graph returned an error, the headline must reflect the detections, not the Threat Graph error.",
    "",
    "Sections — produce all of them in this exact order. Use H2 (##) for each.",
    "",
    "## Headline",
    `**FIRST: scope check.** If a Threat Graph call (when made) returned a 401/403 permission error, render ONLY this section and stop: 'Falcon Threat Graph is **not yet authorized** on this tenant — the API client lacks \`Threat Graph : read\`. No data to render right now.'`,
    `Otherwise, one sentence reconciling the available signals. For hashes: Threat Graph devices-observed count + CS Intel verdict + tenant detection count. For domain/IP (where Threat Graph is intentionally skipped): CS Intel verdict + tenant detection count + a brief 'Threat Graph not queried — API does not support raw ${type} values as vertex IDs.'`,
    "Lead with the strongest signal. If Intel rates HIGH or detections exist, say so first — never lead with 'zero devices' if Threat Graph errored or detections show otherwise.",
    "",
    "## Sensor exposure",
    isHash
      ? "From falcon_get_threatgraph_ran_on, render a table (cap 15): Device ID | Seen (timestamp) | Edge type | Scope, plus a one-line total device count. If the call errored: 'Threat Graph returned <upstream error>. Sensor-exposure data is unavailable for this query — tenant detections (below) remain authoritative.' If zero items: 'No graph evidence — but check tenant detections below before concluding the indicator is absent.'"
      : `Threat Graph was intentionally skipped for this ${type} indicator (the API only accepts hash-keyed vertex IDs). Sensor exposure is determined from tenant detections — see the section below. Render a single line: 'Threat Graph not applicable for ${type} indicators. Detection search (below) is the authoritative pivot.'`,
    "",
    "## Falcon Intel context",
    "malicious_confidence + actor / family attribution. If Intel has nothing: 'Not present in Falcon Adversary Intelligence's curated feed.'",
    "",
    "## Tenant detections",
    "From falcon_search_detections, summarize: how many detections, severities, hosts, process / cmdline if visible. If zero: 'No tenant detections reference this indicator.' If detections exist, this is the authoritative answer regardless of Threat Graph status.",
    "",
    "## Recommended next pivots",
    "Pick by evidence (one or two — be decisive). Reconcile signals — Intel + detections trump a Threat Graph error.",
    "- Detections exist + Intel rates malicious → 'Triage the affected hosts via /investigate. Detection is the source of truth here regardless of Threat Graph status.'",
    "- Detections exist + Intel unknown → 'Confirmed tenant exposure. Pivot to /investigate.'",
    "- No detections + Intel rates malicious + Threat Graph clean → 'No action required — cloud reputation already covers this.'",
    "- No detections + Intel unknown + Threat Graph clean → 'Indicator is unknown both to your tenant and to CS Intel.'",
    "- Threat Graph errored (rest unclear) → 'Re-run after refresh, or pivot to /lookup which uses different APIs.'",
    "",
    "Style:",
    "- Markdown only. H2 headings. Tables for structured sections.",
    "- Be terse and decisive. NEVER report a tool error as a negative result.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Output NOTHING between tool calls. Zero text.",
    "- Make all tool calls in parallel, then write the report ONCE.",
    "- The very first text token you emit must be the Headline H2.",
    "",
    "Citations:",
    "- Tool calls are numbered 1, 2, 3, … in call order.",
    "- End facts with [N] referencing the call number.",
  ].join("\n");
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const rawIndicator = typeof body.indicator === "string" ? body.indicator : "";
  const rawType =
    typeof body.indicator_type === "string"
      ? body.indicator_type.toLowerCase()
      : "";

  let indicator: string;
  let indicatorType: string;
  if (rawType && VALID_TYPES.has(rawType)) {
    // Explicit type still has to pass the same shape check as the classify()
    // path — otherwise an empty/malformed value (or FQL metacharacters) flows
    // straight into the system prompt and into behaviors.<type>:'<value>'.
    const candidate = rawIndicator.trim();
    const lower = candidate.toLowerCase();
    const okForType =
      (rawType === "md5" && /^[a-fA-F0-9]{32}$/.test(candidate)) ||
      (rawType === "sha1" && /^[a-fA-F0-9]{40}$/.test(candidate)) ||
      (rawType === "sha256" && /^[a-fA-F0-9]{64}$/.test(candidate)) ||
      (rawType === "ipv4" && IPV4_RX.test(candidate)) ||
      (rawType === "ipv6" && IPV6_RX.test(candidate) && candidate.includes(":")) ||
      (rawType === "domain" && DOMAIN_RX.test(lower) && lower.includes("."));
    if (!okForType) {
      return NextResponse.json(
        {
          ok: false,
          error: `indicator '${candidate}' does not match the supplied type '${rawType}'`,
        },
        { status: 400 },
      );
    }
    // Normalize the same way classify() does (hashes + domains lowercased).
    indicator =
      rawType === "domain" || rawType === "md5" || rawType === "sha1" || rawType === "sha256"
        ? lower
        : candidate;
    indicatorType = rawType;
  } else {
    const classified = classify(rawIndicator);
    if (!classified) {
      return NextResponse.json(
        {
          ok: false,
          error:
            "supply a valid hash (MD5/SHA-1/SHA-256), domain, IPv4, or IPv6",
        },
        { status: 400 },
      );
    }
    indicator = classified.value;
    indicatorType = classified.type;
  }

  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(indicator, indicatorType),
      initialMessages: [
        {
          role: "user",
          content: `Threat Graph pivot: ${indicator} (${indicatorType})`,
        },
      ],
      emit,
      maxTokensPerTurn: 8192,
      maxIterations: 10,
      surface: "threat-graph",
    });
  });
}

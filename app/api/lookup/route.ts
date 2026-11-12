import { NextResponse } from "next/server";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type ArtifactKind =
  | "sha256"
  | "sha1"
  | "md5"
  | "ipv4"
  | "ipv6"
  | "domain"
  | "url"
  | "unknown";

type Body = { artifact?: string; kind?: ArtifactKind };

function buildPrompt(artifact: string, kind: ArtifactKind): string {
  const today = new Date().toISOString().slice(0, 10);
  const isHash = kind === "sha256" || kind === "sha1" || kind === "md5";
  const isNetwork =
    kind === "ipv4" || kind === "ipv6" || kind === "domain" || kind === "url";

  return [
    "You are producing an artifact lookup report for a CrowdStrike Falcon tenant administrator. The user pasted a single indicator (hash, IP, domain, or URL) and wants one screen that answers: is this thing known-bad, is it on my custom list already, has it touched my tenant, and what should I do.",
    "",
    `Today is ${today} (UTC).`,
    `Artifact: \`${artifact}\``,
    `Kind: ${kind}`,
    "",
    "DATA GATHERING — fan these out in parallel up front:",
    "- `falcon_search_indicators` — Falcon Adversary Intelligence's curated IOC feed. Filter on the artifact value. This tells you whether CrowdStrike already rates this indicator and what their malicious_confidence + actor associations are.",
    "- `falcon_search_iocs` — this tenant's custom IOC list. Tells you whether the artifact is already on the custom list (and with what action — `detect` / `prevent` / `no_action` / `allow`; note `prevent` is only valid for hash IOCs, domain/IP IOCs cap at `detect`).",
    isHash
      ? "- `falcon_search_detections` — search for this hash in detection details. Use a filter that matches the hash field (try `behaviors.sha256:'<hash>'` for SHA-256, or `sha256:'<hash>'`; for MD5 try `behaviors.md5:'<hash>'`)."
      : "- `falcon_search_detections` — search for this network artifact appearing in detections. Try filters like `behaviors.ioc_value:'<value>'`.",
    "- `falcon_search_ngsiem` — run a single CQL search across the last 30 days for this artifact appearing anywhere in event telemetry (process executions, network connections, DNS, etc.). One broad query is enough; do not iterate.",
    isHash
      ? `- \`falcon_get_threatgraph_ran_on\` — pass value=\`${artifact}\`, indicator_type=\`${kind}\`, limit=50. Returns the devices that EXECUTED this hash according to Falcon's sensor-telemetry execution graph. Distinct from detections — a host can have run a binary without a detection firing, so this widens the exposure picture.`
      : "",
    isNetwork
      ? "- For domains/URLs, also call `falcon_search_actors` if the indicator filter returns an actor association — get the actor profile so you can name them."
      : "",
    "",
    "After the initial fan-out, do not loop. Write the report.",
    "",
    "Sections — produce all of them in this exact order. Use H2 (##) for each:",
    "",
    "## Verdict",
    "One sentence. State whether the artifact is: KNOWN-BAD (Falcon Intel rates it malicious), KNOWN-GOOD (whitelisted or benign with high confidence), UNKNOWN (no Intel record), or AMBIGUOUS (mixed signals). Lead with the call.",
    "",
    "## Falcon Intel context",
    "What Falcon Adversary Intelligence knows. malicious_confidence, last seen by Intel, associated actor(s), associated malware family/families, kill-chain stages. If Intel has nothing, say 'Not present in Falcon Adversary Intelligence's curated feed.'",
    "",
    "## Custom IOC list status",
    "Whether this is already on the tenant's custom IOC list. If yes: action (detect / prevent / allow / no_action), date added, source/description, expiration. If no: 'Not on the custom list.'",
    "",
    "## Tenant exposure",
    isHash
      ? "Have we actually seen this in our environment? Combine three sources: detection hits, NGSIEM event hits, and Threat Graph execution evidence (extras_threatgraph_ran_on). Render a small table: Source | Hits | First seen | Last seen | Hosts affected. Threat Graph is the load-bearing one for execution — a host running a binary without a detection still appears here. If extras_threatgraph_ran_on returned `ok: false` or scope_pending, note that and continue with the other two. If all three miss: 'No tenant exposure observed in detections, NGSIEM telemetry, or Threat Graph execution data.'"
      : "Have we actually seen this in our environment? Combine detection hits and NGSIEM event hits. Render a small table: Source | Hits | First seen | Last seen | Hosts affected. If both miss: 'No tenant exposure observed in detections or the last 30 days of NGSIEM telemetry.'",
    "",
    "## Recommended action",
    "One of these patterns, picked by the evidence:",
    "- KNOWN-BAD + already on custom list → 'No action needed. Already covered by [Intel high-confidence + cloud reputation | custom IOC with <its current> action].' Be explicit about which.",
    "- KNOWN-BAD + NOT on custom list + Intel high-confidence → 'No custom IOC needed — Falcon cloud reputation already blocks this tenant-wide.' (Redundancy principle.)",
    isHash
      ? "- KNOWN-BAD + NOT on custom list + Intel medium/low confidence + tenant exposure → 'Propose a custom IOC with `prevent` action.' Suggest the exact `falcon_add_ioc` arguments. Do NOT call the tool — just propose."
      : "- KNOWN-BAD + NOT on custom list + Intel medium/low confidence + tenant exposure → 'Propose a custom IOC with `detect` action.' Suggest the exact `falcon_add_ioc` arguments. Do NOT call the tool — just propose. (Falcon's IOC API only accepts `prevent` for hash types — domain/IPv4/IPv6 IOCs are detect-only; blocking at the network layer is a DNS/NGFW concern, not the endpoint sensor.)",
    "- UNKNOWN + tenant exposure → 'Investigate the affected hosts before deciding. Open detections / pivot to /investigate.' Provide host list.",
    "- UNKNOWN + no tenant exposure → 'No action. Nothing to triage.'",
    "- KNOWN-GOOD → 'No action. Likely false positive if it appears in a detection — verify before adding to allowlist.'",
    "",
    "Style:",
    "- Markdown only. H2 headings.",
    "- Be terse and decisive.",
    "- Tables for tenant exposure if there are multiple sources/hosts.",
    "- If a section has no data, still include the heading with a one-line note.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Output NOTHING between tool calls. Zero text.",
    "- Make all tool calls (in parallel where possible), then write the report ONCE.",
    "- The very first text token you emit must be the verdict H2.",
    "",
    "Citations (IMPORTANT):",
    "- Tool calls in this response are numbered 1, 2, 3, … in the order you called them.",
    "- When you state a fact derived from a tool call, end the sentence with [N] referencing the tool call number.",
    "- Do not invent citations.",
  ]
    .filter(Boolean)
    .join("\n");
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const artifact = (body.artifact ?? "").trim();
  const kind: ArtifactKind = body.kind ?? "unknown";
  if (!artifact) {
    return NextResponse.json(
      { ok: false, error: "artifact required" },
      { status: 400 },
    );
  }

  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(artifact, kind),
      initialMessages: [
        { role: "user", content: `Look up artifact: ${artifact} (kind: ${kind})` },
      ],
      emit,
      maxTokensPerTurn: 8192,
      maxIterations: 12,
      surface: "lookup",
    });
  });
}

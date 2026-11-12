import { NextResponse } from "next/server";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Body = { hashes?: string[] };

const HASH_RX = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;

function buildPrompt(hashes: string[]): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    "You are producing a MALQUERY HASH-LINEAGE report for a CrowdStrike Falcon tenant administrator. The user pasted one or more file hashes and wants one screen that answers: does CrowdStrike's malware research corpus know this binary, what's its prevalence, what family / actor association, and is it visible in our tenant.",
    "",
    `Today is ${today} (UTC).`,
    `Subject hashes (${hashes.length}): ${hashes.map((h) => `\`${h}\``).join(", ")}`,
    "",
    "DATA GATHERING — fan these out in parallel up front:",
    `- \`falcon_get_malquery_file_metadata\` — pass hashes=${JSON.stringify(hashes)}. Returns one record per hash MalQuery knows: sha256/sha1/md5, filesize, filetype, first_seen, and label (malware / clean / unknown). Hashes it doesn't know are simply absent.`,
    `- \`falcon_search_indicators\` — Falcon Adversary Intelligence's curated IOC feed. Filter on each hash. Reveals whether CS Intel rates the indicator (malicious_confidence) and what actor/family it's tied to.`,
    `- \`falcon_search_detections\` — search for any of these hashes in tenant detections. Try filters like \`behaviors.sha256:'<h>'\` or \`behaviors.md5:'<h>'\`.`,
    "",
    "After the initial fan-out, do not loop. Write the report.",
    "",
    "Sections — produce all of them in this exact order. Use H2 (##) for each.",
    "",
    "## Verdict",
    "One sentence per hash. KNOWN-MALWARE (MalQuery has it AND its label is malware, or CS Intel rates it malicious) / KNOWN-CLEAN (no malware corpus hit and no Intel) / UNKNOWN. Lead with the call.",
    "If falcon_get_malquery_file_metadata returned a 401/403 permission error, lead with 'Required Falcon API scope (`MalQuery : read`) is not yet granted on this tenant.' and stop.",
    "",
    "## Corpus prevalence",
    "Render a table: Hash | MalQuery label | File type | Size | First seen | Tenant detections. Pull from MalQuery metadata + falcon_search_detections counts; family / actor attribution comes from Falcon Intel (next section), not MalQuery. If MalQuery has no record, say 'Not present in MalQuery's malware corpus.' for that hash.",
    "",
    "## Falcon Intel context",
    "What CS Intel knows: malicious_confidence + actor / family attribution per hash. If Intel has nothing, 'Not present in Falcon Adversary Intelligence's curated feed.'",
    "",
    "## Tenant exposure",
    "Combine detection hits and any MalQuery prevalence indicators. Render: Hash | Detections | Hosts affected | Last seen in tenant. If both miss: 'No tenant exposure for any subject hash.'",
    "",
    "## Recommended actions",
    "Pick by evidence (one or two — be decisive):",
    "- KNOWN-MALWARE + tenant exposure → 'Investigate the affected hosts, review detections, consider custom-IOC prevent if Intel confidence is medium/low.'",
    "- KNOWN-MALWARE + no tenant exposure → 'No action; cloud reputation already covers this. Optional: hunt similar samples with falcon_start_malquery_exact_search (a distinctive string or byte pattern from a known sample), then poll falcon_get_malquery_request with the returned request id.'",
    "- UNKNOWN + tenant exposure → 'Triage the detections; pivot to /investigate for the affected hosts.'",
    "- UNKNOWN + no exposure → 'No action.'",
    "",
    "Style:",
    "- Markdown only. H2 headings. Tables for structured sections.",
    "- Be terse and decisive.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Output NOTHING between tool calls. Zero text.",
    "- Make all tool calls in parallel, then write the report ONCE.",
    "- The very first text token you emit must be the Verdict H2.",
    "",
    "Citations:",
    "- Tool calls are numbered 1, 2, 3, … in call order.",
    "- End facts with [N] referencing the call number.",
  ].join("\n");
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const raw = Array.isArray(body.hashes) ? body.hashes : [];
  const cleaned: string[] = [];
  for (const h of raw) {
    if (typeof h === "string" && HASH_RX.test(h.trim())) {
      cleaned.push(h.trim().toLowerCase());
    }
  }
  if (cleaned.length === 0) {
    return NextResponse.json(
      { ok: false, error: "supply at least one valid MD5 / SHA-1 / SHA-256 hash" },
      { status: 400 },
    );
  }
  if (cleaned.length > 25) {
    return NextResponse.json(
      { ok: false, error: "max 25 hashes per request" },
      { status: 400 },
    );
  }

  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(cleaned),
      initialMessages: [
        { role: "user", content: `MalQuery hash lineage: ${cleaned.join(", ")}` },
      ],
      emit,
      maxTokensPerTurn: 8192,
      maxIterations: 12,
      surface: "malquery",
    });
  });
}

import { NextResponse } from "next/server";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";
import { findPlaybook, startTimestampHoursAgo } from "@/lib/ngsiem-playbooks";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function buildPrompt(opts: {
  title: string;
  description: string;
  cql: string;
  repository: string;
  start: string;
  mitre: string[];
}): string {
  return [
    "You just ran a curated CQL playbook on behalf of a security operator. The CQL was hand-authored — DO NOT rewrite it. Your job is to execute the curated query exactly as given and present the results.",
    "",
    `Playbook: **${opts.title}**`,
    `Purpose: ${opts.description}`,
    opts.mitre.length > 0 ? `MITRE ATT&CK: ${opts.mitre.join(", ")}` : "",
    `Repository: ${opts.repository}`,
    `Time window start: ${opts.start}`,
    "",
    "Run this CQL exactly via the falcon_search_ngsiem tool — do not modify it:",
    "```cql",
    opts.cql,
    "```",
    "",
    "After you have the result, produce EXACTLY these blocks in order, with no preamble:",
    "1. **Playbook ran** — one short sentence: name + repository + window.",
    "2. **CQL** — a fenced ```cql block with the EXACT query you ran.",
    "3. **Results** — markdown table of the rows (max 25; if more, note truncation).",
    "4. **Observation** — one or two sentences about the data. If empty, say so plainly and suggest an enrichment (widen window, drop a filter, check ingest).",
    "",
    "If the tool errors with a CQL parse error, surface the error verbatim and stop. Do not try to 'fix' the curated query.",
    "If the tool returns 'No content was received' / empty result, that means the search ran but matched no events — say so plainly. Do not retry.",
    "",
    "OUTPUT DISCIPLINE — REQUIRED:",
    "- Output NOTHING between tool calls. Zero text. No 'Let me run this…', no 'I have the results now…'. None.",
    "- Make the tool call, then write the four-block output ONCE.",
    "- The very first text token you emit must be the **Playbook ran** label. Anything else is a failure.",
  ]
    .filter(Boolean)
    .join("\n");
}

type Body = { playbook_id?: string };

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const id = (body.playbook_id ?? "").trim();
  if (!id) {
    return NextResponse.json(
      { ok: false, error: "playbook_id required" },
      { status: 400 },
    );
  }
  const pb = findPlaybook(id);
  if (!pb) {
    return NextResponse.json(
      { ok: false, error: `Unknown playbook: ${id}` },
      { status: 404 },
    );
  }

  const start = startTimestampHoursAgo(pb.windowHours);

  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt({
        title: pb.title,
        description: pb.description,
        cql: pb.cql,
        repository: pb.repository,
        start,
        mitre: pb.mitre,
      }),
      initialMessages: [
        {
          role: "user",
          content: `Run the curated playbook: ${pb.title}. Use start=${start}, repository=${pb.repository}.`,
        },
      ],
      emit,
      maxTokensPerTurn: 4096,
      maxIterations: 6,
      surface: "ngsiem-playbook",
    });
  });
}

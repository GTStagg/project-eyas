import { NextResponse } from "next/server";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";
import { getActiveEnvironmentId } from "@/lib/config/environments";
import { readRecord } from "@/lib/chat/ir-run-record";
import { renderIrReportContext } from "@/lib/ir-report/context";
import { buildIrReportPrompt } from "@/lib/ir-report/prompt";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Generates a leadership-readable incident report from ONE frozen IR engagement
// record. Synthesis-only: the deterministic substrate is renderIrReportContext()
// (built from the same replay extractors the /ir-runs/[file] page uses), and the
// model runs with toolFilter:()=>false so it makes NO upstream Falcon calls and
// NO writes — it just turns the supplied record into prose. Session-authed by the
// root middleware. A report is a per-tenant artifact, so an engagement that ran
// under a different environment is refused (consistent with the scorecard's
// env-scoping); the /ir-runs/[file] detail page itself stays cross-tenant-viewable.
export async function POST(req: Request) {
  let file: unknown;
  try {
    ({ file } = await req.json());
  } catch {
    return NextResponse.json({ ok: false, error: "Invalid request body." }, { status: 400 });
  }

  if (typeof file !== "string" || !file) {
    return NextResponse.json({ ok: false, error: "Missing engagement key." }, { status: 400 });
  }
  // Strict basename — same guard as the detail page.
  if (file.includes("/") || file.includes("\\") || file.includes("..")) {
    return NextResponse.json({ ok: false, error: "Invalid engagement key." }, { status: 400 });
  }

  const record = await readRecord(file);
  if (!record) {
    return NextResponse.json({ ok: false, error: "Engagement not found." }, { status: 404 });
  }

  // Tenant gate: a report is a per-tenant artifact. Refuse an engagement that
  // ran under a different environment than the active one.
  if (record.envId != null && record.envId !== getActiveEnvironmentId()) {
    return NextResponse.json(
      { ok: false, error: "This engagement ran under a different tenant." },
      { status: 404 },
    );
  }

  return streamAgent(async ({ mcp, emit, signal }) => {
    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildIrReportPrompt(),
      initialMessages: [{ role: "user", content: renderIrReportContext(record) }],
      emit,
      // Synthesis-only: zero visible tools → the model writes the report in one
      // pass with no upstream calls and no writes.
      toolFilter: () => false,
      maxTokensPerTurn: 8192,
      maxIterations: 4,
      surface: "incident-report",
    });
  });
}

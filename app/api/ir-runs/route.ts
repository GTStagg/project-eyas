import { NextResponse } from "next/server";
import { listRecords, readRecord, recordBasenameFor } from "@/lib/chat/ir-run-record";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Read-only listing of IR run records. Backed by the ir_runs +
// ir_run_turns tables in data/eyas.db. The on-the-wire shape —
// file: <aid>-<startedAt>.json — doubles as the URL slug for the
// /ir-runs detail page.
//
// GET /api/ir-runs              → list summaries
// GET /api/ir-runs?file=<name>  → full record content (basename-only, no
//                                 traversal)

type RunSummary = {
  file: string;
  aid: string;
  sessionId: string;
  startedAt: number;
  lastTouched: number;
  turnsCount: number;
  totalIterations: number;
  hasErrors: boolean;
  campaignsCount: number | null;
};

export async function GET(request: Request) {
  const url = new URL(request.url);
  const fileParam = url.searchParams.get("file");

  if (fileParam) {
    if (fileParam.includes("/") || fileParam.includes("\\") || fileParam.includes("..")) {
      return NextResponse.json({ ok: false, error: "invalid file" }, { status: 400 });
    }
    const record = await readRecord(fileParam);
    if (!record) {
      return NextResponse.json({ ok: false, error: "not found" }, { status: 404 });
    }
    return NextResponse.json({ ok: true, record });
  }

  const records = await listRecords();
  const summaries: RunSummary[] = records.map((record) => {
    const turnsCount = record.turns.length;
    const totalIterations = record.turns.reduce(
      (acc, t) => acc + (t.iterations ?? 0),
      0,
    );
    const hasErrors = record.turns.some(
      (t) =>
        t.status === "errored" ||
        t.toolCalls.some((c) => c.result?.isError === true),
    );
    let campaignsCount: number | null = null;
    const scope = record.campaignScope as { campaigns?: unknown[] } | null;
    if (scope && Array.isArray(scope.campaigns)) {
      campaignsCount = scope.campaigns.length;
    }
    return {
      file: recordBasenameFor(record.aid, record.startedAt),
      aid: record.aid,
      sessionId: record.sessionId,
      startedAt: record.startedAt,
      lastTouched: record.lastTouched,
      turnsCount,
      totalIterations,
      hasErrors,
      campaignsCount,
    };
  });

  return NextResponse.json({ ok: true, runs: summaries });
}

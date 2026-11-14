import { createHash, timingSafeEqual } from "node:crypto";
import { NextResponse } from "next/server";
import {
  fireJobNow,
  getSchedulerStatus,
  listKnownJobIds,
  startScheduler,
} from "@/lib/scheduler/runtime";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

function authorized(req: Request): boolean {
  const expected = process.env.SCHEDULER_TOKEN?.trim();
  if (!expected) return false;
  const header = req.headers.get("x-scheduler-token") ?? "";
  const auth = req.headers.get("authorization") ?? "";
  const bearer = auth.toLowerCase().startsWith("bearer ") ? auth.slice(7).trim() : "";
  return sameSecret(header, expected) || sameSecret(bearer, expected);
}

// Constant-time compare. Hashing first gives both sides the same length, which
// timingSafeEqual requires, without revealing the token length.
function sameSecret(given: string, expected: string): boolean {
  const a = createHash("sha256").update(given).digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

function jobStatus(kind: string) {
  const status = getSchedulerStatus();
  return status.jobs.find((j) => j.id === kind) ?? null;
}

export async function GET(req: Request, ctx: { params: Promise<{ kind: string }> }) {
  if (!authorized(req)) {
    return NextResponse.json({ ok: false, error: "Unauthorized." }, { status: 401 });
  }
  const { kind } = await ctx.params;
  if (!listKnownJobIds().includes(kind)) {
    return NextResponse.json(
      { ok: false, error: `Unknown job "${kind}"`, known: listKnownJobIds() },
      { status: 404 },
    );
  }
  startScheduler();
  return NextResponse.json({
    ok: true,
    job: jobStatus(kind),
    scheduler: getSchedulerStatus(),
  });
}

export async function POST(req: Request, ctx: { params: Promise<{ kind: string }> }) {
  if (!authorized(req)) {
    return NextResponse.json({ ok: false, error: "Unauthorized." }, { status: 401 });
  }
  const { kind } = await ctx.params;
  if (!listKnownJobIds().includes(kind)) {
    return NextResponse.json(
      { ok: false, error: `Unknown job "${kind}"`, known: listKnownJobIds() },
      { status: 404 },
    );
  }
  const fired = await fireJobNow(kind);
  if (!fired.ok) {
    return NextResponse.json({ ok: false, error: fired.error }, { status: 502 });
  }
  const httpStatus = fired.result.kind === "error" ? 502 : 200;
  return NextResponse.json(
    {
      ok: fired.result.kind !== "error",
      result: fired.result,
      job: jobStatus(kind),
    },
    { status: httpStatus },
  );
}

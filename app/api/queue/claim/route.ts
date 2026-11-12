import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { detectFalconError, isScopeDenied, parseToolResultObjects } from "@/lib/mcp/parse";
import { fail, serverError } from "@/lib/api/respond";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// POST /api/queue/claim — server-side `in_progress` claim fired by the Queue
// UI when the operator clicks Triage / IR. Bypasses the chat approval gate by
// design: marking a detection as being-worked-on is bookkeeping, not a verdict.
// Verdict transitions (true_positive / false_positive / closed) come through
// the agent loop and gate via the write-tools registry.
export async function POST(req: Request) {
  let composite_ids: string[] = [];
  try {
    const body = await req.json();
    if (Array.isArray(body?.composite_ids)) {
      composite_ids = body.composite_ids.filter(
        (x: unknown): x is string => typeof x === "string" && x.length > 0,
      );
    } else if (typeof body?.composite_id === "string") {
      composite_ids = [body.composite_id];
    }
  } catch {
    // empty body / malformed JSON
  }

  if (composite_ids.length === 0) {
    return fail("composite_id or composite_ids required");
  }

  try {
    // Native detection update: returns [] (or {result: [], hint}) on success,
    // an {error, ...} object on failure. callNative-style handling keeps the
    // wrapped-upstream-error case from reading as success.
    const result = await withFalconMcpClient(async (client) => {
      const r = await client.callTool({
        name: "falcon_update_detections",
        arguments: { ids: composite_ids, status: "in_progress" },
      });
      const content = r.content as Array<{ type: string; text?: string }>;
      const err = detectFalconError(parseToolResultObjects<Record<string, unknown>>(content));
      if (err) {
        return isScopeDenied(err)
          ? { ok: false, scope_pending: true, error: err }
          : { ok: false, error: err };
      }
      if (r.isError) {
        const text = content.map((c) => (c.type === "text" && c.text ? c.text : "")).join(" ");
        return { ok: false, error: text.trim() || "detection update failed" };
      }
      return { ok: true, requested: composite_ids.length, status: "in_progress" };
    });
    return NextResponse.json(result);
  } catch (err) {
    return serverError(err);
  }
}

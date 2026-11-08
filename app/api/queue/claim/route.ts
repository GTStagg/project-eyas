import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";
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
    const result = await withFalconExtrasClient(async (client) => {
      const r = await client.callTool({
        name: "extras_update_detection_status",
        arguments: {
          composite_ids,
          status: "in_progress",
        },
      });
      const text = (r.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      try {
        return JSON.parse(text);
      } catch {
        return { ok: false, error: "unparseable sidecar response" };
      }
    });

    // Sidecar already returns an {ok, ...} envelope; pass it through
    // verbatim so per-id reasons survive (vs forcing a re-wrap).
    return NextResponse.json(result);
  } catch (err) {
    return serverError(err);
  }
}

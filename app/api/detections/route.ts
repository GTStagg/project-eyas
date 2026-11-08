import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { detectFalconError, parseConcatenatedJson } from "@/lib/mcp/parse";
import { ok, serverError } from "@/lib/api/respond";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const limit = Math.min(
    Math.max(parseInt(url.searchParams.get("limit") ?? "50", 10) || 50, 1),
    200,
  );

  try {
    const items = await withFalconMcpClient(async (client) => {
      const result = await client.callTool({
        name: "falcon_search_detections",
        arguments: {
          // Endpoint detections only — see app/api/queue/route.ts for the
          // longer rationale. Without this, NGSIEM correlation rules and
          // IDP policy events drown out endpoint signal.
          filter: "product:'epp'",
          limit,
          sort: "created_timestamp.desc",
        },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      const parsed = parseConcatenatedJson<{ created_timestamp?: string }>(text);
      // Promote a wrapped upstream Falcon error (isError:false + {error} body)
      // to a real failure instead of rendering it as a single junk detection.
      const upstreamErr = detectFalconError(parsed);
      if (upstreamErr) throw new Error(upstreamErr);
      // Upstream `sort` arg is unreliable; sort newest-first client-side.
      parsed.sort((a, b) =>
        (b.created_timestamp ?? "").localeCompare(a.created_timestamp ?? ""),
      );
      return parsed;
    });
    return ok({ count: items.length, items });
  } catch (err) {
    return serverError(err);
  }
}

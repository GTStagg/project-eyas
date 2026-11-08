import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { detectFalconError, parseConcatenatedJson } from "@/lib/mcp/parse";
import type { Host } from "@/components/HostsTable";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ALLOWED = /^[A-Za-z0-9._\-]{1,64}$/;

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const q = (searchParams.get("q") ?? "").trim();
  if (!q) {
    return NextResponse.json({ ok: true, items: [] });
  }
  if (!ALLOWED.test(q)) {
    return NextResponse.json(
      {
        ok: false,
        error:
          "query contains characters outside [A-Za-z0-9._-] or exceeds 64 chars",
      },
      { status: 400 },
    );
  }

  try {
    const items = await withFalconMcpClient(async (client) => {
      const result = await client.callTool({
        name: "falcon_search_hosts",
        arguments: {
          filter: `hostname:*'*${q}*'`,
          limit: 50,
          sort: "last_seen.desc",
        },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      const parsed = parseConcatenatedJson<Host>(text);
      const upstreamErr = detectFalconError(parsed);
      if (upstreamErr) throw new Error(upstreamErr);
      return parsed;
    });
    return NextResponse.json({ ok: true, items });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

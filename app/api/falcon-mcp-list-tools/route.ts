import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const result = await withFalconMcpClient(async (client) => {
      const tools = await client.listTools();
      const resources = await client.listResources().catch(() => ({ resources: [] }));
      return { tools, resources };
    });

    return NextResponse.json({
      ok: true,
      tool_count: result.tools.tools.length,
      resource_count: result.resources.resources.length,
      tools: result.tools.tools.map((t) => ({
        name: t.name,
        description: t.description,
        input_schema_keys: t.inputSchema?.properties
          ? Object.keys(t.inputSchema.properties as Record<string, unknown>)
          : [],
      })),
      resources: result.resources.resources.map((r) => ({
        uri: r.uri,
        name: r.name,
        description: r.description,
      })),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return NextResponse.json({ ok: false, error: message }, { status: 500 });
  }
}

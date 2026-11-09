import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { shapeNativePayload } from "@/lib/mcp/native-shape";

// Call a native MCP-server search tool and shape the result like the former
// falcon-extras sidecar payloads that deterministic consumers already read:
//   { ok: true, items, count, total? } | { ok: true, scope_pending: true } | { ok: false, error }
// Used while sidecar twins are retired in favor of eyas-mcp natives, so the
// normalizers downstream (Discover inventory, Identity posture, the posture
// snapshot) keep a single input contract. `total` is the search envelope's
// pagination.total when present. Shaping rules: lib/mcp/native-shape.ts.
export async function nativeSidecarPayload(
  mcp: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const result = await mcp.callTool({ name, arguments: args });
  const content = ((result as { content?: unknown })?.content ?? []) as Array<{
    type: string;
    text?: string;
  }>;
  const text = content.map((c) => (c.type === "text" && c.text ? c.text : "")).join("\n");
  return shapeNativePayload(text);
}

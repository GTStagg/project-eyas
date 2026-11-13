import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { shapeNativePayload } from "@/lib/mcp/native-shape";

// Call a native eyas-mcp search tool and shape the result into the payload
// that deterministic consumers read:
//   { ok: true, items, count, total? } | { ok: true, scope_pending: true } | { ok: false, error }
// The shape predates eyas-mcp (the retired sidecar returned it), so the
// normalizers downstream (Discover inventory, Identity posture, the posture
// snapshot) keep a single input contract. `total` is the search envelope's
// pagination.total when present. Shaping rules: lib/mcp/native-shape.ts.
export async function nativeSearchPayload(
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

import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { parseConcatenatedJson, detectFalconError, isScopeDenied } from "@/lib/mcp/parse";

// Call a native MCP-server search tool and shape the result like the former
// falcon-extras sidecar payloads that deterministic consumers already read:
//   { ok: true, items, count, total? } | { ok: true, scope_pending: true } | { ok: false, error }
// Used while sidecar twins are retired in favor of eyas-mcp natives, so the
// normalizers downstream (Discover inventory, Identity posture, the posture
// snapshot) keep a single input contract. `total` is the search envelope's
// pagination.total when present.
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
  if (isScopeDenied(text)) return { ok: true, scope_pending: true };
  const items = parseConcatenatedJson<Record<string, unknown>>(text);
  const err = detectFalconError(items);
  if (err) return { ok: false, error: err };
  let total: number | undefined;
  try {
    const t = (JSON.parse(text) as { pagination?: { total?: unknown } })?.pagination?.total;
    if (typeof t === "number") total = t;
  } catch {
    // not a single envelope — consumers fall back to items.length
  }
  return { ok: true, items, count: items.length, total };
}

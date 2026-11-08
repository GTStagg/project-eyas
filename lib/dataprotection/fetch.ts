import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { parseConcatenatedJson, detectFalconError, isScopeDenied } from "@/lib/mcp/parse";

// Paged reads over falcon_search_data_security_entities, shared by
// /data-protection and the posture snapshot.
//
// Why paging: the tool queries IDs then hydrates them with one GetByIds call,
// and Falcon caps that hydrate at 200 IDs ("maximum number of IDs exceeded -
// 200", HTTP 400) even though the tool accepts limit up to 500. A tenant with
// more than 200 content patterns / classifications / per-platform policies
// failed the whole surface at limit 500 (seen live on XDR us-2: 208 content
// patterns). Pages of 200 keep each hydrate legal.
//
// Loop on our own offset and stop on a short page or on reaching
// pagination.total. Don't trust pagination.offset: upstream reports
// offset+limit for some entity types.
const DS_PAGE_SIZE = 200;
const DS_MAX_PAGES = 10; // 2,000 records — well past any real DLP config

export type DsFetch =
  | { kind: "scope_pending" }
  | { kind: "error"; error: string }
  | { kind: "ok"; rows: Record<string, unknown>[] };

function toText(result: unknown): string {
  const content = ((result as { content?: unknown })?.content ?? []) as Array<{
    type: string;
    text?: string;
  }>;
  return content.map((c) => (c.type === "text" && c.text ? c.text : "")).join("\n");
}

function envelopeTotal(text: string): number | null {
  try {
    const total = (JSON.parse(text) as { pagination?: { total?: unknown } })?.pagination?.total;
    return typeof total === "number" ? total : null;
  } catch {
    return null;
  }
}

export async function fetchDataSecurityEntities(
  client: Client,
  entityType: string,
  extra: Record<string, unknown> = {},
): Promise<DsFetch> {
  const rows: Record<string, unknown>[] = [];
  for (let page = 0; page < DS_MAX_PAGES; page++) {
    const res = await client.callTool({
      name: "falcon_search_data_security_entities",
      arguments: { entity_type: entityType, ...extra, limit: DS_PAGE_SIZE, offset: rows.length },
    });
    const text = toText(res);
    if (page === 0 && isScopeDenied(text)) return { kind: "scope_pending" };
    const parsed = parseConcatenatedJson<Record<string, unknown>>(text);
    const err = detectFalconError(parsed);
    if (err) return { kind: "error", error: err };
    rows.push(...parsed);
    const total = envelopeTotal(text);
    if (parsed.length < DS_PAGE_SIZE || (total !== null && rows.length >= total)) break;
  }
  return { kind: "ok", rows };
}

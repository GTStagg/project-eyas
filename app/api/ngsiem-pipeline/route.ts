import { NextResponse } from "next/server";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { parseConcatenatedJson, detectFalconError, isScopeDenied } from "@/lib/mcp/parse";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// NGSIEM pipeline-health strip (components/NgsiemPipelineHealth.tsx): data
// connections (with a status rollup), parsers, and lookup files. Backed by the
// MCP server's native NGSIEM listing tools. Counts come from the search
// envelope's `pagination.total`, so they're exact — the former sidecar tools
// stopped at their page size (a tenant with 330 connections showed 200).
//
// Payload contract per cell (unchanged for the card): { ok, count,
// status_counts?, scope_pending?, error? } — or null if the call threw.

type Cell = {
  ok: boolean;
  count?: number;
  status_counts?: Record<string, number>;
  scope_pending?: boolean;
  error?: string;
};

const CONNECTION_PAGE = 200;
const CONNECTION_MAX_PAGES = 5;

function toText(result: unknown): string {
  const content = ((result as { content?: unknown })?.content ?? []) as Array<{
    type: string;
    text?: string;
  }>;
  return content.map((c) => (c.type === "text" && c.text ? c.text : "")).join("\n");
}

type Page = { kind: "denied" } | { kind: "error"; error: string } | { kind: "ok"; rows: Record<string, unknown>[]; total: number | null };

async function page(client: Client, name: string, args: Record<string, unknown>): Promise<Page> {
  const text = toText(await client.callTool({ name, arguments: args }));
  if (isScopeDenied(text)) return { kind: "denied" };
  const rows = parseConcatenatedJson<Record<string, unknown>>(text);
  const err = detectFalconError(rows);
  if (err) return { kind: "error", error: err };
  let total: number | null = null;
  try {
    const t = (JSON.parse(text) as { pagination?: { total?: unknown } })?.pagination?.total;
    if (typeof t === "number") total = t;
  } catch {
    // not a single envelope — fall back to the row count
  }
  return { kind: "ok", rows, total };
}

function fromPage(p: Page): Cell {
  if (p.kind === "denied") return { ok: true, scope_pending: true };
  if (p.kind === "error") return { ok: false, error: p.error };
  return { ok: true, count: p.total ?? p.rows.length };
}

async function connections(client: Client): Promise<Cell> {
  const rows: Record<string, unknown>[] = [];
  let total: number | null = null;
  for (let i = 0; i < CONNECTION_MAX_PAGES; i++) {
    const p = await page(client, "falcon_list_ngsiem_data_connections", {
      limit: CONNECTION_PAGE,
      offset: rows.length,
    });
    if (p.kind !== "ok") return fromPage(p);
    rows.push(...p.rows);
    total = p.total ?? total;
    if (p.rows.length < CONNECTION_PAGE || (total !== null && rows.length >= total)) break;
  }
  const status_counts: Record<string, number> = {};
  for (const r of rows) {
    const s = typeof r.status === "string" && r.status ? r.status.toLowerCase() : "unknown";
    status_counts[s] = (status_counts[s] ?? 0) + 1;
  }
  return { ok: true, count: total ?? rows.length, status_counts };
}

export async function GET() {
  return withFalconMcpClient(async (client) => {
    const [conns, lookupFiles, parsers] = await Promise.all([
      connections(client).catch(() => null),
      // limit 1: only the envelope's total is needed for the count.
      page(client, "falcon_list_ngsiem_lookup_files", { search_domain: "all", limit: 1 })
        .then(fromPage)
        .catch(() => null),
      page(client, "falcon_list_ngsiem_parsers", { limit: 1 })
        .then(fromPage)
        .catch(() => null),
    ]);
    return NextResponse.json({ ok: true, connections: conns, lookupFiles, parsers });
  });
}

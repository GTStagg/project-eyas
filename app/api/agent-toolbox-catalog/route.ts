import { NextResponse, type NextRequest } from "next/server";
import { getToolCatalog } from "@/lib/mcp/catalog";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Diagnostics sibling to /api/eyas-mcp-list-tools, but the curated view: the
// exact agent-visible tool set (suppression applied), both providers, each
// annotated read-only vs. approval-gated. Session-authed by root middleware.ts.
// Backs the /agent-toolbox page's verification probe + optional client refresh.
export async function GET(req: NextRequest) {
  const force = req.nextUrl.searchParams.get("force") === "1";
  const catalog = await getToolCatalog({ force });
  return NextResponse.json(catalog, { status: catalog.ok ? 200 : 503 });
}

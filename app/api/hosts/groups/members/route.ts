import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { nativeSidecarPayload } from "@/lib/mcp/native-payload";
import type { Host } from "@/components/HostsTable";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Cap on members fetched per group. A group larger than this is truncated —
// the response carries `truncated` (and `total`) so the caller can say so
// rather than silently showing a partial roster.
const MEMBER_LIMIT = 100;

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const groupId = (searchParams.get("group_id") ?? "").trim();
  if (!groupId) {
    return NextResponse.json(
      { ok: false, error: "group_id required" },
      { status: 400 },
    );
  }

  try {
    // The native member search returns full host records (rtr_state,
    // os_product_name, external_ip, status), so the action buttons render
    // without a second host lookup.
    const payload = await withFalconMcpClient((client) =>
      nativeSidecarPayload(client, "falcon_search_host_group_members", {
        id: groupId,
        limit: MEMBER_LIMIT,
        sort: "hostname.asc",
      }),
    );
    // A missing scope comes back as { ok: true, scope_pending: true } with no
    // items, so it renders as an empty group.
    if (payload.ok !== true) {
      return NextResponse.json(
        { ok: false, error: String(payload.error ?? "member search failed") },
        { status: 502 },
      );
    }
    const items = (Array.isArray(payload.items) ? payload.items : []) as Host[];
    items.sort((a, b) => (a.hostname ?? "").localeCompare(b.hostname ?? ""));
    const total = typeof payload.total === "number" ? payload.total : items.length;

    return NextResponse.json({
      ok: true,
      items,
      total,
      truncated: total > items.length,
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

import { NextResponse } from "next/server";
import { readAuditLog } from "@/lib/config/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/config/audit?limit=200 — append-only audit log of every write
// to settings (settings_audit table, trigger-enforced no-update/no-delete).
// Records the SHAPE of the change (which env id, which field names) —
// never the values themselves, so this endpoint is safe to expose without
// elevation. Lines after `limit` are dropped from the tail; default 200
// covers ~all dev sessions.
export async function GET(request: Request) {
  const url = new URL(request.url);
  const limitRaw = url.searchParams.get("limit");
  let limit = 200;
  if (limitRaw) {
    const n = Number.parseInt(limitRaw, 10);
    if (Number.isFinite(n) && n > 0 && n <= 5000) limit = n;
  }
  try {
    const entries = await readAuditLog(limit);
    return NextResponse.json({ ok: true, entries, count: entries.length });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 500 },
    );
  }
}

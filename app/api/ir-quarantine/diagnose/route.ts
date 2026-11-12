import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { makeEyasToolContext } from "@/lib/mcp/tool-bridge";
import { diagnoseQuarantineSetup } from "@/lib/eyas-tools/quarantine";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Read-only state check for the IR quarantine setup. Backs the
// "IR quarantine setup" card on /config and the unprovisioned-tenant
// banner on /hosts. Returns one of: no_group_id, group_missing,
// A_no_policy, B_dedicated_single_group, C_shared_policy, ready —
// plus a recommended_action shape the UI can render directly.
//
// host_group_id is read from the active environment's saved settings; the
// diagnostic also accepts an
// override for cases where /config wants to probe a candidate id before
// saving it.
export async function GET(request: Request) {
  const url = new URL(request.url);
  const override = url.searchParams.get("host_group_id");
  try {
    const payload = await withFalconMcpClient((client) =>
      diagnoseQuarantineSetup(makeEyasToolContext(client), override),
    );
    return NextResponse.json(payload);
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

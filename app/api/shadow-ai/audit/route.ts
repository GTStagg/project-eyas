import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { makeEyasToolContext } from "@/lib/mcp/tool-bridge";
import { checkPreventionBinding } from "@/lib/eyas-tools/shadow-ai/prevention";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Diagnoses whether the Shadow-AI Custom IOA rule group is actually
// enforcing on hosts that Ban+Clean moves into the AI-Banned host group.
// Read-only; no operator approval needed. Backs the "Audit prevention"
// chip on the Shadow-AI panel. Runs extras_shadow_ai_check_prevention_binding
// in-process (lib/eyas-tools/shadow-ai).
export async function GET() {
  try {
    const payload = await withFalconMcpClient((client) => checkPreventionBinding(makeEyasToolContext(client)));
    return NextResponse.json(payload);
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

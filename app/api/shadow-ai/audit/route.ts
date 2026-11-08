import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Diagnoses whether the Shadow-AI Custom IOA rule group is actually
// enforcing on hosts that Ban+Clean moves into the AI-Banned host group.
// Read-only; no operator approval needed. Backs the "Audit prevention"
// chip on the Shadow-AI panel.
export async function GET() {
  try {
    const payload = await withFalconExtrasClient(async (client) => {
      const result = await client.callTool({
        name: "extras_shadow_ai_check_prevention_binding",
        arguments: {},
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      try {
        return JSON.parse(text);
      } catch {
        return { ok: false, error: "sidecar returned non-JSON" };
      }
    });
    if (payload === null) {
      return NextResponse.json(
        { ok: false, error: "falcon-extras sidecar is disabled" },
        { status: 503 },
      );
    }
    return NextResponse.json(payload);
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

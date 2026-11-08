import { NextResponse } from "next/server";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";
import { parseExtrasObjectResult } from "@/lib/mcp/parse";
import { updateActiveEnvironment } from "@/lib/config/environments";
import { invalidateHealthCache } from "@/lib/health";
import { isBusy } from "@/lib/chat/in-flight";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const CANONICAL_NAME = "Project Eyas - Shadow-AI Banned";

// POST /api/shadow-ai-banned/adopt
//   { name?: string }   — find an existing host group by exact name and save
//                         its id as the active env's Shadow-AI banned group.
// Backs the "Adopt existing group by name" control on the Shadow-AI banned
// setup card. The sidecar lookup is read-only against Falcon; the only write
// is the settings persistence the operator requested by clicking — same
// posture as the "Save group id" button. Refuses with 409 mid-agent-run.

type AdoptResult = {
  ok?: boolean;
  id?: string;
  name?: string;
  group_type?: string;
  error?: string;
  candidates?: Array<{ id?: string; group_type?: string }>;
};

export async function POST(request: Request) {
  if (isBusy()) {
    return NextResponse.json(
      { ok: false, error: "agent loop is mid-run; finish or cancel before changing tenant config" },
      { status: 409 },
    );
  }

  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    raw = {};
  }
  const requested = (raw as Record<string, unknown> | null)?.name;
  const name = typeof requested === "string" && requested.trim() ? requested.trim() : CANONICAL_NAME;

  let payload: AdoptResult | null;
  try {
    payload = await withFalconExtrasClient(async (client) => {
      const result = await client.callTool({
        name: "extras_adopt_shadow_ai_banned_host_group",
        arguments: { name },
      });
      return parseExtrasObjectResult(result) as AdoptResult;
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }

  if (payload === null) {
    return NextResponse.json(
      { ok: false, error: "falcon-extras sidecar is disabled" },
      { status: 503 },
    );
  }

  // Zero / multiple matches (or any sidecar-side failure) is an expected
  // semantic result, not a transport error — return it at 200 and do NOT
  // persist anything.
  if (payload.ok !== true || typeof payload.id !== "string" || !payload.id) {
    return NextResponse.json({
      ok: false,
      error: payload.error || "could not adopt a host group by that name",
      candidates: payload.candidates,
    });
  }

  await updateActiveEnvironment({ shadowAiBannedGroupId: payload.id });
  invalidateHealthCache();
  return NextResponse.json({ ok: true, id: payload.id, name: payload.name });
}

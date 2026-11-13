import { NextResponse } from "next/server";
import { DEFAULT_FALCON_BASE_URL, getEnvironmentById } from "@/lib/config/environments";
import { probeFalconCredentialsDeep } from "@/lib/falcon/oauth-probe";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// POST /api/environments/:id/probe — verify the stored credentials by
// running the deep probe (OAuth + tenant CID + Hosts:read smoke). The
// stored secret never leaves the server. Returns the probe result for
// the operator to compare against the tenant they expect.
//
// This is what distinguishes environments at-a-glance: each record's
// clientId returns its own tenant's CID, so a clientId pasted into the
// wrong environment record shows up immediately.
export async function POST(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const env = getEnvironmentById(id);
  if (!env) {
    return NextResponse.json({ ok: false, error: "environment not found" }, { status: 404 });
  }
  const { clientId, baseUrl, clientSecret } = env.falcon;
  if (!clientId || !clientSecret) {
    return NextResponse.json(
      {
        ok: false,
        error: "this environment is missing its credentials. Edit it in /config to add them.",
      },
      { status: 400 },
    );
  }
  const result = await probeFalconCredentialsDeep(
    clientId,
    clientSecret,
    baseUrl ?? DEFAULT_FALCON_BASE_URL,
  );
  return NextResponse.json({
    ...result,
    env_id: id,
    env_name: env.name,
    base_url: baseUrl ?? DEFAULT_FALCON_BASE_URL,
  });
}

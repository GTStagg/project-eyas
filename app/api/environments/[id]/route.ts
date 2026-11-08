import { NextResponse } from "next/server";
import {
  AIDR_BASE_URL_RE,
  DEFAULT_FALCON_BASE_URL,
  deleteEnvironment,
  getActiveEnvironmentId,
  getEnvironmentById,
  listEnvironments,
  updateEnvironment,
} from "@/lib/config/environments";
import { FALCON_BASE_URL_RE, probeFalconCredentials } from "@/lib/falcon/oauth-probe";
import { invalidateHealthCache } from "@/lib/health";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// PATCH /api/environments/:id — rename and/or rotate credentials. Body shape
// matches POST /api/environments but every field is optional. When client_id
// or client_secret is provided, runs the OAuth2 probe as a gate before save.
// DELETE /api/environments/:id — refuses if the env is active or last.

type PatchBody = {
  name?: string;
  client_id?: string;
  client_secret?: string;
  base_url?: string;
  member_cid?: string;
  ir_quarantine_group_id?: string;
  aidr_token?: string;
  aidr_base_url?: string;
};

function parsePatch(raw: unknown): { body: PatchBody } | { error: string } {
  if (!raw || typeof raw !== "object") return { error: "body must be a JSON object" };
  const r = raw as Record<string, unknown>;
  const body: PatchBody = {};
  for (const k of [
    "name",
    "client_id",
    "client_secret",
    "base_url",
    "member_cid",
    "ir_quarantine_group_id",
    "aidr_token",
    "aidr_base_url",
  ] as const) {
    const v = r[k];
    if (v === undefined) continue;
    if (typeof v !== "string") return { error: `${k} must be a string` };
    body[k] = v.trim();
  }
  return { body };
}

export async function PATCH(
  request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  const existing = getEnvironmentById(id);
  if (!existing) {
    return NextResponse.json({ ok: false, error: "environment not found" }, { status: 404 });
  }

  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return NextResponse.json({ ok: false, error: "invalid JSON body" }, { status: 400 });
  }
  const parsed = parsePatch(raw);
  if ("error" in parsed) {
    return NextResponse.json({ ok: false, error: parsed.error }, { status: 400 });
  }
  const body = parsed.body;

  // Probe whenever the credential triple is being touched (client_id,
  // client_secret, or base_url). Resolve missing fields from the existing
  // record so the operator can rotate one field at a time.
  const credTouched =
    body.client_id !== undefined ||
    body.client_secret !== undefined ||
    body.base_url !== undefined;

  if (credTouched) {
    const probeClientId = body.client_id || existing.falcon.clientId;
    const probeClientSecret = body.client_secret || existing.falcon.clientSecret;
    const probeBaseUrl = body.base_url || existing.falcon.baseUrl || DEFAULT_FALCON_BASE_URL;
    if (!probeClientId || !probeClientSecret) {
      return NextResponse.json(
        { ok: false, error: "client_id and client_secret are required to rotate credentials" },
        { status: 400 },
      );
    }
    if (!FALCON_BASE_URL_RE.test(probeBaseUrl)) {
      return NextResponse.json(
        { ok: false, error: "base_url must look like https://api.<region>.crowdstrike.com" },
        { status: 400 },
      );
    }
    const probe = await probeFalconCredentials(probeClientId, probeClientSecret, probeBaseUrl);
    if (!probe.ok) {
      return NextResponse.json(
        { ok: false, error: `Connection test failed; refusing to save. ${probe.message}` },
        { status: 400 },
      );
    }
  }

  // The AIDR bearer token rides to this base URL on every chat turn — allowlist
  // it before persisting so a PATCH can't repoint the token at an attacker host.
  // Empty string clears back to the default and is allowed.
  if (body.aidr_base_url && !AIDR_BASE_URL_RE.test(body.aidr_base_url)) {
    return NextResponse.json(
      {
        ok: false,
        error:
          "AIDR base URL must be a CrowdStrike (api.<region>.crowdstrike.com) or Pangea (*.pangea.cloud) https URL.",
      },
      { status: 400 },
    );
  }

  const aidrPatch: { token?: string; baseUrl?: string } | undefined =
    body.aidr_token !== undefined || body.aidr_base_url !== undefined
      ? {
          ...(body.aidr_token !== undefined ? { token: body.aidr_token } : {}),
          ...(body.aidr_base_url !== undefined ? { baseUrl: body.aidr_base_url } : {}),
        }
      : undefined;

  await updateEnvironment(id, {
    name: body.name,
    falcon: {
      clientId: body.client_id || undefined,
      clientSecret: body.client_secret || undefined,
      baseUrl: body.base_url || undefined,
      memberCid: body.member_cid,
    },
    irQuarantineGroupId: body.ir_quarantine_group_id,
    aidr: aidrPatch,
  });
  // If the patched env is the active one, downstream caches must drop.
  if (id === getActiveEnvironmentId()) invalidateHealthCache();

  return NextResponse.json({
    ok: true,
    active_id: getActiveEnvironmentId(),
    environments: listEnvironments(),
  });
}

export async function DELETE(
  _request: Request,
  context: { params: Promise<{ id: string }> },
) {
  const { id } = await context.params;
  if (!getEnvironmentById(id)) {
    return NextResponse.json({ ok: false, error: "environment not found" }, { status: 404 });
  }
  try {
    await deleteEnvironment(id);
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }
  return NextResponse.json({
    ok: true,
    active_id: getActiveEnvironmentId(),
    environments: listEnvironments(),
  });
}

import { NextResponse } from "next/server";
import {
  createEnvironment,
  DEFAULT_FALCON_BASE_URL,
  getActiveEnvironmentId,
  listEnvironments,
} from "@/lib/config/environments";
import { FALCON_BASE_URL_RE, probeFalconCredentials } from "@/lib/falcon/oauth-probe";
import { invalidateHealthCache } from "@/lib/health";
import { inFlightCount } from "@/lib/chat/in-flight";
import { fail, ok } from "@/lib/api/respond";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// GET /api/environments — list of environment views (no secrets) + active_id.
// POST /api/environments — create a new environment. Body:
//   { name, client_id, client_secret, base_url, member_cid?,
//     ir_quarantine_group_id?, activate?: boolean, test_only?: boolean }
// Probes Falcon OAuth2 as a gate before saving. With `test_only: true`,
// runs the probe without persisting (so the form can show success before
// the operator commits).

type CreateBody = {
  name?: string;
  client_id?: string;
  client_secret?: string;
  base_url?: string;
  member_cid?: string;
  ir_quarantine_group_id?: string;
  activate?: boolean;
  test_only?: boolean;
};

function parseCreate(raw: unknown): { body: CreateBody } | { error: string } {
  if (!raw || typeof raw !== "object") return { error: "body must be a JSON object" };
  const r = raw as Record<string, unknown>;
  const body: CreateBody = {};
  for (const k of [
    "name",
    "client_id",
    "client_secret",
    "base_url",
    "member_cid",
    "ir_quarantine_group_id",
  ] as const) {
    const v = r[k];
    if (v === undefined) continue;
    if (typeof v !== "string") return { error: `${k} must be a string` };
    body[k] = v.trim();
  }
  for (const k of ["activate", "test_only"] as const) {
    const v = r[k];
    if (v === undefined) continue;
    if (typeof v !== "boolean") return { error: `${k} must be a boolean` };
    body[k] = v;
  }
  return { body };
}

export async function GET() {
  return ok({
    active_id: getActiveEnvironmentId(),
    environments: listEnvironments(),
    in_flight: inFlightCount(),
  });
}

export async function POST(request: Request) {
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    return fail("invalid JSON body");
  }
  const parsed = parseCreate(raw);
  if ("error" in parsed) return fail(parsed.error);
  const body = parsed.body;
  if (!body.name) return fail("name is required");
  if (!body.client_id || !body.client_secret) {
    return fail("client_id and client_secret are required");
  }
  const baseUrl = body.base_url || DEFAULT_FALCON_BASE_URL;
  if (!FALCON_BASE_URL_RE.test(baseUrl)) {
    return fail("base_url must look like https://api.<region>.crowdstrike.com");
  }

  const probe = await probeFalconCredentials(body.client_id, body.client_secret, baseUrl);

  if (body.test_only) {
    // Dry-run probe: always 200, verdict in the `ok` field — the form
    // uses it to gate the Save button without committing. Non-standard
    // envelope is deliberate; the shared `fail` helper would 4xx and the
    // form would treat it as a real save failure.
    return NextResponse.json({ ok: probe.ok, message: probe.message });
  }
  if (!probe.ok) {
    return fail(`Connection test failed; refusing to save. ${probe.message}`);
  }

  await createEnvironment({
    name: body.name,
    falcon: {
      clientId: body.client_id,
      clientSecret: body.client_secret,
      baseUrl,
      memberCid: body.member_cid || undefined,
    },
    irQuarantineGroupId: body.ir_quarantine_group_id || undefined,
    activate: body.activate ?? false,
  });
  // If we activated, downstream callers (health probes, withFalconMcpClient)
  // need to see the new active env on their next read.
  if (body.activate) invalidateHealthCache();

  return ok({
    active_id: getActiveEnvironmentId(),
    environments: listEnvironments(),
  });
}

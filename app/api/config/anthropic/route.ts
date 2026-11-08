import { NextResponse } from "next/server";
import Anthropic from "@anthropic-ai/sdk";
import {
  getRuntimeConfig,
  saveRuntimeConfig,
  MIN_CHAT_MAX_TOKENS,
  MAX_CHAT_MAX_TOKENS,
  type ConfigFile,
} from "@/lib/config/runtime";
import {
  getDeploymentPolicy,
  validateAnthropicAgainstPolicy,
} from "@/lib/config/deployment-policy";
import { resetAnthropicClient } from "@/lib/llm/anthropic";
import { anthropicBaseUrlError } from "@/lib/llm/base-url";
import { invalidateHealthCache } from "@/lib/health";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// PATCH /api/config/anthropic — edit Anthropic credentials in place. Body:
//   { mode: "apiKey" | "authToken", credential?, baseURL?, model?, chatMaxTokens? }
//
// `chatMaxTokens` is the per-turn output-token cap for the /chat surface
// (integer in [MIN_CHAT_MAX_TOKENS, MAX_CHAT_MAX_TOKENS]; "" clears it back to
// the built-in default). Omit it to leave the stored value untouched.
//
// `credential` rotates the active key/token (empty string clears). `mode`
// picks which slot the credential goes into (apiKey vs authToken). Empty
// string on baseURL/model clears that field. Validates by calling
// `models.retrieve(model)` against the resulting client config — fails
// fast on bad creds before persisting.
//
// `?test=1` runs the validation pass without saving so the form can show
// success before the operator commits.

type PatchBody = {
  mode?: "apiKey" | "authToken";
  credential?: string;
  baseURL?: string;
  model?: string;
  // Validated, normalized to a string here: "" clears (revert to default),
  // otherwise the in-range integer as a string. Stored as-is by the settings
  // layer; parsed back to a number in runtime.ts.
  chatMaxTokens?: string;
};

function parsePatch(raw: unknown): { body: PatchBody } | { error: string } {
  if (!raw || typeof raw !== "object") return { error: "body must be a JSON object" };
  const r = raw as Record<string, unknown>;
  const body: PatchBody = {};
  if (r.mode !== undefined) {
    if (r.mode !== "apiKey" && r.mode !== "authToken") {
      return { error: "mode must be 'apiKey' or 'authToken'" };
    }
    body.mode = r.mode;
  }
  for (const k of ["credential", "baseURL", "model"] as const) {
    const v = r[k];
    if (v === undefined) continue;
    if (typeof v !== "string") return { error: `${k} must be a string` };
    body[k] = v;
  }
  if (r.chatMaxTokens !== undefined) {
    const v = r.chatMaxTokens;
    if (v === "" || v === null) {
      body.chatMaxTokens = ""; // clear → revert to the built-in default
    } else {
      const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
      if (!Number.isInteger(n) || n < MIN_CHAT_MAX_TOKENS || n > MAX_CHAT_MAX_TOKENS) {
        return {
          error: `chatMaxTokens must be an integer between ${MIN_CHAT_MAX_TOKENS} and ${MAX_CHAT_MAX_TOKENS}`,
        };
      }
      body.chatMaxTokens = String(n);
    }
  }
  return { body };
}

async function probeAnthropic(args: {
  apiKey?: string;
  authToken?: string;
  baseURL?: string;
  model: string;
}): Promise<{ ok: boolean; message: string }> {
  try {
    const opts: ConstructorParameters<typeof Anthropic>[0] = {};
    if (args.apiKey) opts.apiKey = args.apiKey;
    if (args.authToken) opts.authToken = args.authToken;
    if (args.baseURL) opts.baseURL = args.baseURL;
    const client = new Anthropic(opts);
    await client.models.retrieve(args.model);
    return { ok: true, message: `Connected and ${args.model} is available.` };
  } catch (err) {
    if (err instanceof Anthropic.NotFoundError) {
      // Many gateways 404 on /v1/models — treat as success since OAuth-ish
      // creds presence at least reached the upstream. Same logic as
      // lib/health.ts::probeAnthropic.
      return {
        ok: true,
        message: "Connected. (Your gateway doesn't expose model listings, which is normal.)",
      };
    }
    return {
      ok: false,
      message: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function PATCH(request: Request) {
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
  const url = new URL(request.url);
  const testOnly = url.searchParams.get("test") === "1";

  const current = getRuntimeConfig();
  const currentMode: "apiKey" | "authToken" = current.anthropic.apiKey
    ? "apiKey"
    : current.anthropic.authToken
      ? "authToken"
      : "apiKey";
  const targetMode = body.mode ?? currentMode;

  // Resolve the effective credential for the probe + the eventual save.
  // - When `credential` is provided, it replaces the slot named by `mode`.
  //   The OTHER slot is cleared so we don't leave stale dual creds around.
  // - When `credential` is omitted, the existing creds carry over and only
  //   baseURL / model can change.
  let nextApiKey = current.anthropic.apiKey;
  let nextAuthToken = current.anthropic.authToken;
  if (body.credential !== undefined) {
    if (targetMode === "apiKey") {
      nextApiKey = body.credential || undefined;
      nextAuthToken = undefined;
    } else {
      nextAuthToken = body.credential || undefined;
      nextApiKey = undefined;
    }
  }
  const nextBaseURL =
    body.baseURL === undefined ? current.anthropic.baseURL : body.baseURL || undefined;
  const nextModel = body.model === undefined ? current.anthropic.model : body.model || undefined;

  // Bail if the result has no credential at all (clearing both slots leaves
  // the app unable to call Anthropic). Operator must explicitly re-enter.
  if (!nextApiKey && !nextAuthToken) {
    return NextResponse.json(
      {
        ok: false,
        error: "an apiKey or authToken is required",
      },
      { status: 400 },
    );
  }

  // Enforce build-time deployment policy: standalone bundles ship with
  // gateway-only mode and (optionally) a forced base URL. Direct API
  // keys and operator-chosen URLs get rejected here even if the request
  // bypassed the wizard's UI gates.
  const policy = getDeploymentPolicy();
  const policyError = validateAnthropicAgainstPolicy({
    apiKey: nextApiKey,
    authToken: nextAuthToken,
    baseURL: nextBaseURL,
  });
  if (policyError) {
    return NextResponse.json({ ok: false, error: policyError }, { status: 400 });
  }
  const urlError = nextBaseURL && !policy.forcedGatewayUrl ? anthropicBaseUrlError(nextBaseURL) : null;
  if (urlError) {
    return NextResponse.json({ ok: false, error: urlError }, { status: 400 });
  }
  // When the policy forces a gateway URL, ignore whatever the operator
  // typed and substitute the locked value. Belt-and-suspenders alongside
  // the UI lock.
  const effectiveBaseURL = policy.forcedGatewayUrl ?? nextBaseURL;

  const probe = await probeAnthropic({
    apiKey: nextApiKey,
    authToken: nextAuthToken,
    baseURL: effectiveBaseURL,
    model: nextModel ?? "claude-sonnet-4-6",
  });
  if (!probe.ok) {
    return NextResponse.json(
      { ok: false, error: `Connection test failed; refusing to save. ${probe.message}` },
      { status: 400 },
    );
  }

  if (testOnly) {
    return NextResponse.json({ ok: true, message: probe.message });
  }

  const patch: Partial<ConfigFile> = {
    anthropic: {
      apiKey: nextApiKey ?? "",
      authToken: nextAuthToken ?? "",
      baseURL: effectiveBaseURL ?? "",
      model: nextModel ?? "",
    },
  };
  // Only touch chatMaxTokens when the operator edited it: "" clears (revert to
  // default), a value sets it. Omitting it preserves the stored value.
  if (body.chatMaxTokens !== undefined) {
    patch.anthropic!.chatMaxTokens = body.chatMaxTokens;
  }
  await saveRuntimeConfig(patch);
  resetAnthropicClient();
  invalidateHealthCache();

  return NextResponse.json({ ok: true, message: probe.message });
}

export async function GET() {
  // Read-only summary used by the /config UI to render the current shape
  // without ever exposing the secret. Mirrors the `getConfigStatus` view
  // for Anthropic but flat.
  const cfg = getRuntimeConfig();
  const policy = getDeploymentPolicy();
  const credentialKind = cfg.anthropic.apiKey
    ? "apiKey"
    : cfg.anthropic.authToken
      ? "authToken"
      : null;
  return NextResponse.json({
    ok: true,
    anthropic: {
      credential_kind: credentialKind,
      credential_set: !!(cfg.anthropic.apiKey || cfg.anthropic.authToken),
      base_url: cfg.anthropic.baseURL ?? null,
      model: cfg.anthropic.model,
      chat_max_tokens: cfg.anthropic.chatMaxTokens,
    },
    policy: {
      gateway_only: policy.gatewayOnly,
      forced_gateway_url: policy.forcedGatewayUrl,
    },
  });
}

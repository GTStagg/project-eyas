"use server";
import { redirect } from "next/navigation";
import { existsSync } from "node:fs";
import path from "node:path";
import { isRegistered, registerWith, MIN_PASSWORD_LENGTH } from "@/lib/auth/store";
import { getSession } from "@/lib/auth/session";
import {
  getConfigStatus,
  getRuntimeConfig,
  invalidateConfigCache,
  saveRuntimeConfig,
  type ConfigFile,
} from "@/lib/config/runtime";
import {
  getDeploymentPolicy,
  validateAnthropicAgainstPolicy,
} from "@/lib/config/deployment-policy";
import { anthropicClientOptions, resetAnthropicClient } from "@/lib/llm/anthropic";
import { invalidateHealthCache } from "@/lib/health";
import { FALCON_BASE_URL_RE, probeFalconCredentials } from "@/lib/falcon/oauth-probe";
import { anthropicBaseUrlError } from "@/lib/llm/base-url";
import Anthropic from "@anthropic-ai/sdk";

export type RegisterState = { error?: string };

function readField(form: FormData, key: string): string {
  return String(form.get(key) ?? "").trim();
}

function buildConfigPatch(form: FormData): Partial<ConfigFile> {
  const apiKey = readField(form, "anthropic_apiKey");
  const authToken = readField(form, "anthropic_authToken");
  const baseURL = readField(form, "anthropic_baseURL");
  const model = readField(form, "anthropic_model");
  const clientId = readField(form, "falcon_clientId");
  const clientSecret = readField(form, "falcon_clientSecret");
  const baseUrl = readField(form, "falcon_baseUrl");
  const memberCid = readField(form, "falcon_memberCid");
  const irGroup = readField(form, "irQuarantineGroupId");

  const patch: Partial<ConfigFile> = {};
  const anthropic: ConfigFile["anthropic"] = {};
  if (apiKey) anthropic.apiKey = apiKey;
  if (authToken) anthropic.authToken = authToken;
  // Deployment policy: when the build forces a gateway URL, override
  // whatever the form supplied. validateConfig already rejects mismatches
  // on the user-facing path; this is the server-side belt-and-suspenders
  // for direct POST attempts.
  const policy = getDeploymentPolicy();
  if (policy.forcedGatewayUrl) anthropic.baseURL = policy.forcedGatewayUrl;
  else if (baseURL) anthropic.baseURL = baseURL;
  if (model) anthropic.model = model;
  if (Object.keys(anthropic).length) patch.anthropic = anthropic;

  const falcon: ConfigFile["falcon"] = {};
  if (clientId) falcon.clientId = clientId;
  if (clientSecret) falcon.clientSecret = clientSecret;
  if (baseUrl) falcon.baseUrl = baseUrl;
  if (memberCid) falcon.memberCid = memberCid;
  if (Object.keys(falcon).length) patch.falcon = falcon;

  // FalconPy sidecar is unconditionally on; the wizard doesn't render a toggle.
  if (irGroup) patch.irQuarantineGroupId = irGroup;
  return patch;
}

function validateConfig(form: FormData, status: ReturnType<typeof getConfigStatus>): string | null {
  const apiKey = readField(form, "anthropic_apiKey");
  const authToken = readField(form, "anthropic_authToken");
  const baseURL = readField(form, "anthropic_baseURL");
  const clientId = readField(form, "falcon_clientId");
  const clientSecret = readField(form, "falcon_clientSecret");
  const baseUrl = readField(form, "falcon_baseUrl");

  const policyError = validateAnthropicAgainstPolicy({
    apiKey,
    authToken,
    baseURL,
  });
  if (policyError) return policyError;
  if (baseURL && !getDeploymentPolicy().forcedGatewayUrl) {
    const urlError = anthropicBaseUrlError(baseURL);
    if (urlError) return urlError;
  }
  const gatewayOnly = process.env.ANTHROPIC_GATEWAY_ONLY === "true";

  const haveAnthropic = !!apiKey || !!authToken || status.anthropic.credential.source !== "missing";
  if (!haveAnthropic) {
    return gatewayOnly
      ? "Provide an Anthropic gateway auth token."
      : "Provide an Anthropic API key or gateway auth token.";
  }
  if (apiKey && authToken) return "Provide only one of: Anthropic API key OR gateway auth token.";
  if (authToken && !baseURL && status.anthropic.baseURL.source === "missing") {
    return "Anthropic gateway auth token requires a Base URL.";
  }
  if (gatewayOnly && !authToken && status.anthropic.credential.kind !== "authToken") {
    return "Provide an Anthropic gateway auth token.";
  }

  const haveClientId = !!clientId || status.falcon.clientId.source !== "missing";
  const haveClientSecret = !!clientSecret || status.falcon.clientSecret.source !== "missing";
  if (!haveClientId || !haveClientSecret) return "Falcon Client ID and Secret are required.";

  if (baseUrl && !FALCON_BASE_URL_RE.test(baseUrl)) {
    return "Falcon Base URL must look like https://api.<region>.crowdstrike.com.";
  }

  return null;
}

export async function registerAction(_prev: RegisterState, formData: FormData): Promise<RegisterState> {
  const password = String(formData.get("password") ?? "");
  const confirm = String(formData.get("confirm") ?? "");

  if (password.length < MIN_PASSWORD_LENGTH) {
    return { error: `Password must be at least ${MIN_PASSWORD_LENGTH} characters.` };
  }
  if (password !== confirm) {
    return { error: "Passwords do not match." };
  }
  if (await isRegistered()) {
    redirect("/login");
  }

  const status = getConfigStatus();
  const validationErr = validateConfig(formData, status);
  if (validationErr) return { error: validationErr };

  try {
    const patch = buildConfigPatch(formData);
    // Claim the account before saving credentials (registerWith inserts the
    // auth row first), so a concurrent first-run submission that loses the
    // race can't overwrite the winner's configuration.
    await registerWith(password, async () => {
      if (Object.keys(patch).length) {
        await saveRuntimeConfig(patch);
      }
    });
    // Drop in-process caches so the dashboard's first probe after the
    // post-register redirect re-runs with the credentials we just saved.
    // Without this the 30s health-cache window can serve a stale "creds
    // missing" verdict to /status + Sidebar capability gates and operators
    // see the bundle as broken until the cache expires. invalidateConfigCache
    // is belt-and-suspenders against any chunk-isolation oddity: the store
    // also pins to globalThis, but forcing the next read to hit disk
    // forecloses any class of bug where chunk A wrote to disk while
    // chunk B's cache somehow stayed warm.
    resetAnthropicClient();
    invalidateConfigCache();
    invalidateHealthCache();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === "EEXIST" || (err as Error)?.message === "Already registered.") {
      redirect("/login");
    }
    return { error: (err as Error).message ?? "Registration failed." };
  }

  const session = await getSession();
  session.authenticated = true;
  session.loginAt = new Date().toISOString();
  await session.save();

  // Falcon-extras venv is created by start.sh on launch. The sidecar is
  // required, so a missing venv on first registration is a one-time
  // restart requirement — cache invalidation can't conjure a missing
  // binary. The post-register page surfaces this as a banner; if the
  // venv exists, we go straight to the activation checklist on
  // /getting-started.
  const venvPython = path.join(process.cwd(), "falcon-extras", ".venv", "bin", "python");
  const needsRestartForExtras = !existsSync(venvPython);
  redirect(needsRestartForExtras ? "/getting-started?postRegister=restart-extras" : "/getting-started");
}

export type TestState = {
  anthropic?: { ok: boolean; message: string };
  falcon?: { ok: boolean; message: string };
};

/**
 * Probes Anthropic + Falcon with the values currently in the form.
 * Pure server-side — credentials are never echoed back to the client, only
 * pass/fail booleans + an explanation string.
 */
export async function testConnectionAction(_prev: TestState, formData: FormData): Promise<TestState> {
  const result: TestState = {};

  // SSRF / credential-exfil guard. This action is reachable unauthenticated
  // (middleware lets /register through) and falls back to STORED creds for any
  // field the form left blank. Once the app is registered, only an
  // authenticated operator may run the probes — otherwise an attacker hitting
  // /register could blank a credential field to trigger the stored-cred
  // fallback and have the server ship the stored Falcon / Anthropic secret to
  // an attacker-chosen Base URL. Pre-registration there are no stored creds to
  // leak (the form values are the caller's own), so first-run setup is
  // unaffected. The Falcon Base URL is additionally allowlisted below.
  if (await isRegistered()) {
    const session = await getSession();
    if (!session.authenticated) {
      const msg = "Sign in to test connections.";
      return { anthropic: { ok: false, message: msg }, falcon: { ok: false, message: msg } };
    }
  }

  const status = getConfigStatus();
  const stored = getRuntimeConfig();

  // Anthropic — submitted form values win, fall back to whatever's stored
  // in the DB for fields the operator didn't re-type. (`.env` is not
  // consulted at runtime — the DB is the only credential source.)
  const apiKey = readField(formData, "anthropic_apiKey") || (status.anthropic.credential.kind === "apiKey" ? stored.anthropic.apiKey ?? "" : "");
  const authToken = readField(formData, "anthropic_authToken") || (status.anthropic.credential.kind === "authToken" ? stored.anthropic.authToken ?? "" : "");
  // On a gateway-locked build, force the baked URL — never probe (and so never
  // ship the Anthropic token to) a form/DB-supplied host. Mirrors the read-seam
  // lock in lib/llm/anthropic.ts.
  const baseURL =
    getDeploymentPolicy().forcedGatewayUrl ||
    readField(formData, "anthropic_baseURL") ||
    stored.anthropic.baseURL ||
    "";
  const model = readField(formData, "anthropic_model") || status.anthropic.model.value;

  try {
    const opts: ConstructorParameters<typeof Anthropic>[0] = {};
    if (apiKey) opts.apiKey = apiKey;
    if (authToken) opts.authToken = authToken;
    if (baseURL) opts.baseURL = baseURL;

    const urlError = baseURL && !getDeploymentPolicy().forcedGatewayUrl ? anthropicBaseUrlError(baseURL) : null;
    if (urlError) {
      result.anthropic = { ok: false, message: urlError };
    } else if (!opts.apiKey && !opts.authToken) {
      result.anthropic = { ok: false, message: "Provide either an Anthropic API key or gateway auth token." };
    } else {
      const client = new Anthropic(anthropicClientOptions({ apiKey, authToken, baseURL }));
      try {
        await client.models.retrieve(model);
        result.anthropic = { ok: true, message: `Authenticated; model "${model}" available.` };
      } catch (err) {
        if (err instanceof Anthropic.AuthenticationError) {
          result.anthropic = { ok: false, message: "Authentication failed (bad key or token)." };
        } else if (err instanceof Anthropic.NotFoundError) {
          if (opts.authToken) {
            result.anthropic = {
              ok: true,
              message: "Authenticated. Gateway does not expose /v1/models; chat uses /v1/messages.",
            };
          } else {
            result.anthropic = { ok: false, message: `Model "${model}" not found for this key.` };
          }
        } else if (err instanceof Anthropic.APIError && err.status) {
          // Status only: the response body could come from any host the form
          // named, and this action can run before anyone has signed in.
          result.anthropic = { ok: false, message: `The endpoint returned HTTP ${err.status}.` };
        } else {
          result.anthropic = { ok: false, message: "Could not reach the Anthropic endpoint. Check the Base URL and network access." };
        }
      }
    }
  } catch (err) {
    result.anthropic = { ok: false, message: err instanceof Error ? err.message : String(err) };
  }

  // Falcon — OAuth2 token endpoint is the cheapest auth probe. Fall back to
  // the stored creds when the form field is blank.
  const clientId = readField(formData, "falcon_clientId") || stored.falcon.clientId || "";
  const clientSecret = readField(formData, "falcon_clientSecret") || stored.falcon.clientSecret || "";
  const baseUrl = (readField(formData, "falcon_baseUrl") || status.falcon.baseUrl.value || "").replace(/\/$/, "");

  if (!clientId || !clientSecret) {
    result.falcon = { ok: false, message: "Falcon Client ID and Secret are required." };
  } else if (!FALCON_BASE_URL_RE.test(baseUrl)) {
    // Allowlist the host BEFORE sending creds anywhere — this is the SSRF +
    // exfil cutoff. Creds only ever leave for an api.<region>.crowdstrike.com
    // origin, never an attacker-chosen Base URL.
    result.falcon = {
      ok: false,
      message: "Falcon Base URL must look like https://api.<region>.crowdstrike.com.",
    };
  } else {
    // probeFalconCredentials carries a 10s timeout (no unbounded fetch).
    const probe = await probeFalconCredentials(clientId, clientSecret, baseUrl);
    result.falcon = {
      ok: probe.ok,
      message: probe.ok ? "OAuth2 token request succeeded." : probe.message,
    };
  }

  return result;
}

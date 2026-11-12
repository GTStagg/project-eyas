import "server-only";
import { promises as fs } from "node:fs";
import path from "node:path";
import Anthropic from "@anthropic-ai/sdk";
import { getAnthropicClient, getAnthropicModel } from "@/lib/llm/anthropic";
import { getRuntimeConfig } from "@/lib/config/runtime";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { isScopeDenied } from "@/lib/mcp/parse";
import { isRegistered } from "@/lib/auth/store";

export type ProbeStatus = "ok" | "error" | "disabled" | "initializing";

// Operator-facing message for the first-launch build window. No dev jargon
// (venv / wheels / pip) — the recipient is an operator, not an engineer.
export const FIRST_LAUNCH_SETUP_MSG =
  "Finishing first-time setup — installing components. This usually takes under a minute; reload shortly.";

// A spawn ENOENT while the standalone bundle's vendored wheels are present
// means start.sh hasn't finished building the offline venv the client spawns
// into. start.sh builds the venv (blocking) before it execs node, so the
// only ways node serves with a venv still absent are (a) a stale pre-reinstall
// node process whose venv was just rsync-deleted out from under it, or (b) the
// brief mid-build window of a manual/parallel launch — both transitional, not a
// failure. Distinguish this from a genuine spawn error (wheels absent → the dev
// `uvx` path, where an ENOENT is a real missing-binary problem) so /status shows
// "setting up" rather than a red error the operator reads as broken.
async function isFirstLaunchSetup(err: unknown, wheelsSubdir: string): Promise<boolean> {
  const code = (err as { code?: string } | null)?.code;
  const msg = err instanceof Error ? err.message : String(err);
  if (code !== "ENOENT" && !/\bENOENT\b/.test(msg)) return false;
  try {
    const entries = await fs.readdir(path.join(process.cwd(), "vendor", wheelsSubdir));
    return entries.length > 0;
  } catch {
    return false;
  }
}

export type ProbeResult = {
  status: ProbeStatus;
  message?: string;
  latencyMs: number;
  detail?: Record<string, string | number>;
  capabilities?: FalconMcpCapabilities;
};

// Capability flags backed by eyas-mcp tools, probed inside probeFalconMcp on
// the same client connection. Each is TRUE when the probe succeeded or was
// ambiguous, FALSE only on a confirmed scope denial — a transient blip never
// hides a surface. Sidebar and pages read these to hide surfaces whose Falcon
// API scope isn't granted on this tenant.
export type FalconMcpCapabilities = {
  intel: boolean;
  // Threat Graph + MalQuery (eyas-mcp native since its sidecar port; were sidecar probes).
  threatGraph: boolean;
  malQuery: boolean;
  // Identity Protection (risky identities — eyas-mcp native; was a sidecar probe).
  idp: boolean;
  // Falcon Intelligence Recon (eyas-mcp native; was a sidecar probe). Gates /recon.
  recon: boolean;
  // Fusion SOAR workflows (eyas-mcp native; was a sidecar probe). Gates /workflows.
  workflows: boolean;
  // Falcon Discover inventory (eyas-mcp native; was a sidecar probe). Gates /discover.
  discover: boolean;
  // Falcon Cases (falcon-mcp 0.10.0). Requires Cases:read scope, which is
  // NOT in this tenant's granted set — so this is normally false and the
  // /cases surface ships staged (nav hidden, page shows a scope-pending
  // banner) until the operator adds the scope.
  cases: boolean;
  // falcon-mcp 0.11.0 modules. Each gates a 0.11.0 decision-doc surface
  // (/quarantine, /correlation, /data-protection). Same staged-build
  // semantics as cases: false only on confirmed scope denial.
  quarantine: boolean;
  correlationRules: boolean;
  dataProtection: boolean;
  // falcon-mcp 0.19.0 Guardian module (AI-agent activity). All 25 tools require
  // AIDR:read; false only on confirmed denial → gates the "AI agent activity"
  // dashboard surface with the same staged-build semantics.
  guardian: boolean;
  // IOA / ML exclusion reads (falcon_search_exclusions). Read scope stands in
  // for write scope: CrowdStrike grants them as a pair, and the create call
  // surfaces its own scope error if they diverge. Gates the /tuning Tune chip.
  mlExclusions: boolean;
  ioaExclusions: boolean;
};

export type AuthInfo = {
  registered: boolean;
  sessionSecretConfigured: boolean;
};

export type HealthReport = {
  anthropic: ProbeResult;
  falconMcp: ProbeResult;
  auth: AuthInfo;
  aidr: ProbeResult;
};

async function probeAnthropic(): Promise<ProbeResult> {
  const t0 = Date.now();
  // Corporate AI gateways often forward only /v1/messages and 404 the
  // /v1/models endpoint (or allowlist a different set of model ids there
  // than at /v1/messages). Treat NotFoundError as a non-fatal probe miss
  // when running through a gateway — auth errors still surface as errors.
  const model_id = getAnthropicModel();
  const onGateway = !!getRuntimeConfig().anthropic.authToken;
  try {
    const client = getAnthropicClient();
    // models.retrieve is a free auth check — no inference, no tokens.
    const model = await client.models.retrieve(model_id);
    return {
      status: "ok",
      latencyMs: Date.now() - t0,
      detail: { model: model.id },
    };
  } catch (err) {
    const latencyMs = Date.now() - t0;
    if (err instanceof Anthropic.AuthenticationError) {
      return { status: "error", latencyMs, message: "Authentication failed (check ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN)." };
    }
    if (err instanceof Anthropic.NotFoundError) {
      if (onGateway) {
        return {
          status: "ok",
          latencyMs,
          message: "Gateway does not expose /v1/models; chat uses /v1/messages and is unaffected.",
          detail: { model: model_id, via: "gateway" },
        };
      }
      return {
        status: "error",
        latencyMs,
        message: `Model "${model_id}" not found for this key. Check ANTHROPIC_MODEL.`,
      };
    }
    if (err instanceof Anthropic.APIError) {
      return { status: "error", latencyMs, message: `API error ${err.status}: ${err.message}` };
    }
    return { status: "error", latencyMs, message: err instanceof Error ? err.message : String(err) };
  }
}

async function probeFalconMcp(): Promise<ProbeResult> {
  const t0 = Date.now();
  try {
    const result = await withFalconMcpClient(async (client) => {
      // Piggyback the intel scope probe on the same handshake. One cheap
      // falcon_search_actors call (limit 1) tells us whether the API client
      // carries Falcon Intelligence: Actors:read scope. The /intel page
      // also needs Indicators:read but Actors is the more obvious gate;
      // the page itself short-circuits cleanly if Indicators is missing.
      //
      // upstream falcon-mcp packages denial as an `{error, details}` JSON
      // envelope with isError:false, not a thrown exception. isScopeDenied
      // keys on the structured signal (details.status_code 403/401 or
      // required_scopes) rather than the human message — defaults to TRUE
      // (capability granted) on any ambiguity so transient blips don't
      // hide nav items.
      const intelProbe = client
        .callTool({
          name: "falcon_search_actors",
          arguments: { limit: 1 },
        })
        .then((r) => {
          const text = (r.content as Array<{ type: string; text?: string }>)
            .map((c) => (c.type === "text" && c.text ? c.text : ""))
            .join("\n");
          return !isScopeDenied(text);
        })
        .catch(() => true);

      // Same shape as the intel probe: one cheap falcon_search_cases call
      // (limit 1) tells us whether the API client carries Cases:read.
      // isScopeDenied handles the {error, details} envelope (isError:false)
      // via the structured status_code/required_scopes signal; default TRUE
      // on any ambiguity so a transient blip never hides the nav item.
      const casesProbe = client
        .callTool({
          name: "falcon_search_cases",
          arguments: { limit: 1 },
        })
        .then((r) => {
          const text = (r.content as Array<{ type: string; text?: string }>)
            .map((c) => (c.type === "text" && c.text ? c.text : ""))
            .join("\n");
          return !isScopeDenied(text);
        })
        .catch(() => true);

      // falcon-mcp 0.11.0 module probes. Same shape as the cases probe — one
      // cheap search (limit 1) per module; isScopeDenied on the structured
      // envelope, default TRUE on ambiguity so a blip never hides a surface.
      const denialProbe = (name: string, args: Record<string, unknown>) =>
        client
          .callTool({ name, arguments: args })
          .then((r) => {
            const text = (r.content as Array<{ type: string; text?: string }>)
              .map((c) => (c.type === "text" && c.text ? c.text : ""))
              .join("\n");
            return !isScopeDenied(text);
          })
          .catch(() => true);

      const quarantineProbe = denialProbe("falcon_search_quarantined_files", { limit: 1 });
      const mlExclusionsProbe = denialProbe("falcon_search_exclusions", { exclusion_type: "ml", limit: 1 });
      const ioaExclusionsProbe = denialProbe("falcon_search_exclusions", { exclusion_type: "ioa", limit: 1 });
      const correlationProbe = denialProbe("falcon_search_correlation_rules", { limit: 1 });
      const dataProtectionProbe = denialProbe("falcon_search_data_security_entities", {
        entity_type: "classification",
        limit: 1,
      });
      // falcon-mcp 0.19.0 Guardian (AIDR:read). falcon_get_guardian_inventory is
      // the cheapest summary tool (no list paging) — ideal denial probe. NOTE the
      // `falcon_` prefix: falcon-mcp namespaces every tool, so the live names are
      // falcon_*_guardian_* even though the module source registers them bare.
      const guardianProbe = denialProbe("falcon_get_guardian_inventory", { time_range: "7d" });
      // Threat Graph: ran-on for the empty-file SHA-256 returns zero results
      // when the scope is granted and a 401/403 envelope when it isn't. (The
      // old sidecar probe called summary with a hash, which the sidecar
      // rejected locally — so it never actually tested the scope.)
      const threatGraphProbe = denialProbe("falcon_get_threatgraph_ran_on", {
        value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        indicator_type: "sha256",
        limit: 1,
      });

      // MalQuery: file metadata for the empty-file SHA-256 — what /malquery
      // depends on. (Exact-pattern hunting needs MalQuery:read separately; on
      // tenants without it, metadata still answers and the hunt reports 403.)
      const malQueryProbe = denialProbe("falcon_get_malquery_file_metadata", {
        hashes: ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
      });

      const idpProbe = denialProbe("falcon_search_risky_identities", { limit: 1 });
      const reconProbe = denialProbe("falcon_search_recon_rules", { limit: 1 });
      const workflowsProbe = denialProbe("falcon_search_workflow_definitions", { limit: 1 });
      const discoverProbe = denialProbe("falcon_search_managed_assets", { limit: 1 });

      const [tools, info, intel, cases, quarantine, correlationRules, dataProtection, guardian, threatGraph, malQuery, idp, recon, workflows, discover, mlExclusions, ioaExclusions] =
        await Promise.all([
          client.listTools(),
          Promise.resolve(client.getServerVersion()),
          intelProbe,
          casesProbe,
          quarantineProbe,
          correlationProbe,
          dataProtectionProbe,
          guardianProbe,
          threatGraphProbe,
          malQueryProbe,
          idpProbe,
          reconProbe,
          workflowsProbe,
          discoverProbe,
          mlExclusionsProbe,
          ioaExclusionsProbe,
        ]);
      return {
        count: tools.tools.length,
        version: info?.version ?? "unknown",
        intel,
        cases,
        quarantine,
        correlationRules,
        dataProtection,
        guardian,
        threatGraph,
        malQuery,
        idp,
        recon,
        workflows,
        discover,
        mlExclusions,
        ioaExclusions,
      };
    });
    return {
      status: "ok",
      latencyMs: Date.now() - t0,
      detail: { tools: result.count, version: result.version },
      capabilities: {
        intel: result.intel,
        cases: result.cases,
        quarantine: result.quarantine,
        correlationRules: result.correlationRules,
        dataProtection: result.dataProtection,
        guardian: result.guardian,
        threatGraph: result.threatGraph,
        malQuery: result.malQuery,
        idp: result.idp,
        recon: result.recon,
        workflows: result.workflows,
        discover: result.discover,
        mlExclusions: result.mlExclusions,
        ioaExclusions: result.ioaExclusions,
      },
    };
  } catch (err) {
    if (await isFirstLaunchSetup(err, "falcon-mcp-wheels")) {
      return { status: "initializing", latencyMs: Date.now() - t0, message: FIRST_LAUNCH_SETUP_MSG };
    }
    return {
      status: "error",
      latencyMs: Date.now() - t0,
      message: err instanceof Error ? err.message : String(err),
    };
  }
}

// Module-scoped cache. /status, header badges, and SSR pages would otherwise
// re-fan-out anthropic + eyas-mcp + auth probes on every request.
// 30s strikes a balance: stale enough to cushion bursty navigation, fresh
// enough that a config change becomes visible quickly. Force a refresh by
// passing { force: true } from a manual reload control.
const HEALTH_TTL_MS = 30_000;
// Pinned to globalThis so Next.js's per-route module duplication can't give
// each route bundle its own cache + in-flight promise — which would defeat
// both the 30s TTL and the in-flight de-dup, re-fanning the probe storm on
// every distinct route. Same rationale as lib/db/client.ts.
const hg = globalThis as unknown as {
  __eyasHealth?: {
    cache: { at: number; report: HealthReport } | null;
    inflight: Promise<HealthReport> | null;
  };
};
const healthState = (hg.__eyasHealth ??= { cache: null, inflight: null });

async function probeAuth(): Promise<AuthInfo> {
  // AUTH_SESSION_SECRET stays env-only (it's the bootstrap secret, generated
  // by start.sh; it intentionally lives outside data/ so a corrupted config
  // doesn't lock the operator out).
  const secret = process.env.AUTH_SESSION_SECRET ?? "";
  const sessionSecretConfigured = secret.length >= 32;
  let registered = false;
  try {
    registered = await isRegistered();
  } catch {
    registered = false;
  }
  return { registered, sessionSecretConfigured };
}

async function probeAidr(): Promise<ProbeResult> {
  // Per-environment optional credential. When unconfigured we mark the
  // probe "disabled" — same shape /status uses for other intentionally-off
  // features — rather than "error", so the operator isn't nagged about a
  // feature they chose not to enable.
  const t0 = Date.now();
  const { scanInput, isAidrEnabled } = await import("@/lib/aidr/client");
  if (!isAidrEnabled()) {
    return {
      status: "disabled",
      latencyMs: 0,
      message: "Not configured for the active environment.",
    };
  }
  // Validate the configured base URL against the CrowdStrike/Pangea allowlist
  // BEFORE sending the probe. The config layer rejects a bad URL on save, but a
  // DB that somehow holds a disallowed host must fail loudly here rather than
  // ship the AIDR token to an attacker-controlled endpoint.
  const { getActiveAidrCredential, AIDR_BASE_URL_RE } = await import(
    "@/lib/config/environments"
  );
  const aidrCred = getActiveAidrCredential();
  if (aidrCred && !AIDR_BASE_URL_RE.test(aidrCred.baseUrl)) {
    return {
      status: "error",
      latencyMs: Date.now() - t0,
      message: `AIDR base URL is not an allowed CrowdStrike/Pangea host: ${aidrCred.baseUrl}`,
    };
  }
  try {
    // Minimal benign call as the connectivity probe — verifies token +
    // base URL + the collector→policy binding all the way through. The
    // payload is plain English so detectors don't fire spuriously.
    const verdict = await scanInput({
      messages: [{ role: "user", content: "health check" }],
    });
    return {
      status: "ok",
      latencyMs: Date.now() - t0,
      detail: {
        policy: verdict?.policy ?? "(unknown)",
      },
    };
  } catch (err) {
    return {
      status: "error",
      latencyMs: Date.now() - t0,
      message: (err as Error).message,
    };
  }
}

async function runProbes(): Promise<HealthReport> {
  const [anthropic, falconMcp, auth, aidr] = await Promise.all([
    probeAnthropic(),
    probeFalconMcp(),
    probeAuth(),
    probeAidr(),
  ]);
  return { anthropic, falconMcp, auth, aidr };
}

/**
 * Drop the cached health report so the next `getHealthReport()` call re-probes
 * from scratch. Call this whenever runtime config changes (e.g. the /register
 * wizard saves new creds) — without it, a probe that ran with empty creds
 * before save will keep serving its failure verdict for HEALTH_TTL_MS even
 * though the underlying config is now correct.
 */
export function invalidateHealthCache(): void {
  healthState.cache = null;
}

export async function getHealthReport(opts?: { force?: boolean }): Promise<HealthReport> {
  if (!opts?.force && healthState.cache && Date.now() - healthState.cache.at < HEALTH_TTL_MS) {
    return healthState.cache.report;
  }
  if (healthState.inflight) return healthState.inflight;
  healthState.inflight = runProbes()
    .then((report) => {
      healthState.cache = { at: Date.now(), report };
      return report;
    })
    .finally(() => {
      healthState.inflight = null;
    });
  return healthState.inflight;
}

import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { withFalconExtrasClient } from "@/lib/mcp/falcon-extras-client";
import { parseConcatenatedJson, detectFalconError, isScopeDenied } from "@/lib/mcp/parse";
import { db } from "@/lib/db/client";
import { postureSnapshots } from "@/lib/db/schema";
import { getActiveEnvironmentId } from "@/lib/config/environments";
import {
  normalizeAssets,
  normalizeApplications,
  normalizeAccounts,
  summarizeDiscover,
  type DiscoverSnapshot,
} from "@/lib/discover/inventory";
import {
  normalizePolicies,
  normalizeContentPatterns,
  summarizeDataProtection,
} from "@/lib/dataprotection/posture";
import { fetchDataSecurityEntities } from "@/lib/dataprotection/fetch";
import { nativeDiscoverEntity } from "@/lib/discover/native";
import { nativeSidecarPayload } from "@/lib/mcp/native-payload";
import { clusterCampaigns } from "@/lib/queue/campaigns";
import type { RankInput } from "@/lib/queue/rank";
import type { Detection } from "@/components/DetectionsTable";
import {
  POSTURE_SCHEMA_VERSION,
  emptyPostureMetrics,
  metricsArePartial,
  type PostureMetrics,
} from "./types";

// Deterministic point-in-time capture of the tenant's posture, written to
// posture_snapshots for trending. Pure data gathering — no LLM. Each of the
// seven categories is captured independently under Promise.allSettled: a
// rejected category (missing scope, upstream error) leaves its metrics null
// and flips the snapshot's `partial` flag, rather than failing the whole
// capture. Mirrors the dashboard routes' own fetch+parse (queue, discover,
// data-protection, identity, prevention, cases, vulnerabilities) and reuses
// their deterministic summarizers so the numbers match what the operator sees.

const DETECTION_WINDOW_DAYS = 14;
const SPOTLIGHT_FILTER = "status:'open'+cve.exprt_rating:['CRITICAL','HIGH']";

// Both extras tools and falcon-mcp tools return text content blocks; join them.
function toText(result: unknown): string {
  const content = ((result as { content?: unknown })?.content ?? []) as Array<{
    type: string;
    text?: string;
  }>;
  return content.map((c) => (c.type === "text" && c.text ? c.text : "")).join("\n");
}

// Sidecar (extras_*) tools return a single JSON object, not concatenated rows.
function parseExtras(result: unknown): Record<string, unknown> | null {
  try {
    const j = JSON.parse(toText(result)) as unknown;
    return j && typeof j === "object" ? (j as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

// ---- detections -----------------------------------------------------------

async function captureDetections(
  mcp: Client,
  extras: Client,
): Promise<Pick<PostureMetrics, "detections">> {
  const cutoff = new Date(
    Date.now() - DETECTION_WINDOW_DAYS * 86_400_000,
  ).toISOString();

  // Endpoint detections only (product:'epp'), mirroring /queue + /hosts/at-risk.
  const detResult = await mcp.callTool({
    name: "falcon_search_detections",
    arguments: {
      filter: `product:'epp'+created_timestamp:>'${cutoff}'+status:['new','reopened','in_progress']`,
      limit: 200,
      sort: "created_timestamp.desc",
    },
  });
  const detections = parseConcatenatedJson<Detection>(toText(detResult));
  const err = detectFalconError(detections);
  if (err) throw new Error(err);

  // Contained hosts via the sidecar — tolerated if unavailable (stays null).
  const containedAids = new Set<string>();
  let containedHosts: number | null = null;
  try {
    const cRes = await extras.callTool({
      name: "extras_host_list_contained",
      arguments: { limit: 200 },
    });
    const payload = parseExtras(cRes);
    if (payload?.ok === true && Array.isArray(payload.items)) {
      const items = payload.items as Array<{ device_id?: string }>;
      for (const h of items) if (h.device_id) containedAids.add(h.device_id);
      containedHosts = items.length;
    }
  } catch {
    // contained_hosts stays null
  }

  // Prefer Falcon's own severity bucket name; fall back to the numeric scale.
  const name = (d: Detection) => (d.severity_name ?? "").toLowerCase();
  const isCritical = (d: Detection) =>
    name(d) === "critical" || (!d.severity_name && (d.severity ?? 0) >= 90);
  const isHigh = (d: Detection) =>
    name(d) === "high" ||
    (!d.severity_name && (d.severity ?? 0) >= 70 && (d.severity ?? 0) < 90);

  const atRisk = new Set<string>();
  for (const d of detections) {
    const aid = d.device?.device_id;
    if (aid) atRisk.add(aid);
  }

  const merged: RankInput[] = detections.map((d) => ({ ...d, source: "epp" as const }));
  const campaigns = clusterCampaigns(merged, containedAids);

  return {
    detections: {
      open: detections.length,
      critical: detections.filter(isCritical).length,
      high: detections.filter(isHigh).length,
      contained_hosts: containedHosts,
      at_risk_hosts: atRisk.size,
      campaigns: campaigns.length,
    },
  };
}

// ---- vulnerabilities ------------------------------------------------------

type RawVuln = {
  id?: string;
  aid?: string;
  exprt_rating?: string;
  cve?: {
    id?: string;
    exprt_rating?: string;
    exploit_status?: number | string;
    is_cisa_kev?: boolean;
    cisa_info?: { is_cisa_kev?: boolean };
  };
  exploit_status?: number | string;
  host_info?: { device_id?: string };
};

async function captureVulns(mcp: Client): Promise<Pick<PostureMetrics, "vulns">> {
  // Scope to open CRITICAL/HIGH (same filter as the patch digest) to stay well
  // under the Spotlight ~5000-row timeout. falcon-mcp 0.14.0 lets `facet` take a
  // list (PR #460), so one call hydrates both the cve and host_info blocks per
  // record — no more cve+host_info fan-out + merge (empirically confirmed the
  // combined endpoint returns both sub-objects + top-level aid per row).
  const r = await mcp.callTool({
    name: "falcon_search_vulnerabilities",
    arguments: {
      filter: SPOTLIGHT_FILTER,
      sort: "created_timestamp|desc",
      limit: 1000,
      facet: ["cve", "host_info"],
    },
  });
  const rows = parseConcatenatedJson<RawVuln>(toText(r));
  const e = detectFalconError(rows);
  if (e) throw new Error(e);

  let openCritical = 0;
  let openHigh = 0;
  let kev = 0;
  let exploited = 0;
  const hosts = new Set<string>();
  for (const v of rows) {
    const cve = v.cve ?? {};
    const rating = String(cve.exprt_rating ?? v.exprt_rating ?? "").toUpperCase();
    if (rating === "CRITICAL") openCritical += 1;
    else if (rating === "HIGH") openHigh += 1;
    // KEV / exploit_status are stable Falcon Spotlight CVE fields not surfaced
    // by the token-bounded projection; read defensively off the raw payload.
    if (cve.cisa_info?.is_cisa_kev === true || cve.is_cisa_kev === true) kev += 1;
    const status = Number(cve.exploit_status ?? v.exploit_status);
    if (Number.isFinite(status) && status >= 90) exploited += 1; // 90 = "Actively Used"
    // host_info facet carries the device id at top-level `aid` (the host_info
    // sub-object holds hostname).
    const id = v.aid ?? v.host_info?.device_id;
    if (id) hosts.add(id);
  }

  return {
    vulns: {
      open_critical: openCritical,
      open_high: openHigh,
      kev,
      actively_exploited: exploited,
      affected_hosts: hosts.size,
    },
  };
}

// ---- coverage (Falcon Discover) -------------------------------------------

async function captureCoverage(
  mcp: Client,
  extras: Client,
): Promise<Pick<PostureMetrics, "coverage">> {
  const call = async (nm: string, args: Record<string, unknown>) => {
    const r = await extras.callTool({
      name: nm,
      arguments: { limit: 100, ...args },
    });
    return parseExtras(r);
  };
  const [assetsRaw, appsRaw, accountsRaw] = await Promise.all([
    call("extras_discover_assets", { scope: "all" }),
    call("extras_discover_applications", {}),
    nativeDiscoverEntity(mcp, "falcon_search_accounts", { limit: 100 }),
  ]);
  const snapshot: DiscoverSnapshot = {
    assets: normalizeAssets(assetsRaw),
    applications: normalizeApplications(appsRaw),
    accounts: normalizeAccounts(accountsRaw),
  };
  const summary = summarizeDiscover(snapshot);

  // Per-entity availability — an entity missing its scope (or erroring) nulls
  // only its own metrics rather than reporting a misleading zero. Counts are
  // over the sampled subset (Discover caps at 100/entity), so trend direction
  // is meaningful even though absolute coverage is a sample.
  const assetsOk = !snapshot.assets.scopePending && !snapshot.assets.error;
  const accountsOk = !snapshot.accounts.scopePending && !snapshot.accounts.error;
  const appsOk = !snapshot.applications.scopePending && !snapshot.applications.error;

  return {
    coverage: {
      managed: assetsOk ? summary.assets.managed : null,
      unmanaged: assetsOk ? summary.assets.unmanaged : null,
      stale_hosts: assetsOk ? summary.assets.stale.length : null,
      privileged_accounts: accountsOk ? summary.accounts.privileged : null,
      local_admins: accountsOk ? summary.accounts.localAdmins.length : null,
      suspicious_apps: appsOk ? summary.applications.suspicious.length : null,
    },
  };
}

// ---- identity -------------------------------------------------------------

async function captureIdentity(
  mcp: Client,
  extras: Client,
): Promise<Pick<PostureMetrics, "identity">> {
  // Three independent IDP calls; each nulls its own field on failure so a
  // partial-scope tenant still records what it can.
  const out: PostureMetrics["identity"] = {
    risky_entities: null,
    idp_detections_7d: null,
    policy_rules_enabled: null,
  };

  try {
    const p = await nativeSidecarPayload(mcp, "falcon_search_risky_identities", { limit: 100 });
    if (p?.ok === true && Array.isArray(p.items)) {
      const items = p.items as Array<{ riskScoreSeverity?: string }>;
      out.risky_entities = items.filter((n) => {
        const s = (n.riskScoreSeverity ?? "").toUpperCase();
        return s === "HIGH" || s === "CRITICAL";
      }).length;
    }
  } catch {
    // risky_entities stays null
  }

  try {
    const r = await extras.callTool({
      name: "extras_identity_detections",
      arguments: { hours: 168, limit: 500 },
    });
    const p = parseExtras(r);
    if (p?.ok === true && Array.isArray(p.items)) {
      out.idp_detections_7d = p.items.length;
    }
  } catch {
    // idp_detections_7d stays null
  }

  try {
    const p = await nativeSidecarPayload(mcp, "falcon_search_idp_policy_rules", { limit: 500 });
    if (p?.ok === true && Array.isArray(p.items)) {
      const items = p.items as Array<{ enabled?: boolean }>;
      out.policy_rules_enabled = items.filter((x) => x.enabled === true).length;
    }
  } catch {
    // policy_rules_enabled stays null
  }

  return { identity: out };
}

// ---- prevention -----------------------------------------------------------

async function capturePrevention(
  extras: Client,
): Promise<Pick<PostureMetrics, "prevention">> {
  const r = await extras.callTool({
    name: "extras_prevention_policy_posture",
    arguments: { limit: 500 },
  });
  const p = parseExtras(r);
  if (!p || p.ok !== true || !Array.isArray(p.items)) {
    return { prevention: { policies_preventing: null, policies_detect_only: null } };
  }
  const items = p.items as Array<{ enabled?: boolean; flags?: string[] }>;
  let preventing = 0;
  let detectOnly = 0;
  for (const it of items) {
    const flags = Array.isArray(it.flags) ? it.flags : [];
    const isDetectOnly = flags.some((f) => f.endsWith("_detect_only"));
    if (isDetectOnly) detectOnly += 1;
    if (it.enabled === true && !isDetectOnly) preventing += 1;
  }
  return {
    prevention: { policies_preventing: preventing, policies_detect_only: detectOnly },
  };
}

// ---- data protection ------------------------------------------------------

async function captureDataProtection(
  mcp: Client,
): Promise<Pick<PostureMetrics, "dataProtection">> {
  // Policies require platform_name; probe win first to short-circuit on a
  // missing scope (mirrors /data-protection). Paged — see lib/dataprotection/fetch.
  const win = await fetchDataSecurityEntities(mcp, "policy", { platform_name: "win" });
  if (win.kind === "scope_pending") {
    return { dataProtection: { policies_enabled: null, content_patterns: null } };
  }
  if (win.kind === "error") throw new Error(win.error);

  const [mac, patterns] = await Promise.all([
    fetchDataSecurityEntities(mcp, "policy", { platform_name: "mac" }),
    fetchDataSecurityEntities(mcp, "content_pattern"),
  ]);
  // A failed read must not record as "0 content patterns" in posture history.
  if (mac.kind === "error") throw new Error(mac.error);
  if (patterns.kind === "error") throw new Error(patterns.error);

  const policies = [
    ...normalizePolicies(win.rows, "win"),
    ...normalizePolicies(mac.kind === "ok" ? mac.rows : [], "mac"),
  ];
  const posture = summarizeDataProtection(
    policies,
    [],
    normalizeContentPatterns(patterns.kind === "ok" ? patterns.rows : []),
  );

  return {
    dataProtection: {
      policies_enabled: posture.policyCounts.enabled,
      content_patterns: posture.contentPatternCount,
    },
  };
}

// ---- cases ----------------------------------------------------------------

type RawCase = Record<string, unknown>;

async function captureCases(mcp: Client): Promise<Pick<PostureMetrics, "cases">> {
  const r = await mcp.callTool({
    name: "falcon_search_cases",
    // Sampling metric: caps at 200 most-recent cases. On a tenant with >200
    // open cases these counts under-report (there is no native case-count
    // aggregation to lean on) — acceptable for a posture headline, same as the
    // vulns `truncated` heuristic. Revisit if a case-aggregation read appears.
    arguments: { limit: 200, sort: "created_timestamp.desc" },
  });
  const text = toText(r);
  if (isScopeDenied(text)) {
    return { cases: { total: null, open: null, unassigned: null, high_sev: null } };
  }
  const parsed = parseConcatenatedJson<RawCase>(text);
  const err = detectFalconError(parsed);
  if (err) throw new Error(err);

  const str = (v: unknown) => (typeof v === "string" && v.trim() ? v : undefined);
  const num = (v: unknown) =>
    typeof v === "number" && Number.isFinite(v) ? v : undefined;

  const rows = parsed
    .filter((c) => str(c.id))
    .map((c) => ({
      status: str(c.status) ?? "unknown",
      severity: num(c.severity) ?? 0,
      assignee:
        str(c.assigned_to_name) ?? str(c.assigned_to) ?? str(c.assignee),
    }));

  return {
    cases: {
      total: rows.length,
      open: rows.filter(
        (c) =>
          c.status === "new" ||
          c.status === "in_progress" ||
          c.status === "reopened",
      ).length,
      unassigned: rows.filter((c) => !c.assignee).length,
      high_sev: rows.filter((c) => c.severity >= 75).length,
    },
  };
}

// ---- orchestration + persistence ------------------------------------------

function countNonNull(m: PostureMetrics): number {
  let n = 0;
  for (const cat of Object.values(m)) {
    for (const v of Object.values(cat as Record<string, unknown>)) {
      if (v !== null) n += 1;
    }
  }
  return n;
}

function insertSnapshot(
  metrics: PostureMetrics,
  meta: { capturedAt: string; envId: string; captureMs: number; partial: boolean },
): { ok: true } | { ok: false; error: string } {
  try {
    db()
      .insert(postureSnapshots)
      .values({
        capturedAt: meta.capturedAt,
        envId: meta.envId,
        schemaVersion: POSTURE_SCHEMA_VERSION,
        metricsJson: JSON.stringify(metrics),
        captureMs: meta.captureMs,
        partial: meta.partial,
      })
      .run();
    return { ok: true };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

export type CaptureResult = {
  ok: boolean;
  envId: string;
  capturedAt: string;
  captureMs: number;
  partial: boolean;
  metricsWritten: number;
  error?: string;
};

// Capture one posture snapshot for the active environment and persist it.
// Never throws — returns a result object the scheduler job renders. An empty
// capture (every category failed) is NOT persisted, to keep the trend clean.
export async function captureSnapshot(): Promise<CaptureResult> {
  const startedAt = Date.now();
  const capturedAt = new Date().toISOString();
  const envId = getActiveEnvironmentId();
  const metrics = emptyPostureMetrics();

  try {
    await withFalconMcpClient(async (mcp) =>
      withFalconExtrasClient(async (extras) => {
        const settled = await Promise.allSettled([
          captureDetections(mcp, extras),
          captureVulns(mcp),
          captureCoverage(mcp, extras),
          captureIdentity(mcp, extras),
          capturePrevention(extras),
          captureDataProtection(mcp),
          captureCases(mcp),
        ]);
        for (const s of settled) {
          if (s.status === "fulfilled") {
            Object.assign(metrics, s.value);
          } else {
            console.warn(
              "[posture] category capture failed:",
              s.reason instanceof Error ? s.reason.message : String(s.reason),
            );
          }
        }
      }),
    );
  } catch (err) {
    // Failed to open the Falcon clients at all (missing creds / sidecar down).
    return {
      ok: false,
      envId,
      capturedAt,
      captureMs: Date.now() - startedAt,
      partial: true,
      metricsWritten: 0,
      error: err instanceof Error ? err.message : String(err),
    };
  }

  const captureMs = Date.now() - startedAt;
  const partial = metricsArePartial(metrics);
  const metricsWritten = countNonNull(metrics);

  if (metricsWritten === 0) {
    return {
      ok: false,
      envId,
      capturedAt,
      captureMs,
      partial: true,
      metricsWritten: 0,
      error: "No posture categories could be captured (check Falcon connection and scopes).",
    };
  }

  const inserted = insertSnapshot(metrics, { capturedAt, envId, captureMs, partial });
  if (!inserted.ok) {
    return { ok: false, envId, capturedAt, captureMs, partial, metricsWritten, error: inserted.error };
  }

  return { ok: true, envId, capturedAt, captureMs, partial, metricsWritten };
}

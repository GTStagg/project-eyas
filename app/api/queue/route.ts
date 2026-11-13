import { NextResponse } from "next/server";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { fetchContainedAids } from "@/lib/hosts/contained";
import { fetchIdentityDetections } from "@/lib/identity/fetch-detections";
import type { IdentityDetection } from "@/lib/identity/detections";
import { parseConcatenatedJson } from "@/lib/mcp/parse";
import {
  rankDetections,
  type IdentityOverlap,
  type QueueRow,
  type RankInput,
} from "@/lib/queue/rank";
import { clusterCampaigns, type Campaign } from "@/lib/queue/campaigns";
import { enrichRowsWithAdversary } from "@/lib/intel/adversary";
import type { Detection } from "@/components/DetectionsTable";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const WINDOW_DAYS = 14;
const ENDPOINT_LIMIT = 200;
const IDP_LIMIT = 50;
// Cap identity correlation to the top-N endpoint rows in the `top` bucket.
// Each correlation call spawns a fresh extras subprocess (~2s handshake) +
// the actual IDP GraphQL + Alerts query — keeping the count bounded matters.
const IDENTITY_OVERLAY_TOP_N = 5;
// 5-min process-scoped cache of correlation results keyed by AID. Falcon
// device records and IDP risk scores don't change minute-to-minute; this
// amortizes the ~10s correlation pass across repeat /queue loads. Module
// scope intentionally — not unstable_cache, which has a 2 MB envelope and
// poor invalidation here. Per-process means a server restart drops it.
const OVERLAY_TTL_MS = 5 * 60 * 1000;
const overlayCache = new Map<
  string,
  { overlay: IdentityOverlap; ts: number }
>();



export async function GET() {
  const cutoff = new Date(
    Date.now() - WINDOW_DAYS * 24 * 60 * 60 * 1000,
  ).toISOString();

  try {
    // The endpoint and identity detection searches and the adversary-name
    // resolution share ONE native client (the server handles concurrent
    // requests on one connection), saving extra spawns + OAuth token mints.
    // Contained AIDs open their own client.
    return await withFalconMcpClient(async (mcpClient) => {
      const [endpointRows, idpRows, containedAids] = await Promise.all([
        fetchOpenEndpointDetections(mcpClient, cutoff),
        fetchOpenIdpDetections(mcpClient),
        fetchContainedAids(),
      ]);

      const merged: RankInput[] = [
        ...endpointRows.map((d) => ({ ...d, source: "epp" as const })),
        ...idpRows,
      ];

      const rows: QueueRow[] = rankDetections(merged, containedAids);

      // Identity overlay: enrich the top-N endpoint rows in parallel via the
      // native host-identity correlation tool. Endpoint-only because IDP rows have no AID.
      // Fire-and-forget tolerant — if a single correlation call fails the row
      // simply lacks the field; the queue still renders.
      const overlayCount = await enrichTopRowsWithIdentity(rows);

      // Falcon-native adversary chip: resolve `adversary_ids` (set by Falcon's
      // own correlation engine on the raw detection record) to the canonical
      // actor name. One batched falcon_search_actors call covers every
      // distinct id across rows. Sparse signal — most rows leave the chip
      // unset. Reuses the shared client opened above.
      const adversaryCount = await enrichRowsWithAdversary(mcpClient, rows);

      // Cross-host campaign clustering — pure function over the merged set.
      // Artifact-based (sha256 / image+technique / lateral-movement-by-user),
      // never tactic-only. ≥2 unique hosts required per cluster.
      const campaigns: Campaign[] = clusterCampaigns(merged, containedAids);

      return NextResponse.json({
        ok: true,
        rows,
        campaigns,
        meta: {
          window_days: WINDOW_DAYS,
          total: rows.length,
          epp: rows.filter((r) => r.source === "epp").length,
          idp: rows.filter((r) => r.source === "idp").length,
          top: rows.filter((r) => r.bucket === "top").length,
          active: rows.filter((r) => r.bucket === "active").length,
          stale: rows.filter((r) => r.bucket === "stale").length,
          contained_overlay: containedAids.size,
          identity_overlay: overlayCount,
          adversary_overlay: adversaryCount,
          campaigns: campaigns.length,
        },
      });
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

async function fetchOpenEndpointDetections(
  client: Client,
  cutoffIso: string,
): Promise<Detection[]> {
  // Scope to ENDPOINT detections (product:'epp'). The unified Alerts API
  // backing falcon_search_detections returns every product type — endpoint,
  // ngsiem (correlation rules), idp, etc. Without this filter, tenants
  // with NGSIEM test rules or chatty correlation rules drown out the
  // endpoint queue.
  //
  // IDP detections come in via fetchOpenIdpDetections (open only, with the
  // policy-match noise dropped). NGSIEM correlation results live on /ngsiem.
  const filter =
    `product:'epp'+` +
    `created_timestamp:>'${cutoffIso}'+` +
    `status:['new','reopened','in_progress']`;
  const result = await client.callTool({
    name: "falcon_search_detections",
    arguments: {
      filter,
      limit: ENDPOINT_LIMIT,
      sort: "created_timestamp.desc",
    },
  });
  const text = (result.content as Array<{ type: string; text?: string }>)
    .map((c) => (c.type === "text" && c.text ? c.text : ""))
    .join("\n");
  return parseConcatenatedJson<Detection>(text);
}

async function fetchOpenIdpDetections(client: Client): Promise<RankInput[]> {
  // Open identity detections from the native detection search, with Eyas's
  // rules on top (lib/identity/detections.ts): open status only, and the
  // "Policy rule match" enforcement noise (empty tactic) dropped. If the
  // tenant lacks Identity Protection scopes this returns [] silently — the
  // queue degrades to endpoint-only with no error surfaced to the user.
  let items: IdentityDetection[] = [];
  try {
    const payload = await fetchIdentityDetections(client, {
      hours: WINDOW_DAYS * 24,
      limit: IDP_LIMIT,
    });
    if (payload.ok === true && Array.isArray(payload.items)) {
      items = payload.items as IdentityDetection[];
    }
  } catch {
    items = [];
  }

  if (items.length === 0) return [];

  // Normalize to the Detection shape so rankDetections can score uniformly.
  // The hostname slot on the synthetic device gets source_endpoint_host_name
  // (with .domain stripped) so the per-host concentration counter still
  // works across endpoint + identity rows on the same machine.
  return items.map((it) => {
    const rawHost = it.source_endpoint_host_name ?? "";
    const shortHost = rawHost.split(".")[0]?.toUpperCase() || "";
    return {
      source: "idp" as const,
      composite_id: it.composite_id,
      id: it.id,
      severity: it.severity,
      severity_name: it.severity_name,
      display_name: it.display_name,
      description: it.description,
      created_timestamp: it.created_timestamp,
      status: it.status,
      tactic: it.tactic,
      technique: it.technique,
      user_name: it.user_name ?? it.source_account_name,
      device: shortHost
        ? { hostname: shortHost, platform_name: "Identity" }
        : undefined,
      falcon_host_link: it.falcon_host_link,
      // IDP-specific extras for UI rendering — typed as additional fields on
      // QueueRow downstream.
      idp_user_name: it.user_name ?? it.source_account_name,
      idp_source_account: it.source_account_name
        ? `${it.source_account_domain ?? ""}\\${it.source_account_name}`.replace(
            /^\\/,
            "",
          )
        : undefined,
      idp_source_endpoint: it.source_endpoint_host_name,
    } as RankInput;
  });
}

// Mutates the rows array in place: attaches identity_overlap to up to
// IDENTITY_OVERLAY_TOP_N endpoint rows in the `top` bucket. Returns the
// number of rows actually enriched. All correlation calls share a single
// eyas-mcp client connection rather than spawning per-call.
async function enrichTopRowsWithIdentity(rows: QueueRow[]): Promise<number> {
  const candidates = rows
    .filter(
      (r) =>
        r.source === "epp" &&
        r.bucket === "top" &&
        Boolean(
          (r as { device?: { device_id?: string } }).device?.device_id,
        ),
    )
    // Dedup by device_id — multiple detections on the same host share an
    // overlay, no need to fan out twice.
    .reduce<QueueRow[]>((acc, r) => {
      const aid = (r as { device?: { device_id?: string } }).device?.device_id;
      if (!aid) return acc;
      if (!acc.some((x) => x.device?.device_id === aid)) acc.push(r);
      return acc;
    }, [])
    .slice(0, IDENTITY_OVERLAY_TOP_N);

  if (candidates.length === 0) return 0;

  // Cache hit / miss split.
  const now = Date.now();
  const overlays = new Map<string, IdentityOverlap>();
  const toFetch: string[] = [];
  for (const r of candidates) {
    const aid = r.device?.device_id;
    if (!aid) continue;
    const hit = overlayCache.get(aid);
    if (hit && now - hit.ts < OVERLAY_TTL_MS) {
      overlays.set(aid, hit.overlay);
    } else {
      toFetch.push(aid);
    }
  }

  if (toFetch.length > 0) {
    // Native host -> identity correlation (eyas-mcp). One shared client:
    // the server handles concurrent requests on a connection.
    await withFalconMcpClient(async (client) => {
      await Promise.all(
        toFetch.map(async (aid) => {
          try {
            const result = await client.callTool({
              name: "falcon_correlate_host_identity",
              arguments: { device_id: aid },
            });
            const text = (
              result.content as Array<{ type: string; text?: string }>
            )
              .map((c) => (c.type === "text" && c.text ? c.text : ""))
              .join("\n");
            const payload = JSON.parse(text);
            // Native shape: { host, identity (camelCase) | null, identity_match,
            // idp_detections[] } — an error returns an { error } envelope.
            if (!payload || payload.error || !payload.host) return;
            const identity = payload.identity ?? null;
            const overlay: IdentityOverlap = {
              identity_resolved: identity !== null,
              last_login_user: payload.host?.last_login_user ?? undefined,
              primary_display_name: identity?.primaryDisplayName ?? undefined,
              risk_score: identity?.riskScore ?? undefined,
              risk_score_severity: identity?.riskScoreSeverity ?? undefined,
              risk_factors: identity?.riskFactors ?? undefined,
              idp_detection_count: Array.isArray(payload.idp_detections)
                ? payload.idp_detections.length
                : 0,
            };
            overlays.set(aid, overlay);
            overlayCache.set(aid, { overlay, ts: Date.now() });
          } catch {
            // Tolerated — row simply lacks the field.
          }
        }),
      );
    });
  }

  let attached = 0;
  for (const r of rows) {
    const aid = (r as { device?: { device_id?: string } }).device?.device_id;
    if (!aid) continue;
    const overlay = overlays.get(aid);
    if (overlay) {
      r.identity_overlap = overlay;
      attached += 1;
    }
  }
  return attached;
}


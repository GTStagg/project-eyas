import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { detectFalconError, parseConcatenatedJson } from "@/lib/mcp/parse";
import type { Host } from "@/components/HostsTable";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Detection = {
  device?: {
    device_id?: string;
    hostname?: string;
  };
  created_timestamp?: string;
  severity?: number;
  status?: string;
};

type AtRiskHost = {
  device_id: string;
  hostname: string;
  platform_name?: string;
  os_product_name?: string;
  os_version?: string;
  rtr_state?: string;
  status?: string;
  product_type_desc?: string;
  detection_count_24h: number; // legacy field name; window is now 72h
  highest_severity: number;
  most_recent_detection_ts: string;
};

export async function GET() {
  const cutoff = new Date(Date.now() - 72 * 60 * 60 * 1000).toISOString();

  try {
    const items = await withFalconMcpClient(async (client) => {
      const detResult = await client.callTool({
        name: "falcon_search_detections",
        arguments: {
          // Endpoint detections only (product:'epp'). Without this, NGSIEM
          // correlation rules — which have no device_id and would be skipped
          // anyway — consume the 200-row limit and starve real endpoint
          // detections off the at-risk list. See app/api/queue/route.ts for
          // the longer rationale.
          filter: `product:'epp'+created_timestamp:>'${cutoff}'`,
          limit: 200,
          sort: "created_timestamp.desc",
        },
      });
      const detText = (
        detResult.content as Array<{ type: string; text?: string }>
      )
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      const detections = parseConcatenatedJson<Detection>(detText);
      // Promote a wrapped upstream error / structured scope-denial (both arrive
      // as a single {error, details:{status_code}} object) to a real failure
      // instead of rendering it as a junk host row. NOTE: do NOT use
      // isScopeDenied here — its prose-substring fallback ("unauthorized",
      // "access denied") false-positives on legitimate detection names/cmdlines.
      // detectFalconError keys on the structured single-object envelope only.
      const detErr = detectFalconError(detections);
      if (detErr) throw new Error(detErr);

      const byHost = new Map<string, AtRiskHost>();
      for (const d of detections) {
        const aid = d.device?.device_id;
        const host = d.device?.hostname;
        if (!aid || !host) continue;
        const existing = byHost.get(aid);
        if (existing) {
          existing.detection_count_24h += 1;
          if ((d.severity ?? 0) > existing.highest_severity) {
            existing.highest_severity = d.severity ?? 0;
          }
          // Upstream `sort` is silently ignored on falcon_search_detections, so
          // don't assume rows arrive newest-first — track the true max.
          if ((d.created_timestamp ?? "") > existing.most_recent_detection_ts) {
            existing.most_recent_detection_ts = d.created_timestamp ?? existing.most_recent_detection_ts;
          }
        } else {
          byHost.set(aid, {
            device_id: aid,
            hostname: host,
            detection_count_24h: 1,
            highest_severity: d.severity ?? 0,
            most_recent_detection_ts: d.created_timestamp ?? "",
          });
        }
      }

      // Enrich with host records — detection.device is sparse and lacks
      // rtr_state, platform_name, os_product_name. Without this the action
      // buttons mis-classify hosts as "not RTR-eligible" because rtr_state
      // is undefined. One extra API call for all unique AIDs.
      const aids = Array.from(byHost.keys());
      if (aids.length > 0) {
        const filterValue =
          "device_id:[" + aids.map((a) => `'${a}'`).join(",") + "]";
        const hostsResult = await client.callTool({
          name: "falcon_search_hosts",
          arguments: { filter: filterValue, limit: aids.length },
        });
        const hostsText = (
          hostsResult.content as Array<{ type: string; text?: string }>
        )
          .map((c) => (c.type === "text" && c.text ? c.text : ""))
          .join("\n");
        const hostRecords = parseConcatenatedJson<Host>(hostsText);
        for (const h of hostRecords) {
          if (!h.device_id) continue;
          const r = byHost.get(h.device_id);
          if (!r) continue;
          r.platform_name = h.platform_name;
          r.os_product_name = h.os_product_name;
          r.os_version = h.os_version;
          r.rtr_state = h.rtr_state;
          r.status = h.status;
          r.product_type_desc = h.product_type_desc;
        }
      }

      return Array.from(byHost.values()).sort((a, b) => {
        if (b.highest_severity !== a.highest_severity) {
          return b.highest_severity - a.highest_severity;
        }
        return b.most_recent_detection_ts.localeCompare(
          a.most_recent_detection_ts,
        );
      });
    });

    return NextResponse.json({ ok: true, items });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

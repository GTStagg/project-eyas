import { NextResponse } from "next/server";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { detectFalconError, parseConcatenatedJson } from "@/lib/mcp/parse";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Action-time host enumeration for a patch bundle. The /vulnerabilities page
// fetches a capped firehose of (host × CVE) rows; if a popular CVE exists on
// many hosts, the sample undercounts. Before the patch agent runs we re-query
// Spotlight with a CVE-scoped filter and no client-side truncation so the
// agent operates on the full host set.
type Body = { cve_ids?: string[] };
type Vuln = {
  aid?: string;
  hostname?: string;
  host_info?: { device_id?: string; hostname?: string };
};

const CVE_RX = /^CVE-\d{4}-\d{1,7}$/i;
const MAX_CVE_IDS = 50;
const FETCH_LIMIT = 5000;

// FQL filter length matters; chunk to 100 device ids per call. falcon-mcp
// 0.16.0 (#478) interleaves concurrent requests on ONE connection, so a single
// shared client with bounded concurrency beats the old 4-client shard pool for
// this moderate call shape — a probe measured ~1.7x faster (fleet 1051, 106
// chunks: ~16s vs ~28s) with 3 fewer process spawns + OAuth mints. The 40-token
// server-side limiter comfortably covers this cap.
const CHUNK_SIZE = 100;
const MAX_CONCURRENCY = 8;

type ManagedFilterResult = {
  managed: Set<string>;
  // Ids we COULDN'T verify because the sensor-managed lookup faulted for their
  // chunk. They're included in `managed` (permissive fallback — better than
  // dropping hosts the operator expects patched), but the caller is told the
  // filter was degraded so "N hosts" isn't read as "N verified sensor hosts".
  unverified: Set<string>;
};

async function managedHostFilter(ids: string[]): Promise<ManagedFilterResult> {
  if (ids.length === 0) return { managed: new Set(), unverified: new Set() };
  const chunks: string[][] = [];
  for (let i = 0; i < ids.length; i += CHUNK_SIZE) chunks.push(ids.slice(i, i + CHUNK_SIZE));
  const managed = new Set<string>();
  const unverified = new Set<string>();

  await withFalconMcpClient(async (client) => {
    const lookupChunk = async (chunk: string[]) => {
      const filter = `device_id:[${chunk.map((id) => `'${id}'`).join(",")}]`;
      try {
        const result = await client.callTool({
          name: "falcon_search_hosts",
          arguments: { filter, limit: CHUNK_SIZE },
        });
        const text = (result.content as Array<{ type: string; text?: string }>)
          .map((c) => (c.type === "text" && c.text ? c.text : ""))
          .join("\n");
        const parsed = parseConcatenatedJson<{ device_id?: string }>(text);
        const upstreamErr = detectFalconError(parsed);
        if (upstreamErr) throw new Error(upstreamErr);
        for (const h of parsed) if (h.device_id) managed.add(h.device_id);
      } catch {
        // On lookup failure, treat the whole chunk as managed (permissive
        // fallback) — better to over-include than to silently drop hosts the
        // operator expects patched. Flag them unverified so the response can
        // signal a degraded filter instead of routing patch actions to
        // possibly-sensorless hosts with no warning.
        for (const id of chunk) {
          managed.add(id);
          unverified.add(id);
        }
      }
    };

    // Bounded-concurrency map over chunks on the single shared client. Set
    // mutations are race-free (single-threaded event loop; only await points
    // interleave).
    let next = 0;
    const workers = Array.from(
      { length: Math.min(MAX_CONCURRENCY, chunks.length) },
      async () => {
        while (next < chunks.length) {
          await lookupChunk(chunks[next++]);
        }
      },
    );
    await Promise.all(workers);
  });

  return { managed, unverified };
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const cveIds = (Array.isArray(body.cve_ids) ? body.cve_ids : [])
    .filter((s): s is string => typeof s === "string" && CVE_RX.test(s))
    .slice(0, MAX_CVE_IDS);
  if (cveIds.length === 0) {
    return NextResponse.json(
      { ok: false, error: "cve_ids required (CVE-YYYY-NNNN format)" },
      { status: 400 },
    );
  }
  const filter = `status:'open'+cve.id:[${cveIds.map((id) => `'${id}'`).join(",")}]`;

  try {
    const items = await withFalconMcpClient(async (client) => {
      const result = await client.callTool({
        name: "falcon_search_vulnerabilities",
        arguments: { filter, facet: "host_info", limit: FETCH_LIMIT },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      const parsed = parseConcatenatedJson<Vuln>(text);
      const upstreamErr = detectFalconError(parsed);
      if (upstreamErr) throw new Error(upstreamErr);
      return parsed;
    });

    const candidateIds = new Set<string>();
    const hostnames = new Set<string>();
    for (const v of items) {
      const id = v.aid ?? v.host_info?.device_id;
      if (id) candidateIds.add(id);
      const hn = v.hostname ?? v.host_info?.hostname;
      if (hn) hostnames.add(hn);
    }

    // Cross-reference against managed Hosts before returning. NVA-discovered
    // hosts have no sensor; the RTR session would fail to initialize. Filter
    // them out here so the patch agent only ever sees actionable device ids.
    const { managed, unverified } = await managedHostFilter(Array.from(candidateIds));
    const deviceIds = Array.from(candidateIds).filter((id) => managed.has(id));
    const droppedNva = candidateIds.size - deviceIds.length;
    const unverifiedCount = deviceIds.filter((id) => unverified.has(id)).length;

    return NextResponse.json({
      ok: true,
      device_ids: deviceIds,
      hostnames: Array.from(hostnames),
      row_count: items.length,
      truncated: items.length >= FETCH_LIMIT,
      dropped_nva: droppedNva,
      // The sensor-managed cross-check faulted for some ids; they're included
      // (permissive) but unverified, so a few may be sensorless and fail RTR.
      filter_degraded: unverifiedCount > 0,
      unverified_count: unverifiedCount,
    });
  } catch (err) {
    return NextResponse.json(
      { ok: false, error: err instanceof Error ? err.message : String(err) },
      { status: 502 },
    );
  }
}

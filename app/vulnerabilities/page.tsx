import Link from "next/link";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";
import { detectFalconError, parseConcatenatedJson } from "@/lib/mcp/parse";
import { classifyPatchCoverage } from "@/lib/eyas-tools/rtr-tools";
import AppShell from "@/components/AppShell";
import VulnerabilitiesTable, {
  type Vulnerability,
  type ViewMode,
  type FilterKey,
} from "@/components/VulnerabilitiesTable";
import VulnerabilityTriagePanel from "@/components/VulnerabilityTriagePanel";

export const dynamic = "force-dynamic";

type Mode = "newest" | "exploited" | "critical";

const MODES: Record<Mode, { filter: string; label: string; sub: string; defaultLimit: number }> = {
  newest: {
    filter: "status:'open'",
    label: "Newest",
    sub: "freshest detections across the fleet",
    defaultLimit: 500,
  },
  critical: {
    filter: "status:'open'+cve.exprt_rating:['CRITICAL','HIGH']",
    label: "Critical + High",
    sub: "ExPRT rating Critical or High (CrowdStrike risk-adjusted)",
    defaultLimit: 1000,
  },
  exploited: {
    filter: "status:'open'+cve.exprt_rating:['CRITICAL']",
    label: "Actively exploited",
    sub: "ExPRT rating Critical only. Actively-exploited tier.",
    defaultLimit: 1000,
  },
};

const LIMIT_OPTIONS = [100, 500, 2000] as const;
// Critical-first: an analyst landing here wants "what's scary right now",
// not the freshest 500 rows. Modes default to their own depth, view, and
// filter chips so the surface is actionable on first paint.
const DEFAULT_MODE: Mode = "critical";

// Per-host cap: server-side trim that keeps the worst-K vulns per host so a
// single noisy host (5,000+ open vulns is normal on stale servers) can't
// saturate the depth-limited fetch. Without this, the 2,000-row Spotlight
// budget gets eaten by 1-2 hosts and the rest of the fleet's Critical CVEs
// never make it into the table. Ranked by ExPRT bucket → exploit_status →
// CISA KEV → CVSS so the top-K reflect "what would I actually patch first".
// Posture/hero stats are computed off the uncapped set so headline numbers
// don't shift with the cap.
const CAP_OPTIONS = [3, 5, 10, 0] as const; // 0 = off
const DEFAULT_CAP = 5;
type Cap = (typeof CAP_OPTIONS)[number];

function pickMode(raw: string | undefined): Mode {
  if (raw === "exploited" || raw === "critical" || raw === "newest") return raw;
  return DEFAULT_MODE;
}
function pickLimit(raw: string | undefined, mode: Mode): number {
  const n = raw ? parseInt(raw, 10) : NaN;
  if (!Number.isFinite(n)) return MODES[mode].defaultLimit;
  return LIMIT_OPTIONS.find((opt) => opt === n) ?? MODES[mode].defaultLimit;
}
function pickView(raw: string | undefined, mode: Mode): ViewMode {
  if (raw === "flat" || raw === "patch" || raw === "host") return raw;
  // Critical/exploited modes default to By patch — that's the actionable
  // shape ("Update Firefox · 150.0 closes 23 hosts"). Newest stays flat.
  return mode === "newest" ? "flat" : "patch";
}
function pickCap(raw: string | undefined): Cap {
  if (raw == null) return DEFAULT_CAP;
  const n = parseInt(raw, 10);
  if (!Number.isFinite(n)) return DEFAULT_CAP;
  return (CAP_OPTIONS as readonly number[]).includes(n) ? (n as Cap) : DEFAULT_CAP;
}
function pickFilters(raw: string | undefined, mode: Mode): FilterKey[] {
  if (raw == null) {
    // Default filter chips per mode. Critical/exploited surface only patchable
    // items so the By-patch view doesn't get crowded by no-fix bundles.
    if (mode === "newest") return [];
    if (mode === "exploited") return ["exploited", "hasFix"];
    return ["criticalHigh", "hasFix"];
  }
  const valid: FilterKey[] = ["criticalHigh", "exploited", "hasFix", "stale", "kev"];
  return raw
    .split(",")
    .map((s) => s.trim() as FilterKey)
    .filter((s) => valid.includes(s));
}

// Single-connection fetch: one facet-list vuln call + one managed-hosts query
// in one Promise.all over a shared MCP connection. falcon-mcp 0.14.0 accepts a
// list `facet` (PR #460), so ONE call hydrates the cve, host_info and
// remediation blocks per record — no per-facet fan-out + merge. Cached at the
// call site via unstable_cache.
async function fetchAndEnrich(
  filter: string,
  limit: number,
): Promise<{ items: Vulnerability[] } | { error: string }> {
  const attempt = async (): Promise<Vulnerability[]> =>
    withFalconMcpClient(async (client) => {
      const baseArgs = { filter, sort: "created_timestamp|desc", limit };
      const fetchManagedHosts = async (): Promise<Set<string>> => {
        const result = await client.callTool({
          name: "falcon_search_hosts",
          arguments: { limit: 5000 },
        });
        const text = (result.content as Array<{ type: string; text?: string }>)
          .map((c) => (c.type === "text" && c.text ? c.text : ""))
          .join("\n");
        const parsed = parseConcatenatedJson<{ device_id?: string }>(text);
        const upstreamErr = detectFalconError(parsed);
        if (upstreamErr) throw new Error(upstreamErr);
        const set = new Set<string>();
        for (const h of parsed) if (h.device_id) set.add(h.device_id);
        return set;
      };
      // One facet-list call (falcon-mcp 0.14.0 PR #460) hydrates the cve,
      // host_info and remediation blocks per record — no more per-facet fan-out
      // + merge-by-id (mirrors lib/posture/snapshot.ts + patch-digest.ts).
      // Fanned out alongside the managed-host enrollment so the cross-reference
      // overlaps the Spotlight call.
      const fetchVulns = async (): Promise<Vulnerability[]> => {
        const result = await client.callTool({
          name: "falcon_search_vulnerabilities",
          arguments: { ...baseArgs, facet: ["cve", "host_info", "remediation"] },
        });
        const text = (result.content as Array<{ type: string; text?: string }>)
          .map((c) => (c.type === "text" && c.text ? c.text : ""))
          .join("\n");
        const parsed = parseConcatenatedJson<Vulnerability>(text);
        const upstreamErr = detectFalconError(parsed);
        if (upstreamErr) throw new Error(upstreamErr);
        return parsed;
      };
      const [rows, managed] = await Promise.all([fetchVulns(), fetchManagedHosts()]);
      // Each row already carries cve + host_info + remediation sub-objects plus
      // a top-level aid, so no cross-facet merge-by-id is needed. Normalize the
      // top-level hostname/platform/os_version off host_info and stamp
      // _unmanaged from the managed-host set, exactly as before.
      const merged: Vulnerability[] = rows.map((r) => {
        const aid = r.aid ?? r.host_info?.device_id;
        return {
          ...r,
          hostname: r.hostname ?? r.host_info?.hostname,
          platform: r.platform ?? r.host_info?.platform,
          os_version: r.os_version ?? r.host_info?.os_version,
          _unmanaged: !aid || !managed.has(aid),
        };
      });
      merged.sort((a, b) =>
        (b.created_timestamp ?? "").localeCompare(a.created_timestamp ?? ""),
      );
      return merged;
    });

  try {
    return { items: await attempt() };
  } catch {
    try {
      return { items: await attempt() };
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  }
}

// Per-host fan-out fetcher. Solves the saturation bug Spotlight's row-clustered
// ordering creates: a tenant where 2 hosts hold 600+ Critical+High vulns each
// will see ALL 1,000-2,000 globally-fetched rows come from those 2 hosts, and
// the rest of the fleet's worst CVEs never enter the table. Strategy:
//   1. Enumerate managed hosts (single falcon_search_hosts call, ~5s).
//   2. Fan out per-AID Spotlight queries — one facet-list call (cve +
//      remediation) per host — across PARALLEL_WORKERS fresh MCP clients. Each
//      worker handles its slice serially (falcon-mcp serializes JSON-RPC per
//      client per the persistent-singleton lesson), so true concurrency comes
//      from spawning multiple clients. A probe confirmed that for these heavy
//      Spotlight queries the multi-process fan-out beats a single pooled client.
//   3. Apply per-host top-K trim so we only render the worst-K per host
//      (remediation entities already ride on each row from step 2).
// Truncates fleets larger than MAX_FANOUT_HOSTS to keep wallclock bounded.
// 8 parallel falcon-mcp child processes. Each is its own withFalconMcpClient
// context — falcon-mcp serializes JSON-RPC per client, so true concurrency
// only comes from spawning multiple clients (see CLAUDE.md "MCP concurrency"
// gotcha + the persistent-singleton revert). On a 200-host fleet sweep,
// 4 workers → ~1m40s wall-clock; 8 workers halves that. The cost is 4 extra
// short-lived python processes (~50 MB RSS each) for the duration of the
// fan-out — well inside the budget on any host running this app.
const FANOUT_PARALLEL_WORKERS = 8;
const FANOUT_MAX_HOSTS = 200;

type FanoutMeta = {
  affectedHosts: number;
  trimmedHosts: number;
  trimmedRows: number;
  worstHost?: { hostname: string; total: number };
  fleetTruncated: boolean;
  fleetSize: number;
};

async function fetchPerHostFanout(
  baseFilter: string,
  perHostCap: number,
): Promise<{ items: Vulnerability[]; meta: FanoutMeta } | { error: string }> {
  const PER_HOST_LIMIT = Math.max(perHostCap * 3, 30);

  type HostRecord = {
    device_id?: string;
    hostname?: string;
    platform_name?: string;
    os_product_name?: string;
    os_version?: string;
  };

  try {
    const managed = await withFalconMcpClient(async (client) => {
      const result = await client.callTool({
        name: "falcon_search_hosts",
        arguments: { limit: 5000 },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      const parsed = parseConcatenatedJson<HostRecord>(text);
      const upstreamErr = detectFalconError(parsed);
      if (upstreamErr) throw new Error(upstreamErr);
      return parsed;
    });

    const aidToHost = new Map<string, HostRecord>();
    for (const h of managed) if (h.device_id) aidToHost.set(h.device_id, h);
    const aids = Array.from(aidToHost.keys());
    const fleetTruncated = aids.length > FANOUT_MAX_HOSTS;
    const targetAids = fleetTruncated ? aids.slice(0, FANOUT_MAX_HOSTS) : aids;

    // Round-robin distribute AIDs across worker shards so each worker has
    // roughly equal sequential work to process.
    const shards: string[][] = Array.from({ length: FANOUT_PARALLEL_WORKERS }, () => []);
    targetAids.forEach((aid, i) => shards[i % FANOUT_PARALLEL_WORKERS].push(aid));

    const allRows: Vulnerability[] = (
      await Promise.all(
        shards.map(async (shard): Promise<Vulnerability[]> => {
          if (shard.length === 0) return [];
          return withFalconMcpClient(async (client) => {
            const out: Vulnerability[] = [];
            for (const aid of shard) {
              const baseArgs = {
                filter: `${baseFilter}+aid:'${aid}'`,
                sort: "created_timestamp|desc",
                limit: PER_HOST_LIMIT,
              };
              const callFacet = async (
                facet: string | string[],
              ): Promise<Vulnerability[]> => {
                const result = await client.callTool({
                  name: "falcon_search_vulnerabilities",
                  arguments: { ...baseArgs, facet },
                });
                const text = (result.content as Array<{ type: string; text?: string }>)
                  .map((c) => (c.type === "text" && c.text ? c.text : ""))
                  .join("\n");
                const parsed = parseConcatenatedJson<Vulnerability>(text);
                if (detectFalconError(parsed)) return [];
                return parsed;
              };
              try {
                // One facet-list call per host (falcon-mcp 0.14.0 PR #460): the
                // cve (ExPRT/exploit_status/KEV) and remediation (entities for
                // By-patch grouping) blocks hydrate as sub-objects on a single
                // row set, so the old two-call fan-out + merge-by-id is gone.
                // host_info is intentionally NOT requested here — it's stamped
                // from the managed-host enumeration in the normalization step
                // below. (The 8-client shard topology stays: for these heavy
                // Spotlight queries the multi-process fan-out beats a single
                // pooled client, and the gap widens with fleet size.)
                const rows = await callFacet(["cve", "remediation"]);
                for (const r of rows) {
                  if (!r.aid) r.aid = aid;
                }
                out.push(...rows);
              } catch {
                // Per-host failures don't kill the whole fan-out.
                continue;
              }
            }
            return out;
          });
        }),
      )
    ).flat();

    // Per-host trim: keep top perHostCap rows ranked by composite score.
    const byAid = new Map<string, Vulnerability[]>();
    for (const r of allRows) {
      const aid = r.aid ?? r.host_info?.device_id;
      if (!aid) continue;
      const arr = byAid.get(aid);
      if (arr) arr.push(r);
      else byAid.set(aid, [r]);
    }
    let trimmedHosts = 0;
    let trimmedRows = 0;
    let worstHost: { hostname: string; total: number } | undefined;
    const trimmed: Vulnerability[] = [];
    for (const [aid, rows] of byAid) {
      rows.sort((a, b) => rowScore(b) - rowScore(a));
      const keep = rows.slice(0, perHostCap);
      trimmed.push(...keep);
      if (rows.length > perHostCap) {
        trimmedHosts += 1;
        trimmedRows += rows.length - perHostCap;
        const hn = aidToHost.get(aid)?.hostname ?? aid;
        // PER_HOST_LIMIT caps what the fetch returned, so `rows.length` is at
        // most PER_HOST_LIMIT — undercounts true totals on saturating hosts.
        // Reported value is "rows seen in this fetch", not authoritative.
        if (!worstHost || rows.length > worstHost.total) {
          worstHost = { hostname: hn, total: rows.length };
        }
      }
    }

    // Remediation entities already ride on each row from the per-host
    // facet-list call (cve + remediation hydrated together, no merge).
    const merged: Vulnerability[] = trimmed.map((r) => {
      const aid = r.aid ?? r.host_info?.device_id;
      const h = aid ? aidToHost.get(aid) : undefined;
      return {
        ...r,
        hostname: r.hostname ?? h?.hostname,
        platform: r.platform ?? h?.platform_name,
        os_version: r.os_version ?? h?.os_version,
        host_info:
          r.host_info ??
          (h
            ? {
                hostname: h.hostname,
                device_id: h.device_id,
                platform: h.platform_name,
                os_version: h.os_version,
              }
            : undefined),
        // Every aid in this path came from the managed-host enumeration, so
        // by construction these are sensor-installed; no _unmanaged stamp.
        _unmanaged: false,
      };
    });
    merged.sort((a, b) => rowScore(b) - rowScore(a));

    return {
      items: merged,
      meta: {
        affectedHosts: byAid.size,
        trimmedHosts,
        trimmedRows,
        worstHost,
        fleetTruncated,
        fleetSize: aids.length,
      },
    };
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

// 60s in-memory TTL cache keyed on (filter, limit). Module-scoped, lives
// for the Node process lifetime. We use this instead of next/cache's
// unstable_cache because the full vuln payload (1000+ rows × nested CVE +
// apps + remediation) exceeds unstable_cache's 2MB serialization limit.
// Fine for a single-instance deployment; if we ever shard, swap for Redis.
type FetchResult =
  | { items: Vulnerability[]; meta?: FanoutMeta }
  | { error: string };
type CacheEntry = { expiresAt: number; result: FetchResult };
const FETCH_CACHE = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 60_000;

// Coverage-gap enrichment. Both fetch paths funnel through cachedFetchAndEnrich,
// so this single pre-cache pass stamps `capability_gap` on the global AND the
// per-host fan-out result. A "gap" is a Windows remediation that no curated
// patch script covers but the generic installer can still close at runtime
// (operator supplies a vendor URL). The sidecar classifier is the source of
// truth; we just feed it the distinct (vendor, product, os) triples.
//
// Dedup is load-bearing: thousands of rows collapse to dozens of products, so
// the sidecar payload stays tiny. Index alignment (results[i] <-> triples[i])
// is guaranteed by classify_patch_coverage. Never throws — a sidecar that's
// down or scope-gated degrades to "no badge", never a broken page.
const GAP_TRIPLE_SEP = "";
function deriveGapTriple(r: Vulnerability): { vendor: string; product: string; os: string } {
  const app = r.apps?.[0];
  const vendor = app?.vendor ?? app?.vendor_normalized ?? "";
  const product =
    app?.product_name_normalized ?? app?.product_name_version ?? r.product ?? "";
  const os = r.platform ?? r.host_info?.platform ?? "";
  return { vendor, product, os };
}
function gapTripleKey(t: { vendor: string; product: string; os: string }): string {
  return `${t.vendor}${GAP_TRIPLE_SEP}${t.product}${GAP_TRIPLE_SEP}${t.os}`.toLowerCase();
}

async function attachCapabilityGap(rows: Vulnerability[]): Promise<Vulnerability[]> {
  if (rows.length === 0) return rows;
  try {
    const distinct = new Map<string, { vendor: string; product: string; os: string }>();
    for (const r of rows) {
      const t = deriveGapTriple(r);
      if (!t.product) continue; // can't classify without a product name
      const key = gapTripleKey(t);
      if (!distinct.has(key)) distinct.set(key, t);
    }
    if (distinct.size === 0) return rows;

    const triples = [...distinct.values()];
    // Classified against Eyas's own patch catalog; no Falcon call.
    const parsed = classifyPatchCoverage(triples) as {
      ok?: boolean;
      results?: Array<{ generic_installer_eligible?: boolean }>;
    };
    const eligible = new Set<string>();
    if (parsed.ok && Array.isArray(parsed.results)) {
      parsed.results.forEach((res, i) => {
        if (res.generic_installer_eligible && triples[i]) eligible.add(gapTripleKey(triples[i]));
      });
    }

    if (eligible.size === 0) return rows;
    return rows.map((r) => {
      const t = deriveGapTriple(r);
      if (!t.product) return r;
      return eligible.has(gapTripleKey(t)) ? { ...r, capability_gap: true } : r;
    });
  } catch {
    return rows;
  }
}

async function cachedFetchAndEnrich(
  filter: string,
  limit: number,
  cap: number,
): Promise<FetchResult> {
  // cap > 0 → per-host fan-out path (fleet-spread). cap = 0 → original
  // global Spotlight fetch (raw set, can saturate to 1-2 hosts).
  const key = cap > 0 ? `fanout::${filter}::cap=${cap}` : `global::${filter}::limit=${limit}`;
  const now = Date.now();
  const cached = FETCH_CACHE.get(key);
  if (cached && cached.expiresAt > now) return cached.result;
  const result: FetchResult = cap > 0
    ? await fetchPerHostFanout(filter, cap)
    : await fetchAndEnrich(filter, limit);
  // Don't cache errors — let the next request retry instead of pinning a
  // failure for 60s. Successful empty results are still cached.
  if ("items" in result) {
    // Stamp generic-installer coverage gaps before caching so both fetch
    // paths get the badge and the classification is paid once per 60s window.
    result.items = await attachCapabilityGap(result.items);
    FETCH_CACHE.set(key, { expiresAt: now + CACHE_TTL_MS, result });
    // Soft-prune expired entries each write so the map doesn't grow
    // unbounded on tenants that touch many distinct (filter, limit) combos.
    if (FETCH_CACHE.size > 32) {
      for (const [k, v] of FETCH_CACHE) {
        if (v.expiresAt <= now) FETCH_CACHE.delete(k);
      }
    }
  }
  return result;
}

// Mode-independent hero-stats fetch. Pulls all open vulns at a high cap
// using only the two facets the hero cards need (cve + remediation), so
// "Drop everything" / "ExPRT Critical" describe the whole tenant rather
// than whatever subset the current mode/depth happens to have loaded.
// Cached longer than the per-mode fetch (5 min) since it's not parameterized.
//
// Why limit=2000: 5000-row Spotlight calls were timing out at the falcon-mcp
// 60s ceiling. 2000 fits well inside the
// timeout and still describes the bulk of any realistic tenant. The `total`
// value below also drives the "Open vulnerabilities" tile (which previously
// did its own paginated count up to 20k — three sequential 60s calls that
// dominated page load). Tile renders "2,000+" when truncated; precise tenant
// totals are a Spotlight Console concern, not a triage one.
type HeroStatsAll = {
  exploitedWithFix: number;
  exprtCritical: number;
  exprtHigh: number;
  exprtCriticalHigh: number;
  activelyExploited: number;
  exprtExploited: number;
  kevCount: number;
  total: number;
  truncated: boolean;
};
const HERO_STATS_LIMIT = 2000;
const HERO_STATS_TTL_MS = 5 * 60_000;
let HERO_STATS_CACHE: { expiresAt: number; result: HeroStatsAll | { error: string } } | null = null;

async function fetchHeroStatsAll(): Promise<HeroStatsAll | { error: string }> {
  const now = Date.now();
  if (HERO_STATS_CACHE && HERO_STATS_CACHE.expiresAt > now) return HERO_STATS_CACHE.result;

  const attempt = async (): Promise<HeroStatsAll> =>
    withFalconMcpClient(async (client) => {
      // falcon-mcp 0.14.0 accepts a list facet (PR #460): one call hydrates the
      // cve and remediation blocks per record, so the prior "call cve facet +
      // call remediation facet + merge by id" collapses to a single call whose
      // rows already carry both sub-objects (mirrors lib/posture/snapshot.ts +
      // lib/scheduler/patch-digest.ts).
      const result = await client.callTool({
        name: "falcon_search_vulnerabilities",
        arguments: {
          filter: "status:'open'",
          sort: "created_timestamp|desc",
          limit: HERO_STATS_LIMIT,
          facet: ["cve", "remediation"],
        },
      });
      const text = (result.content as Array<{ type: string; text?: string }>)
        .map((c) => (c.type === "text" && c.text ? c.text : ""))
        .join("\n");
      const merged = parseConcatenatedJson<Vulnerability>(text);
      const upstreamErr = detectFalconError(merged);
      if (upstreamErr) throw new Error(upstreamErr);
      const s = heroStats(merged);
      return { ...s, total: merged.length, truncated: merged.length >= HERO_STATS_LIMIT };
    });

  try {
    const result = await attempt();
    HERO_STATS_CACHE = { expiresAt: now + HERO_STATS_TTL_MS, result };
    return result;
  } catch {
    try {
      const result = await attempt();
      HERO_STATS_CACHE = { expiresAt: now + HERO_STATS_TTL_MS, result };
      return result;
    } catch (err) {
      return { error: err instanceof Error ? err.message : String(err) };
    }
  }
}

function hostCount(items: Vulnerability[]): number {
  const set = new Set<string>();
  for (const v of items) {
    const h = v.hostname ?? v.host_info?.hostname;
    if (h) set.add(h);
  }
  return set.size;
}

// Hero strip stats. Computed from a separate, mode-independent fetch
// (`fetchHeroStatsAll`) so the cards always describe the full open-vuln
// universe — switching posture mode or depth cap doesn't move them.
//
// activelyExploited is CrowdStrike's union signal: ExPRT High/Critical OR
// exploit_status >= 60 OR CISA KEV. ExPRT is the lead — this is a CrowdStrike
// tool, and the analyst-curated rating + exploit_status are the primary
// signals. CISA KEV is folded in because the catalog occasionally adds CVEs
// ahead of ExPRT graduating them, so leaving it out under-reads the surface.
// exprtExploited and kevCount are kept separately so the sub-line can break
// the headline number out by source.
function heroStats(items: Vulnerability[]): {
  exploitedWithFix: number;
  exprtCritical: number;
  exprtHigh: number;
  exprtCriticalHigh: number;
  activelyExploited: number;
  exprtExploited: number;
  kevCount: number;
} {
  let exploitedWithFix = 0;
  let exprtCritical = 0;
  let exprtHigh = 0;
  let activelyExploited = 0;
  let exprtExploited = 0;
  let kevCount = 0;
  for (const v of items) {
    const exprt = (v.exprt_rating ?? v.cve?.exprt_rating ?? "").toUpperCase();
    const exploitStatus = v.cve?.exploit_status ?? 0;
    const exprtSide = exprt === "CRITICAL" || exprt === "HIGH" || exploitStatus >= 60;
    const kev = v.cve?.cisa_info?.is_cisa_kev === true;
    const rem = v.remediation;
    const hasFix = Array.isArray(rem)
      ? rem.length > 0
      : !!(rem && ((rem.entities && rem.entities.length > 0) || (rem.ids && rem.ids.length > 0)));
    if ((exprtSide || kev) && hasFix) exploitedWithFix += 1;
    if (exprt === "CRITICAL") exprtCritical += 1;
    if (exprt === "HIGH") exprtHigh += 1;
    if (exprtSide) exprtExploited += 1;
    if (kev) kevCount += 1;
    if (exprtSide || kev) activelyExploited += 1;
  }
  return {
    exploitedWithFix,
    exprtCritical,
    exprtHigh,
    exprtCriticalHigh: exprtCritical + exprtHigh,
    activelyExploited,
    exprtExploited,
    kevCount,
  };
}

// Posture-health tiles. Pure derivation from the fetched items — describes the
// shape of the open-vuln set in the current posture mode. Unlike hero cards
// (which call out drop-everything urgency), these answer "how big is my
// problem". On a filtered fetch (mode=critical/exploited) the totals describe
// that filtered universe — labels make this explicit.
function postureStats(items: Vulnerability[]): {
  total: number;
  hosts: number;
  avgAgeDays: number | null;
  patchableCount: number;
  patchablePct: number;
  unmanagedHosts: number;
} {
  if (items.length === 0) {
    return { total: 0, hosts: 0, avgAgeDays: null, patchableCount: 0, patchablePct: 0, unmanagedHosts: 0 };
  }
  const hostSet = new Set<string>();
  const unmanagedHostSet = new Set<string>();
  let ageSum = 0;
  let ageN = 0;
  let patchable = 0;
  const now = Date.now();
  for (const v of items) {
    const hn = v.hostname ?? v.host_info?.hostname;
    if (hn) {
      hostSet.add(hn);
      if (v._unmanaged) unmanagedHostSet.add(hn);
    }
    if (v.created_timestamp) {
      const t = Date.parse(v.created_timestamp);
      if (!Number.isNaN(t)) {
        ageSum += Math.floor((now - t) / 86_400_000);
        ageN += 1;
      }
    }
    const rem = v.remediation;
    const hasFix = Array.isArray(rem)
      ? rem.length > 0
      : !!(rem && ((rem.entities && rem.entities.length > 0) || (rem.ids && rem.ids.length > 0)));
    if (hasFix) patchable += 1;
  }
  return {
    total: items.length,
    hosts: hostSet.size,
    avgAgeDays: ageN > 0 ? Math.round(ageSum / ageN) : null,
    patchableCount: patchable,
    patchablePct: Math.round((patchable / items.length) * 100),
    unmanagedHosts: unmanagedHostSet.size,
  };
}

function buildHref(params: {
  mode?: Mode;
  limit?: number;
  view?: ViewMode;
  filter?: FilterKey[];
  cap?: Cap;
}): string {
  const sp = new URLSearchParams();
  if (params.mode) sp.set("mode", params.mode);
  if (params.limit) sp.set("limit", String(params.limit));
  if (params.view) sp.set("view", params.view);
  if (params.filter && params.filter.length > 0) sp.set("filter", params.filter.join(","));
  if (params.cap != null && params.cap !== DEFAULT_CAP) sp.set("cap", String(params.cap));
  return `/vulnerabilities?${sp.toString()}`;
}

const EXPRT_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  MINIMAL: 0,
};
function rowScore(v: Vulnerability): number {
  const exprt = (v.exprt_rating ?? v.cve?.exprt_rating ?? "").toUpperCase();
  const r = EXPRT_RANK[exprt] ?? 0;
  const es = v.cve?.exploit_status ?? 0;
  const kev = v.cve?.cisa_info?.is_cisa_kev ? 1 : 0;
  const cvss = v.cve?.base_score ?? v.cvss_base_score ?? 0;
  // Composite: ExPRT bucket dominates, then exploit_status (0–100), KEV
  // tiebreaker (~exploit_status one-band), CVSS finest tiebreaker.
  return r * 1_000_000 + es * 1000 + kev * 500 + Math.round(cvss * 10);
}
function applyPerHostCap(
  items: Vulnerability[],
  cap: number,
): {
  items: Vulnerability[];
  trimmedHosts: number;
  trimmedRows: number;
  worstHost?: { hostname: string; total: number };
} {
  if (cap <= 0) return { items, trimmedHosts: 0, trimmedRows: 0 };
  const byHost = new Map<string, Vulnerability[]>();
  const noHost: Vulnerability[] = [];
  for (const v of items) {
    const h = v.hostname ?? v.host_info?.hostname;
    if (!h) {
      noHost.push(v);
      continue;
    }
    const arr = byHost.get(h);
    if (arr) arr.push(v);
    else byHost.set(h, [v]);
  }
  let trimmedHosts = 0;
  let trimmedRows = 0;
  let worstHost: { hostname: string; total: number } | undefined;
  const out: Vulnerability[] = [];
  for (const [hostname, rows] of byHost) {
    if (rows.length <= cap) {
      out.push(...rows);
      continue;
    }
    rows.sort((a, b) => rowScore(b) - rowScore(a));
    out.push(...rows.slice(0, cap));
    trimmedHosts += 1;
    trimmedRows += rows.length - cap;
    if (!worstHost || rows.length > worstHost.total) {
      worstHost = { hostname, total: rows.length };
    }
  }
  out.push(...noHost);
  // Re-sort the capped set by composite score so the table opens with the
  // worst-of-the-worst at top regardless of host. Original surface sorted by
  // created_timestamp; that behaviour is preserved by the table's own sort
  // controls — this is just the initial paint order.
  out.sort((a, b) => rowScore(b) - rowScore(a));
  return { items: out, trimmedHosts, trimmedRows, worstHost };
}

export default async function VulnerabilitiesPage({
  searchParams,
}: {
  searchParams?: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = (await searchParams) ?? {};
  const mode = pickMode(typeof sp.mode === "string" ? sp.mode : undefined);
  const limit = pickLimit(typeof sp.limit === "string" ? sp.limit : undefined, mode);
  const view = pickView(typeof sp.view === "string" ? sp.view : undefined, mode);
  const filters = pickFilters(typeof sp.filter === "string" ? sp.filter : undefined, mode);
  const cap = pickCap(typeof sp.cap === "string" ? sp.cap : undefined);
  const modeDef = MODES[mode];
  const [result, heroAll] = await Promise.all([
    cachedFetchAndEnrich(modeDef.filter, limit, cap),
    fetchHeroStatsAll(),
  ]);
  const fullItems = "items" in result ? result.items : [];
  const fanoutMeta = "items" in result ? result.meta : undefined;
  // In fan-out path the items are already per-host trimmed; in global path
  // we trim here. `capResult` carries the trim metadata for the global path.
  const capResult = fanoutMeta ? null : applyPerHostCap(fullItems, cap);
  const items = capResult ? capResult.items : fullItems;
  const hosts = hostCount(items);
  // Global-path truncation = "Spotlight returned a full page". Fan-out path
  // truncation = "fleet exceeded MAX_FANOUT_HOSTS" — surfaced via meta.
  const truncated = !fanoutMeta && fullItems.length >= limit;
  // Hero cards prefer the unfiltered fleet stats; fall back to in-mode if that
  // fetch errored so the strip never goes blank.
  // In the fan-out path, `fullItems` is already per-host-trimmed, so it
  // can't drive hero stats (would underreport). Hero strip falls back to
  // the unfiltered heroAll fetch. If that also failed, we accept the
  // underreport rather than blank cards.
  const stats = "error" in heroAll ? heroStats(fullItems) : heroAll;
  const heroTotalLabel = "error" in heroAll
    ? null
    : { value: heroAll.total, truncated: heroAll.truncated };
  // postureStats off the rendered set in fan-out path is the right call —
  // total = trimmed set size, hosts = fleet coverage, both meaningful.
  const posture = postureStats(items);

  return (
    <AppShell title="Vulnerabilities">
      <main className="flex-1 px-6 py-8 sm:py-10">
        <div className="mx-auto max-w-6xl animate-fade-in-up">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <div className="eyebrow">Spotlight // Vulnerabilities</div>
              <h1 className="mt-2 text-4xl font-bold tracking-tight text-white">Open vulnerabilities</h1>
            </div>
            <span className="font-mono text-[12px] uppercase tracking-[0.12em] text-neutral-400">
              {items.length} vulns · {hosts}{" "}
              {hosts === 1 ? "host" : "hosts"}
              {fanoutMeta ? ` of ${fanoutMeta.fleetSize}${fanoutMeta.fleetTruncated ? "+" : ""}` : ""}
              {" · "}{modeDef.label.toLowerCase()}
              {cap > 0 ? ` · cap ${cap}/host (fleet sweep)` : ` · top ${limit} (raw)`}
            </span>
          </div>

          {"error" in result ? null : (
            <>
              <div className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
                <PostureTile
                  label="Open vulnerabilities"
                  value={
                    heroTotalLabel
                      ? `${heroTotalLabel.value.toLocaleString()}${heroTotalLabel.truncated ? "+" : ""}`
                      : posture.total.toLocaleString()
                  }
                  sub={
                    heroTotalLabel
                      ? heroTotalLabel.truncated
                        ? `at least this many across the fleet (sampled to ${HERO_STATS_LIMIT.toLocaleString()})`
                        : "across the fleet · all open"
                      : `in this view (${modeDef.label.toLowerCase()})`
                  }
                />
                <PostureTile
                  label="Hosts affected"
                  value={posture.hosts.toLocaleString()}
                  sub={posture.hosts > 0 ? `at least one open vuln` : "no exposed hosts"}
                />
                <PostureTile
                  label="Avg vuln age"
                  value={posture.avgAgeDays != null ? `${posture.avgAgeDays}d` : "—"}
                  sub="days since first detected"
                  tone={posture.avgAgeDays != null && posture.avgAgeDays >= 30 ? "amber" : "neutral"}
                />
                <PostureTile
                  label="Patchable today"
                  value={`${posture.patchablePct}%`}
                  sub={`${posture.patchableCount.toLocaleString()} of ${posture.total.toLocaleString()} have a vendor fix`}
                />
                <PostureTile
                  label="Unmanaged hosts"
                  value={posture.unmanagedHosts.toLocaleString()}
                  sub={
                    posture.unmanagedHosts > 0
                      ? "🛰 NVA-discovered · no Falcon sensor · manual remediation only"
                      : "every exposed host runs the Falcon sensor"
                  }
                  tone={posture.unmanagedHosts > 0 ? "amber" : "neutral"}
                />
              </div>
            <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              <HeroCard
                tone={stats.exploitedWithFix > 0 ? "red" : "good"}
                eyebrow="Drop everything"
                value={`${stats.exploitedWithFix}`}
                label="Actively exploited · fix available"
                sub={
                  stats.exploitedWithFix > 0
                    ? "Pick the worst patch bundle in By-patch view, build a plan."
                    : "✓ none right now. Every exploited CVE you can patch is patched."
                }
                href={buildHref({ mode: "critical", view: "patch", filter: ["exploited", "hasFix"], limit: 2000 })}
              />
              <HeroCard
                tone={stats.exprtCriticalHigh > 0 ? "amber" : "good"}
                eyebrow="ExPRT High+Critical"
                value={`${stats.exprtCriticalHigh}`}
                label="Top-tier risk across the fleet"
                sub={
                  stats.exprtCriticalHigh > 0
                    ? `${stats.exprtCritical} critical · ${stats.exprtHigh} high. Sorted by patch impact in the table below.`
                    : "✓ no High- or Critical-rated vulnerabilities open"
                }
                href={buildHref({ mode: "critical", view: "patch", filter: ["criticalHigh"], limit: 2000 })}
              />
              <HeroCard
                tone={stats.activelyExploited > 0 ? "red" : "good"}
                eyebrow="Actively exploited"
                value={`${stats.activelyExploited}`}
                label="CrowdStrike ExPRT or CISA KEV"
                sub={
                  stats.activelyExploited > 0
                    ? `${stats.exprtExploited} flagged by ExPRT · ${stats.kevCount} on CISA KEV. Patch first.`
                    : "✓ none right now. Every actively-exploited CVE in your tenant is closed."
                }
                href={buildHref({ mode: "critical", view: "patch", filter: ["exploited"], limit: 2000 })}
              />
            </div>
            <div className="mt-2 flex justify-end font-mono text-[11px] uppercase tracking-[0.14em]">
              <Link
                href="/vulnerabilities/adversary-exposure"
                className="rounded border border-neutral-800 bg-neutral-950 px-2 py-1 text-neutral-400 transition-colors hover:text-neutral-200"
                title="Cross-reference open CVEs against Falcon Intel adversaries. Coverage is sparse; use as enrichment, not as the headline triage signal."
              >
                Run adversary attribution agent →
              </Link>
            </div>
            </>
          )}

          <div className="mt-6 flex flex-wrap items-center gap-2 font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-400">
            <span>posture //</span>
            {(Object.keys(MODES) as Mode[]).map((m) => (
              <Link
                key={m}
                href={buildHref({ mode: m, cap })}
                className={`rounded border px-2 py-1 transition-colors ${
                  m === mode
                    ? "border-brand-700 bg-brand-950/40 text-oxblood-200"
                    : "border-neutral-800 bg-neutral-950 text-neutral-400 hover:text-neutral-200"
                }`}
                title={MODES[m].sub}
              >
                {MODES[m].label}
              </Link>
            ))}
            <span className="ml-3">depth //</span>
            {LIMIT_OPTIONS.map((n) => (
              <Link
                key={n}
                href={buildHref({ mode, view, filter: filters, limit: n, cap })}
                className={`rounded border px-2 py-1 transition-colors ${
                  n === limit
                    ? "border-brand-700 bg-brand-950/40 text-oxblood-200"
                    : "border-neutral-800 bg-neutral-950 text-neutral-400 hover:text-neutral-200"
                }`}
              >
                {n}
              </Link>
            ))}
            <span
              className="ml-3"
              title="Cap rows per host to prevent a single noisy server from saturating the depth budget. Within each host, the worst CVEs (ExPRT → exploit_status → KEV → CVSS) are kept."
            >
              per-host //
            </span>
            {CAP_OPTIONS.map((n) => (
              <Link
                key={n}
                href={buildHref({ mode, view, filter: filters, limit, cap: n })}
                className={`rounded border px-2 py-1 transition-colors ${
                  n === cap
                    ? "border-brand-700 bg-brand-950/40 text-oxblood-200"
                    : "border-neutral-800 bg-neutral-950 text-neutral-400 hover:text-neutral-200"
                }`}
              >
                {n === 0 ? "off" : `top ${n}`}
              </Link>
            ))}
          </div>

          {cap > 0 && fanoutMeta && (
            <div className="mt-3 rounded-md border border-neutral-800 bg-neutral-950/60 px-3 py-2 text-xs text-neutral-300">
              Fleet sweep: queried {fanoutMeta.fleetSize.toLocaleString()}
              {fanoutMeta.fleetTruncated ? `+ (capped at ${FANOUT_MAX_HOSTS})` : ""} managed{" "}
              {fanoutMeta.fleetSize === 1 ? "host" : "hosts"}, found{" "}
              {fanoutMeta.affectedHosts.toLocaleString()} with matching vulns, kept top {cap}{" "}
              per host.
              {fanoutMeta.trimmedRows > 0 &&
                ` Trimmed ${fanoutMeta.trimmedRows.toLocaleString()} lower-priority ${fanoutMeta.trimmedRows === 1 ? "row" : "rows"} across ${fanoutMeta.trimmedHosts} ${fanoutMeta.trimmedHosts === 1 ? "host" : "hosts"}.`}
              {fanoutMeta.worstHost &&
                ` ${fanoutMeta.worstHost.hostname} alone returned ${fanoutMeta.worstHost.total.toLocaleString()}+ rows; drill into that host for full coverage.`}{" "}
              Switch to <span className="font-mono">off</span> above for the raw global fetch.
            </div>
          )}
          {cap > 0 && fanoutMeta && fanoutMeta.fleetTruncated && (
            <div className="mt-2 rounded-md border border-amber-900/60 bg-amber-950/30 px-3 py-2 text-xs text-amber-200">
              Fleet sweep capped at {FANOUT_MAX_HOSTS} hosts; tenant has{" "}
              {fanoutMeta.fleetSize.toLocaleString()}. Hosts beyond the cap weren&apos;t queried.
            </div>
          )}

          {truncated && (
            <div className="mt-3 rounded-md border border-amber-900/60 bg-amber-950/30 px-3 py-2 text-xs text-amber-200">
              Showing top {limit} rows — your tenant has more matches than this depth.
              Counts and By-patch host totals shown on this page may undercount.
              {limit < 2000 && " Bump depth to 2000 above for a more complete picture."}
              {" "}The patch agent always re-enumerates the full host list per bundle before running, so execution is unaffected.
            </div>
          )}

          {"error" in result ? (
            <div className="mt-6 rounded-lg border border-red-900 bg-red-950/40 px-4 py-3 text-sm text-red-200">
              <div className="font-semibold">Failed to load vulnerabilities</div>
              <div className="mt-1 font-mono text-xs">{result.error}</div>
              <div className="mt-2 text-xs text-oxblood-300/70">
                Upstream Falcon API failure (retried once). This is usually
                transient — refresh in a moment.
              </div>
            </div>
          ) : (
            <>
              <div className="mt-6">
                <VulnerabilityTriagePanel openCount={items.length} />
              </div>
              <VulnerabilitiesTable items={items} defaultView={view} defaultFilters={filters} />
            </>
          )}
        </div>
      </main>
    </AppShell>
  );
}

const POSTURE_TILE_TONE: Record<"neutral" | "amber", { border: string; value: string }> = {
  neutral: { border: "border-neutral-800 bg-neutral-950/60", value: "text-neutral-100" },
  amber: { border: "border-amber-900/60 bg-amber-950/30", value: "text-amber-200" },
};

function PostureTile({
  label,
  value,
  sub,
  tone = "neutral",
}: {
  label: string;
  value: string;
  sub: string;
  tone?: "neutral" | "amber";
}) {
  const t = POSTURE_TILE_TONE[tone];
  return (
    <div className={`rounded-lg border px-4 py-3 ${t.border}`}>
      <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-400">{label}</div>
      <div className={`mt-1 font-mono text-2xl font-semibold tabular-nums ${t.value}`}>{value}</div>
      <div className="mt-1 text-xs text-neutral-400">{sub}</div>
    </div>
  );
}

const HERO_TONE: Record<"red" | "amber" | "good", string> = {
  red: "border-red-800 bg-red-950/40 hover:border-red-700",
  amber: "border-amber-800 bg-amber-950/40 hover:border-amber-700",
  good: "border-emerald-900/60 bg-emerald-950/30 hover:border-emerald-800",
};

const HERO_VALUE_TONE: Record<"red" | "amber" | "good", string> = {
  red: "text-red-200",
  amber: "text-amber-200",
  good: "text-emerald-300",
};

function HeroCard({
  tone,
  eyebrow,
  value,
  label,
  sub,
  href,
}: {
  tone: "red" | "amber" | "good";
  eyebrow: string;
  value: string;
  label: string;
  sub: string;
  href: string;
}) {
  return (
    <Link
      href={href}
      className={`block rounded-lg border px-4 py-3 transition-colors ${HERO_TONE[tone]}`}
    >
      <div className="font-mono text-[11px] uppercase tracking-[0.14em] text-neutral-400">{eyebrow}</div>
      <div className="mt-1 flex items-baseline gap-3">
        <span className={`font-mono text-3xl font-semibold tabular-nums ${HERO_VALUE_TONE[tone]}`}>
          {value}
        </span>
        <span className="text-sm font-medium text-neutral-200">{label}</span>
      </div>
      <div className="mt-1 text-xs text-neutral-400">{sub}</div>
    </Link>
  );
}

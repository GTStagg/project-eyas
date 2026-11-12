// Campaign-aware IR Phase 0 scope (extras_ir_campaign_scope).
//
// For every open endpoint detection on the host, walk the process ancestry
// once per unique pivot pid (detections sharing a pivot pay one walk), then
// union-find the pivots by shared NON-SYSTEM ancestor pid. Each cluster is one
// campaign: the detections rooted in the same attacker chain. System processes
// (explorer, services, svchost, lsass, …) never join two pivots, so unrelated
// user activity doesn't merge through the OS root.
//
// Each walk is one eyas-mcp falcon_get_process_tree call (no descendants),
// four at a time, inside a 50 s overall deadline and at most 24 pivots per
// call, newest first. Ported from the sidecar's ir/campaign_scope.py +
// ir/ancestry.py; clustering is tested in scripts/test-process-tree.mjs.

import type { EyasToolContext } from "../types";
import { annotateNodeVerdicts, basename, classifyDeliveryVector, type TreeNode } from "../process-tree/classifier";
import { alertId, checkDeviceId, displayName, OPEN_STATUSES, pick, statusOf, walkHostAlerts } from "./alerts";
import { ancestryOf, nativeTree, normalizePivotTime, toPid } from "./process-tree";

type Obj = Record<string, unknown>;
type Pid = number | string;

// Processes that sit above almost every user process. Excluded from the
// shared-ancestor match.
export const SYSTEM_ANCESTOR_BASENAMES = new Set([
  "system",
  "smss.exe",
  "csrss.exe",
  "wininit.exe",
  "winlogon.exe",
  "services.exe",
  "lsass.exe",
  "svchost.exe",
  "explorer.exe",
  "userinit.exe",
  "dwm.exe",
  "spoolsv.exe",
  "taskhostw.exe",
  "runtimebroker.exe",
  "fontdrvhost.exe",
  "sihost.exe",
  "ctfmon.exe",
  "searchhost.exe",
  "searchindexer.exe",
]);

const GLOBAL_DEADLINE_MS = 50_000;
const MAX_PIVOTS = 24;
const PARALLEL_WALKS = 4;
// Per-walk native time budget: what's left of the deadline, within these.
const WALK_BUDGET_MIN_S = 10;
const WALK_BUDGET_MAX_S = 35;
const WALK_WINDOW_MINUTES = 30;
const WALK_ANCESTRY_MAX = 12;

/** The pivot a detection names: its process_id, else the first behavior's
 *  process_id / target_process_id that is a whole number. */
export function extractPivotPid(rec: Obj): Pid | null {
  const own = rec.process_id;
  if (own !== null && own !== undefined) {
    const p = toPid(typeof own === "number" ? own : String(own));
    if (p !== null) return p;
  }
  for (const b of Array.isArray(rec.behaviors) ? rec.behaviors : []) {
    if (!b || typeof b !== "object") continue;
    for (const k of ["process_id", "target_process_id"]) {
      const v = (b as Obj)[k];
      if (v === null || v === undefined) continue;
      const p = toPid(typeof v === "number" ? v : String(v));
      if (p !== null) return p;
    }
  }
  return null;
}

const key = (p: unknown): string | null =>
  (typeof p === "number" && Number.isInteger(p)) || (typeof p === "string" && /^\d+$/.test(p)) ? String(p) : null;

/**
 * Union-find the pivots by shared non-system ancestor pid. Returns each
 * cluster's root pivot → its member pivots (insertion order of `ancestryByPivot`).
 */
export function clusterBySharedAncestry(ancestryByPivot: Map<Pid, TreeNode[]>): Map<Pid, Pid[]> {
  const pivots = [...ancestryByPivot.keys()];
  const byKey = new Map(pivots.map((p) => [String(p), p]));
  const parent = new Map<string, string>(pivots.map((p) => [String(p), String(p)]));
  const find = (x: string): string => {
    while ((parent.get(x) ?? x) !== x) {
      const px = parent.get(x) as string;
      parent.set(x, parent.get(px) ?? px);
      x = parent.get(x) as string;
    }
    return x;
  };
  const union = (a: string, b: string) => {
    const ra = find(a);
    const rb = find(b);
    if (ra !== rb) parent.set(ra, rb);
  };

  const ancestorToPivots = new Map<string, string[]>();
  for (const [pivot, ancestry] of ancestryByPivot) {
    for (const node of ancestry) {
      const apid = key(node.pid);
      if (apid === null) continue;
      if (SYSTEM_ANCESTOR_BASENAMES.has(basename(node.image))) continue;
      const list = ancestorToPivots.get(apid) ?? [];
      list.push(String(pivot));
      ancestorToPivots.set(apid, list);
    }
  }
  for (const list of ancestorToPivots.values()) {
    for (const other of list.slice(1)) union(list[0], other);
  }

  const clusters = new Map<Pid, Pid[]>();
  for (const pivot of pivots) {
    const root = byKey.get(find(String(pivot))) as Pid;
    const members = clusters.get(root) ?? [];
    members.push(pivot);
    clusters.set(root, members);
  }
  return clusters;
}

const pidSort = (a: Pid, b: Pid) => {
  const x = BigInt(a);
  const y = BigInt(b);
  return x < y ? -1 : x > y ? 1 : 0;
};

type Item = Obj & { composite_id: string; created_timestamp: unknown };

/** Per-cluster campaign records, biggest first. */
export function buildCampaignRecords(
  clusters: Map<Pid, Pid[]>,
  ancestryByPivot: Map<Pid, TreeNode[]>,
  byPivot: Map<Pid, Item[]>,
): Obj[] {
  const campaigns: Obj[] = [];
  for (const [rootPivot, members] of clusters) {
    const compositeIds: string[] = [];
    const timestamps: string[] = [];
    const ancestorCounts = new Map<string, number>();
    let deepest: TreeNode[] = [];
    for (const pp of members) {
      for (const it of byPivot.get(pp) ?? []) {
        compositeIds.push(it.composite_id);
        if (typeof it.created_timestamp === "string") timestamps.push(it.created_timestamp);
      }
      const anc = ancestryByPivot.get(pp) ?? [];
      for (const node of anc) {
        const apid = key(node.pid);
        if (apid !== null) ancestorCounts.set(apid, (ancestorCounts.get(apid) ?? 0) + 1);
      }
      if (anc.length > deepest.length) deepest = anc;
    }

    // Campaign root: the non-system ancestor in the most member chains, then
    // the highest up.
    let rootPid: unknown = null;
    let rootImage: unknown = null;
    let best = -1;
    for (const [apid, count] of ancestorCounts) {
      for (const pp of members) {
        const anc = ancestryByPivot.get(pp) ?? [];
        const depth = anc.findIndex((n) => key(n.pid) === apid);
        if (depth < 0) continue;
        const node = anc[depth];
        if (SYSTEM_ANCESTOR_BASENAMES.has(basename(node.image))) continue;
        const score = count * 10 + depth;
        if (score > best) {
          best = score;
          rootPid = node.pid;
          rootImage = node.image ?? null;
        }
      }
    }

    let dv: Obj;
    try {
      deepest.forEach((n, i) => (n.depth = i));
      annotateNodeVerdicts(deepest);
      dv = classifyDeliveryVector(deepest, { windowWidened: false });
    } catch (e) {
      dv = {
        kind: "unknown",
        confidence: "low",
        rationale: `classifier error: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`,
      };
    }

    timestamps.sort();
    campaigns.push({
      campaign_id: `cluster-${rootPivot}`,
      count: compositeIds.length,
      composite_ids: compositeIds,
      member_pivot_pids: [...members].sort(pidSort),
      root_pid: rootPid,
      root_image: rootImage,
      delivery_vector: dv,
      first_ts: timestamps[0] ?? null,
      last_ts: timestamps[timestamps.length - 1] ?? null,
      sample_ancestry: deepest.map((n) => ({
        pid: n.pid ?? null,
        image: n.image ?? null,
        cmdline: String(n.cmdline ?? "").slice(0, 200),
        ppid: n.ppid ?? null,
        ts: n.ts ?? null,
        ...(n.blocked === true ? { blocked: true } : {}),
      })),
    });
  }
  campaigns.sort((a, b) => {
    const d = (b.count as number) - (a.count as number);
    if (d !== 0) return d;
    const x = String(a.first_ts ?? "");
    const y = String(b.first_ts ?? "");
    return x < y ? -1 : x > y ? 1 : 0;
  });
  return campaigns;
}

const maxTs = (items: Item[]) =>
  items.reduce((m, d) => {
    const t = typeof d.created_timestamp === "string" ? d.created_timestamp : "";
    return t > m ? t : m;
  }, "");

/** extras_ir_campaign_scope. `now` is injectable for tests. */
export async function irCampaignScope(ctx: EyasToolContext, input: Obj, now: () => number = Date.now): Promise<Obj> {
  const startedAt = now();
  const deviceId = input.device_id;
  const bad = checkDeviceId(deviceId);
  if (bad) return bad;
  const aid = deviceId as string;

  // 1. Open endpoint detections on the host.
  const walk = await walkHostAlerts(ctx, aid, { openOnly: true });
  if (!walk.ok) return walk.payload;
  const items: Item[] = [];
  for (const r of walk.alerts) {
    if (!OPEN_STATUSES.has(statusOf(r))) continue;
    const cid = alertId(r);
    if (!cid) continue;
    items.push({
      composite_id: cid,
      created_timestamp: pick(r, "created_timestamp"),
      severity: pick(r, "severity"),
      severity_name: pick(r, "severity_name"),
      display_name: displayName(r),
      tactic: pick(r, "tactic"),
      technique: pick(r, "technique"),
      pivot_pid: extractPivotPid(r),
    });
  }
  if (items.length === 0) {
    return {
      ok: true,
      device_id: aid,
      campaigns: [],
      unclustered: [],
      total_open: 0,
      unique_pivots_walked: 0,
      walk_seconds: 0.0,
      note: "No open detections on this host.",
    };
  }

  // 2. Group by pivot.
  const byPivot = new Map<Pid, Item[]>();
  const pivotOfKey = new Map<string, Pid>();
  const noPivot: Item[] = [];
  for (const it of items) {
    const p = it.pivot_pid as Pid | null;
    if (p === null) {
      noPivot.push(it);
      continue;
    }
    const k = String(p);
    const canon = pivotOfKey.get(k) ?? p;
    pivotOfKey.set(k, canon);
    const list = byPivot.get(canon) ?? [];
    list.push(it);
    byPivot.set(canon, list);
  }

  // 3. Walk each pivot's ancestry, newest first, under the deadline.
  const deadline = startedAt + GLOBAL_DEADLINE_MS;
  const order = [...byPivot.entries()].sort((a, b) => {
    const x = maxTs(a[1]);
    const y = maxTs(b[1]);
    return x < y ? 1 : x > y ? -1 : 0;
  });
  const walked = order.slice(0, MAX_PIVOTS);
  const deferred = order.slice(MAX_PIVOTS);

  const ancestryByPivot = new Map<Pid, TreeNode[]>();
  const walkFailures = new Map<Pid, string>();
  for (const [pid] of deferred) {
    walkFailures.set(
      pid,
      `deferred — host has ${byPivot.size} unique pivots, capped at ${MAX_PIVOTS} per call (sorted by recency)`,
    );
  }

  const walkOne = async (pid: Pid, group: Item[]): Promise<void> => {
    const tsIso = maxTs(group);
    if (!tsIso) {
      walkFailures.set(pid, "no created_timestamp on any detection");
      return;
    }
    const pivotTime = normalizePivotTime(tsIso);
    if (!pivotTime) {
      walkFailures.set(pid, `bad pivot_ts_iso: ${tsIso}`);
      return;
    }
    const remainingS = Math.floor((deadline - now()) / 1000) - 2;
    if (remainingS < WALK_BUDGET_MIN_S) {
      walkFailures.set(pid, "deadline reached before walk completed");
      return;
    }
    const r = await nativeTree(ctx, {
      deviceId: aid,
      pivotTime,
      pivotPid: pid,
      windowMinutes: WALK_WINDOW_MINUTES,
      ancestryMax: WALK_ANCESTRY_MAX,
      descendantsMax: 1,
      budgetSeconds: Math.min(WALK_BUDGET_MAX_S, remainingS),
    });
    if (!r.ok) {
      walkFailures.set(pid, r.error);
      return;
    }
    const ancestry = ancestryOf(r.tree);
    if (ancestry.length === 0) {
      walkFailures.set(pid, "ancestry not reconstructible (telemetry aged out or pivot missing)");
      return;
    }
    ancestryByPivot.set(pid, ancestry);
  };

  let next = 0;
  const worker = async () => {
    while (next < walked.length) {
      const [pid, group] = walked[next++];
      if (now() >= deadline) {
        walkFailures.set(pid, "deadline reached before walk completed");
        continue;
      }
      await walkOne(pid, group);
    }
  };
  await Promise.all(Array.from({ length: Math.min(PARALLEL_WALKS, walked.length) }, worker));

  // Keep walk results in recency order so clusters list deterministically.
  const ordered = new Map<Pid, TreeNode[]>();
  for (const [pid] of walked) {
    const anc = ancestryByPivot.get(pid);
    if (anc) ordered.set(pid, anc);
  }

  // 4. Cluster and build the records.
  const clusters = clusterBySharedAncestry(ordered);
  const campaigns = buildCampaignRecords(clusters, ordered, byPivot);

  const unclustered: Obj[] = noPivot.map((det) => ({
    composite_id: det.composite_id,
    created_timestamp: det.created_timestamp ?? null,
    display_name: det.display_name ?? null,
    reason: "no pivot_pid on detection",
  }));
  for (const [pid] of order) {
    const reason = walkFailures.get(pid);
    if (reason === undefined) continue;
    for (const det of byPivot.get(pid) ?? []) {
      unclustered.push({
        composite_id: det.composite_id,
        created_timestamp: det.created_timestamp ?? null,
        display_name: det.display_name ?? null,
        pivot_pid: pid,
        reason,
      });
    }
  }

  const finishedAt = now();
  const walkSeconds = Math.round((finishedAt - startedAt) / 10) / 100;
  const deadlineReached = finishedAt >= deadline;
  const capped = deferred.length > 0;
  let note =
    "Phase 0 IR scope: pick the campaign matching the engagement (usually largest count + matching delivery_vector), " +
    "pass its `composite_ids` to Phase 4 close. `unclustered` are detections whose ancestry couldn't be reconstructed " +
    "— surface to operator for manual decision (do NOT bulk-include or bulk-exclude).";
  if (capped || deadlineReached) {
    note +=
      ` PARTIAL RESULT: walked ${ordered.size} of ${byPivot.size} unique pivots` +
      (deadlineReached ? " (deadline reached)" : "") +
      (capped ? ` (capped at ${MAX_PIVOTS})` : "") +
      ". Operator should review unclustered list for additional campaigns before closing.";
  }
  return {
    ok: true,
    device_id: aid,
    campaigns,
    unclustered,
    total_open: items.length,
    unique_pivots_walked: ordered.size,
    unique_pivots_total: byPivot.size,
    deadline_reached: deadlineReached,
    capped,
    walk_seconds: walkSeconds,
    note,
  };
}

import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { parseConcatenatedJson } from "@/lib/mcp/parse";

// Per-row attachment: a single resolved adversary chip. Rows with no
// adversary_ids leave `adversary` unset; rows with multiple ids attach
// the first that resolves (Falcon assigns a primary id when there are
// multiple — the lowest-id convention is consistent across the few
// multi-id rows seen).
export type AdversaryRef = { id: string; name?: string };

type RowWithAdversary = {
  has_adversary?: boolean;
  adversary_ids?: string[];
  adversary?: AdversaryRef;
};

type RawDetectionShape = {
  has_adversary?: boolean;
  adversary_ids?: unknown;
};

type RawActor = { id?: string | number; name?: string };

// Pull adversary_ids off a raw detection record (numbers coerced to strings
// for consistent map keys). Mirrors the extractor in lib/intel/attribution.ts
// so dashboards that bypass the agent-path projection still get the field.
export function extractAdversaryIds(d: RawDetectionShape): string[] {
  if (d.has_adversary !== true) return [];
  const raw = d.adversary_ids;
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  for (const id of raw) {
    if (typeof id === "string" && id) out.push(id);
    else if (typeof id === "number" && Number.isFinite(id)) out.push(String(id));
  }
  return out;
}

// 5-min process-scoped cache. Adversary id → name resolution is stable
// across a tenant's lifetime; the only churn is when CrowdStrike Intel
// renames a tracked adversary (rare). Module scope intentionally — drops
// on server restart.
const ACTOR_NAME_TTL_MS = 5 * 60 * 1000;
const actorNameCache = new Map<string, { name: string; ts: number }>();

// Batch-resolve a set of adversary ids to actor names via a single
// falcon_search_actors call using FQL set-membership: `id:[1,2,3]`.
// Returns a Map keyed by string id. Misses are simply absent — caller
// should skip the chip, not error.
export async function resolveAdversaryNames(
  mcp: Client,
  ids: string[],
): Promise<Map<string, string>> {
  const result = new Map<string, string>();
  if (ids.length === 0) return result;

  const now = Date.now();
  const toFetch: string[] = [];
  for (const id of ids) {
    const hit = actorNameCache.get(id);
    if (hit && now - hit.ts < ACTOR_NAME_TTL_MS) {
      result.set(id, hit.name);
    } else {
      toFetch.push(id);
    }
  }
  if (toFetch.length === 0) return result;

  // FQL `id:[1,2,3]` set membership. Numeric values, no quotes.
  const filter = `id:[${toFetch.join(",")}]`;
  try {
    const resp = (await mcp.callTool({
      name: "falcon_search_actors",
      arguments: { filter, limit: Math.min(toFetch.length, 50) },
    })) as { content: Array<{ type: string; text?: string }> };
    const text = resp.content
      .map((c) => (c.type === "text" && c.text ? c.text : ""))
      .join("\n");
    const records = parseConcatenatedJson<RawActor>(text);
    for (const rec of records) {
      const id = rec.id == null ? "" : String(rec.id);
      const name = typeof rec.name === "string" ? rec.name : "";
      if (id && name) {
        result.set(id, name);
        actorNameCache.set(id, { name, ts: Date.now() });
      }
    }
  } catch {
    // Tolerated — rows simply won't get the chip.
  }
  return result;
}

// Walk rows, collect distinct adversary ids, batch-resolve, attach the
// resolved chip in place. Returns count of rows enriched. Caller must
// have already populated `adversary_ids` on each row (extractAdversaryIds
// for raw rows, or pass-through from upstream).
export async function enrichRowsWithAdversary<T extends RowWithAdversary>(
  mcp: Client,
  rows: T[],
): Promise<number> {
  const allIds = new Set<string>();
  for (const r of rows) {
    for (const id of r.adversary_ids ?? []) allIds.add(id);
  }
  if (allIds.size === 0) return 0;

  const names = await resolveAdversaryNames(mcp, [...allIds]);
  let attached = 0;
  for (const r of rows) {
    const ids = r.adversary_ids ?? [];
    if (ids.length === 0) continue;
    // Attach the first id that resolves to a name. If none resolve, leave
    // `adversary` unset rather than rendering a chip with just a numeric id.
    for (const id of ids) {
      const name = names.get(id);
      if (name) {
        r.adversary = { id, name };
        attached += 1;
        break;
      }
    }
  }
  return attached;
}

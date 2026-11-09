import { parseConcatenatedJson, detectFalconError, isScopeDenied } from "@/lib/mcp/parse";

// Pure shaping for nativeSidecarPayload (lib/mcp/native-payload.ts): turn a
// native MCP-server search result's text into the payload the deterministic
// consumers read:
//   { ok: true, items, count, total?, totals_by_entity_type? } | { ok: true, scope_pending: true } | { ok: false, error }
//
// Two traps this handles:
// - Some native tools wrap an error as {results: [err], filter_used, fql_guide,
//   hint} with no `pagination`, which parseConcatenatedJson does not unwrap, so
//   a non-403 error would otherwise come back as one "row".
// - Scope denial is judged on the error object only. isScopeDenied's
//   substring fallback ("unauthorized", "access denied", …) must never run
//   over real data, where an application name or path can contain those words.

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);

/** The error dict a result carries, or null when it carries rows. */
function errorObject(rows: unknown[]): Obj | null {
  if (rows.length !== 1 || !isObj(rows[0])) return null;
  const first = rows[0];
  if (typeof first.error === "string") return first;
  // FQL-error wrapper: {results: [err], ...} without a pagination block.
  if (Array.isArray(first.results) && first.results.length === 1 && !isObj(first.pagination)) {
    const inner = first.results[0];
    if (isObj(inner) && typeof inner.error === "string") return inner;
  }
  return null;
}

export function shapeNativePayload(text: string): Obj {
  const rows = parseConcatenatedJson<unknown>(text);

  const err = errorObject(rows);
  if (err) {
    if (isScopeDenied(JSON.stringify(err))) return { ok: true, scope_pending: true };
    return { ok: false, error: detectFalconError([err]) ?? String(err.error) };
  }
  // Unparseable text (no rows at all): fall back to the wording check.
  if (rows.length === 0 && text.trim() && isScopeDenied(text)) {
    return { ok: true, scope_pending: true };
  }

  const items = rows.filter(isObj);
  let total: number | undefined;
  let typeTotals: Obj | undefined;
  try {
    const env = JSON.parse(text) as { pagination?: { total?: unknown }; totals_by_entity_type?: unknown };
    const t = env?.pagination?.total;
    if (typeof t === "number") total = t;
    // falcon_search_assets with include_type_totals: per-entity-type counts.
    if (isObj(env?.totals_by_entity_type)) typeTotals = env.totals_by_entity_type;
  } catch {
    // not a single envelope — consumers fall back to items.length
  }
  return {
    ok: true,
    items,
    count: items.length,
    total,
    ...(typeTotals ? { totals_by_entity_type: typeTotals } : {}),
  };
}

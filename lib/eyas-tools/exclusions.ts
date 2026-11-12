// IOA and ML exclusions: list (read) and create (approval-gated writes),
// formerly the sidecar's exclusions.py. Every Falcon call is an eyas-mcp
// native (falcon_search_exclusions / falcon_create_exclusion; the native
// create stays hidden from the agent in NATIVE_WRITE_SUPPRESS because these
// add the checks below).
//
// Both creates refuse a duplicate before the write (an existing exclusion
// means the operator's earlier decision still applies, and duplicates clutter
// the tenant). The IOA create also rejects zero-width assertions (^, $, \b,
// \A, \Z, \B), which Falcon's IOA DFA engine refuses with a cryptic error;
// bound the pattern with trailing `(\W.*)?` instead. Agent-supplied values
// interpolated into FQL literals are rejected if they hold a single quote,
// never escaped. Tested in scripts/test-exclusions.mjs.

import type { EyasToolContext } from "./types";
import { groupIdsOf } from "./quarantine";

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const pick = (r: Obj, k: string): unknown => (r[k] === undefined ? null : r[k]);

const ZERO_WIDTH = new Set(["\\b", "\\A", "\\Z", "\\B"]);

/** The first zero-width assertion in an IOA regex, or null. Escape-aware and
 *  character-class-aware: inside `[...]`, `^` is negation, `$` is a literal
 *  and `\b` is a backspace, all legal for the DFA. */
export function findZeroWidthAssertion(pattern: string): string | null {
  let escaped = false;
  let inClass = false;
  let classStart = -1;
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (escaped) {
      escaped = false;
      if (!inClass && ZERO_WIDTH.has(`\\${ch}`)) return `\\${ch}`;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      continue;
    }
    if (inClass) {
      // `]` closes the class unless it is the first member (`[]` / `[^]`).
      const firstMember = classStart + (pattern[classStart + 1] === "^" ? 2 : 1);
      if (ch === "]" && i > firstMember) inClass = false;
      continue;
    }
    if (ch === "[") {
      inClass = true;
      classStart = i;
      continue;
    }
    if (ch === "^") return "^";
    if (ch === "$") return "$";
  }
  return null;
}

/** Python repr of a str (for messages that quoted values with !r). */
export function pyRepr(s: string): string {
  const q = s.includes("'") && !s.includes('"') ? '"' : "'";
  const body = s.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t");
  return q + (q === "'" ? body.replace(/'/g, "\\'") : body) + q;
}

function scopePayload(surface: string, diagnostic: string): Obj {
  return {
    ok: true,
    scope_pending: true,
    surface,
    items: [],
    count: 0,
    note:
      `This call returned a permission error. The ${surface} surface renders empty until the Falcon ` +
      "API client is granted the required scope. Tell the operator: 'No data — required Falcon API " +
      `scope for ${surface} is not yet granted on this tenant.'`,
    _diagnostic: diagnostic.slice(0, 200),
  };
}

async function failPayload(surface: string, error: string): Promise<Obj> {
  const { isScopeDenied } = await import("@/lib/mcp/parse");
  return isScopeDenied(error) ? scopePayload(surface, error) : { ok: false, error, surface };
}

type Search = { ok: true; items: Obj[] } | { ok: false; payload: Obj };

async function searchExclusions(ctx: EyasToolContext, type: "ml" | "ioa", args: Obj, surface: string): Promise<Search> {
  const r = await ctx.searchNative("falcon_search_exclusions", { exclusion_type: type, ...args });
  if (!r.ok) return { ok: false, payload: await failPayload(surface, r.error) };
  if (r.scope_pending) return { ok: false, payload: scopePayload(surface, "permission denied") };
  return { ok: true, items: r.items };
}

// eyas-mcp returns an exclusion's host groups as id strings — under `groups`
// for ML and `host_groups` for IOA — where FalconPy gave {id, name} objects.
// group_ids reads either; groups shows each name when the record carries one
// and the id otherwise, so a group-scoped exclusion never looks unscoped.
const groupList = (r: Obj): unknown[] => [
  ...(Array.isArray(r.groups) ? r.groups : []),
  ...(Array.isArray(r.host_groups) ? r.host_groups : []),
];
const groupNames = (r: Obj) =>
  groupList(r)
    .map((g) => (typeof g === "string" ? g : isObj(g) ? (g.name ?? g.id ?? null) : null))
    .filter((g) => g !== null);
const groupIds = (r: Obj) => groupIdsOf(r);
const capLimit = (v: unknown) => Math.min(Math.max(typeof v === "number" && Number.isFinite(v) ? Math.trunc(v) : 100, 1), 500);

/** extras_list_ml_exclusions. */
export async function listMlExclusions(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  // Combined-endpoint sort uses a dot, not a pipe.
  const args: Obj = { limit: capLimit(input.limit), sort: "last_modified.desc" };
  if (typeof input.filter === "string" && input.filter) args.filter = input.filter;
  const s = await searchExclusions(ctx, "ml", args, "MLExclusions");
  if (!s.ok) return s.payload;
  const items = s.items.map((r) => ({
    id: pick(r, "id"),
    value: pick(r, "value"),
    regexp_value: pick(r, "regexp_value"),
    value_hash: pick(r, "value_hash"),
    applied_globally: pick(r, "applied_globally"),
    groups: groupNames(r),
    group_ids: groupIds(r),
    excluded_from: r.excluded_from || [],
    description: r.description || "",
    created_by: pick(r, "created_by"),
    created_on: pick(r, "created_on"),
    last_modified: pick(r, "last_modified"),
    modified_by: pick(r, "modified_by"),
  }));
  return { ok: true, items, count: items.length };
}

/** extras_list_ioa_exclusions. */
export async function listIoaExclusions(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  // The IOA exclusions endpoint rejects sort= entirely.
  const args: Obj = { limit: capLimit(input.limit) };
  if (typeof input.filter === "string" && input.filter) args.filter = input.filter;
  const s = await searchExclusions(ctx, "ioa", args, "IOAExclusions");
  if (!s.ok) return s.payload;
  const items = s.items.map((r) => ({
    id: pick(r, "id"),
    name: pick(r, "name"),
    description: pick(r, "description"),
    pattern_id: pick(r, "pattern_id"),
    pattern_name: pick(r, "pattern_name"),
    ifn_regex: pick(r, "ifn_regex"),
    cl_regex: pick(r, "cl_regex"),
    applied_globally: pick(r, "applied_globally"),
    groups: groupNames(r),
    group_ids: groupIds(r),
    created_by: pick(r, "created_by"),
    created_on: pick(r, "created_on"),
    last_modified: pick(r, "last_modified"),
    modified_by: pick(r, "modified_by"),
  }));
  return { ok: true, items, count: items.length };
}

const VALID_ML_EXCLUDED_FROM = ["blocking", "extraction"];
const strList = (v: unknown): string[] | null =>
  v === null || v === undefined ? null : Array.isArray(v) ? v.map(String) : null;

/** extras_create_ml_exclusion. */
export async function createMlExclusion(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const value = input.value;
  const comment = input.comment;
  if (!value || typeof value !== "string") return { ok: false, error: "value is required and must be a string" };
  if (!comment || typeof comment !== "string") {
    return { ok: false, error: "comment is required — document WHY this exclusion is safe (audit trail)" };
  }
  const excludedFrom = strList(input.excluded_from) ?? ["blocking"];
  const bad = excludedFrom.filter((x) => !VALID_ML_EXCLUDED_FROM.includes(x));
  if (bad.length) {
    return {
      ok: false,
      error: `invalid excluded_from values [${bad.map(pyRepr).join(", ")}]; must be from ['blocking', 'extraction']`,
    };
  }
  if (value.includes("'")) return { ok: false, error: "value cannot contain a single-quote character (FQL literal delimiter)" };
  const groups = strList(input.group_ids) ?? [];

  const existing = await searchExclusions(ctx, "ml", { filter: `value:'${value}'`, limit: 5 }, "MLExclusions");
  if (!existing.ok) return existing.payload;
  const ids = existing.items.map((r) => r.id).filter((x) => x !== undefined && x !== null);
  if (ids.length) {
    return {
      ok: false,
      duplicate: true,
      existing_ids: ids,
      error:
        `An ML exclusion with value=${pyRepr(value)} already exists (id=${String(ids[0])}). Verify the existing ` +
        "exclusion covers your case before creating another.",
    };
  }
  const args: Obj = { exclusion_type: "ml", value, comment, excluded_from: excludedFrom };
  if (groups.length) args.host_groups = groups;
  const r = await ctx.callNative("falcon_create_exclusion", args);
  if (r.error) return failPayload("MLExclusions", r.error);
  return {
    ok: true,
    id: r.obj && typeof r.obj.id === "string" ? r.obj.id : null,
    value,
    scope: groups.length ? "groups" : "global",
    excluded_from: excludedFrom,
  };
}

/** extras_create_ioa_exclusion. */
export async function createIoaExclusion(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const { name, pattern_id: patternId, ifn_regex: ifnRegex, comment } = input;
  const clRegex = input.cl_regex ?? null;
  const description = input.description ?? null;
  if (!name || typeof name !== "string") return { ok: false, error: "name is required" };
  if (!patternId || typeof patternId !== "string") {
    return { ok: false, error: "pattern_id is required (from detection behaviors[].pattern_id)" };
  }
  if (!ifnRegex || typeof ifnRegex !== "string") return { ok: false, error: "ifn_regex is required" };
  if (!comment || typeof comment !== "string") {
    return { ok: false, error: "comment is required — document WHY this is safe (audit trail)" };
  }
  if (patternId.includes("'")) return { ok: false, error: "pattern_id cannot contain a single-quote (FQL literal delimiter)" };
  for (const [field, pattern] of [
    ["ifn_regex", ifnRegex],
    ["cl_regex", clRegex],
  ] as const) {
    if (typeof pattern !== "string") continue;
    const bad = findZeroWidthAssertion(pattern);
    if (bad) {
      return {
        ok: false,
        error:
          `${field}: contains zero-width assertion ${pyRepr(bad)}, which the Falcon IOA engine rejects. Drop the ` +
          "anchor and bound with \\W trailing context instead (e.g. '...exe(\\W.*)?').",
      };
    }
  }
  const groups = strList(input.group_ids) ?? [];

  // Only an existing exclusion with the same pattern AND image regex counts.
  const existing = await searchExclusions(ctx, "ioa", { filter: `pattern_id:'${patternId}'`, limit: 50 }, "IOAExclusions");
  if (!existing.ok) return existing.payload;
  const dupes = existing.items.filter((r) => r.ifn_regex === ifnRegex).map((r) => r.id ?? null);
  if (dupes.length) {
    return {
      ok: false,
      duplicate: true,
      existing_ids: dupes,
      error:
        `An IOA exclusion with pattern_id=${pyRepr(patternId)} and ifn_regex=${pyRepr(ifnRegex)} already exists ` +
        `(id=${String(dupes[0])}). Verify it covers your case before creating another.`,
    };
  }
  const args: Obj = { exclusion_type: "ioa", name, pattern_id: patternId, ifn_regex: ifnRegex, comment };
  if (typeof clRegex === "string" && clRegex) args.cl_regex = clRegex;
  if (typeof description === "string" && description) args.description = description;
  if (groups.length) args.host_groups = groups;
  const r = await ctx.callNative("falcon_create_exclusion", args);
  if (r.error) return failPayload("IOAExclusions", r.error);
  return {
    ok: true,
    id: r.obj && typeof r.obj.id === "string" ? r.obj.id : null,
    name,
    pattern_id: patternId,
    ifn_regex: ifnRegex,
    scope: groups.length ? "groups" : "global",
  };
}

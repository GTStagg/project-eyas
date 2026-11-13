// Shared plumbing for the IR scope walkers and closers: input checks, the
// paged native detection search, hydration by id and the batched close.
// Every Falcon call goes through eyas-mcp (falcon_search_detections,
// falcon_get_detection_details, falcon_update_detections).

import type { EyasToolContext } from "../types";

export type Obj = Record<string, unknown>;

export const OPEN_STATUSES = new Set(["new", "reopened", "in_progress"]);
const OPEN_FQL = "status:['new','reopened','in_progress']";

// Rows per native search page. eyas-mcp hydrates every id of a page, so a
// moderate page keeps each call well inside the 60 s tool timeout.
export const PAGE = 200;
// 25 pages. A host with more open detections than this is broken some other
// way; the walkers report `truncated`.
export const HARD_CAP = 5000;
// Ids per hydration and per close call (Falcon takes up to 500 per update).
export const ID_BATCH = 500;

export const VALID_VERDICTS = ["false_positive", "true_positive"] as const;
export type Verdict = (typeof VALID_VERDICTS)[number];

const AID = /^[0-9a-fA-F]{32}$/;

/** Device_id checks (same messages as the former sidecar's): reject anything but a
 *  32-hex AID before it reaches an FQL literal. */
export function checkDeviceId(v: unknown): Obj | null {
  if (!v || typeof v !== "string") return { ok: false, error: "device_id required" };
  if (!AID.test(v)) return { ok: false, error: "device_id must be a 32-character hex Agent ID" };
  return null;
}

export function checkVerdict(v: unknown): Obj | null {
  if (typeof v === "string" && (VALID_VERDICTS as readonly string[]).includes(v)) return null;
  return {
    ok: false,
    error: `verdict must be one of ['false_positive', 'true_positive']; got '${typeof v === "string" ? v : String(v)}'`,
  };
}

// An ISO 8601 date or date-time. Strict, because since_iso is interpolated
// into an FQL literal.
const ISO_RX = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?)?(?:Z|[+-]\d{2}:\d{2})?$/;

/** Epoch milliseconds of an ISO 8601 timestamp (no zone = UTC), or null. */
export function parseIso(v: unknown): number | null {
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!ISO_RX.test(s)) return null;
  let norm = s.replace(" ", "T");
  if (norm.length === 10) norm += "T00:00:00";
  if (!/(?:Z|[+-]\d{2}:\d{2})$/.test(norm)) norm += "Z";
  const ms = Date.parse(norm);
  return Number.isNaN(ms) ? null : ms;
}

export function isIsoTimestamp(v: unknown): v is string {
  return typeof v === "string" && ISO_RX.test(v) && parseIso(v) !== null;
}

/** composite_id (or id) of an alert record. */
export function alertId(r: Obj): string | null {
  const v = r.composite_id || r.id;
  return typeof v === "string" && v ? v : null;
}

export const statusOf = (r: Obj) => (typeof r.status === "string" ? r.status.toLowerCase() : "");

/** The record's value, null when absent (Python's dict.get). */
export const pick = (r: Obj, k: string): unknown => (r[k] === undefined ? null : r[k]);
/** `display_name or name`. */
export const displayName = (r: Obj): unknown => r.display_name || pick(r, "name");

function scopePayload(diagnostic: string): Obj {
  const surface = "Alerts";
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

type Walk = { ok: true; alerts: Obj[]; truncated: boolean } | { ok: false; payload: Obj };

/**
 * Every endpoint detection on the host matching `extraFql`, newest first
 * unless `sort` says otherwise, hydrated. Paged until a short page or the
 * hard cap.
 */
export async function walkHostAlerts(
  ctx: EyasToolContext,
  deviceId: string,
  opts: { openOnly?: boolean; extraFql?: string; sort?: string } = {},
): Promise<Walk> {
  const filter = [
    "product:'epp'",
    `device.device_id:'${deviceId}'`,
    ...(opts.openOnly ? [OPEN_FQL] : []),
    ...(opts.extraFql ? [opts.extraFql] : []),
  ].join("+");
  const alerts: Obj[] = [];
  let offset = 0;
  while (offset < HARD_CAP) {
    const r = await ctx.searchNative("falcon_search_detections", {
      filter,
      limit: PAGE,
      offset,
      sort: opts.sort ?? "created_timestamp.desc",
    });
    if (!r.ok) return { ok: false, payload: { ok: false, error: r.error } };
    if (r.scope_pending) return { ok: false, payload: scopePayload("falcon_search_detections: permission denied") };
    alerts.push(...r.items);
    if (r.items.length < PAGE) break;
    offset += PAGE;
  }
  return { ok: true, alerts, truncated: offset >= HARD_CAP };
}

/** Alert records for these composite ids (ids the store no longer has are
 *  simply absent). */
export async function alertsByIds(
  ctx: EyasToolContext,
  ids: string[],
): Promise<{ ok: true; alerts: Obj[] } | { ok: false; payload: Obj }> {
  const alerts: Obj[] = [];
  for (let i = 0; i < ids.length; i += ID_BATCH) {
    const r = await ctx.searchNative("falcon_get_detection_details", { ids: ids.slice(i, i + ID_BATCH) });
    if (!r.ok) return { ok: false, payload: { ok: false, error: r.error } };
    if (r.scope_pending) return { ok: false, payload: scopePayload("falcon_get_detection_details: permission denied") };
    alerts.push(...r.items);
  }
  return { ok: true, alerts };
}

/**
 * Close ids in batches with the verdict tag and comment. A permission error
 * on the first batch returns the scope payload; later failures are listed in
 * batch_errors and the rest still run.
 */
export async function closeIds(
  ctx: EyasToolContext,
  ids: string[],
  verdict: Verdict,
  comment: string,
): Promise<{ updated: number; batchErrors: Obj[]; denied: Obj | null }> {
  const { isScopeDenied } = await import("@/lib/mcp/parse");
  let updated = 0;
  const batchErrors: Obj[] = [];
  for (let start = 0; start < ids.length; start += ID_BATCH) {
    const chunk = ids.slice(start, start + ID_BATCH);
    const r = await ctx.callNative("falcon_update_detections", {
      ids: chunk,
      status: "closed",
      add_tags: [verdict],
      append_comment: comment,
    });
    if (r.error) {
      if (isScopeDenied(r.error)) {
        if (updated === 0) return { updated: 0, batchErrors: [], denied: scopePayload(r.error) };
        batchErrors.push({ batch_start: start, error: "scope_pending" });
        break;
      }
      batchErrors.push({ batch_start: start, error: r.error, size: chunk.length });
      continue;
    }
    updated += chunk.length;
  }
  return { updated, batchErrors, denied: null };
}

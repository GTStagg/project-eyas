// Detection classifiers for IR Phase 0 (workflow-entry triage) and Phase 3
// (verification).
//
// Three false-positive detection shapes fire reliably around an agentic IR
// run:
//
// 1. Workflow self-triggered: RTR's `runscript -CloudFile=<name>` transport
//    starts PowerShell with a fixed `-EncodedCommand` preamble (it decodes to
//    `Set-Location 'C:\'`). Aggressive PowerShell detectors (PShellMimikatz
//    et al.) fire on `-EncodedCommand` whatever the payload, so every IR
//    cleanup step can raise one.
// 2. Retrospective IOC match: a custom IOC added during or after the IR makes
//    Falcon's matching engine backfill stored telemetry, raising detections
//    with a fresh created_timestamp for activity that happened days earlier.
// 3. Shadow-AI audit IOC fire: the detect-only domain IOCs Shadow-AI Ban+Clean
//    creates for AI-provider endpoints fire on continued AI use. That is an
//    audit trail, not malware.
//
// Every classifier is conservative: any doubt leaves the detection "real" /
// actionable. Wasting a quarantine cycle is acceptable; closing real malware
// as noise is not.
//
// Pure: no I/O. Tested in scripts/test-ir-classifiers.mjs.

import { RTR_PREAMBLE_BASE64 } from "../quarantine";
import egressCatalog from "../ai-egress-catalog.json";

type Obj = Record<string, unknown>;

const isObj = (v: unknown): v is Obj => !!v && typeof v === "object" && !Array.isArray(v);
const asList = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const lower = (v: unknown): string => (typeof v === "string" ? v.toLowerCase() : "");

// Shared with the sidecar's Shadow-AI tools (shadow_ai/catalog.py); a sidecar
// test keeps the two in sync. Each pattern must match the whole domain.
const AI_EGRESS_RX: RegExp[] = (egressCatalog as Array<{ pattern: string }>).map(
  (row) => new RegExp(`^(?:${row.pattern})$`, "i"),
);

/** `[true, domain]` when a behavior fired on a domain IOC for a known
 *  AI-provider endpoint (a Shadow-AI audit IOC), else `[false, null]`. */
export function detectionIsShadowAiIocAudit(rec: Obj): [boolean, string | null] {
  for (const b of asList(rec.behaviors)) {
    if (!isObj(b)) continue;
    if (lower(b.ioc_type) !== "domain") continue;
    const value = b.ioc_value;
    if (typeof value !== "string" || !value) continue;
    const domain = value.toLowerCase().trim();
    if (AI_EGRESS_RX.some((rx) => rx.test(domain))) return [true, domain];
  }
  return [false, null];
}

/** Did the detection fire on the RTR runscript preamble (the IR's own cleanup
 *  step)? Looks in cmdline, parent_details.cmdline and behaviors[].cmdline. */
export function detectionIsWorkflowSelfTriggered(rec: Obj): boolean {
  const has = (v: unknown) => typeof v === "string" && v.includes(RTR_PREAMBLE_BASE64);
  if (has(rec.cmdline)) return true;
  if (isObj(rec.parent_details) && has(rec.parent_details.cmdline)) return true;
  return asList(rec.behaviors).some((b) => isObj(b) && has(b.cmdline));
}

const NUMERIC = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/;
const ISO = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?)?(?:Z|[+-]\d{2}:?\d{2})?$/;

/** A Falcon timestamp (epoch seconds as a number or numeric string, or ISO
 *  8601) as epoch seconds, or null. */
export function parseTimestamp(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!s) return null;
  if (NUMERIC.test(s)) return Number(s);
  if (!ISO.test(s)) return null;
  // Date keeps milliseconds only; carry the fractional seconds separately so
  // microsecond timestamps survive (they show in the reason strings).
  const frac = /\.(\d+)/.exec(s)?.[1];
  const ms = Date.parse(s.replace(" ", "T").replace(/\.\d+/, ""));
  return Number.isNaN(ms) ? null : ms / 1000 + (frac ? Number(`0.${frac}`) : 0);
}

/** Timestamps of the events a detection summarizes, NOT created_timestamp
 *  (when the detection was scored). */
export function underlyingEventTimestamps(rec: Obj): number[] {
  const out: number[] = [];
  const push = (v: unknown) => {
    const ts = parseTimestamp(v);
    if (ts !== null) out.push(ts);
  };
  for (const na of asList(rec.network_accesses)) if (isObj(na)) push(na.access_timestamp);
  for (const b of asList(rec.behaviors)) {
    if (!isObj(b)) continue;
    push(b.timestamp);
    push(b.behavior_timestamp);
    push(b.first_behavior);
  }
  push(rec.context_timestamp);
  return out;
}

/** UTC ISO 8601 the way Python's datetime.isoformat() writes it (the sidecar's
 *  reason strings): microseconds only when non-zero, `+00:00` suffix. */
function isoUtc(epochSeconds: number): string {
  const d = new Date(Math.floor(epochSeconds) * 1000);
  const base = d.toISOString().slice(0, 19);
  const micros = Math.round((epochSeconds - Math.floor(epochSeconds)) * 1e6);
  return `${base}${micros ? `.${String(micros).padStart(6, "0")}` : ""}+00:00`;
}

/** Phase 3: retrospective when every underlying event predates the Phase 1
 *  quarantine point. Needs at least one underlying timestamp. */
export function detectionIsRetrospectiveIocMatch(rec: Obj, sinceTsS: number): [boolean, string | null] {
  const ts = underlyingEventTimestamps(rec);
  if (ts.length === 0) return [false, null];
  const newest = Math.max(...ts);
  if (newest >= sinceTsS) return [false, null];
  return [true, `all underlying event timestamps predate Phase 1 quarantine (newest underlying: ${isoUtc(newest)})`];
}

/** 24 h separates a backfill (events days or weeks old) from a detection of
 *  recent activity (scored minutes to hours after the event). */
export const RETRO_BACKFILL_MIN_GAP_S = 24 * 3600;

/** Phase 0 (no quarantine point yet): retrospective when the detection was
 *  created at least `minGapSeconds` after its newest underlying event. Not
 *  "older than now" — every real detection's events are older than now. */
export function detectionIsRetrospectiveBackfill(
  rec: Obj,
  minGapSeconds = RETRO_BACKFILL_MIN_GAP_S,
): [boolean, string | null] {
  const ts = underlyingEventTimestamps(rec);
  if (ts.length === 0) return [false, null];
  const created = parseTimestamp(rec.created_timestamp);
  if (created === null) return [false, null];
  const newest = Math.max(...ts);
  const gap = created - newest;
  if (gap < minGapSeconds) return [false, null];
  return [
    true,
    `fresh detection envelope but newest underlying event is ${(gap / 3600).toFixed(1)}h older than ` +
      `created_timestamp (newest underlying: ${isoUtc(newest)}) — Falcon IOC backfill, not new activity`,
  ];
}

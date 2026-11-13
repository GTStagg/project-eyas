// Process-tree reconstruction with Eyas's delivery-vector classifier.
//
// eyas-mcp's falcon_get_process_tree does the NGSIEM work: it searches
// ProcessRollup2 around the pivot time, finds the pivot by TargetProcessId (or
// the named image closest in time), re-centres the window on the process's own
// start when a behavioural detection fired long after it launched, looks a
// missing parent up once over the previous 7 days, and walks descendants. Eyas
// maps its nodes into the shape the former sidecar returned, then runs its own
// classifier (lib/eyas-tools/process-tree/classifier.ts) over the chain.
//
// The native tool stays hidden from the agent (NATIVE_READ_KEEP in
// lib/mcp/tool-bridge.ts): its own delivery_vector is a generic heuristic, and
// the IR playbook branches on Eyas's vocabulary.

import type { EyasToolContext } from "../types";
import { annotateNodeVerdicts, classifyDeliveryVector, type TreeNode } from "../process-tree/classifier";

type Obj = Record<string, unknown>;

const AID = /^[a-fA-F0-9]{32}$/;
const IMAGE = /^[A-Za-z0-9_. \-]{1,96}$/;

// Every search inside one native call finishes within this, leaving room under
// the 60 s tool timeout.
const TREE_BUDGET_SECONDS = 45;
const TREE_TIMEOUT_MS = 65_000;

/** A process id as the former sidecar returned it: a number when it fits exactly, the
 *  digit string otherwise, null when absent or not digits. */
export function toPid(v: unknown): number | string | null {
  if (typeof v === "number" && Number.isInteger(v)) return v;
  if (typeof v !== "string" || !/^\d{1,20}$/.test(v.trim())) return null;
  const n = Number(v.trim());
  return Number.isSafeInteger(n) ? n : v.trim();
}

const strOrNull = (v: unknown): string | null => (typeof v === "string" && v ? v : null);

/** A native tree node in the former sidecar's {pid, ppid, os_pid, image, cmdline,
 *  user, user_sid, signed, ts} shape, plus the native `sha256`, raw `signing`
 *  and, when present, `blocked` / `source_event` / `parent_image` (a process
 *  the sensor blocked before it ran has no ProcessRollup2; eyas-mcp ≥ 11e9564
 *  builds it from its ProcessBlocked event). */
export function nodeFromNative(n: Obj): TreeNode {
  const signing = n.signing && typeof n.signing === "object" ? (n.signing as Obj) : null;
  const fileSign = signing ? String(signing.file_sign_info ?? "") : "";
  const cmd = typeof n.command_line === "string" ? n.command_line : "";
  const node: TreeNode = {
    pid: toPid(n.process_id),
    ppid: toPid(n.parent_process_id),
    os_pid: toPid(n.os_pid),
    image: typeof n.image === "string" ? n.image : "",
    cmdline: cmd.slice(0, 480),
    user: strOrNull(n.user_name),
    user_sid: strOrNull(n.user_sid),
    // FileSignInfo, when the sensor sends it. Other platforms' signing fields
    // ride along raw in `signing`.
    signed: fileSign ? fileSign.toLowerCase().startsWith("signed") : null,
    ts: strOrNull(n.process_start_time) ?? strOrNull(n.timestamp),
  };
  if (strOrNull(n.sha256)) node.sha256 = n.sha256;
  if (signing) node.signing = signing;
  if (typeof n.blocked === "boolean") node.blocked = n.blocked;
  if (strOrNull(n.source_event)) node.source_event = n.source_event;
  if (strOrNull(n.parent_image)) node.parent_image = n.parent_image;
  if (typeof n.depth === "number") node.depth = n.depth;
  return node;
}

/** Whether a parent came from the native tool's wider lookup (it demotes a
 *  high confidence to medium). */
function parentLookupFound(tree: Obj): boolean {
  const searches = Array.isArray(tree.searches) ? (tree.searches as Obj[]) : [];
  return searches.some((s) => s && s.purpose === "parent_lookup" && typeof s.event_count === "number" && s.event_count > 0);
}

type NativeTree = { ok: true; tree: Obj } | { ok: false; error: string };

/** One falcon_get_process_tree call. `pivotTime` must already be valid ISO. */
export async function nativeTree(
  ctx: EyasToolContext,
  args: {
    deviceId: string;
    pivotTime: string;
    pivotPid?: number | string | null;
    pivotImage?: string | null;
    windowMinutes: number;
    ancestryMax: number;
    descendantsMax: number;
    budgetSeconds?: number;
  },
): Promise<NativeTree> {
  const input: Obj = {
    device_id: args.deviceId,
    pivot_time: args.pivotTime,
    window_minutes: args.windowMinutes,
    ancestry_max: args.ancestryMax,
    descendants_max: args.descendantsMax,
    time_budget_seconds: args.budgetSeconds ?? TREE_BUDGET_SECONDS,
  };
  if (args.pivotPid !== null && args.pivotPid !== undefined) input.pivot_process_id = String(args.pivotPid);
  if (args.pivotImage) input.pivot_image = args.pivotImage;
  const r = await ctx.callNative("falcon_get_process_tree", input, { timeoutMs: TREE_TIMEOUT_MS });
  if (r.error) return { ok: false, error: r.error };
  if (!r.obj) return { ok: false, error: "falcon_get_process_tree returned no result" };
  return { ok: true, tree: r.obj };
}

/** The chain pivot-first: the pivot, then its ancestors nearest first, each
 *  with `depth` (pivot 0). Empty when the native tree found no pivot. */
export function ancestryOf(tree: Obj): TreeNode[] {
  if (!tree.pivot || typeof tree.pivot !== "object") return [];
  const ancestors = Array.isArray(tree.ancestry) ? (tree.ancestry as Obj[]) : [];
  return [tree.pivot as Obj, ...ancestors].map((n, i) => ({ ...nodeFromNative(n), depth: i }));
}

/** The ISO time a pivot timestamp names, at millisecond precision (eyas-mcp
 *  parses it with Python's fromisoformat, which rejects nanoseconds), or null. */
export function normalizePivotTime(v: string): string | null {
  const s = v.trim();
  const m = /^(\d{4}-\d{2}-\d{2})(?:[T ](\d{2}:\d{2}(?::\d{2})?)(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?$/i.exec(s);
  if (!m) return null;
  const frac = m[3] ? m[3].slice(0, 4) : "";
  const time = m[2] ? (m[2].length === 5 ? `${m[2]}:00` : m[2]) : "00:00:00";
  const zone = !m[4] || m[4].toUpperCase() === "Z" ? "Z" : m[4].includes(":") ? m[4] : `${m[4].slice(0, 3)}:${m[4].slice(3)}`;
  const ms = Date.parse(`${m[1]}T${time}${frac}${zone}`);
  return Number.isNaN(ms) ? null : new Date(ms).toISOString();
}

function unknownVector(rationale: string): Obj {
  return { kind: "unknown", confidence: "low", rationale };
}

const intIn = (v: unknown, lo: number, hi: number) => typeof v === "number" && Number.isInteger(v) && v >= lo && v <= hi;

/** extras_host_process_tree. */
export async function hostProcessTree(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const deviceId = input.device_id;
  const pivotPid = input.pivot_pid ?? null;
  const pivotImage = input.pivot_image ?? null;
  const pivotTs = input.pivot_ts_iso;
  const windowMinutes = input.window_minutes ?? 10;
  const ancestryMax = input.ancestry_max ?? 12;
  const descendantsMax = input.descendants_max ?? 200;

  if (typeof deviceId !== "string" || !AID.test(deviceId)) return { ok: false, error: "device_id must be a 32-char hex AID" };
  if (!pivotTs || typeof pivotTs !== "string") {
    return { ok: false, error: "pivot_ts_iso (ISO 8601 detection timestamp) is required" };
  }
  if (pivotPid === null && !pivotImage) return { ok: false, error: "one of pivot_pid or pivot_image is required" };
  if (!intIn(windowMinutes, 1, 120)) return { ok: false, error: "window_minutes must be an integer in 1-120" };
  if (!intIn(ancestryMax, 1, 30)) return { ok: false, error: "ancestry_max must be an integer in 1-30" };
  if (!intIn(descendantsMax, 1, 1000)) return { ok: false, error: "descendants_max must be an integer in 1-1000" };
  if (pivotImage !== null && (typeof pivotImage !== "string" || !IMAGE.test(pivotImage))) {
    return { ok: false, error: "pivot_image must be a basename like 'powershell.exe'" };
  }
  const pid = pivotPid === null ? null : toPid(pivotPid);
  if (pivotPid !== null && pid === null) return { ok: false, error: "pivot_pid must be the detection's process id (digits only)" };
  const pivotTime = normalizePivotTime(pivotTs);
  if (!pivotTime) return { ok: false, error: `pivot_ts_iso could not be parsed as ISO 8601: ${pivotTs}` };

  const r = await nativeTree(ctx, {
    deviceId,
    pivotTime,
    pivotPid: pid,
    pivotImage: (pivotImage as string | null) || null,
    windowMinutes: windowMinutes as number,
    ancestryMax: ancestryMax as number,
    descendantsMax: descendantsMax as number,
  });
  if (!r.ok) return { ok: false, error: r.error };
  const tree = r.tree;
  const win = tree.window && typeof tree.window === "object" ? (tree.window as Obj) : {};
  const eventsScanned = typeof win.events_scanned === "number" ? win.events_scanned : 0;
  const notes = Array.isArray(tree.notes) ? tree.notes.filter((n): n is string => typeof n === "string") : [];
  const partial = tree.partial === true;
  const extra: Obj = notes.length ? { notes } : {};
  if (partial) extra.partial = true;

  const ancestry = ancestryOf(tree);
  if (ancestry.length === 0) {
    const searches = Array.isArray(tree.searches) ? (tree.searches as Obj[]) : [];
    const windowDone = searches.some((s) => s && s.purpose === "window" && s.status === "completed");
    let rationale: string;
    let truncated = false;
    if (!windowDone) {
      rationale = "NGSIEM search did not complete within the polling budget. Re-run with a tighter window_minutes.";
      truncated = true;
    } else if (eventsScanned === 0 && !win.anchor_recovered) {
      rationale =
        `No ProcessRollup2 events found on this host within ±${windowMinutes}m of the detection timestamp. ` +
        "NGSIEM retention may have aged out, or telemetry isn't flowing for this AID.";
    } else {
      rationale =
        "Pivot process not found in NGSIEM ProcessRollup2 for this AID over the last 7 days. The detection may " +
        "reference a process whose telemetry never landed in NGSIEM, or NGSIEM retention has aged it out. " +
        "Falcon Console's process explorer may still have the chain via Threat Graph.";
    }
    return {
      ok: true,
      pivot: null,
      delivery_vector: unknownVector(rationale),
      ancestry: [],
      descendants: [],
      events_scanned: eventsScanned,
      truncated,
      ...extra,
    };
  }

  const windowWidened = parentLookupFound(tree);
  annotateNodeVerdicts(ancestry);
  const deliveryVector = classifyDeliveryVector(ancestry, { windowWidened });
  const descendants = (Array.isArray(tree.descendants) ? (tree.descendants as Obj[]) : []).map(nodeFromNative);
  const unresolved = toPid(tree.unresolved_parent_process_id);
  const pivot = ancestry[0];
  return {
    ok: true,
    pivot: { pid: pivot.pid, image: pivot.image, cmdline: pivot.cmdline, ts: pivot.ts, blocked: pivot.blocked === true },
    delivery_vector: deliveryVector,
    ancestry,
    descendants,
    unaccounted_pids: unresolved === null ? [] : [unresolved],
    events_scanned: eventsScanned,
    window_widened: windowWidened,
    anchor_recovered: win.anchor_recovered === true,
    truncated: tree.descendants_truncated === true,
    ...extra,
  };
}

import "server-only";
import path from "node:path";
import { and, desc, eq } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { irRuns, irRunTurns } from "@/lib/db/schema";
import { getActiveEnvironmentId } from "@/lib/config/environments";
import { costOf } from "@/lib/cost/pricing";

// Per-IR-session audit record. Backed by the `ir_runs` + `ir_run_turns`
// tables of data/eyas.db.
//
// The exported API operates on a string key of the form
// `<aid>-<startedAt>.json` — that string is the URL slug for
// /ir-runs/[file] and also the lookup key for the underlying
// (aid, startedAt) composite. Consumers (chat route, /ir-runs page,
// /api/ir-runs) treat it as an opaque token.

export type ToolCallRecord = {
  id: string;
  name: string;
  input: unknown;
  approval: "none" | "allow" | "deny" | "timeout";
  result: {
    isError: boolean;
    contentExcerpt: string;
    durationMs?: number;
    /** Structured counts pulled from the FULL tool result at capture time,
     *  before `contentExcerpt` is truncated to EXCERPT_LIMIT. The replay
     *  analysis (ir-run-analysis.ts) reads these instead of re-parsing the
     *  excerpt, which silently miscounts to 0 once a ledger-close payload
     *  exceeds the excerpt cap. Absent on records written before this field
     *  existed — analysis falls back to parsing the excerpt for those. */
    metrics?: ToolResultMetrics;
  } | null;
  ts: number;
};

/** Capture-time structured summary of an analysis-relevant tool result. Keys
 *  are only populated for the tools whose counts the replay surface reports;
 *  every field is optional so the shape stays forward-compatible. */
export type ToolResultMetrics = {
  closedCount?: number;
  unmatchedCount?: number;
  closedHasEvidence?: boolean;
  updatedCount?: number;
  retrospectiveCount?: number;
  workflowSelfCount?: number;
};

export type TurnRecord = {
  turnIndex: number;
  startedAt: number;
  endedAt: number;
  userInput: string;
  toolCalls: ToolCallRecord[];
  status: "completed" | "cancelled" | "errored";
  usage: {
    input_tokens: number;
    output_tokens: number;
    cache_creation_input_tokens: number;
    cache_read_input_tokens: number;
  };
  iterations: number;
};

export type IrRunRecord = {
  schemaVersion: 1;
  aid: string;
  sessionId: string;
  envId: string | null;
  startedAt: number;
  lastTouched: number;
  campaignScope: unknown;
  playbook: { ok: boolean; error?: string; textLength: number };
  /** Host facts captured at kickoff (S1), null when the fetch failed/unknown.
   *  These are the agent-independent ground truth behind the contain/lift
   *  backstop and the verified approval card. */
  containedAtStart: boolean | null;
  hostRole: string | null;
  turns: TurnRecord[];
};

const EXCERPT_LIMIT = 2048;

function excerpt(text: string): string {
  if (text.length <= EXCERPT_LIMIT) return text;
  return text.slice(0, EXCERPT_LIMIT) + `\n…[truncated, ${text.length - EXCERPT_LIMIT} bytes]`;
}

/** Pull analysis-relevant counts from the FULL tool result before it's
 *  truncated for storage. Runs at capture time in TurnObserver so the replay
 *  surface never depends on the (truncated) excerpt for its numbers. Returns
 *  undefined for tools whose results carry nothing the analysis reports. */
function extractResultMetrics(toolName: string, fullContent: string): ToolResultMetrics | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(fullContent);
  } catch {
    parsed = null;
  }
  const obj =
    parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;

  switch (toolName) {
    case "extras_ir_close_remediated": {
      if (!obj) return undefined;
      const closed = Array.isArray(obj.closed) ? obj.closed : [];
      const unmatched = Array.isArray(obj.unmatched) ? obj.unmatched : [];
      const closedHasEvidence = closed.some(
        (e) =>
          e &&
          typeof e === "object" &&
          Array.isArray((e as Record<string, unknown>).evidence) &&
          ((e as Record<string, unknown>).evidence as unknown[]).length > 0,
      );
      return {
        closedCount: closed.length,
        unmatchedCount: unmatched.length,
        closedHasEvidence,
      };
    }
    case "extras_ir_close_untouched_originals":
    case "extras_close_all_open_detections_on_host": {
      if (!obj) return undefined;
      return {
        updatedCount: typeof obj.updated === "number" ? obj.updated : 0,
      };
    }
    case "extras_ir_phase3_verification_scope": {
      if (!obj) return undefined;
      const num = (k: string) => (typeof obj[k] === "number" ? (obj[k] as number) : 0);
      return {
        retrospectiveCount: num("retrospective_count"),
        workflowSelfCount: num("workflow_self_count"),
      };
    }
    default:
      return undefined;
  }
}

/** Filename-shaped key for the record at this aid+startedAt. Doubles as
 *  the URL slug for /ir-runs/[file] and the stash value for
 *  irMode.recordPath, so callers treat it as a single opaque token. */
export function recordBasenameFor(aid: string, startedAt: number): string {
  const safeAid = aid.replace(/[^A-Za-z0-9_-]/g, "_");
  return `${safeAid}-${startedAt}.json`;
}

/** Back-compat alias — older callers stash this in irMode.recordPath. */
export function recordPathFor(aid: string, startedAt: number): string {
  return recordBasenameFor(aid, startedAt);
}

/** Parse the `<aid>-<startedAt>.json` key into its (aid, startedAt) parts.
 *  Tolerates a full filesystem path on the way in for legacy callers that
 *  still synthesize one via path.join(...). */
function parseKey(keyOrPath: string): { aid: string; startedAt: number } | null {
  const basename = path.basename(keyOrPath);
  const stripped = basename.endsWith(".json")
    ? basename.slice(0, -".json".length)
    : basename;
  const lastDash = stripped.lastIndexOf("-");
  if (lastDash <= 0) return null;
  const aid = stripped.slice(0, lastDash);
  const startedAt = Number(stripped.slice(lastDash + 1));
  if (!Number.isFinite(startedAt)) return null;
  return { aid, startedAt };
}

function tryParseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

type IrRunRow = typeof irRuns.$inferSelect;
type IrRunTurnRow = typeof irRunTurns.$inferSelect;

function turnFromRow(row: IrRunTurnRow): TurnRecord {
  return {
    turnIndex: row.turnIndex,
    startedAt: row.startedAt,
    endedAt: row.endedAt,
    userInput: row.userInput,
    toolCalls: JSON.parse(row.toolCallsJson) as ToolCallRecord[],
    status: row.status as TurnRecord["status"],
    usage: JSON.parse(row.usageJson) as TurnRecord["usage"],
    iterations: row.iterations,
  };
}

function recordFromRows(run: IrRunRow, turns: IrRunTurnRow[]): IrRunRecord {
  return {
    schemaVersion: 1,
    aid: run.aid,
    sessionId: run.sessionId,
    envId: run.envId,
    startedAt: run.startedAt,
    lastTouched: run.lastTouched,
    campaignScope: tryParseJson(run.campaignScopeJson),
    playbook: {
      ok: run.playbookOk,
      error: run.playbookError ?? undefined,
      textLength: run.playbookTextLength,
    },
    containedAtStart: run.containedAtStart ?? null,
    hostRole: run.hostRole ?? null,
    turns: turns.map(turnFromRow),
  };
}

/** All records, newest first (by last_touched). Pass `envId` to restrict to a
 *  single environment (per-tenant metrics, e.g. the scorecard); omit it for the
 *  install-wide view the audit surfaces use. */
export async function listRecords(envId?: string): Promise<IrRunRecord[]> {
  const runs = db()
    .select()
    .from(irRuns)
    .where(envId ? eq(irRuns.envId, envId) : undefined)
    .orderBy(desc(irRuns.lastTouched))
    .all();
  if (runs.length === 0) return [];
  const out: IrRunRecord[] = [];
  for (const run of runs) {
    const turns = db()
      .select()
      .from(irRunTurns)
      .where(and(eq(irRunTurns.aid, run.aid), eq(irRunTurns.runStartedAt, run.startedAt)))
      .orderBy(irRunTurns.turnIndex)
      .all();
    out.push(recordFromRows(run, turns));
  }
  return out;
}

/** Read one record by its key. Accepts either the bare basename
 *  (`<aid>-<startedAt>.json`) or a legacy full filesystem path. */
export async function readRecord(keyOrPath: string): Promise<IrRunRecord | null> {
  const parsed = parseKey(keyOrPath);
  if (!parsed) return null;
  const run = db()
    .select()
    .from(irRuns)
    .where(and(eq(irRuns.aid, parsed.aid), eq(irRuns.startedAt, parsed.startedAt)))
    .get();
  if (!run) return null;
  const turns = db()
    .select()
    .from(irRunTurns)
    .where(and(eq(irRunTurns.aid, parsed.aid), eq(irRunTurns.runStartedAt, parsed.startedAt)))
    .orderBy(irRunTurns.turnIndex)
    .all();
  return recordFromRows(run, turns);
}

export async function createRecord(opts: {
  aid: string;
  sessionId: string;
  startedAt: number;
  campaignScopeText: string;
  playbookOk: boolean;
  playbookError?: string;
  playbookTextLength: number;
  containedAtStart?: boolean | null;
  hostRole?: string | null;
}): Promise<{ filepath: string; record: IrRunRecord }> {
  // Preserve the parsed-when-possible storage that callers depend on (the
  // /ir-runs UI walks campaignScope.campaigns directly when available).
  const parsedScope = tryParseJson(opts.campaignScopeText);
  const scopeJson =
    typeof parsedScope === "string"
      ? JSON.stringify(opts.campaignScopeText)
      : JSON.stringify(parsedScope);
  // Attribute the engagement to the environment it ran under (env switch is
  // refused while a turn is in flight, so the active env at creation is right).
  let envId: string | null = null;
  try {
    envId = getActiveEnvironmentId();
  } catch {
    // leave unattributed rather than block the run
  }
  const containedAtStart = opts.containedAtStart ?? null;
  const hostRole = opts.hostRole ?? null;
  // Store the aid canonical (lowercase hex) so the aid-keyed ground-truth
  // reader (getLatestIrRunIdentity, which lowercases its lookup) always finds
  // the row. The primer regex admits uppercase; without this an upper/mixed-
  // case kickoff aid would store un-normalized and the lift/release backstops
  // would silently miss on the fallback (aid-keyed) lookup. Used for the row,
  // the returned record, and the URL-slug basename so all three agree.
  const aid = opts.aid.toLowerCase();
  db()
    .insert(irRuns)
    .values({
      aid,
      startedAt: opts.startedAt,
      sessionId: opts.sessionId,
      lastTouched: opts.startedAt,
      campaignScopeJson: scopeJson,
      playbookOk: opts.playbookOk,
      playbookError: opts.playbookError ?? null,
      playbookTextLength: opts.playbookTextLength,
      schemaVersion: 1,
      containedAtStart,
      hostRole,
      envId,
    })
    .run();
  const record: IrRunRecord = {
    schemaVersion: 1,
    aid,
    sessionId: opts.sessionId,
    envId,
    startedAt: opts.startedAt,
    lastTouched: opts.startedAt,
    campaignScope: parsedScope,
    playbook: {
      ok: opts.playbookOk,
      error: opts.playbookError,
      textLength: opts.playbookTextLength,
    },
    containedAtStart,
    hostRole,
    turns: [],
  };
  return { filepath: recordBasenameFor(aid, opts.startedAt), record };
}

export type IrRunSummary = {
  aid: string;
  recordFile: string;
  startedAt: number;
  lastTouched: number;
  turnsCount: number;
  totalIterations: number;
  hasErrors: boolean;
  campaignsCount: number | null;
};

function summarize(record: IrRunRecord): IrRunSummary {
  const turnsCount = record.turns.length;
  const totalIterations = record.turns.reduce(
    (acc, t) => acc + (t.iterations ?? 0),
    0,
  );
  const hasErrors = record.turns.some(
    (t) =>
      t.status === "errored" ||
      t.toolCalls.some((c) => c.result?.isError === true),
  );
  let campaignsCount: number | null = null;
  const scope = record.campaignScope as { campaigns?: unknown[] } | null;
  if (scope && Array.isArray(scope.campaigns)) campaignsCount = scope.campaigns.length;
  return {
    aid: record.aid,
    recordFile: recordBasenameFor(record.aid, record.startedAt),
    startedAt: record.startedAt,
    lastTouched: record.lastTouched,
    turnsCount,
    totalIterations,
    hasErrors,
    campaignsCount,
  };
}

export function totalUsdForRun(record: IrRunRecord, modelId: string): number {
  let total = 0;
  for (const t of record.turns) {
    total += costOf(t.usage, modelId);
  }
  return total;
}

export async function recentIrCostProjection(
  modelId: string,
  opts: { window?: number } = {},
): Promise<{ averageUsd: number; sampleSize: number } | null> {
  const window = opts.window ?? 5;
  const records = await listRecords();
  const eligible = records
    .filter(
      (r) =>
        r.turns.length > 0 &&
        r.turns.every((t) => t.status === "completed" || t.status === "cancelled"),
    )
    .slice(0, window);
  if (eligible.length < 3) return null;
  const total = eligible.reduce((acc, r) => acc + totalUsdForRun(r, modelId), 0);
  return { averageUsd: total / eligible.length, sampleSize: eligible.length };
}

/** Most recent run for this AID, derived from ir_runs (the legacy
 *  by-aid/<aid>.json pointer file is no longer needed — the index on
 *  (aid, started_at DESC) makes the lookup trivial). */
export async function getLastRunForAid(aid: string): Promise<IrRunSummary | null> {
  const run = db()
    .select()
    .from(irRuns)
    .where(eq(irRuns.aid, aid))
    .orderBy(desc(irRuns.startedAt))
    .limit(1)
    .get();
  if (!run) return null;
  const turns = db()
    .select()
    .from(irRunTurns)
    .where(and(eq(irRunTurns.aid, run.aid), eq(irRunTurns.runStartedAt, run.startedAt)))
    .orderBy(irRunTurns.turnIndex)
    .all();
  return summarize(recordFromRows(run, turns));
}

export async function appendTurn(
  keyOrPath: string,
  turn: TurnRecord,
): Promise<void> {
  const parsed = parseKey(keyOrPath);
  if (!parsed) return;
  // The legacy file-backed implementation tolerated a missing record by
  // synthesizing a stub. Preserve that: better to keep the audit data than
  // drop it on the floor when createRecord races/fails.
  const run = db()
    .select()
    .from(irRuns)
    .where(and(eq(irRuns.aid, parsed.aid), eq(irRuns.startedAt, parsed.startedAt)))
    .get();
  if (!run) {
    let envId: string | null = null;
    try {
      envId = getActiveEnvironmentId();
    } catch {
      // leave unattributed
    }
    db()
      .insert(irRuns)
      .values({
        aid: parsed.aid,
        startedAt: parsed.startedAt,
        sessionId: "unknown",
        lastTouched: turn.endedAt,
        campaignScopeJson: "null",
        playbookOk: false,
        playbookError: "record not initialized",
        playbookTextLength: 0,
        schemaVersion: 1,
        envId,
      })
      .run();
  }
  db()
    .insert(irRunTurns)
    .values({
      aid: parsed.aid,
      runStartedAt: parsed.startedAt,
      turnIndex: turn.turnIndex,
      startedAt: turn.startedAt,
      endedAt: turn.endedAt,
      userInput: turn.userInput,
      toolCallsJson: JSON.stringify(turn.toolCalls),
      status: turn.status,
      usageJson: JSON.stringify(turn.usage),
      iterations: turn.iterations,
    })
    .run();
  db()
    .update(irRuns)
    .set({ lastTouched: turn.endedAt })
    .where(and(eq(irRuns.aid, parsed.aid), eq(irRuns.startedAt, parsed.startedAt)))
    .run();
}

/** Excerpt utility re-exported only because TurnObserver below uses it. */
export { excerpt as _excerpt };

/** Live-build a TurnRecord from observed SSE events. Wrap the chat route's
 *  emit() so this observes everything the agent loop fires; finalize() returns
 *  a complete TurnRecord ready to pass to appendTurn(). */
export class TurnObserver {
  private startedAt: number;
  private toolCalls: Map<string, ToolCallRecord> = new Map();
  private toolOrder: string[] = [];
  private status: TurnRecord["status"] = "errored";
  private usage: TurnRecord["usage"] = {
    input_tokens: 0,
    output_tokens: 0,
    cache_creation_input_tokens: 0,
    cache_read_input_tokens: 0,
  };
  private iterations = 0;

  constructor(
    private readonly turnIndex: number,
    private readonly userInput: string,
  ) {
    this.startedAt = Date.now();
  }

  observe(event: string, data: unknown): void {
    switch (event) {
      case "tool_use": {
        const d = data as { id: string; name: string; input: unknown };
        if (!this.toolCalls.has(d.id)) {
          this.toolCalls.set(d.id, {
            id: d.id,
            name: d.name,
            input: d.input,
            approval: "none",
            result: null,
            ts: Date.now(),
          });
          this.toolOrder.push(d.id);
        }
        break;
      }
      case "tool_pending_approval":
        break;
      case "tool_approval_resolved": {
        const d = data as { id: string; decision: "allow" | "deny" | "timeout" };
        const rec = this.toolCalls.get(d.id);
        if (rec) rec.approval = d.decision;
        break;
      }
      case "tool_result": {
        const d = data as {
          tool_use_id: string;
          content: string;
          is_error: boolean;
          duration_ms?: number;
        };
        const rec = this.toolCalls.get(d.tool_use_id);
        if (rec) {
          rec.result = {
            isError: d.is_error,
            contentExcerpt: excerpt(d.content),
            durationMs: d.duration_ms,
            metrics: extractResultMetrics(rec.name, d.content),
          };
        }
        break;
      }
      case "done": {
        const d = data as { usage: TurnRecord["usage"]; iterations: number };
        this.status = "completed";
        if (d.usage) this.usage = d.usage;
        if (typeof d.iterations === "number") this.iterations = d.iterations;
        break;
      }
      case "cancelled": {
        const d = data as { usage: TurnRecord["usage"]; iterations: number };
        this.status = "cancelled";
        if (d.usage) this.usage = d.usage;
        if (typeof d.iterations === "number") this.iterations = d.iterations;
        break;
      }
      case "error":
        break;
    }
  }

  recordSyntheticCall(call: ToolCallRecord): void {
    if (!this.toolCalls.has(call.id)) {
      this.toolCalls.set(call.id, call);
      this.toolOrder.push(call.id);
    }
  }

  finalize(): TurnRecord {
    const toolCalls = this.toolOrder
      .map((id) => this.toolCalls.get(id))
      .filter((c): c is ToolCallRecord => c !== undefined);
    return {
      turnIndex: this.turnIndex,
      startedAt: this.startedAt,
      endedAt: Date.now(),
      userInput: this.userInput,
      toolCalls,
      status: this.status,
      usage: this.usage,
      iterations: this.iterations,
    };
  }
}

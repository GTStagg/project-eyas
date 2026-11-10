import "server-only";
import type Anthropic from "@anthropic-ai/sdk";
import { and, desc, eq, gt, isNull, lt } from "drizzle-orm";
import { db } from "@/lib/db/client";
import { chatSessions } from "@/lib/db/schema";

// Chat-history store. In-memory Map is the hot cache (zero-cost reads/writes
// on the agent-loop hot path); `chat_sessions` in data/eyas.db is the
// durability layer so an idle session survives a server restart inside the
// rolling 7-day TTL window. Single-process app, but the DB-backing also means
// a future horizontal-scale move only needs to lose the cache layer.
//
// As of the conversation-history work the table also carries `title` +
// `created_at`, used by the /chat left rail to list prior conversations.
//
// Pinned to globalThis so dev-mode per-route module duplication doesn't
// fragment state across route files (/api/chat, /api/chat/reset, etc.).

export type IrMode = {
  aid: string;
  startedAt: number;
  /** Key under which the audit record is stored (ir_runs + ir_run_turns).
   *  Shape is `<aid>-<startedAt>.json` — kept filename-shaped because the
   *  /ir-runs/[file] URL slug and irMode.recordPath need to round-trip. */
  recordPath: string;
  turnCount: number;
};

type Entry = {
  messages: Anthropic.Beta.BetaMessageParam[];
  lastTouched: number;
  irMode?: IrMode;
  title?: string;
  createdAt: number;
};

export const TTL_MS = 72 * 60 * 60 * 1000; // 72-hour rolling idle
const TITLE_MAX_LEN = 60;

function deriveTitleFromMessages(messages: Anthropic.Beta.BetaMessageParam[]): string | null {
  for (const m of messages) {
    if (m.role !== "user") continue;
    let text: string;
    if (typeof m.content === "string") {
      text = m.content;
    } else if (Array.isArray(m.content)) {
      text = m.content
        .map((b) => (b.type === "text" ? b.text : ""))
        .join(" ");
    } else {
      continue;
    }
    const cleaned = text
      .replace(/^[#>\s*-]+/, "")
      .replace(/`+/g, "")
      .replace(/\s+/g, " ")
      .trim();
    if (!cleaned) continue;
    const firstSentence = cleaned.split(/(?<=[.!?])\s/, 1)[0] ?? cleaned;
    return firstSentence.slice(0, TITLE_MAX_LEN);
  }
  return null;
}

const globalForConversations = globalThis as unknown as {
  __falconConversations?: Map<string, Entry>;
};
const conversations: Map<string, Entry> =
  globalForConversations.__falconConversations ??
  (globalForConversations.__falconConversations = new Map());

function persist(id: string, entry: Entry): void {
  // Best-effort: a logging failure must not surface as an agent-loop failure.
  try {
    db()
      .insert(chatSessions)
      .values({
        id,
        messagesJson: JSON.stringify(entry.messages),
        irModeJson: entry.irMode ? JSON.stringify(entry.irMode) : null,
        lastTouched: entry.lastTouched,
        title: entry.title ?? null,
        createdAt: entry.createdAt,
      })
      .onConflictDoUpdate({
        target: chatSessions.id,
        set: {
          messagesJson: JSON.stringify(entry.messages),
          irModeJson: entry.irMode ? JSON.stringify(entry.irMode) : null,
          lastTouched: entry.lastTouched,
          // title is set-once: don't overwrite on subsequent saves. The
          // chat route's setSessionTitle() is the only path that updates it.
        },
      })
      .run();
  } catch {
    // intentionally swallowed
  }
}

function dbDelete(id: string): void {
  try {
    db().delete(chatSessions).where(eq(chatSessions.id, id)).run();
  } catch {
    /* intentionally swallowed */
  }
}

/** Hydrate the in-memory entry from chat_sessions if missing or stale.
 *  Returns the entry if one exists (in cache or DB) and is still inside TTL;
 *  otherwise null. Also evicts expired rows from both layers on the way. */
function hydrate(id: string, now: number = Date.now()): Entry | null {
  const cached = conversations.get(id);
  if (cached) {
    if (now - cached.lastTouched > TTL_MS) {
      conversations.delete(id);
      dbDelete(id);
      return null;
    }
    return cached;
  }
  try {
    const row = db()
      .select()
      .from(chatSessions)
      .where(eq(chatSessions.id, id))
      .get();
    if (!row) return null;
    if (now - row.lastTouched > TTL_MS) {
      dbDelete(id);
      return null;
    }
    const entry: Entry = {
      messages: JSON.parse(row.messagesJson) as Anthropic.Beta.BetaMessageParam[],
      lastTouched: row.lastTouched,
      irMode: row.irModeJson ? (JSON.parse(row.irModeJson) as IrMode) : undefined,
      title: row.title ?? undefined,
      createdAt: row.createdAt || row.lastTouched,
    };
    conversations.set(id, entry);
    return entry;
  } catch {
    return null;
  }
}

function sweepExpired(now: number = Date.now()): number {
  let removed = 0;
  for (const [id, entry] of conversations) {
    if (now - entry.lastTouched > TTL_MS) {
      conversations.delete(id);
      removed++;
    }
  }
  // Sweep the DB independently — a process restart can leave rows older than
  // anything in memory.
  try {
    db().delete(chatSessions).where(lt(chatSessions.lastTouched, now - TTL_MS)).run();
  } catch {
    /* intentionally swallowed */
  }
  return removed;
}

export function loadConversation(id: string): Anthropic.Beta.BetaMessageParam[] {
  const entry = hydrate(id);
  return entry ? entry.messages : [];
}

export function saveConversation(id: string, messages: Anthropic.Beta.BetaMessageParam[]): void {
  const prev = conversations.get(id);
  const now = Date.now();
  const entry: Entry = {
    messages,
    lastTouched: now,
    irMode: prev?.irMode,
    title: prev?.title,
    createdAt: prev?.createdAt ?? now,
  };
  conversations.set(id, entry);
  persist(id, entry);
}

export function resetConversation(id: string): void {
  conversations.delete(id);
  dbDelete(id);
}

export function getIrMode(id: string): IrMode | null {
  const entry = hydrate(id);
  return entry?.irMode ?? null;
}

export function setIrMode(id: string, irMode: IrMode): void {
  const entry = hydrate(id);
  if (entry) {
    entry.irMode = irMode;
    entry.lastTouched = Date.now();
    persist(id, entry);
  } else {
    const now = Date.now();
    const fresh: Entry = { messages: [], lastTouched: now, irMode, createdAt: now };
    conversations.set(id, fresh);
    persist(id, fresh);
  }
}

export function bumpIrTurnCount(id: string): number {
  const entry = hydrate(id);
  if (!entry || !entry.irMode) return 0;
  entry.irMode.turnCount += 1;
  entry.lastTouched = Date.now();
  persist(id, entry);
  return entry.irMode.turnCount;
}

export function inspectConversation(id: string): {
  turnCount: number;
  idleMs: number;
} | null {
  const entry = hydrate(id);
  if (!entry) return null;
  let turnCount = 0;
  for (const m of entry.messages) {
    if (m.role === "user") turnCount++;
  }
  return { turnCount, idleMs: Date.now() - entry.lastTouched };
}

/** Set the conversation title. Set-once semantics: an existing non-empty
 *  title is preserved. Used by the chat route on the first user turn to
 *  derive a scannable label from the first ~60 chars of the prompt. */
export function setSessionTitle(id: string, title: string): void {
  const trimmed = title.replace(/\s+/g, " ").trim().slice(0, TITLE_MAX_LEN);
  if (!trimmed) return;
  const entry = hydrate(id);
  if (entry && !entry.title) {
    entry.title = trimmed;
    persist(id, entry);
  }
  // Update the DB even when there's no cache entry yet — e.g. when the
  // first /api/chat call is in mid-stream and the title-derivation fires
  // before saveConversation has had a chance to run. WHERE title IS NULL
  // preserves set-once semantics: a resumed session whose cache entry was
  // evicted must not have its existing title clobbered.
  try {
    db()
      .update(chatSessions)
      .set({ title: trimmed })
      .where(and(eq(chatSessions.id, id), isNull(chatSessions.title)))
      .run();
  } catch {
    /* intentionally swallowed */
  }
}

export type SessionSummary = {
  id: string;
  title: string | null;
  createdAt: number;
  lastTouched: number;
  turnCount: number;
  expiresAt: number;
  irActive: boolean;
};

/** List all non-expired conversations newest-first. Used by the /chat left
 *  rail. Reads from the DB directly — the in-memory cache only ever holds
 *  the currently-active session(s), so it's not a complete picture. */
export function listSessions(): SessionSummary[] {
  // Drop expired rows opportunistically while we're here. Cheaper than
  // waiting on the 10-min sweep, and a list call is the natural moment to
  // hide rows the user no longer cares about.
  const now = Date.now();
  try {
    db().delete(chatSessions).where(lt(chatSessions.lastTouched, now - TTL_MS)).run();
  } catch {
    /* intentionally swallowed */
  }
  let rows: Array<typeof chatSessions.$inferSelect>;
  try {
    rows = db()
      .select()
      .from(chatSessions)
      .where(gt(chatSessions.lastTouched, now - TTL_MS))
      .orderBy(desc(chatSessions.lastTouched))
      .all();
  } catch {
    return [];
  }
  const out: SessionSummary[] = [];
  for (const row of rows) {
    let messages: Anthropic.Beta.BetaMessageParam[];
    try {
      messages = JSON.parse(row.messagesJson) as Anthropic.Beta.BetaMessageParam[];
    } catch {
      continue;
    }
    let turnCount = 0;
    for (const m of messages) {
      if (m.role === "user") turnCount++;
    }
    // turnCount === 0 is the "fresh session id, never sent a prompt"
    // shape. Skip — surfacing it in the list would be confusing.
    if (turnCount === 0) continue;
    // Fallback: rows from before the title feature (or any row that somehow
    // missed setSessionTitle) carry a null title and render as a bare
    // timestamp in the rail. Synthesize from the first user message so every
    // row has something scannable.
    const title = row.title || deriveTitleFromMessages(messages);
    out.push({
      id: row.id,
      title,
      createdAt: row.createdAt || row.lastTouched,
      lastTouched: row.lastTouched,
      turnCount,
      expiresAt: row.lastTouched + TTL_MS,
      irActive: !!row.irModeJson,
    });
  }
  return out;
}

export type FullSession = {
  id: string;
  title: string | null;
  createdAt: number;
  lastTouched: number;
  expiresAt: number;
  messages: Anthropic.Beta.BetaMessageParam[];
  irMode: IrMode | null;
};

/** Return the full conversation history for the resume path. Returns null
 *  if the session is expired or missing. */
export function getFullSession(id: string): FullSession | null {
  const entry = hydrate(id);
  if (!entry) return null;
  return {
    id,
    title: entry.title ?? null,
    createdAt: entry.createdAt,
    lastTouched: entry.lastTouched,
    expiresAt: entry.lastTouched + TTL_MS,
    messages: entry.messages,
    irMode: entry.irMode ?? null,
  };
}

export function clearAllConversations(): number {
  const n = conversations.size;
  conversations.clear();
  try {
    db().delete(chatSessions).run();
  } catch {
    /* intentionally swallowed */
  }
  return n;
}

export function getStats(): {
  sessionCount: number;
  totalMessages: number;
  oldestIdleMs: number | null;
} {
  sweepExpired();
  let total = 0;
  let oldestTouched: number | null = null;
  const now = Date.now();
  for (const entry of conversations.values()) {
    total += entry.messages.length;
    if (oldestTouched === null || entry.lastTouched < oldestTouched) {
      oldestTouched = entry.lastTouched;
    }
  }
  return {
    sessionCount: conversations.size,
    totalMessages: total,
    oldestIdleMs: oldestTouched === null ? null : now - oldestTouched,
  };
}

// Periodic sweep so idle sessions evict even without traffic.
const globalForSweep = globalThis as unknown as { __falconSweepArmed?: boolean };
if (!globalForSweep.__falconSweepArmed) {
  globalForSweep.__falconSweepArmed = true;
  setInterval(() => sweepExpired(), 10 * 60 * 1000).unref?.();
}

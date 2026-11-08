import "server-only";
import path from "node:path";
import fs from "node:fs";
import Database from "better-sqlite3";
import { drizzle, BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import * as schema from "./schema";

// Single SQLite handle for the process. Pinned to globalThis so Next.js
// standalone's per-chunk module duplication can't fragment the handle
// (same pattern as lib/config/store.ts and lib/chat/state.ts). See
// `module_state_globalthis_pinning` in MEMORY.md.

const DATA_DIR = process.env.FALCON_DATA_DIR ?? path.join(process.cwd(), "data");
const DB_PATH = path.join(DATA_DIR, "eyas.db");

type DbState = {
  raw: Database.Database;
  orm: BetterSQLite3Database<typeof schema>;
};

const globalForDb = globalThis as unknown as { __eyasDb?: DbState };

/** chmod, ignoring missing files and platforms where chmod is a no-op. */
export function restrictToOwner(file: string, mode: number): void {
  try {
    if (fs.existsSync(file)) fs.chmodSync(file, mode);
  } catch {
    // non-fatal
  }
}

function openDatabase(): DbState {
  fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });
  const raw = new Database(DB_PATH);
  // WAL — concurrent reader/writer safety for the Next.js process +
  // the scheduler tick. NORMAL sync is the recommended WAL pairing
  // (durable across crashes, only loses uncommitted txs on power loss).
  raw.pragma("journal_mode = WAL");
  // mode 0600 on the database AND its -wal / -shm companions (which hold
  // recent writes, including encrypted credentials). better-sqlite3 creates
  // them with the process umask, so fix them explicitly. SQLite reuses the
  // existing companion files' permissions when it recreates them.
  restrictToOwner(DATA_DIR, 0o700);
  for (const f of [DB_PATH, `${DB_PATH}-wal`, `${DB_PATH}-shm`]) restrictToOwner(f, 0o600);
  raw.pragma("synchronous = NORMAL");
  raw.pragma("foreign_keys = ON");
  raw.pragma("busy_timeout = 5000");
  installShutdownCheckpoint();
  const orm = drizzle(raw, { schema });
  return { raw, orm };
}

// Without this hook, every dev restart / SIGTERM left writes in eyas.db-wal
// that were never checkpointed back into the main file. The main DB looked
// empty (~12 KB), so any tool that read the file alone — backups, sync
// utilities, a curious `cat` — got no data. Worse, deleting the WAL files
// alone wiped the user's entire config silently. The migration runner only
// checkpoints on pending migrations, which doesn't fire on a normal boot.
//
// We install the checkpoint at open-time, idempotently. SIGTERM is the
// hot path (dev-server clean-restart, `kill <pid>`, container stop);
// SIGINT covers Ctrl-C; `beforeExit` covers Node's natural quiet exits.
//
// The handlers are registered ONCE per process and resolve the live handle
// from globalForDb at fire time rather than closing over a specific `raw`.
// That way, if closeDb() runs and a later db() call reopens a fresh handle,
// the existing handlers checkpoint the NEW handle — no need to reset the
// install flag (which would double-register the signal handlers and race the
// stale one's process.exit() against the live one).
const globalForShutdown = globalThis as unknown as { __eyasDbShutdownInstalled?: boolean };
function installShutdownCheckpoint(): void {
  if (globalForShutdown.__eyasDbShutdownInstalled) return;
  globalForShutdown.__eyasDbShutdownInstalled = true;
  const cleanup = (signal: string | null) => {
    const handle = globalForDb.__eyasDb;
    if (!handle) return;
    try {
      handle.raw.pragma("wal_checkpoint(TRUNCATE)");
    } catch (err) {
      console.warn(`[db] checkpoint on ${signal ?? "exit"} failed:`, (err as Error).message);
    }
    try {
      handle.raw.close();
    } catch {
      /* ignore */
    }
    globalForDb.__eyasDb = undefined;
  };
  for (const sig of ["SIGTERM", "SIGINT", "SIGHUP"] as const) {
    process.on(sig, () => {
      cleanup(sig);
      // Re-raise the default behavior so the process actually exits.
      // Default Node behavior for these signals is termination with the
      // matching exit code; once we've checkpointed we want to honor it.
      process.exit(sig === "SIGINT" ? 130 : sig === "SIGTERM" ? 143 : 129);
    });
  }
  process.on("beforeExit", () => cleanup(null));
}

export function db(): BetterSQLite3Database<typeof schema> {
  if (!globalForDb.__eyasDb) globalForDb.__eyasDb = openDatabase();
  return globalForDb.__eyasDb.orm;
}

export function rawDb(): Database.Database {
  if (!globalForDb.__eyasDb) globalForDb.__eyasDb = openDatabase();
  return globalForDb.__eyasDb.raw;
}

export function dbFilePath(): string {
  return DB_PATH;
}

export function closeDb(): void {
  if (globalForDb.__eyasDb) {
    try {
      globalForDb.__eyasDb.raw.close();
    } catch {
      /* ignore */
    }
    globalForDb.__eyasDb = undefined;
  }
}

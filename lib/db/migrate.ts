import "server-only";
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { rawDb, dbFilePath } from "./client";

// Forward-only migration runner with three safety properties beyond a
// naive "apply every .sql once":
//
//   1. Checksum each shipped migration. If a previously-applied file's
//      on-disk content no longer matches the recorded hash, refuse to
//      boot. This catches the foot-gun of editing a shipped migration
//      (rule: never edit, always add 000N_<name>.sql for new schema work).
//
//   2. Forward-only schema guard. If the DB records a migration id that
//      isn't on disk in this binary, the operator has downgraded onto an
//      older bundle that doesn't know how to read the newer schema.
//      Refuse to boot — they need to either roll back the DB from the
//      backup taken before the upgrade, or move to a binary that supports
//      the schema.
//
//   3. Backup-before-migrate. If any new migrations are pending, snapshot
//      the existing eyas.db to data/backups/eyas.db.pre-<lastApplied>.<ts>
//      before applying. WAL is checkpointed first so the backup file is
//      self-contained. Rolling retention keeps the latest 5.
//
// We deliberately don't use drizzle-orm's `migrate()` from drizzle-kit's
// journal — that format has churned across versions and we don't want
// the bundle to depend on drizzle-kit at runtime. Drizzle ORM is still
// used for typesafe queries (lib/db/schema.ts).

const MIGRATIONS_DIR = path.join(process.cwd(), "lib", "db", "migrations");
const BACKUPS_DIR_NAME = "backups";
const MAX_BACKUPS = 5;

type MigrationFile = { id: string; filePath: string; checksum: string };
type AppliedRow = { id: string; checksum: string };

export class MigrationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MigrationError";
  }
}

function sha256(buf: Buffer): string {
  return createHash("sha256").update(buf).digest("hex");
}

function listMigrations(): MigrationFile[] {
  if (!fs.existsSync(MIGRATIONS_DIR)) return [];
  return fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => /^\d{4}_.+\.sql$/.test(f))
    .sort()
    .map((f) => {
      const filePath = path.join(MIGRATIONS_DIR, f);
      const buf = fs.readFileSync(filePath);
      return { id: f.replace(/\.sql$/, ""), filePath, checksum: sha256(buf) };
    });
}

function ensureMigrationsTable(): void {
  // Bootstrap __migrations itself — we can't rely on 0001_init.sql to
  // create it because we need to READ it to know if 0001 already ran.
  // The DDL is identical to the one in 0001_init.sql.
  rawDb().exec(`
    CREATE TABLE IF NOT EXISTS __migrations (
      id TEXT PRIMARY KEY,
      checksum TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
  `);
}

function appliedRows(): Map<string, string> {
  const rows = rawDb().prepare("SELECT id, checksum FROM __migrations").all() as AppliedRow[];
  return new Map(rows.map((r) => [r.id, r.checksum]));
}

function verifyShippedMatchesApplied(
  applied: Map<string, string>,
  shipped: MigrationFile[],
): void {
  const shippedById = new Map(shipped.map((m) => [m.id, m]));

  // Property 1: checksum drift on a previously-applied migration.
  for (const [id, recorded] of applied) {
    const onDisk = shippedById.get(id);
    if (!onDisk) continue; // handled by property 2 below
    if (onDisk.checksum !== recorded) {
      throw new MigrationError(
        `Migration "${id}" was modified after being applied ` +
          `(recorded checksum ${recorded.slice(0, 12)}…, on-disk ${onDisk.checksum.slice(0, 12)}…). ` +
          `Shipped migrations are forward-only. Revert the edit or create a new 000N_<name>.sql.`,
      );
    }
  }

  // Property 2: forward-only / downgrade guard.
  for (const id of applied.keys()) {
    if (!shippedById.has(id)) {
      throw new MigrationError(
        `Database has migration "${id}" applied but this binary doesn't ship it. ` +
          `You likely downgraded — roll back the DB from data/${BACKUPS_DIR_NAME}/ or upgrade the binary.`,
      );
    }
  }
}

function snapshotBeforeMigrate(lastApplied: string | null): string | null {
  const dbPath = dbFilePath();
  if (!fs.existsSync(dbPath)) return null; // fresh DB — nothing to back up
  const dataDir = path.dirname(dbPath);
  const backupsDir = path.join(dataDir, BACKUPS_DIR_NAME);
  fs.mkdirSync(backupsDir, { recursive: true, mode: 0o700 });

  // Checkpoint WAL so the .db file is self-contained at copy time.
  try {
    rawDb().pragma("wal_checkpoint(TRUNCATE)");
  } catch {
    /* non-fatal: backup still useful even if checkpoint partial */
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const tag = lastApplied ?? "fresh";
  const dest = path.join(backupsDir, `eyas.db.pre-${tag}.${stamp}`);
  fs.copyFileSync(dbPath, dest);
  // Backups hold the same encrypted credentials as the live database.
  try {
    fs.chmodSync(backupsDir, 0o700);
    fs.chmodSync(dest, 0o600);
  } catch {
    // non-fatal on platforms where chmod is a no-op
  }

  // Rolling retention.
  const existing = fs
    .readdirSync(backupsDir)
    .filter((f) => f.startsWith("eyas.db.pre-"))
    .sort();
  while (existing.length > MAX_BACKUPS) {
    const drop = existing.shift();
    if (drop) {
      try {
        fs.unlinkSync(path.join(backupsDir, drop));
      } catch {
        /* ignore */
      }
    }
  }
  return dest;
}

function applyOne(m: MigrationFile): void {
  const sql = fs.readFileSync(m.filePath, "utf8");
  const stmts = sql
    .split(/^\s*-->\s*$/m)
    .map((s) => s.trim())
    .filter(Boolean);
  const tx = rawDb().transaction(() => {
    for (const stmt of stmts) rawDb().exec(stmt);
    rawDb()
      .prepare("INSERT OR REPLACE INTO __migrations (id, checksum, applied_at) VALUES (?, ?, ?)")
      .run(m.id, m.checksum, new Date().toISOString());
  });
  tx();
}

export type MigrationResult = {
  applied: string[];
  alreadyApplied: number;
  backupPath: string | null;
};

export function runMigrations(): MigrationResult {
  ensureMigrationsTable();
  const applied = appliedRows();
  const shipped = listMigrations();
  verifyShippedMatchesApplied(applied, shipped);

  const pending = shipped.filter((m) => !applied.has(m.id));
  if (pending.length === 0) {
    return { applied: [], alreadyApplied: applied.size, backupPath: null };
  }

  const lastApplied = [...applied.keys()].sort().pop() ?? null;
  const backupPath = snapshotBeforeMigrate(lastApplied);

  const appliedNow: string[] = [];
  for (const m of pending) {
    applyOne(m);
    appliedNow.push(m.id);
  }
  return { applied: appliedNow, alreadyApplied: applied.size, backupPath };
}

export function currentSchemaVersion(): string | null {
  try {
    ensureMigrationsTable();
    const row = rawDb()
      .prepare("SELECT id FROM __migrations ORDER BY id DESC LIMIT 1")
      .get() as { id: string } | undefined;
    return row?.id ?? null;
  } catch {
    return null;
  }
}

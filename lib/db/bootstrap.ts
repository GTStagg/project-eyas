import "server-only";
import { runMigrations, MigrationError } from "./migrate";
import { debugLog } from "@/lib/log";

// Single boot entry point. Called from instrumentation.ts during nodejs
// runtime register(). MUST complete before any route serves a request —
// `standalone_secret_warmup_blocking` pattern: auth/settings reads must
// not race the migration runner.
//
// Fresh-install only. No legacy / cross-version data import path.

type BootResult = {
  ok: boolean;
  appliedMigrations: string[];
  alreadyApplied: number;
  backupPath: string | null;
  error?: string;
};

let bootPromise: Promise<BootResult> | null = null;
let lastResult: BootResult | null = null;

export function bootstrapDb(): Promise<BootResult> {
  if (!bootPromise) {
    bootPromise = (async () => {
      const t0 = Date.now();
      try {
        const result = runMigrations();
        // Newly-applied migrations are operationally interesting (rare,
        // one-shot per release) — always log so the operator sees the
        // schema change in the boot trail.
        if (result.applied.length) {
          console.log(
            `[db] applied ${result.applied.length} migration(s): ${result.applied.join(", ")} ` +
              `(already at ${result.alreadyApplied}; backup: ${result.backupPath ?? "none"})`,
          );
        }
        const out: BootResult = {
          ok: true,
          appliedMigrations: result.applied,
          alreadyApplied: result.alreadyApplied,
          backupPath: result.backupPath,
        };
        lastResult = out;
        debugLog(`[db] bootstrap complete in ${Date.now() - t0}ms`);
        return out;
      } catch (err) {
        // MigrationError is fatal-but-recoverable: surface it loudly so the
        // operator sees the cause (checksum drift, downgrade trap) instead
        // of a generic 500 in routes.
        const msg = err instanceof MigrationError ? err.message : (err as Error).message;
        console.error("[db] bootstrap failed:", msg);
        const out: BootResult = {
          ok: false,
          appliedMigrations: [],
          alreadyApplied: 0,
          backupPath: null,
          error: msg,
        };
        lastResult = out;
        // Reset bootPromise so a retry can re-attempt after operator fixes it.
        bootPromise = null;
        return out;
      }
    })();
  }
  return bootPromise;
}

export function lastBootResult(): BootResult | null {
  return lastResult;
}

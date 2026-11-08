// Next.js boot hook. Runs once per server lifetime.
// https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
//
// process.env.NEXT_RUNTIME is replaced by Next at build time as a constant
// per output ("edge" vs "nodejs"), so the import below is dead-code-eliminated
// from the edge bundle and never traced through @modelcontextprotocol/sdk's
// stdio client (which requires `child_process`) or better-sqlite3 (which
// requires a native binary).
export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    const secret = process.env.AUTH_SESSION_SECRET;
    if (!secret || secret.length < 32) {
      // Don't crash production hot-reload, but make the misconfig loud at boot.
      // The middleware separately fails closed by redirecting to /login?err=config.
      console.error(
        "[auth] AUTH_SESSION_SECRET is missing or shorter than 32 chars. " +
          "All routes will redirect to /login until set. Generate with: openssl rand -hex 32",
      );
    }
    // Block on DB bootstrap before serving any route. Runs schema
    // migrations (with checksum verification + pre-migrate backup).
    // `standalone_secret_warmup_blocking` pattern: a route that reads
    // settings or auth must not race the runner.
    const { bootstrapDb } = await import("./lib/db/bootstrap");
    const result = await bootstrapDb();
    if (!result.ok) {
      // Don't crash — middleware will surface this via /login?err=config
      // and /api/health will expose the migration error to /status.
      console.error("[boot] DB bootstrap returned !ok — auth/settings routes will fail.");
    }
    if (process.env.SCHEDULER_ENABLED !== "true") return;
    const { startScheduler } = await import("./lib/scheduler/runtime");
    startScheduler();
  }
}

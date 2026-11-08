// Regression test for lib/auth/login-throttle.ts: free attempts, exponential
// delay, cap, recovery after success or idle reset, and client keying
// (shared bucket by default; right-most X-Forwarded-For only when
// EYAS_TRUST_PROXY=true, so a spoofed left-hand entry can't pick the key).
//
// Run as:  npm run test:login-throttle   (spawns this under tsx)

import { spawnSync } from "node:child_process";

if (!process.env.LOGIN_THROTTLE_CHILD) {
  const res = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", import.meta.filename],
    { env: { ...process.env, LOGIN_THROTTLE_CHILD: "1" }, encoding: "utf8" },
  );
  process.stdout.write(res.stdout ?? "");
  if (res.stderr && res.stderr.trim()) process.stderr.write(res.stderr);
  const m = (res.stdout ?? "").match(/::result:: failed=(\d+)/);
  const failed = m ? Number(m[1]) : 1;
  if (failed) {
    console.log(`\n${failed} check(s) failed`);
    process.exit(1);
  }
  console.log("\nAll login-throttle checks passed.");
  process.exit(0);
}

await runChild();

async function runChild() {
  const Module = (await import("node:module")).default;
  const { join } = await import("node:path");
  const stubPath = join(process.cwd(), "node_modules/next/dist/compiled/server-only/empty.js");
  const origResolve = Module._resolveFilename;
  Module._resolveFilename = function patched(request, ...rest) {
    if (request === "server-only") return stubPath;
    return origResolve.call(this, request, ...rest);
  };
  const { pathToFileURL } = await import("node:url");
  const t = await import(pathToFileURL(join(process.cwd(), "lib/auth/login-throttle.ts")).href);

  let failed = 0;
  const check = (label, ok, detail) => {
    if (ok) console.log(`  ok  ${label}`);
    else {
      console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ""}`);
      failed++;
    }
  };

  const T0 = 1_000_000_000;
  const k = "global";

  t._resetLoginThrottle();
  for (let i = 1; i <= 4; i++) t.recordFailure(k, T0);
  check("4 failures: no delay yet", t.retryAfterMs(k, T0) === 0);
  t.recordFailure(k, T0);
  check("5th failure: 30s delay", t.retryAfterMs(k, T0) === 30_000, String(t.retryAfterMs(k, T0)));
  check("delay elapses", t.retryAfterMs(k, T0 + 30_000) === 0);
  t.recordFailure(k, T0 + 30_000);
  check("6th failure: 60s delay", t.retryAfterMs(k, T0 + 30_000) === 60_000);
  for (let i = 0; i < 20; i++) t.recordFailure(k, T0 + 40_000);
  check("delay capped at 15 min", t.retryAfterMs(k, T0 + 40_000) === 15 * 60_000);
  check("idle reset after 1h", t.retryAfterMs(k, T0 + 40_000 + 60 * 60_000 + 1) === 0);

  t._resetLoginThrottle();
  for (let i = 0; i < 6; i++) t.recordFailure(k, T0);
  t.recordSuccess(k);
  check("success clears the record", t.retryAfterMs(k, T0) === 0);
  t.recordFailure(k, T0);
  check("after success the count restarts", t.retryAfterMs(k, T0) === 0);

  const h = (xff) => new Headers(xff ? { "x-forwarded-for": xff } : {});
  delete process.env.EYAS_TRUST_PROXY;
  check("default: X-Forwarded-For ignored", t.clientKey(h("1.2.3.4")) === "global");
  process.env.EYAS_TRUST_PROXY = "true";
  check("trusted proxy: right-most entry", t.clientKey(h("6.6.6.6, 10.0.0.9")) === "ip:10.0.0.9");
  check("trusted proxy: no header falls back", t.clientKey(h()) === "global");

  t._resetLoginThrottle();
  for (let i = 0; i < 10; i++) t.recordFailure("ip:6.6.6.6", T0);
  check("one client's failures don't delay another", t.retryAfterMs("ip:10.0.0.9", T0) === 0);

  console.log(`::result:: failed=${failed}`);
}

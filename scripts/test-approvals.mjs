#!/usr/bin/env node
// Unit tests for lib/chat/approvals.ts — the per-tool human-in-the-loop
// approval core. This is the heart of the write-gating guarantee, so the
// invariants below are load-bearing:
//   1. allow / deny resolve the awaiting promise with that decision + {ok:true};
//   2. a resolve presenting the WRONG sessionId is refused
//      ({ok:false, reason:"session_mismatch"}) and leaves the promise pending —
//      a forged/stray request from another tab can't approve a write;
//   3. resolving an unknown id returns {ok:false, reason:"not_found"};
//   4. an abort signal (client Stop / disconnect) resolves the awaiting promise
//      as "timeout" and removes the pending entry (so a resume can't re-stamp a
//      live Allow on a dead loop); a pre-aborted signal short-circuits the same
//      way without ever registering a pending entry;
//   5. listPendingForSession is session-scoped (resume re-stamp correctness).
//
// Single process, no DB. approvals.ts imports "server-only", so the child
// patches the CJS resolver to Next's bundled stub (same convention as
// scripts/test-settings-store.mjs).
//
// Run as:  npm run test:approvals   (spawns this under tsx)

import { spawnSync } from "node:child_process";

if (!process.env.APPROVALS_TEST_CHILD) {
  // Parent — spawn the child under tsx so the .ts source loads without a build
  // step (same convention as scripts/test-settings-store.mjs).
  const res = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", import.meta.filename],
    { env: { ...process.env, APPROVALS_TEST_CHILD: "1" }, encoding: "utf8" },
  );
  process.stdout.write(res.stdout ?? "");
  if (res.stderr && res.stderr.trim()) process.stderr.write(res.stderr);
  const m = (res.stdout ?? "").match(/::result:: failed=(\d+)/);
  const failed = m ? Number(m[1]) : 1;
  if (failed) {
    console.log(`\n${failed} check(s) failed`);
    process.exit(1);
  }
  console.log("\nAll approvals checks passed.");
  process.exit(0);
}

await runChild();

async function runChild() {
  // Patch the CJS resolver so "server-only" loads to Next's bundled stub.
  const Module = (await import("node:module")).default;
  const { join } = await import("node:path");
  const stubPath = join(process.cwd(), "node_modules/next/dist/compiled/server-only/empty.js");
  const origResolve = Module._resolveFilename;
  Module._resolveFilename = function patched(request, ...rest) {
    if (request === "server-only") return stubPath;
    return origResolve.call(this, request, ...rest);
  };

  const { pathToFileURL } = await import("node:url");
  const imp = (rel) => import(pathToFileURL(join(process.cwd(), rel)).href);

  const { awaitApproval, resolveApproval, listPendingForSession } = await imp(
    "lib/chat/approvals.ts",
  );

  let failed = 0;
  const check = (label, ok, detail) => {
    if (ok) console.log(`  ok  ${label}`);
    else {
      console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ""}`);
      failed++;
    }
  };

  // Resolve a promise OR report it's still pending after `ms` (timers in
  // awaitApproval are unref'd, so an unsettled promise can't hang the process —
  // but we still bound the wait so the test stays fast).
  const settleOrPending = (promise, ms = 40) =>
    Promise.race([
      promise.then((value) => ({ settled: true, value })),
      new Promise((res) => setTimeout(() => res({ settled: false }), ms)),
    ]);

  let id = 0;
  const nextId = () => `tu-${++id}`;

  // 1. allow resolves the promise + {ok:true}
  {
    const tu = nextId();
    const p = awaitApproval(tu, "extras_host_contain", "sessA");
    const r = resolveApproval(tu, "allow", "sessA");
    check("allow → resolveApproval returns {ok:true}", r.ok === true, JSON.stringify(r));
    const d = await p;
    check("allow → awaiting promise resolves 'allow'", d === "allow", d);
    // The entry must be gone after a successful allow — a lingering entry would
    // let a resume re-stamp a live Allow button on an already-resolved write.
    const stillListed = listPendingForSession("sessA").some((e) => e.toolUseId === tu);
    check("allow → pending entry is removed after resolve", stillListed === false);
  }

  // 1b. deny resolves the promise + {ok:true}
  {
    const tu = nextId();
    const p = awaitApproval(tu, "extras_host_contain", "sessA");
    const r = resolveApproval(tu, "deny", "sessA");
    check("deny → resolveApproval returns {ok:true}", r.ok === true, JSON.stringify(r));
    const d = await p;
    check("deny → awaiting promise resolves 'deny'", d === "deny", d);
    // Same cleanup invariant on the deny path.
    const stillListed = listPendingForSession("sessA").some((e) => e.toolUseId === tu);
    check("deny → pending entry is removed after resolve", stillListed === false);
  }

  // 2. session mismatch is refused AND leaves the promise pending
  {
    const tu = nextId();
    const p = awaitApproval(tu, "extras_host_lift_containment", "sessA");
    const r = resolveApproval(tu, "allow", "sessB");
    check(
      "session mismatch → {ok:false, reason:'session_mismatch'}",
      r.ok === false && r.reason === "session_mismatch",
      JSON.stringify(r),
    );
    const race = await settleOrPending(p);
    check("session mismatch → awaiting promise stays pending", race.settled === false, JSON.stringify(race));
    // The entry must still be listed under the ORIGINAL session.
    const listedA = listPendingForSession("sessA").some((e) => e.toolUseId === tu);
    check("session mismatch → entry still pending under original session", listedA);
    // Clean up: resolve with the correct session so no entry lingers.
    resolveApproval(tu, "deny", "sessA");
    await p;
  }

  // 3. not_found for an unknown id
  {
    const r = resolveApproval("does-not-exist", "allow", "sessA");
    check(
      "unknown id → {ok:false, reason:'not_found'}",
      r.ok === false && r.reason === "not_found",
      JSON.stringify(r),
    );
  }

  // 4. abort signal resolves 'timeout' and removes the pending entry
  {
    const tu = nextId();
    const ac = new AbortController();
    const p = awaitApproval(tu, "extras_host_contain", "sessC", ac.signal);
    const before = listPendingForSession("sessC").some((e) => e.toolUseId === tu);
    check("abort → entry is pending before abort", before);
    ac.abort();
    const d = await p;
    check("abort → awaiting promise resolves 'timeout'", d === "timeout", d);
    const after = listPendingForSession("sessC").some((e) => e.toolUseId === tu);
    check("abort → pending entry is deleted after abort", after === false);
  }

  // 4b. pre-aborted signal short-circuits to 'timeout' without registering
  {
    const tu = nextId();
    const ac = new AbortController();
    ac.abort();
    const p = awaitApproval(tu, "extras_host_contain", "sessD", ac.signal);
    const d = await p;
    check("pre-aborted → resolves 'timeout' immediately", d === "timeout", d);
    const listed = listPendingForSession("sessD").some((e) => e.toolUseId === tu);
    check("pre-aborted → never registered a pending entry", listed === false);
  }

  // 5. listPendingForSession is session-scoped
  {
    const a1 = nextId();
    const a2 = nextId();
    const b1 = nextId();
    const pa1 = awaitApproval(a1, "extras_host_contain", "scopeA");
    const pa2 = awaitApproval(a2, "extras_rtr_run_cleanup", "scopeA");
    const pb1 = awaitApproval(b1, "extras_host_contain", "scopeB");

    const aIds = listPendingForSession("scopeA").map((e) => e.toolUseId).sort();
    const bIds = listPendingForSession("scopeB").map((e) => e.toolUseId);
    check(
      "listPendingForSession(scopeA) returns exactly its two ids",
      aIds.length === 2 && aIds.includes(a1) && aIds.includes(a2),
      JSON.stringify(aIds),
    );
    check(
      "listPendingForSession(scopeB) returns exactly its one id",
      bIds.length === 1 && bIds[0] === b1,
      JSON.stringify(bIds),
    );
    check(
      "listPendingForSession carries the toolName",
      listPendingForSession("scopeB")[0]?.toolName === "extras_host_contain",
    );
    check("empty session → empty list", listPendingForSession("no-such-session").length === 0);

    // Clean up.
    resolveApproval(a1, "deny", "scopeA");
    resolveApproval(a2, "deny", "scopeA");
    resolveApproval(b1, "deny", "scopeB");
    await Promise.all([pa1, pa2, pb1]);
  }

  console.log(`::result:: failed=${failed}`);
  if (failed) process.exitCode = 1;
}

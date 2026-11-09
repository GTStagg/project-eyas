#!/usr/bin/env node
// Tests for lib/mcp/rtr-dispatch.ts: Eyas's rendered patch / cleanup scripts
// run on eyas-mcp's native RTR tools (upload → run → always delete), and the
// result keeps the shape prompts, the IR ledger and the UI read.
// Run as: node scripts/test-rtr-dispatch.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.RTR_DISPATCH_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-rtr-dispatch.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, RTR_DISPATCH_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const { runDispatch, dispatchOf, DISPATCH_TOOLS } = await import(
  pathToFileURL(path.join(root, "lib/mcp/rtr-dispatch.ts")).href
);

const AID1 = "a".repeat(32);
const AID2 = "B".repeat(32);

/** Fake eyas-mcp: records calls, answers from a table of handlers. */
function fakeNative(handlers) {
  const calls = [];
  const call = async (name, args, opts) => {
    calls.push({ name, args, opts });
    const h = handlers[name];
    if (!h) return { obj: null, error: `unexpected ${name}` };
    return h(args);
  };
  return { call, calls };
}

const scriptResult = (over = {}) => ({
  ok: true,
  dry_run: false,
  script_id: "host-kill-process",
  title: "Kill process",
  dispatch: { kind: "rtr_script", script_body: "Write-Output hi", platform: "windows", device_ids: [AID1, AID2] },
  ...over,
});

test("only the three Eyas RTR tools dispatch", () => {
  assert.deepEqual([...DISPATCH_TOOLS].sort(), [
    "extras_rtr_check_patch_status",
    "extras_rtr_run_cleanup",
    "extras_rtr_run_patch",
  ]);
  assert.equal(dispatchOf({ ok: true }), null);
});

test("upload → run → delete, and the result keeps the sidecar shape", async () => {
  const n = fakeNative({
    falcon_create_rtr_script: () => ({ obj: { created: true, id: "sid-1", name: "eyas-run-x" }, error: null }),
    falcon_run_rtr_script_on_hosts: () => ({
      obj: {
        batch_id: "b-1",
        results: [
          { device_id: AID1, session_id: "s1", complete: true, task_id: "t1", stdout: "done", stderr: "" },
          { device_id: AID2.toLowerCase(), session_id: "s2", complete: false, task_id: "t2", stdout: "", stderr: "" },
        ],
        failed_hosts: [],
      },
      error: null,
    }),
    falcon_delete_rtr_scripts: () => ({ obj: { deleted: 1 }, error: null }),
  });
  const out = await runDispatch(scriptResult(), n.call, () => "eyas-run-x");

  assert.deepEqual(n.calls.map((c) => c.name), [
    "falcon_create_rtr_script",
    "falcon_run_rtr_script_on_hosts",
    "falcon_delete_rtr_scripts",
  ]);
  const create = n.calls[0].args;
  assert.equal(create.name, "eyas-run-x");
  assert.equal(create.content, "Write-Output hi");
  assert.equal(create.platform, "windows");
  assert.equal(create.permission_type, "private");
  const run = n.calls[1];
  assert.equal(run.args.script_name, "eyas-run-x");
  assert.deepEqual(run.args.device_ids, [AID1, AID2.toLowerCase()]);
  assert.ok(run.opts.timeoutMs > 60000, "the run gets a client timeout above 60 s");
  assert.deepEqual(n.calls[2].args, { ids: ["sid-1"] });

  assert.equal(out.dispatch, undefined, "the envelope never reaches the agent");
  assert.equal(out.script_id, "host-kill-process");
  assert.equal(out.dry_run, false);
  assert.equal(out.ok, true);
  assert.equal(out.host_count, 2);
  assert.equal(out.ok_count, 1);
  assert.deepEqual(out.results[0], {
    device_id: AID1, ok: true, stdout: "done", stderr: "", exit_code: null, error: null, cloud_request_id: "t1", complete: true,
  });
  assert.equal(out.results[1].complete, false);
  assert.equal(out.results[1].cloud_request_id, "t2");
});

test("the script is deleted even when the run fails", async () => {
  const n = fakeNative({
    falcon_create_rtr_script: () => ({ obj: { created: true, id: "sid-2" }, error: null }),
    falcon_run_rtr_script_on_hosts: () => ({ obj: null, error: "Failed to open RTR batch session (upstream HTTP 404)" }),
    falcon_delete_rtr_scripts: () => ({ obj: {}, error: null }),
  });
  const out = await runDispatch(scriptResult(), n.call);
  assert.equal(n.calls.at(-1).name, "falcon_delete_rtr_scripts");
  assert.equal(out.ok, false);
  assert.equal(out.stage, "run_script");
  assert.match(out.error, /404/);
});

test("a failed delete is reported, not dropped", async () => {
  const n = fakeNative({
    falcon_create_rtr_script: () => ({ obj: { id: "sid-6" }, error: null }),
    falcon_run_rtr_script_on_hosts: () => ({
      obj: { results: [{ device_id: AID1, complete: true, task_id: "t", stdout: "x" }], failed_hosts: [] },
      error: null,
    }),
    falcon_delete_rtr_scripts: () => ({ obj: null, error: "Permission denied (upstream HTTP 403)" }),
  });
  const out = await runDispatch(scriptResult(), n.call, () => "eyas-run-y");
  assert.equal(out.ok, true);
  assert.match(out.cleanup_warning, /eyas-run-y/);
  assert.match(out.cleanup_warning, /403/);
});

test("the script is deleted even when the run call throws", async () => {
  const n = fakeNative({
    falcon_create_rtr_script: () => ({ obj: { created: true, id: "sid-3" }, error: null }),
    falcon_run_rtr_script_on_hosts: () => { throw new Error("transport closed"); },
    falcon_delete_rtr_scripts: () => ({ obj: {}, error: null }),
  });
  await assert.rejects(runDispatch(scriptResult(), n.call), /transport closed/);
  assert.equal(n.calls.at(-1).name, "falcon_delete_rtr_scripts");
});

test("an upload without a readable id is not run", async () => {
  const n = fakeNative({
    falcon_create_rtr_script: () => ({ obj: { created: true, warning: "lookup failed" }, error: null }),
  });
  const out = await runDispatch(scriptResult(), n.call);
  assert.equal(out.ok, false);
  assert.equal(out.stage, "create_script");
  assert.deepEqual(n.calls.map((c) => c.name), ["falcon_create_rtr_script"]);
});

test("hosts that never opened a session are failures with nothing to poll", async () => {
  const n = fakeNative({
    falcon_create_rtr_script: () => ({ obj: { id: "sid-4" }, error: null }),
    falcon_run_rtr_script_on_hosts: () => ({
      obj: { batch_id: "b", results: [], failed_hosts: [{ device_id: AID1, phase: "init", errors: "offline" }], warning: "No host had an open RTR session, so nothing was run." },
      error: null,
    }),
    falcon_delete_rtr_scripts: () => ({ obj: {}, error: null }),
  });
  const out = await runDispatch(scriptResult(), n.call);
  assert.equal(out.ok, false);
  assert.equal(out.results[0].ok, false);
  assert.equal(out.results[0].complete, true);
  assert.equal(out.results[0].cloud_request_id, null);
  assert.equal(out.results[0].error, "offline");
  assert.match(out.warning, /nothing was run/);
});

test("bad envelopes are refused before anything is uploaded", async () => {
  const n = fakeNative({});
  for (const d of [
    { script_body: "", platform: "windows", device_ids: [AID1] },
    { script_body: "x", platform: "solaris", device_ids: [AID1] },
    { script_body: "x", platform: "windows", device_ids: ["not-an-aid"] },
  ]) {
    const out = await runDispatch({ ok: true, dispatch: { kind: "rtr_script", ...d } }, n.call);
    assert.equal(out.ok, false);
    assert.equal(out.stage, "render");
  }
  assert.equal(n.calls.length, 0);
});

test("macos maps to eyas-mcp's mac platform", async () => {
  const n = fakeNative({
    falcon_create_rtr_script: () => ({ obj: { id: "sid-5" }, error: null }),
    falcon_run_rtr_script_on_hosts: () => ({ obj: { results: [], failed_hosts: [] }, error: null }),
    falcon_delete_rtr_scripts: () => ({ obj: {}, error: null }),
  });
  await runDispatch(scriptResult({ dispatch: { kind: "rtr_script", script_body: "echo", platform: "macos", device_ids: [AID1] } }), n.call);
  assert.equal(n.calls[0].args.platform, "mac");
});

test("status checks go through falcon_check_rtr_admin_command_status", async () => {
  const n = fakeNative({
    falcon_check_rtr_admin_command_status: (args) => ({
      obj: {
        requested: args.cloud_request_ids.length,
        results: [
          { cloud_request_id: "t1", complete: true, stdout: "ok", stderr: "" },
          { cloud_request_id: "t2", complete: false, error: "Failed to check" },
        ],
      },
      error: null,
    }),
  });
  const out = await runDispatch({ ok: true, dispatch: { kind: "rtr_status", cloud_request_ids: ["t1", "t2"] } }, n.call);
  assert.deepEqual(n.calls[0].args, { cloud_request_ids: ["t1", "t2"] });
  assert.equal(out.ok, true);
  assert.equal(out.count, 2);
  assert.equal(out.complete_count, 1);
  assert.equal(out.results[0].stdout, "ok");
  assert.equal(out.results[1].error, "Failed to check");
});

#!/usr/bin/env node
// Tests for Eyas's RTR script library and its agent tools
// (lib/eyas-tools/rtr/library.ts, lib/eyas-tools/rtr-tools.ts): every script
// renders to ASCII, params are reject-validated, the batch guard holds, dry
// runs never reach eyas-mcp, and a live run uploads → runs → deletes.
// Run as: node scripts/test-rtr-library.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.RTR_LIBRARY_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-rtr-library.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, RTR_LIBRARY_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const lib = await import(pathToFileURL(path.join(root, "lib/eyas-tools/rtr/library.ts")).href);
const { RTR_TOOLS, classifyPatchCoverage, LARGE_BATCH_THRESHOLD } = await import(
  pathToFileURL(path.join(root, "lib/eyas-tools/rtr-tools.ts")).href
);
const tool = (name) => RTR_TOOLS.find((t) => t.name === name);
const AID = "a1b2c3d4e5f60718293a4b5c6d7e8f90";

const SAMPLES = {
  service_name: "Spooler", task_path: "\\Microsoft\\Task", value_name: "Updater", image_name: "sethc.exe",
  value: "1", path: "C:\\Temp\\x.exe", install_root: "C:\\Tools\\ComfyUI", filter_name: "BadFilter",
  username: "baduser", remote_ip: "10.0.0.5", pid: "1234", package_name_pattern: "Microsoft.Foo*",
  kb_filter: "KB5034441", url: "https://example.com/app.msi", product: "Example App", package: "curl",
};
const sampleParams = (spec) => {
  const out = {};
  for (const [k, p] of Object.entries(spec.params ?? {})) {
    if ("default" in p || p.optional) continue;
    out[k] = p.type === "enum" ? p.values[0] : SAMPLES[k] ?? "x";
  }
  return out;
};

function fakeNative(responses = {}) {
  const calls = [];
  const callNative = async (name, args) => {
    calls.push({ name, args });
    const r = responses[name];
    return typeof r === "function" ? r(args) : r ?? { obj: {}, error: null };
  };
  return { calls, callNative };
}
const run = async (name, input, ctx = fakeNative()) => {
  const r = await tool(name).run(input, ctx);
  return { ...JSON.parse(r.content), isError: r.isError };
};

test("every patch and cleanup script renders to pure ASCII with a params header", () => {
  for (const catalog of ["patching", "cleanup"]) {
    for (const spec of lib.loadManifest(catalog).scripts) {
      const plan = lib.resolvePlan(catalog, spec.id, sampleParams(spec));
      assert.ok(plan.rendered.length > 100, spec.id);
      assert.ok([...plan.rendered].every((c) => c.codePointAt(0) < 128), `${spec.id} non-ASCII`);
      assert.ok(plan.rendered.startsWith(`# Rendered by Eyas (${catalog} library)\n# script_id: ${spec.id}\n`));
      assert.ok(plan.preview.split("\n").length <= 41);
    }
  }
});

test("'?' survives rendering (the Python renderer dropped it)", () => {
  const plan = lib.resolvePlan("patching", "linux-pkg-upgrade", { package: "curl" });
  assert.match(plan.rendered, /rc=\$\?/);
  const edge = lib.resolvePlan("patching", "app-edge", {});
  assert.match(edge.rendered, /fwlink\/\?linkid=/);
  const gen = lib.resolvePlan("patching", "win-app-install", { url: "https://example.com/dl?id=5&x=1", product: "App" });
  assert.match(gen.rendered, /Url = 'https:\/\/example\.com\/dl\?id=5&x=1'/);
});

test("ASCII coercion maps smart punctuation and drops the rest", () => {
  assert.equal(lib.asciiCoerce("a\u2014b \u201cq\u201d caf\u00e9 \u{1F600}?"), 'a--b "q" caf ?');
});

test("params: unknown keys, bad enums, pattern misses and missing values are refused", () => {
  assert.throws(() => lib.resolvePlan("patching", "win-update-install", { reboot: "now" }), /'now' not in \['never'/);
  assert.throws(() => lib.resolvePlan("patching", "linux-pkg-upgrade", { package: "curl; rm -rf /" }), /does not match pattern/);
  assert.throws(() => lib.resolvePlan("patching", "linux-pkg-upgrade", {}), /required, not supplied/);
  assert.throws(() => lib.resolvePlan("patching", "linux-pkg-upgrade", { package: "curl", extra: 1 }), /unknown params: \['extra'\]/);
  assert.throws(() => lib.resolvePlan("patching", "nope", {}), /unknown script id: 'nope'/);
  assert.throws(() => lib.resolvePlan("cleanup", "host-kill-process", { pid: 12 }), /must be string/);
});

test("evidence-vouched keys use the wider, still-bounded pattern", () => {
  const p = { path: "C:\\Temp\\a+b=c;d[1].exe" };
  assert.throws(() => lib.resolvePlan("cleanup", "host-delete-file", p), /does not match pattern/);
  assert.ok(lib.resolvePlan("cleanup", "host-delete-file", p, new Set(["path"])));
  assert.throws(
    () => lib.resolvePlan("cleanup", "host-delete-file", { path: "C:\\Temp\\a*b.exe" }, new Set(["path"])),
    /evidence-vouched/,
  );
});

test("PowerShell and bash literals escape single quotes", () => {
  assert.equal(lib.toPwshLiteral("it's"), "'it''s'");
  assert.equal(lib.toBashLiteral("it's"), `'it'"'"'s'`);
  assert.equal(lib.renderParamsBlock({ kb_filter: "KB1" }, "windows"), "$Params = @{\n    KbFilter = 'KB1'\n}\n");
  assert.equal(lib.renderParamsBlock({ package: "curl" }, "linux"), "PACKAGE='curl'\n");
});

test("Spotlight matching: first declared wins, OS filter, (?i), Linux fallback", () => {
  assert.equal(lib.matchRemediation("Microsoft", "Windows Subsystem for Linux", "windows").id, "win-wsl-update");
  assert.equal(lib.matchRemediation("Microsoft", "microsoft EXCEL", "windows").id, "app-office");
  assert.equal(lib.matchRemediation("Google LLC", "Chrome", "macos").id, "macos-app-chrome");
  assert.equal(lib.matchRemediation("Unknown", "Thing", null), null);
  assert.deepEqual(lib.linuxPkgFallback("ntfs-3g 1:2022.10.3-1ubuntu4.4").params, { package: "ntfs-3g" });
  assert.equal(lib.linuxPkgFallback("bad;pkg 1.0"), null);
  assert.equal(lib.linuxPkgFallback("   "), null);
});

test("agent-facing schemas keep the required params pinned", () => {
  const req = (n) => tool(n).input_schema.required ?? [];
  assert.deepEqual(req("extras_rtr_run_cleanup").slice().sort(), ["device_ids", "script_id"]);
  assert.deepEqual(req("extras_rtr_run_patch").slice().sort(), ["device_ids", "script_id"]);
  assert.deepEqual(req("extras_save_patch_profile").slice().sort(), ["kind", "name", "product", "url"]);
  assert.equal(RTR_TOOLS.length, 10);
  // The catalogs must reach the agent whole (the cleanup one is over 12 KB).
  assert.equal(tool("extras_rtr_list_cleanup_scripts").rawResult, true);
  assert.equal(tool("extras_rtr_list_patch_scripts").rawResult, true);
});

test("dry runs (the default) never reach eyas-mcp", async () => {
  const ctx = fakeNative();
  const r = await run("extras_rtr_run_cleanup", { script_id: "host-kill-process", device_ids: [AID], params: { pid: "42" } }, ctx);
  assert.equal(r.ok, true);
  assert.equal(r.dry_run, true);
  assert.equal(r.host_count, 1);
  assert.equal(ctx.calls.length, 0);
  const p = await run("extras_rtr_run_patch", { script_id: "win-app-install", device_ids: [AID], params: { url: "https://example.com/a.msi", product: "A" } }, ctx);
  assert.equal(p.hash_pinned, false);
  assert.equal(ctx.calls.length, 0);
});

test("batch guard refuses a wide run without confirm_large_batch", async () => {
  const ids = Array.from({ length: LARGE_BATCH_THRESHOLD + 1 }, (_, i) => i.toString(16).padStart(32, "0"));
  const r = await run("extras_rtr_run_patch", { script_id: "app-edge", device_ids: ids, dry_run: false });
  assert.equal(r.ok, false);
  assert.equal(r.threshold, LARGE_BATCH_THRESHOLD);
  const empty = await run("extras_rtr_run_patch", { script_id: "app-edge", device_ids: [] });
  assert.match(empty.error, /non-empty/);
});

test("a live run uploads the rendered script, runs it and deletes it", async () => {
  const ctx = fakeNative({
    falcon_create_rtr_script: { obj: { id: "script-1" }, error: null },
    falcon_run_rtr_script_on_hosts: {
      obj: { results: [{ device_id: AID, complete: true, stdout: "done", stderr: "", errors: [] }] },
      error: null,
    },
    falcon_delete_rtr_scripts: { obj: {}, error: null },
  });
  const r = await run(
    "extras_rtr_run_cleanup",
    { script_id: "host-kill-process", device_ids: [AID], params: { pid: "42" }, dry_run: false },
    ctx,
  );
  assert.deepEqual(ctx.calls.map((c) => c.name), [
    "falcon_create_rtr_script",
    "falcon_run_rtr_script_on_hosts",
    "falcon_delete_rtr_scripts",
  ]);
  const uploaded = ctx.calls[0].args;
  assert.match(String(uploaded.content ?? uploaded.script_body ?? JSON.stringify(uploaded)), /Pid = '42'/);
  assert.equal(r.dry_run, false);
  assert.equal(r.script_id, "host-kill-process");
  assert.ok(Array.isArray(r.results));
  assert.equal(r.dispatch, undefined);
});

test("patch status checks go to eyas-mcp; empty ids are refused", async () => {
  const empty = await run("extras_rtr_check_patch_status", { cloud_request_ids: [" "] });
  assert.equal(empty.ok, false);
  const ctx = fakeNative({ falcon_check_rtr_admin_command_status: { obj: { complete: true, stdout: "ok" }, error: null } });
  await run("extras_rtr_check_patch_status", { cloud_request_ids: ["req-1"] }, ctx);
  assert.equal(ctx.calls[0].name, "falcon_check_rtr_admin_command_status");
});

test("resolve: no match on Windows offers the generic installer; Linux falls back", async () => {
  const gap = await run("extras_rtr_resolve_patch_plan", { spotlight_remediation: { vendor: "X", product: "Y" }, device_ids: [AID], os_hint: "Windows" });
  assert.equal(gap.ok, false);
  assert.equal(gap.generic_installer_available, true);
  const lin = await run("extras_rtr_resolve_patch_plan", { spotlight_remediation: { vendor: "V", product: "httpd 2.4.57-5.el9" }, device_ids: [AID], os_hint: "linux" });
  assert.equal(lin.script_id, "linux-pkg-upgrade");
  assert.deepEqual(lin.params, { package: "httpd" });
  const bad = await run("extras_rtr_resolve_patch_plan", { spotlight_remediation: {}, device_ids: [], os_hint: "bsd" });
  assert.match(bad.error, /os_hint must be one of/);
});

test("saving a patch profile reuses the installer's validation", async () => {
  const ok = await run("extras_save_patch_profile", { name: " 7-Zip ", product: "7-Zip", url: "https://www.7-zip.org/a/7z.msi", kind: "msi", sha256: "A".repeat(64) });
  assert.equal(ok.ok, true);
  assert.match(ok.profile.id, /^pp_[0-9a-f]{12}$/);
  assert.equal(ok.profile.name, "7-Zip");
  assert.equal(ok.hash_pinned, true);
  const bad = await run("extras_save_patch_profile", { name: "x", product: "x", url: "http://insecure", kind: "msi" });
  assert.match(bad.error, /param 'url'/);
  assert.match((await run("extras_save_patch_profile", { name: "x".repeat(65) })).error, /64 characters/);
});

test("coverage classification", () => {
  const r = classifyPatchCoverage([
    { vendor: "Google LLC", product: "Chrome", os: "Windows" },
    { vendor: "X", product: "Y", os: "Win10" },
    { vendor: "V", product: "openssl 3.0.2", os: "Linux" },
    { vendor: "X", product: "Y", os: "BeOS" },
    "junk",
  ]);
  assert.deepEqual(r.results.map((x) => [x.os, x.script_id, x.generic_installer_eligible]), [
    ["windows", "app-chrome", false],
    ["windows", null, true],
    ["linux", "linux-pkg-upgrade", false],
    [null, null, false],
    [null, null, false],
  ]);
  assert.equal(classifyPatchCoverage("nope").ok, false);
});

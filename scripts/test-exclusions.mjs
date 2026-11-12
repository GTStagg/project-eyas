#!/usr/bin/env node
// Tests for the exclusion and Data Protection tools
// (lib/eyas-tools/exclusions.ts, lib/eyas-tools/data-protection.ts) against a
// fake eyas-mcp. Includes the port of falcon-extras' test_exclusions.py.
// Run as: node scripts/test-exclusions.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.EXCLUSIONS_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-exclusions.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, EXCLUSIONS_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const load = (p) => import(pathToFileURL(path.join(root, p)).href);
const ex = await load("lib/eyas-tools/exclusions.ts");
const dlp = await load("lib/eyas-tools/data-protection.ts");

// ------------------------------------------------ regex pre-flight (port)

test("zero-width assertion pre-flight", () => {
  const cases = [
    [String.raw`.*\\powershell\.exe(\W.*)?`, null], // the IR-readiness pattern
    [String.raw`.*\\powershell\.exe$`, "$"],
    [String.raw`^.*\\cmd\.exe`, "^"],
    [String.raw`.*\bmimikatz\b.*`, "\\b"],
    [String.raw`\A.*`, "\\A"],
    [String.raw`.*\Z`, "\\Z"],
    [String.raw`.*\B.*`, "\\B"],
    [String.raw`.*\$HOME.*`, null], // escaped dollar is a literal
    [String.raw`.*\\\\$`, "$"], // escaped backslashes, then a real anchor
    [String.raw`[^/]*\.exe`, null], // class negation
    ["[$]x", null], // dollar inside a class
    [String.raw`[\b]x`, null], // backspace inside a class
    ["[]^]x", null], // leading ] is a literal, ^ inside the class
    ["[^]$]x", null],
    ["[a-z]+$", "$"], // the class closed before the anchor
    ["", null],
  ];
  for (const [pattern, want] of cases) assert.equal(ex.findZeroWidthAssertion(pattern), want, pattern);
});

test("Python-style repr", () => {
  assert.equal(ex.pyRepr("C:\\a"), "'C:\\\\a'");
  assert.equal(ex.pyRepr("it's"), '"it\'s"');
});

// ------------------------------------------------ fake eyas-mcp

function fakeCtx(handlers) {
  const calls = [];
  const run = async (name, args) => {
    calls.push({ name, args });
    const h = handlers[name];
    if (!h) throw new Error(`unexpected native ${name}`);
    return h(args);
  };
  return {
    calls,
    ctx: {
      callNative: async (name, args) => {
        const o = await run(name, args);
        return o && o.__error ? { obj: null, error: o.__error } : { obj: o, error: null };
      },
      searchNative: async (name, args) => {
        const o = await run(name, args);
        if (o && o.__error) return { ok: false, error: o.__error };
        if (o && o.__scope) return { ok: true, scope_pending: true, items: [] };
        return { ok: true, items: o };
      },
    },
  };
}

// ------------------------------------------------ lists

test("list ML exclusions: sort, limit cap, record shape", async () => {
  const f = fakeCtx({
    falcon_search_exclusions: () => [{ id: "e1", value: "C:\\a.exe", groups: [{ id: "g1", name: "G" }], applied_globally: false }],
  });
  const out = await ex.listMlExclusions(f.ctx, { limit: 9999, filter: "applied_globally:true" });
  assert.deepEqual(f.calls[0].args, { exclusion_type: "ml", limit: 500, sort: "last_modified.desc", filter: "applied_globally:true" });
  assert.deepEqual(out.items[0].groups, ["G"]);
  assert.deepEqual(out.items[0].group_ids, ["g1"]);
  // eyas-mcp's own shape: id strings, under `groups` (ML) or `host_groups` (IOA).
  const nat = fakeCtx({ falcon_search_exclusions: () => [{ id: "e2", groups: ["g7"] }, { id: "e3", host_groups: ["g8", "g9"] }] });
  const items = (await ex.listMlExclusions(nat.ctx, {})).items;
  assert.deepEqual([items[0].groups, items[0].group_ids], [["g7"], ["g7"]]);
  assert.deepEqual([items[1].groups, items[1].group_ids], [["g8", "g9"], ["g8", "g9"]]);
  assert.deepEqual(out.items[0].excluded_from, []);
  assert.equal(out.items[0].description, "");
  assert.equal(out.count, 1);
});

test("list IOA exclusions: no sort; scope denial", async () => {
  const f = fakeCtx({ falcon_search_exclusions: () => [] });
  await ex.listIoaExclusions(f.ctx, {});
  assert.deepEqual(f.calls[0].args, { exclusion_type: "ioa", limit: 100 });
  const d = fakeCtx({ falcon_search_exclusions: () => ({ __scope: true }) });
  assert.equal((await ex.listIoaExclusions(d.ctx, {})).scope_pending, true);
});

// ------------------------------------------------ creates

test("ML create: refuses a duplicate, otherwise creates with host groups", async () => {
  const dup = fakeCtx({ falcon_search_exclusions: () => [{ id: "old" }] });
  const d = await ex.createMlExclusion(dup.ctx, { value: "C:\\a.exe", comment: "benign" });
  assert.deepEqual([d.ok, d.duplicate, d.existing_ids], [false, true, ["old"]]);
  assert.equal(dup.calls[0].args.filter, "value:'C:\\a.exe'");
  assert.equal(dup.calls.length, 1);

  const ok = fakeCtx({ falcon_search_exclusions: () => [], falcon_create_exclusion: () => ({ id: "new" }) });
  const c = await ex.createMlExclusion(ok.ctx, { value: "/opt/x", comment: "benign", group_ids: ["g1"] });
  assert.deepEqual(c, { ok: true, id: "new", value: "/opt/x", scope: "groups", excluded_from: ["blocking"] });
  assert.deepEqual(ok.calls[1].args, { exclusion_type: "ml", value: "/opt/x", comment: "benign", excluded_from: ["blocking"], host_groups: ["g1"] });
});

test("ML create: input checks", async () => {
  const f = fakeCtx({});
  assert.match((await ex.createMlExclusion(f.ctx, { comment: "c" })).error, /value is required/);
  assert.match((await ex.createMlExclusion(f.ctx, { value: "v" })).error, /comment is required/);
  assert.equal((await ex.createMlExclusion(f.ctx, { value: "v", comment: "c", excluded_from: ["x"] })).error, "invalid excluded_from values ['x']; must be from ['blocking', 'extraction']");
  assert.match((await ex.createMlExclusion(f.ctx, { value: "it's", comment: "c" })).error, /single-quote/);
  assert.equal(f.calls.length, 0);
});

test("IOA create: zero-width rejected; duplicate only on the same image regex", async () => {
  const f = fakeCtx({});
  const z = await ex.createIoaExclusion(f.ctx, { name: "n", pattern_id: "1", ifn_regex: ".*x\\.exe$", comment: "c" });
  assert.match(z.error, /^ifn_regex: contains zero-width assertion '\$'/);
  assert.equal(f.calls.length, 0);

  const same = fakeCtx({ falcon_search_exclusions: () => [{ id: "e1", ifn_regex: ".*\\\\a\\.exe" }] });
  const d = await ex.createIoaExclusion(same.ctx, { name: "n", pattern_id: "42", ifn_regex: ".*\\\\a\\.exe", comment: "c" });
  assert.deepEqual([d.duplicate, d.existing_ids], [true, ["e1"]]);
  assert.equal(same.calls[0].args.filter, "pattern_id:'42'");

  const other = fakeCtx({
    falcon_search_exclusions: () => [{ id: "e1", ifn_regex: ".*\\\\b\\.exe" }],
    falcon_create_exclusion: () => ({ id: "new" }),
  });
  const c = await ex.createIoaExclusion(other.ctx, {
    name: "n",
    pattern_id: "42",
    ifn_regex: ".*\\\\a\\.exe",
    cl_regex: ".*-x(\\W.*)?",
    comment: "c",
    description: "d",
  });
  assert.deepEqual(c, { ok: true, id: "new", name: "n", pattern_id: "42", ifn_regex: ".*\\\\a\\.exe", scope: "global" });
  assert.deepEqual(other.calls[1].args, {
    exclusion_type: "ioa",
    name: "n",
    pattern_id: "42",
    ifn_regex: ".*\\\\a\\.exe",
    comment: "c",
    cl_regex: ".*-x(\\W.*)?",
    description: "d",
  });
});

test("IOA create: input checks and a write error", async () => {
  const f = fakeCtx({});
  assert.match((await ex.createIoaExclusion(f.ctx, {})).error, /name is required/);
  assert.match((await ex.createIoaExclusion(f.ctx, { name: "n" })).error, /pattern_id is required/);
  assert.match((await ex.createIoaExclusion(f.ctx, { name: "n", pattern_id: "1'" , ifn_regex: "x", comment: "c" })).error, /single-quote/);
  const bad = fakeCtx({ falcon_search_exclusions: () => [], falcon_create_exclusion: () => ({ __error: "HTTP 400 bad regex" }) });
  assert.deepEqual(await ex.createIoaExclusion(bad.ctx, { name: "n", pattern_id: "1", ifn_regex: "x", comment: "c" }), {
    ok: false,
    error: "HTTP 400 bad regex",
    surface: "IOAExclusions",
  });
});

// ------------------------------------------------ Data Protection

test("content pattern: dashes cleaned, defaults, native body", async () => {
  const f = fakeCtx({ falcon_create_data_security_entity: () => ({ id: "cp1" }) });
  const out = await dlp.createContentPattern(f.ctx, { name: "Codename — Falcon", regexes: ["FALCON-\\d+"], category: "Custom", description: "a – b" });
  assert.deepEqual(f.calls[0].args, {
    entity_type: "content_pattern",
    body: { name: "Codename - Falcon", regexes: ["FALCON-\\d+"], category: "Custom", region: "ALL", min_match_threshold: 1, description: "a - b" },
  });
  assert.deepEqual(out, { ok: true, id: "cp1", name: "Codename — Falcon", category: "Custom", region: "ALL", regex_count: 1 });
});

test("classification: monitor-first defaults", async () => {
  const f = fakeCtx({ falcon_create_data_security_entity: () => ({ id: "c1" }) });
  const out = await dlp.createClassification(f.ctx, { name: "PII", content_patterns: ["cp1"] });
  const body = f.calls[0].args.body;
  assert.equal(f.calls[0].args.entity_type, "classification");
  assert.equal(body.classification_properties.protection_mode, "monitor");
  assert.deepEqual(body.classification_properties.rules[0], {
    detection_severity: "informational",
    response_action: "allow",
    user_scope: "all",
    web_locations_scope: "all",
    trigger_detection: true,
    notify_end_user: false,
    enable_web_locations: true,
    enable_usb_devices: true,
    enable_printer_egress: true,
  });
  assert.equal(out.protection_mode, "monitor");
  assert.equal((await dlp.createClassification(f.ctx, { name: "x", content_patterns: ["a"], protection_mode: "kill" })).error, "protection_mode must be one of ['enforce', 'monitor']");
});

test("policy: platform required, monitor-safe properties, platform_name passed", async () => {
  const f = fakeCtx({ falcon_create_data_security_entity: () => ({ id: "p1" }) });
  const out = await dlp.createPolicy(f.ctx, { name: "DLP — win", platform: "win", classifications: ["c1"], precedence: 2 });
  assert.equal(f.calls[0].args.platform_name, "win");
  const body = f.calls[0].args.body;
  assert.equal(body.name, "DLP - win");
  assert.equal(body.precedence, 2);
  assert.equal(body.policy_properties.block_all_data_access, false);
  assert.equal(body.policy_properties.inspection_depth, "balanced");
  assert.deepEqual(out, { ok: true, id: "p1", name: "DLP — win", platform: "win", classifications: ["c1"] });
  assert.equal((await dlp.createPolicy(f.ctx, { name: "x", platform: "linux", classifications: ["c"] })).error, "platform must be one of ['mac', 'win']");
});

test("DLP scope denial becomes scope_pending", async () => {
  const f = fakeCtx({ falcon_create_data_security_entity: () => ({ __error: "Permission denied. The API credentials don't have the required access. (status 403)" }) });
  assert.equal((await dlp.createContentPattern(f.ctx, { name: "n", regexes: ["x"], category: "Custom" })).scope_pending, true);
});

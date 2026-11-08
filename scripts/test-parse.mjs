#!/usr/bin/env node
// Pure-function tests for lib/mcp/parse.ts — parseConcatenatedJson and
// detectFalconError. This parser is load-bearing across 15+ dashboard routes
// AND the agent tool-result path: a regression silently turns real Falcon data
// into [] (empty dashboards) or lets an upstream error envelope render as a
// single empty row. It was previously untested. (audit 2026-06-08)
//
// Run as:  node scripts/test-parse.mjs
//
// Mirrors scripts/test-knowledge.mjs (re-spawn under tsx --test) but parse.ts
// carries `import "server-only"`, so the child stubs that resolution first.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.PARSE_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-parse.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, PARSE_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

// ───────────────────────────────────────────────────────── child (tsx --test)

import { test } from "node:test";
import assert from "node:assert/strict";

// parse.ts imports "server-only" (a throwing module outside RSC). Redirect it
// to Next's empty stub before importing.
import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const { parseConcatenatedJson, detectFalconError, isScopeDenied, parseToolResultObjects, unwrapSearchEnvelope } =
  await import(path.join(root, "lib/mcp/parse.ts"));

// ── parseConcatenatedJson ────────────────────────────────────────────────

test("empty / whitespace returns []", () => {
  assert.deepEqual(parseConcatenatedJson(""), []);
  assert.deepEqual(parseConcatenatedJson("   \n\t "), []);
});

test("single object", () => {
  assert.deepEqual(parseConcatenatedJson('{"id":1,"name":"a"}'), [{ id: 1, name: "a" }]);
});

test("multiple objects separated by newlines", () => {
  const out = parseConcatenatedJson('{"id":1}\n{"id":2}\n{"id":3}');
  assert.deepEqual(out, [{ id: 1 }, { id: 2 }, { id: 3 }]);
});

test("adjacent objects with NO newline between them", () => {
  // Falls through the fast path (which only wraps "}\n{") to the brace counter.
  assert.deepEqual(parseConcatenatedJson('{"a":1}{"b":2}'), [{ a: 1 }, { b: 2 }]);
});

test("braces and quotes INSIDE strings are not treated as structure", () => {
  const out = parseConcatenatedJson('{"path":"C:\\\\Temp\\\\{weird}\\"q\\""}');
  assert.equal(out.length, 1);
  assert.equal(out[0].path, 'C:\\Temp\\{weird}"q"');
});

test("nested objects/arrays parse as one top-level object", () => {
  const out = parseConcatenatedJson('{"a":{"b":[1,2,{"c":3}]}}\n{"d":4}');
  assert.deepEqual(out, [{ a: { b: [1, 2, { c: 3 }] } }, { d: 4 }]);
});

test("trailing whitespace / blank lines tolerated", () => {
  assert.deepEqual(parseConcatenatedJson('  {"id":1}\n\n  {"id":2}  \n'), [
    { id: 1 },
    { id: 2 },
  ]);
});

test("malformed TAIL: valid leading objects recovered, junk dropped", () => {
  const out = parseConcatenatedJson('{"a":1}\n{"b":2}\n{garbage-no-close');
  assert.deepEqual(out, [{ a: 1 }, { b: 2 }]);
});

test("malformed MIDDLE object is skipped, valid ones kept", () => {
  const out = parseConcatenatedJson('{"a":1}\n{bad}\n{"c":3}');
  assert.deepEqual(out, [{ a: 1 }, { c: 3 }]);
});

// ── detectFalconError ────────────────────────────────────────────────────

test("detectFalconError returns null for real data", () => {
  assert.equal(detectFalconError([{ id: 1 }]), null);
  assert.equal(detectFalconError([{ id: 1 }, { id: 2 }]), null);
  assert.equal(detectFalconError([]), null);
});

test("detectFalconError recognizes the {error,details} envelope with HTTP + upstream message", () => {
  const env = {
    error: "Failed to search detections",
    details: { status_code: 500, body: { errors: [{ message: "trace-id boom" }] } },
  };
  const msg = detectFalconError([env]);
  assert.ok(msg, "should detect");
  assert.match(msg, /Failed to search detections/);
  assert.match(msg, /500/);
  assert.match(msg, /trace-id boom/);
});

test("detectFalconError only fires for a SINGLE object (not a multi-row payload)", () => {
  const env = { error: "x", details: { status_code: 403 } };
  // A real data payload that happens to be >1 row is never an error envelope.
  assert.equal(detectFalconError([env, { id: 2 }]), null);
});

test("end-to-end: error envelope text parses to one object that detectFalconError catches", () => {
  const raw = '{"error":"Permission denied","details":{"status_code":403}}';
  const parsed = parseConcatenatedJson(raw);
  assert.equal(parsed.length, 1);
  const msg = detectFalconError(parsed);
  assert.match(msg, /Permission denied/);
  assert.match(msg, /403/);
});

// ── isScopeDenied ────────────────────────────────────────────────────────
// Prefer the structured signal (details.status_code / required_scopes /
// scope_pending) over prose — 0.13.0's 403 message is "Permission denied. The
// API credentials don't have the required access." (no "scope not permitted" /
// "access denied"), so a bare substring match on the old phrases would miss it.

test("isScopeDenied: falcon-mcp 403 envelope (structured, current 0.13.0 wording)", () => {
  const raw =
    '{"error":"Permission denied. The API credentials don\\u0027t have the required access.","details":{"status_code":403}}';
  assert.equal(isScopeDenied(raw), true);
});

test("isScopeDenied: 401 envelope", () => {
  assert.equal(isScopeDenied('{"error":"Authentication failed","details":{"status_code":401}}'), true);
});

test("isScopeDenied: top-level required_scopes list", () => {
  assert.equal(
    isScopeDenied('{"error":"denied","details":{"status_code":403},"required_scopes":["Cases:read"]}'),
    true,
  );
});

test("isScopeDenied: sidecar scope_pending shape", () => {
  assert.equal(isScopeDenied('{"ok":true,"scope_pending":true,"items":[]}'), true);
});

test("isScopeDenied: cases FQL envelope nests the error dict under results[0]", () => {
  const raw =
    '{"results":[{"error":"Permission denied","details":{"status_code":403}}],"filter_used":"","fql_guide":"...","hint":"..."}';
  assert.equal(isScopeDenied(raw), true);
});

test("isScopeDenied: legacy raw-body wording still trips the fallback", () => {
  assert.equal(isScopeDenied("upstream: access denied, scope not permitted"), true);
});

test("isScopeDenied: real data is NOT a denial (no false positive)", () => {
  const raw = '{"id":"abc","status":"new"}\n{"id":"def","status":"closed"}';
  assert.equal(isScopeDenied(raw), false);
});

test("isScopeDenied: a 500 error is not a scope denial", () => {
  assert.equal(isScopeDenied('{"error":"Server error","details":{"status_code":500}}'), false);
});

test("isScopeDenied: empty text is not a denial", () => {
  assert.equal(isScopeDenied(""), false);
});

// ── parseToolResultObjects ───────────────────────────────────────────────
// The MCP SDK emits one TextContent block per row; parse each block directly
// rather than join-then-re-split.

test("parseToolResultObjects: one object per content block", () => {
  const content = [
    { type: "text", text: '{"id":1}' },
    { type: "text", text: '{"id":2}' },
  ];
  assert.deepEqual(parseToolResultObjects(content), [{ id: 1 }, { id: 2 }]);
});

test("parseToolResultObjects: pretty-printed multi-line block parses", () => {
  const content = [{ type: "text", text: '{\n  "id": 1,\n  "name": "a"\n}' }];
  assert.deepEqual(parseToolResultObjects(content), [{ id: 1, name: "a" }]);
});

test("parseToolResultObjects: a JSON array block is flattened", () => {
  const content = [{ type: "text", text: '[{"id":1},{"id":2}]' }];
  assert.deepEqual(parseToolResultObjects(content), [{ id: 1 }, { id: 2 }]);
});

test("parseToolResultObjects: a block with concatenated objects falls back to the counter", () => {
  const content = [{ type: "text", text: '{"id":1}\n{"id":2}' }];
  assert.deepEqual(parseToolResultObjects(content), [{ id: 1 }, { id: 2 }]);
});

test("parseToolResultObjects: non-text blocks and empties are skipped", () => {
  const content = [
    { type: "image", data: "..." },
    { type: "text", text: "   " },
    { type: "text", text: '{"id":3}' },
  ];
  assert.deepEqual(parseToolResultObjects(content), [{ id: 3 }]);
});

test("parseToolResultObjects: undefined / empty content returns []", () => {
  assert.deepEqual(parseToolResultObjects(undefined), []);
  assert.deepEqual(parseToolResultObjects([]), []);
});

// ── 0.15.0 (#470) search pagination envelope ──────────────────────────────
// Search tools now return ONE object {results:[...], pagination:{...}} instead
// of a bare row list. Both parsers must unwrap it to the rows or every search
// consumer (agent projections + dashboards) silently collapses to junk.

const POPULATED_ENVELOPE = JSON.stringify(
  {
    results: [
      { device_id: "aid111", hostname: "host-a" },
      { device_id: "aid222", hostname: "host-b" },
    ],
    pagination: { total: 2, offset: 0, limit: 100, next: null },
    filter_used: "platform_name:'Windows'",
  },
  null,
  2, // indent=2 — matches falcon-mcp's pydantic_core.to_json(indent=2) wire shape
);

test("unwrapSearchEnvelope: returns rows for a {results,pagination} envelope", () => {
  const rows = unwrapSearchEnvelope(JSON.parse(POPULATED_ENVELOPE));
  assert.equal(rows.length, 2);
  assert.equal(rows[0].device_id, "aid111");
});

test("unwrapSearchEnvelope: null for shapes without pagination (FQL-error / sidecar / bare)", () => {
  // FQL-error shape has results but NO pagination — must NOT unwrap (isScopeDenied peeks results[0]).
  assert.equal(unwrapSearchEnvelope({ results: [{ error: "x" }], fql_guide: "…", hint: "…" }), null);
  // native ngsiem empty shape — results but no pagination.
  assert.equal(unwrapSearchEnvelope({ results: [], query_used: "q", cql_guide: "…", hint: "…" }), null);
  // sidecar shape.
  assert.equal(unwrapSearchEnvelope({ ok: true, items: [{ id: 1 }] }), null);
  // pagination present but not an object → not an envelope.
  assert.equal(unwrapSearchEnvelope({ results: [], pagination: "nope" }), null);
  // bare list / scalar.
  assert.equal(unwrapSearchEnvelope([{ id: 1 }]), null);
  assert.equal(unwrapSearchEnvelope(null), null);
});

test("parseConcatenatedJson: unwraps a pretty-printed envelope to its rows (dashboard path)", () => {
  const out = parseConcatenatedJson(POPULATED_ENVELOPE);
  assert.deepEqual(out, [
    { device_id: "aid111", hostname: "host-a" },
    { device_id: "aid222", hostname: "host-b" },
  ]);
});

test("parseConcatenatedJson: empty envelope unwraps to [] (not one junk row)", () => {
  const raw = JSON.stringify({ results: [], pagination: { total: 0, next: null } }, null, 2);
  assert.deepEqual(parseConcatenatedJson(raw), []);
});

test("parseToolResultObjects: single envelope block unwraps to its rows (agent path)", () => {
  const content = [{ type: "text", text: POPULATED_ENVELOPE }];
  assert.deepEqual(parseToolResultObjects(content), [
    { device_id: "aid111", hostname: "host-a" },
    { device_id: "aid222", hostname: "host-b" },
  ]);
});

test("envelope unwrap does NOT trip detectFalconError (success stays quiet)", () => {
  // Populated envelope → rows → not a single {error} object.
  assert.equal(detectFalconError(parseConcatenatedJson(POPULATED_ENVELOPE)), null);
  // A real upstream error is still list-wrapped [{error,details}] (no pagination) and must still fire.
  const err = parseToolResultObjects([
    { type: "text", text: '[{"error":"Failed to search hosts","details":{"status_code":500}}]' },
  ]);
  assert.match(detectFalconError(err), /Failed to search hosts/);
});

test("envelope unwrap preserves the cases FQL-error scope-denied peek", () => {
  // {results:[{error,403}], fql_guide, hint} has NO pagination → not unwrapped →
  // isScopeDenied still finds the nested denial at results[0].
  const raw =
    '{"results":[{"error":"Permission denied","details":{"status_code":403}}],"filter_used":"","fql_guide":"…","hint":"…"}';
  assert.equal(isScopeDenied(raw), true);
});

// ── 0.17.0 new-module search surfaces (Fusion SOAR, Zero Trust Assessment) ──
// unwrapSearchEnvelope is shape-keyed ({results,pagination}), not tool-keyed, so
// the new-module search tools ride the same path. These lock that in against a
// future refactor — the row shapes differ (Fusion executions vs ZTA {aid,score}).
test("envelope unwrap covers Fusion workflow-executions rows", () => {
  const raw = JSON.stringify(
    {
      results: [
        { id: "exec1", definition_name: "Contain host", status: "Completed" },
        { id: "exec2", definition_name: "Contain host", status: "Running" },
      ],
      pagination: { total: 2, next: null },
    },
    null,
    2,
  );
  assert.deepEqual(parseConcatenatedJson(raw), [
    { id: "exec1", definition_name: "Contain host", status: "Completed" },
    { id: "exec2", definition_name: "Contain host", status: "Running" },
  ]);
  assert.equal(detectFalconError(parseConcatenatedJson(raw)), null);
});

test("envelope unwrap covers ZTA {aid,score} rows (agent path)", () => {
  const content = [
    {
      type: "text",
      text: JSON.stringify({
        results: [
          { aid: "aid111", score: 61 },
          { aid: "aid222", score: 42 },
        ],
        pagination: { total: 2, next: null },
      }),
    },
  ];
  assert.deepEqual(parseToolResultObjects(content), [
    { aid: "aid111", score: 61 },
    { aid: "aid222", score: 42 },
  ]);
});

// ── Data Security projection (falcon-mcp 0.20.0 #576) ────────────────────
// One search tool serves ten entity_type record shapes, so the projection is
// shape-agnostic: scalars + short scalar arrays pass through, nested blobs
// collapse to a pointer at falcon_get_data_security_entities. Row shapes below
// are the live-probed policy / content_pattern / cloud_application keys.
const { projectToolResult } = await import(path.join(root, "lib/mcp/projections.ts"));

test("data security projection keeps scalars, collapses heavy blobs, never empties a shape", () => {
  const raw = JSON.stringify({
    results: [
      {
        id: "pol1", cid: "c", name: "Default", platform_name: "win", is_enabled: true,
        precedence: 1, host_groups: ["hg1", "hg2"],
        policy_properties: { enable_content_inspection: true, classifications: ["cl1"] },
      },
      {
        id: "cp1", cid: "c", name: "US SSN", category: "PII", region: "US", type: "predefined",
        regexes: [{ value: "\\d{3}-\\d{2}-\\d{4}" }], min_match_threshold: 1,
      },
      {
        id: "app1", cid: "c", name: "Dropbox", app_tier: 2,
        urls: Array.from({ length: 40 }, (_, i) => `u${i}.example.com`),
      },
    ],
    pagination: { total: 3, next: null },
  });
  const out = projectToolResult("falcon_search_data_security_entities", raw);
  const rows = parseConcatenatedJson(out.split("\n\n[Note:")[0]);
  assert.equal(rows.length, 3);
  const [pol, cp, app] = rows;
  assert.equal(pol.cid, undefined);
  assert.equal(pol.is_enabled, true);
  assert.deepEqual(pol.host_groups, ["hg1", "hg2"]);
  assert.match(pol.policy_properties, /^\{2 fields — see falcon_get_data_security_entities\}$/);
  assert.equal(cp.category, "PII");
  assert.match(cp.regexes, /^\[1 item — /);
  assert.equal(app.name, "Dropbox");
  assert.match(app.urls, /^\[40 items — /);
});

// ── Threat Graph ran-on projection (eyas-mcp native, formerly sidecar) ────
// Live record shape (XDR us-2): ~1 KB of raw edge per device. A full 50-device
// page must project under the 12 KB generic cap — it overflowed (14.3 KB, last
// ~8 devices truncated) while the ~100-char vertex `id` was kept.
test("threat graph ran-on: 50-device page projects untruncated, pivot fields only", () => {
  const hash = "f".repeat(64);
  const results = Array.from({ length: 50 }, (_, i) => {
    const aid = i.toString(16).padStart(32, "a");
    return {
      path: `https://api.us-2.crowdstrike.com/threatgraph/combined/modules/summary/v1?ids=mod%3A${aid}%3A${hash}&scope=device`,
      id: `mod:${aid}:${hash}`,
      device_id: aid,
      customer_id: "c".repeat(32),
      object_id: hash,
      direction: "primary",
      edge_id: `e${i}`,
      source_vertex_id: `pid:${aid}:123456789`,
      scope: "device",
      edge_type: "module_loaded_by",
      timestamp: "2025-12-08T20:33:11Z",
      properties: {},
    };
  });
  const raw = JSON.stringify({ results, pagination: { next: "https://api.us-2.crowdstrike.com/threatgraph/combined/ran-on/v1?limit=50" } });
  const out = projectToolResult("falcon_get_threatgraph_ran_on", raw);
  assert.ok(!out.includes("[Truncated"), `truncated at ${out.length} chars`);
  const rows = parseConcatenatedJson(out.split("\n\n[Note:")[0]);
  assert.equal(rows.length, 50);
  assert.deepEqual(Object.keys(rows[0]).sort(), ["device_id", "edge_type", "scope", "timestamp"]);
});

// ── NGSIEM listing projections (eyas-mcp native, formerly sidecar) ────────
test("ngsiem data-connection projection drops ingest_url, keeps rollup fields", () => {
  const raw = JSON.stringify({
    results: [{
      id: "3ee6", vendor_name: "Generic", vendor_product_name: "HEC", name: "NiFi Ingest",
      parser_name: "json", status: "Idle", source_type: "Push", last_ingested_volume_one_day: "0 B",
      ingest_url: "https://ingest.us-2.crowdstrike.com/api/ingest/hec/3ee6/v1/services/collector",
    }],
    pagination: { total: 330, offset: 0, limit: 1, next: null },
  });
  const out = projectToolResult("falcon_list_ngsiem_data_connections", raw);
  const [row] = parseConcatenatedJson(out.split("\n\n[Note:")[0]);
  assert.equal(row.ingest_url, undefined);
  assert.equal(row.vendor, "Generic");
  assert.equal(row.status, "Idle");
});

// ── Hunting-guide projection (eyas-mcp native, formerly sidecar CAO) ──────
test("hunting guide projection collapses queries + mitre, stays small", () => {
  const guide = {
    id: "g1", name: "Steganography C2", description: "long ".repeat(200), ai_short_description: "Short summary.",
    category: "Command and Control", adversaries: [{ name: "FANCY BEAR" }], malware_families: [{ name: "X" }],
    mitre: Array.from({ length: 40 }, (_, i) => ({ technique_id: `T1001.${i}`, tactic_id: "TA0011", technique_name: "n", tactic_name: "t" })),
    hunt_count: 3, cql_query_count: 561, languages: ["cql"], environments: ["windows"], last_updated_at: "2026-10-01",
    queries: Array.from({ length: 561 }, (_, i) => ({ id: "q".repeat(160) + i, name: `CrowdStrike_CSA_${i}` })),
  };
  const out = projectToolResult("falcon_search_hunting_guides", JSON.stringify({ results: [guide], pagination: { total: 1 } }));
  const [row] = parseConcatenatedJson(out.split("\n\n[Note:")[0]);
  assert.equal(row.query_count, 561);
  assert.equal(row.queries, undefined);
  assert.equal(row.mitre_techniques.length, 16); // 15 ids + "+25 more"
  assert.equal(row.description, "Short summary.");
  assert.ok(out.length < 2000, `projected guide is ${out.length} chars`);
});

// ── Finished-intel projections (eyas-mcp native, formerly sidecar) ────────
// Live shape: the report BODY is in `description` with WordPress
// [vc_*] shortcodes; `summary` is null. kill_chain repeats every phase as
// rich_text_* HTML. /intel-dossier follows report.actors[].id.
const { projectIntelReport, projectIntelActor } = await import(path.join(root, "lib/mcp/projections.ts"));

test("intel report projection: body from description, shortcodes stripped, actor ids kept", () => {
  const r = projectIntelReport({
    id: 100001, name: "CSIR-00001", summary: null,
    description: "[vc_row][vc_column][vc_column_text]\r\nFANCY BEAR clusters since 2017.[/vc_column_text][/vc_column][/vc_row]",
    actors: [{ id: 2139, name: "FANCY BEAR", slug: "fancy-bear", thumbnail: { url: "x" } }],
    motivations: [{ id: 1, slug: "state-sponsored", value: "State-Sponsored" }],
    malware: [{ family_name: "SedUpLoader", slug: "s" }],
    type: { id: 3130, slug: "intel-elite-report", name: "Intel Elite" },
  });
  assert.equal(r.body, "FANCY BEAR clusters since 2017.");
  assert.deepEqual(r.actors, [{ id: 2139, name: "FANCY BEAR" }]);
  assert.deepEqual(r.motivations, ["State-Sponsored"]);
  assert.deepEqual(r.malware, ["SedUpLoader"]);
  assert.equal(r.type, "Intel Elite");
});

test("intel actor projection drops rich_text_* kill-chain duplicates", () => {
  const a = projectIntelActor({
    id: 2139, name: "FANCY BEAR", actor_type: "targeted",
    kill_chain: { delivery: "\r\n\tSpear phishing\r\n", rich_text_delivery: "<p>Spear phishing</p>" },
    uses_threats: [{ family_name: "X-Agent-Linux" }],
  });
  assert.deepEqual(a.kill_chain, { delivery: "Spear phishing" });
  assert.deepEqual(a.uses_threats, ["X-Agent-Linux"]);
});

// ── Identity projections (eyas-mcp native, formerly sidecar) ──────────────
test("idp policy-rule projection drops ruleAction / notification blobs", () => {
  const rule = {
    _id: "r1", name: "Watch admins", templateId: null, enabled: true, simulationMode: false,
    ruleAction: { action: "ADD_TO_WATCH_LIST", globalProperties: { default: { gracePeriodDuration: 120000 } } },
    ruleConditions: [{ trigger: { access: true } }, { sourceUser: {} }],
    emailNotification: { recipients: Array(40).fill("someone@example.com") },
  };
  const out = projectToolResult("falcon_search_idp_policy_rules", JSON.stringify({ results: [rule], pagination: { total: 1 } }));
  const [row] = parseConcatenatedJson(out.split("\n\n[Note:")[0]);
  assert.deepEqual(row, { id: "r1", name: "Watch admins", enabled: true, simulation_mode: false, action: "ADD_TO_WATCH_LIST", condition_count: 2 });
});

test("risky-identity projection flattens factors and accounts", () => {
  const e = {
    entityId: "e1", primaryDisplayName: "Clark Monroe", type: "USER", riskScore: 0.82, riskScoreSeverity: "HIGH",
    riskFactors: [{ type: "DC_SYNC", severity: "MEDIUM" }],
    accounts: [{ domain: "LAB.EXAMPLE.COM", samAccountName: "clark.monroe", enabled: true, passwordAttributes: {} }, {}],
  };
  const out = projectToolResult("falcon_search_risky_identities", JSON.stringify({ results: [e], pagination: { total: 1 } }));
  const [row] = parseConcatenatedJson(out.split("\n\n[Note:")[0]);
  assert.deepEqual(row.risk_factors, ["DC_SYNC:MEDIUM"]);
  assert.deepEqual(row.accounts, [{ sam: "clark.monroe", domain: "LAB.EXAMPLE.COM", enabled: true }]);
});

// ── Falcon-published RTR script run (eyas-mcp native, formerly sidecar) ───
// Native shape: results[].output = { script, result: [...], cid, aid }.
test("falcon script run: caps each host's output.result at 50, drops cid, compact", () => {
  const result = Array.from({ length: 93 }, (_, i) => ({ ProcessId: i, WS: 8192, ProcessName: `p${i}.exe`, HandleCount: 1, ParentProcessId: 0 }));
  const raw = JSON.stringify({
    batch_id: "b1", script_name: "Process", hosts_requested: 1, hosts_completed: 1, failed_hosts: [],
    results: [{ device_id: "a".repeat(32), complete: true, stderr: "", output: { script: "Process", result, cid: "c".repeat(32), aid: "a".repeat(32) } }],
  });
  const out = projectToolResult("falcon_run_falcon_script", raw);
  assert.ok(!out.includes("[Truncated"), `truncated at ${out.length}`);
  const j = JSON.parse(out);
  assert.equal(j.results[0].output.result.length, 50);
  assert.match(j.results[0].output._truncated, /50 of 93/);
  assert.equal(j.results[0].output.cid, undefined);
  assert.deepEqual(j.failed_hosts, []);
});

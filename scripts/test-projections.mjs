#!/usr/bin/env node
// Tests for lib/mcp/projections.ts: native search totals (`pagination.total`)
// reach the agent, first, whether or not the tool has a projection and even
// when the result is capped.
// Run as: node scripts/test-projections.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.PROJECTIONS_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-projections.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, PROJECTIONS_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

// projections.ts imports parse.ts, which imports "server-only"; use Next's stub.
import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const { projectToolResult, searchTotalsHeader } = await import(
  pathToFileURL(path.join(root, "lib/mcp/projections.ts")).href
);
const { parseToolResultObjects } = await import(pathToFileURL(path.join(root, "lib/mcp/parse.ts")).href);

const envelope = (results, pagination) => JSON.stringify({ results, pagination });
const group = (i) => ({
  id: `g${i}`,
  name: `Group ${i}`,
  group_type: i % 2 ? "static" : "dynamic",
  description: "x".repeat(300),
  assignment_rule: "tags:'x'",
  created_by: "someone",
  created_timestamp: "2026-01-01T00:00:00Z",
});

/** What the bridge does: parse once, then project. */
function viaBridge(tool, raw) {
  const parsed = parseToolResultObjects([{ type: "text", text: raw }]);
  return projectToolResult(tool, raw, parsed);
}

test("a projected search carries pagination.total ahead of the rows", () => {
  const raw = envelope([group(1), group(2)], { total: 157, offset: 0, limit: 2, next: null });
  const out = viaBridge("falcon_search_host_groups", raw);
  assert.ok(out.startsWith("[Search totals: 157 matching record(s) in total"), out.slice(0, 120));
  assert.match(out.split("\n")[0], /2 on this page/);
  assert.match(out.split("\n")[0], /more pages available \(offset 2\)/);
  assert.match(out, /"name": "Group 1"/, "rows are still projected");
});

test("the total survives the length cap on a huge page", () => {
  const rows = Array.from({ length: 400 }, (_, i) => group(i));
  const raw = envelope(rows, { total: 400, offset: 0, limit: 400, next: null });
  const out = viaBridge("falcon_search_host_groups", raw);
  assert.match(out, /\[Truncated:/, "the page itself is capped");
  assert.ok(out.startsWith("[Search totals: 400 matching record(s) in total"));
  assert.ok(!/more pages available/.test(out.split("\n")[0]), "the whole set is on this page");
});

test("a tool without a projection gets the header too", () => {
  const raw = envelope([{ id: "a" }], { total: 9, offset: 0, limit: 1, next: "tok" });
  const out = viaBridge("falcon_search_some_new_thing", raw);
  assert.ok(out.startsWith('[Search totals: 9 matching record(s) in total (pagination.total), 1 on this page; more pages available (next: "tok")'));
});

test("no total reported → says so instead of guessing", () => {
  assert.match(
    searchTotalsHeader(envelope([{ id: "a" }], { total: null, offset: 0, limit: 1, next: null })),
    /1 returned on this page; the API reported no total/,
  );
});

test("non-envelope results are left alone", () => {
  assert.equal(searchTotalsHeader(JSON.stringify([{ id: "a" }])), null);
  assert.equal(searchTotalsHeader(JSON.stringify({ error: "x", details: { status_code: 500 } })), null);
  assert.equal(searchTotalsHeader("not json"), null);
  const plain = viaBridge("falcon_search_host_groups", JSON.stringify({ id: "g1", name: "Solo" }));
  assert.ok(!plain.includes("[Search totals"));
});

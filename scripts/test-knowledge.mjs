#!/usr/bin/env node
// Pure-function tests for the knowledge base: lib/knowledge/chunk.ts
// (chunkText) and the FTS query sanitizer in lib/knowledge/retrieve.ts
// (sanitizeFtsQuery — pure, no DB). Retrieval against a live FTS5 index is
// covered end-to-end by the /verify-feature Playwright pass, not here.
//
// Run as:  node scripts/test-knowledge.mjs
//
// Mirrors scripts/test-ir-run-analysis.mjs: re-spawn under tsx --test so the
// .ts sources load without a build step.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.KNOWLEDGE_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-knowledge.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, KNOWLEDGE_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

// ───────────────────────────────────────────────────────── child (tsx --test)

import { test } from "node:test";
import assert from "node:assert/strict";

const { chunkText } = await import(path.join(root, "lib/knowledge/chunk.ts"));
// sanitizeFtsQuery lives in fts-query.ts (no "server-only" guard, no DB) so it
// imports cleanly here. retrieve.ts re-exports it for production callers.
const { sanitizeFtsQuery } = await import(path.join(root, "lib/knowledge/fts-query.ts"));

test("chunkText returns [] for empty / whitespace input", () => {
  assert.deepEqual(chunkText(""), []);
  assert.deepEqual(chunkText("   \n\n  "), []);
});

test("chunkText keeps a short doc as a single chunk", () => {
  const out = chunkText("# Title\n\nOne short paragraph.");
  assert.equal(out.length, 1);
  assert.match(out[0], /One short paragraph/);
});

test("chunkText splits past maxChars and overlaps", () => {
  const para = (n) => `Paragraph ${n} ` + "word ".repeat(40);
  const text = Array.from({ length: 20 }, (_, i) => para(i)).join("\n\n");
  const out = chunkText(text, { maxChars: 600, overlapChars: 80 });
  assert.ok(out.length > 1, "should produce multiple chunks");
  for (const c of out) assert.ok(c.length <= 600 + 80 + 50, `chunk within bound: ${c.length}`);
  // Overlap: the tail of chunk 0 should reappear at the head of chunk 1.
  const tailWord = out[0].trim().split(/\s+/).slice(-1)[0];
  assert.ok(out[1].includes(tailWord), "overlap carries trailing context forward");
});

test("chunkText hard-splits a single oversized block", () => {
  const giant = "x".repeat(5000);
  const out = chunkText(giant, { maxChars: 1000, overlapChars: 0 });
  assert.ok(out.length >= 5, "oversized block is hard-split");
  for (const c of out) assert.ok(c.length <= 1000, "no chunk exceeds maxChars");
});

test("chunkText attaches a heading to the prose beneath it", () => {
  // maxChars chosen so the two blocks land in separate chunks but each block
  // stays whole — the heading must travel WITH the prose beneath it, not the
  // line above. overlap 0 so the section chunk is exactly the heading block.
  const out = chunkText("Intro line.\n\n# Section\nBody under section.", {
    maxChars: 30,
    overlapChars: 0,
  });
  const sectionChunk = out.find((c) => c.includes("# Section"));
  assert.ok(sectionChunk, "heading is present");
  assert.match(sectionChunk, /Body under section/);
  assert.doesNotMatch(sectionChunk, /Intro line/, "heading not glued to the line above");
});

test("sanitizeFtsQuery quotes terms and ORs them", () => {
  assert.equal(sanitizeFtsQuery("quarantine the host"), '"quarantine" OR "the" OR "host"');
});

test("sanitizeFtsQuery neutralizes FTS operators + quotes", () => {
  const out = sanitizeFtsQuery('NEAR("evil"* OR x) -drop');
  // No bare operators/control chars survive; every term is double-quoted.
  assert.ok(!/[()*^:]/.test(out), `no FTS metacharacters: ${out}`);
  assert.match(out, /"near"/);
});

test("sanitizeFtsQuery returns null when nothing searchable", () => {
  assert.equal(sanitizeFtsQuery("   *** !! "), null);
  assert.equal(sanitizeFtsQuery(""), null);
});

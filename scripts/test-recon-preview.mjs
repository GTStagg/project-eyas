#!/usr/bin/env node
// Pure-function tests for lib/recon/preview.ts.
// Run as: node scripts/test-recon-preview.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.RECON_PREVIEW_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-recon-preview.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, RECON_PREVIEW_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const { reconPreviewArgs, summarizeReconPreview } = await import(
  pathToFileURL(path.join(root, "lib/recon/preview.ts")).href
);

test("builds parenthesized rule filters per kind", () => {
  assert.deepEqual(reconPreviewArgs("Example.COM", "domain"), {
    topic: "SA_DOMAIN",
    filter: "(domain:'example.com')",
  });
  assert.deepEqual(reconPreviewArgs("ceo@example.com", "email"), {
    topic: "SA_EMAIL",
    filter: "(email:'ceo@example.com')",
  });
  assert.deepEqual(reconPreviewArgs("203.0.113.1", "ip"), { topic: "SA_IP", filter: "(ip:'203.0.113.1')" });
  assert.deepEqual(reconPreviewArgs("Acme Corp", "keyword"), {
    topic: "SA_CUSTOM",
    filter: "(keyword:'Acme Corp')",
  });
});

test("rejects values that could break out of the literal", () => {
  assert.equal(reconPreviewArgs("acme' + x", "keyword"), null);
  assert.equal(reconPreviewArgs("a\\b", "keyword"), null);
  assert.equal(reconPreviewArgs("exa'mple.com", "domain"), null);
  assert.equal(reconPreviewArgs("999.1.1.1", "ip"), null);
  assert.equal(reconPreviewArgs("", "keyword"), null);
  assert.equal(reconPreviewArgs("x".repeat(201), "keyword"), null);
});

const sample = [
  { name: "count", buckets: [{ label: "count", count: 42 }] },
  { name: "channel", buckets: [{ label: "forum", count: 30 }, { label: "chat_medium", count: "12" }] },
  { name: "site", buckets: [{ label: "telegram.org", count: 12 }, { label: "", count: 3 }] },
  { name: "unknown", buckets: [{ label: "x", count: 1 }] },
];

test("flattens the count, channel and site aggregations", () => {
  assert.deepEqual(summarizeReconPreview(sample), {
    total_hits: 42,
    channels: [
      { label: "forum", count: 30 },
      { label: "chat_medium", count: 12 },
    ],
    top_sites: [{ label: "telegram.org", count: 12 }],
  });
});

test("accepts the aggregations as one JSON array", () => {
  assert.equal(summarizeReconPreview([sample]).total_hits, 42);
});

test("empty or malformed input gives zero hits", () => {
  assert.deepEqual(summarizeReconPreview([]), { total_hits: 0, channels: [], top_sites: [] });
  assert.deepEqual(summarizeReconPreview([null, "x", { name: "count" }]), {
    total_hits: 0,
    channels: [],
    top_sites: [],
  });
});

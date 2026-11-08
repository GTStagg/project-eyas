#!/usr/bin/env node
// Pure-function tests for lib/quarantine/review.ts (normalize + summarize).
// Run as: node scripts/test-quarantine.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.QUARANTINE_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-quarantine.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, QUARANTINE_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const { normalizeQuarantineRecords, summarizeQuarantine, renderQuarantineContext } = await import(
  path.join(root, "lib/quarantine/review.ts")
);

test("normalize tolerates alternate key names + object paths", () => {
  const recs = normalizeQuarantineRecords([
    { id: "1", sha256: "abc", hostname: "h1", state: "quarantined", paths: [{ path: "/tmp/x" }] },
    { quarantine_id: "2", sha256_hash: "def", host_name: "h2", status: "released", path: "/y" },
    "not an object",
    null,
  ]);
  assert.equal(recs.length, 2);
  assert.equal(recs[0].paths[0], "/tmp/x");
  assert.equal(recs[1].id, "2");
  assert.equal(recs[1].sha256, "def");
  assert.equal(recs[1].hostname, "h2");
  assert.equal(recs[1].state, "released");
  assert.equal(recs[1].paths[0], "/y");
});

test("summarize counts states + clusters by host and hash", () => {
  const recs = normalizeQuarantineRecords([
    { id: "1", sha256: "h_a", hostname: "alpha", state: "quarantined" },
    { id: "2", sha256: "h_b", hostname: "alpha", state: "quarantined" }, // alpha: 2 distinct hashes
    { id: "3", sha256: "h_a", hostname: "beta", state: "released" }, // h_a on 2 hosts
    { id: "4", sha256: "h_c", hostname: "gamma", state: "weird" },
  ]);
  const s = summarizeQuarantine(recs);
  assert.equal(s.total, 4);
  assert.equal(s.byState.quarantined, 2);
  assert.equal(s.byState.released, 1);
  assert.equal(s.byState.other, 1);
  assert.equal(s.hostCount, 3);
  assert.equal(s.hashCount, 3);
  // repeat host: alpha has 2 distinct hashes
  assert.equal(s.repeatHosts.length, 1);
  assert.equal(s.repeatHosts[0].hostname, "alpha");
  assert.equal(s.repeatHosts[0].count, 2);
  // spread hash: h_a on alpha + beta
  assert.equal(s.spreadHashes.length, 1);
  assert.equal(s.spreadHashes[0].sha256, "h_a");
  assert.equal(s.spreadHashes[0].count, 2);
});

test("summarize handles empty input", () => {
  const s = summarizeQuarantine([]);
  assert.equal(s.total, 0);
  assert.equal(s.hostCount, 0);
  assert.deepEqual(s.repeatHosts, []);
});

test("renderQuarantineContext produces bounded, labeled text", () => {
  const recs = normalizeQuarantineRecords(
    Array.from({ length: 60 }, (_, i) => ({
      id: String(i),
      sha256: `hash${i}`,
      hostname: `host${i % 3}`,
      state: "quarantined",
    })),
  );
  const txt = renderQuarantineContext(summarizeQuarantine(recs));
  assert.match(txt, /Deterministic quarantine summary/);
  assert.match(txt, /Total quarantine records: 60/);
  // sample-record lines (host · sha256 · state · id) capped at 40
  const sampleLines = txt.split("\n").filter((l) => l.startsWith("- ") && l.includes(" · "));
  assert.equal(sampleLines.length, 40, `sample bounded to 40, got ${sampleLines.length}`);
});

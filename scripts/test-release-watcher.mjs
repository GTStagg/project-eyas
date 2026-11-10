#!/usr/bin/env node
// Tests for lib/scheduler/jobs/release-watcher-format.ts: the eyas-mcp update
// watcher compares Eyas's pinned commit with eyas-mcp's main branch and only
// reports when main has moved past the pin.
// Run as: node scripts/test-release-watcher.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.RELEASE_WATCHER_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-release-watcher.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, RELEASE_WATCHER_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const { checkForUpdate, EYAS_MCP_REPO } = await import(
  pathToFileURL(path.join(root, "lib/scheduler/jobs/release-watcher-format.ts")).href
);

const PIN = "c0341319fc05d0437437da4c9ac0e2ac33b14d7b";
const commit = (sha, message, date = "2026-11-12T10:00:00Z") => ({ sha, commit: { message, author: { date } } });

test("watches eyas-mcp, not falcon-mcp", () => {
  assert.equal(EYAS_MCP_REPO, "GTStagg/eyas-mcp");
});

test("an identical compare is not news", () => {
  const out = checkForUpdate({ status: "identical", ahead_by: 0, commits: [] }, PIN, "0.21.0");
  assert.equal(out.kind, "current");
});

test("new commits produce a notice naming the pin and the newest commit first", () => {
  const out = checkForUpdate(
    {
      status: "ahead",
      ahead_by: 2,
      html_url: "https://github.com/GTStagg/eyas-mcp/compare/c034131...main",
      commits: [
        commit("aaaaaaa1111111111111111111111111111111", "feat: first\n\nbody"),
        commit("bbbbbbb2222222222222222222222222222222", "fix: second"),
      ],
    },
    PIN,
    "0.21.0",
  );
  assert.equal(out.kind, "update");
  assert.equal(out.headSha, "bbbbbbb2222222222222222222222222222222");
  assert.equal(out.aheadBy, 2);
  assert.match(out.heading, /2 new commits/);
  assert.match(out.markdown, /Pinned: `c0341319fc05` \(0\.21\.0\)/);
  assert.ok(out.markdown.indexOf("fix: second") < out.markdown.indexOf("feat: first"), "newest first");
  assert.ok(!out.markdown.includes("body"), "only the commit subject line");
  assert.match(out.markdown, /mcp-server-ref/);
  assert.ok(!/falcon-mcp/.test(out.markdown));
});

test("a diverged pin is flagged", () => {
  const out = checkForUpdate({ status: "diverged", ahead_by: 1, commits: [commit("c".repeat(40), "x")] }, PIN, "0.21.0");
  assert.equal(out.kind, "update");
  assert.match(out.markdown, /diverged/);
});

test("long histories are capped", () => {
  const commits = Array.from({ length: 20 }, (_, i) => commit(String(i).padStart(40, "0"), `c${i}`));
  const out = checkForUpdate({ status: "ahead", ahead_by: 20, commits }, PIN, "0.21.0");
  assert.match(out.markdown, /and 5 earlier/);
  assert.equal(out.headSha, commits[19].sha);
});

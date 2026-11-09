#!/usr/bin/env node
// Tests for lib/prevention/posture.ts: eyas-mcp's falcon_get_prevention_posture
// reduced to the shape /prevention, the home dashboard, Shadow-AI setup and the
// posture snapshot read, with Eyas's own detect-only rule.
// Run as: node scripts/test-prevention-posture.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.PREVENTION_POSTURE_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-prevention-posture.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, PREVENTION_POSTURE_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

// posture.ts imports parse.ts, which imports "server-only"; use Next's stub.
import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const { shapePosture } = await import(pathToFileURL(path.join(root, "lib/prevention/posture.ts")).href);

const slider = (detection, prevention) => ({ detection, prevention });
const policy = (over) => ({
  id: "p",
  name: "Policy",
  platform: "Windows",
  enabled: true,
  groups: [{ id: "g1", name: "Group 1" }],
  ml_sliders: {},
  flags: [],
  ...over,
});
const native = (policies) => JSON.stringify({ summary: { policies: policies.length }, policies });

test("Eyas flags only sensor ML and cloud AV as detect-only", () => {
  const out = shapePosture(
    native([
      policy({ id: "a", name: "ML detect", ml_sliders: { OnSensorMLSlider: slider("MODERATE", "DISABLED") } }),
      policy({ id: "b", name: "Cloud detect", ml_sliders: { CloudAntiMalware: slider("AGGRESSIVE", "") } }),
      // eyas-mcp would flag this (detect_only_sliders), Eyas doesn't.
      policy({ id: "c", name: "Adware only", ml_sliders: { AdwarePUP: slider("MODERATE", "DISABLED"), OnSensorMLSlider: slider("MODERATE", "MODERATE") }, flags: ["detect_only_sliders"] }),
      policy({ id: "d", name: "Off", enabled: false }),
    ]),
  );
  assert.equal(out.ok, true);
  const byId = Object.fromEntries(out.items.map((i) => [i.id, i]));
  assert.deepEqual(byId.a.flags, ["ml_detect_only"]);
  assert.deepEqual(byId.b.flags, ["cloud_av_detect_only"]);
  assert.deepEqual(byId.c.flags, []);
  assert.deepEqual(byId.d.flags, ["disabled"]);
  assert.deepEqual(out.summary, { total: 4, disabled: 1, detect_only: 2 });
  assert.deepEqual(out.platform_counts, { Windows: 4 });
});

test("settings keep the dashboard's slider names", () => {
  const out = shapePosture(
    native([policy({ ml_sliders: { OnSensorMLSlider: slider("MODERATE", "CAUTIOUS"), CloudAntiMalware: slider("MODERATE", "MODERATE"), SensorAntiMalware: slider("x", "y") } })]),
  );
  assert.deepEqual(out.items[0].settings, {
    ml_detection: "MODERATE",
    ml_prevention: "CAUTIOUS",
    cloud_anti_malware_detection: "MODERATE",
    cloud_anti_malware_prevention: "MODERATE",
  });
  assert.deepEqual(out.items[0].groups, [{ id: "g1", name: "Group 1" }]);
});

test("disabled policies sort first within a platform", () => {
  const out = shapePosture(
    native([
      policy({ id: "1", name: "B", platform: "Windows" }),
      policy({ id: "2", name: "A", platform: "Windows", enabled: false }),
      policy({ id: "3", name: "Z", platform: "Linux" }),
    ]),
  );
  assert.deepEqual(out.items.map((i) => i.id), ["3", "2", "1"]);
});

test("a permission error becomes scope_pending", () => {
  const out = shapePosture(
    JSON.stringify({ error: "Permission denied.", details: { status_code: 403 }, required_scopes: ["Prevention policies:read"] }),
  );
  assert.equal(out.ok, true);
  assert.equal(out.scope_pending, true);
});

test("an upstream error is ok:false with the message", () => {
  const out = shapePosture(JSON.stringify({ error: "Failed to list prevention policies", details: { status_code: 500 } }));
  assert.equal(out.ok, false);
  assert.match(out.error, /Failed to list prevention policies/);
});

const { projectToolResult } = await import(pathToFileURL(path.join(root, "lib/mcp/projections.ts")).href);

test("the agent sees every policy of a large tenant, one line each", () => {
  const big = { name: "x".repeat(60), toggles_enabled: 30, toggles_total: 40 };
  const sliders = Object.fromEntries(Array.from({ length: 12 }, (_, i) => [`Slider${i}`, slider("MODERATE", "DISABLED")]));
  const policies = Array.from({ length: 100 }, (_, i) =>
    policy({
      ...big,
      id: `p${i}`,
      name: `Policy ${i}`,
      ml_sliders: { ...sliders, OnSensorMLSlider: slider("MODERATE", "DISABLED"), CloudAntiMalware: slider("MODERATE", "MODERATE") },
      detect_only_sliders: ["OnSensorMLSlider", "Slider1"],
      flags: ["detect_only_sliders"],
    }),
  );
  const raw = JSON.stringify({ summary: { policies: 100 }, policies });
  assert.ok(raw.length > 24000, "the raw result is larger than any cap");
  const out = projectToolResult("falcon_get_prevention_posture", raw);
  assert.ok(out.includes("Policy 0 |") && out.includes("Policy 99 |"), "first and last policy present");
  assert.match(out, /sensorML=MODERATE\/DISABLED \| cloudAV=MODERATE\/MODERATE/);
  assert.match(out, /other_detect_only=Slider1/);
  assert.ok(!out.includes("truncated"), "not truncated");
});

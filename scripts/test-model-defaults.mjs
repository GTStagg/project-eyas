#!/usr/bin/env node
// Tests for lib/llm/request.ts (Claude request defaults: max_tokens floor and
// explicit effort only where the model accepts it) and lib/cost/pricing.ts
// (per-version prices for the current models).
// Run as: node scripts/test-model-defaults.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.MODEL_DEFAULTS_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-model-defaults.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, MODEL_DEFAULTS_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const { withModelDefaults, supportsEffort, MIN_OUTPUT_TOKENS } = await import(
  pathToFileURL(path.join(root, "lib/llm/request.ts")).href
);
const { pricingFor } = await import(pathToFileURL(path.join(root, "lib/cost/pricing.ts")).href);

test("small max_tokens are raised to the floor; larger ones are kept", () => {
  assert.equal(withModelDefaults({ model: "claude-sonnet-5-5", max_tokens: 1024 }).max_tokens, MIN_OUTPUT_TOKENS);
  assert.equal(withModelDefaults({ model: "claude-sonnet-5-5", max_tokens: 64000 }).max_tokens, 64000);
});

test("the 5.5 generation gets an explicit medium effort", () => {
  for (const model of ["claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5", "anthropic.claude-opus-5-5"]) {
    assert.deepEqual(withModelDefaults({ model, max_tokens: 1 }).output_config, { effort: "medium" }, model);
  }
});

test("models that reject effort don't get it", () => {
  for (const model of ["claude-haiku-4-5", "claude-haiku-4-5-20251001", "claude-sonnet-4-5", "claude-3-5-sonnet", "my-gateway-model"]) {
    assert.equal(supportsEffort(model), false, model);
    assert.equal("output_config" in withModelDefaults({ model, max_tokens: 1 }), false, model);
  }
  for (const model of ["claude-sonnet-4-6", "claude-opus-4-5", "claude-opus-4-8", "claude-fable-5-2"]) {
    assert.equal(supportsEffort(model), true, model);
  }
});

test("other params pass through untouched", () => {
  const out = withModelDefaults({ model: "claude-sonnet-5-5", max_tokens: 1, system: "s", messages: [] });
  assert.equal(out.system, "s");
  assert.deepEqual(out.messages, []);
  assert.equal("temperature" in out, false);
  assert.equal("thinking" in out, false);
});

test("current models are priced per version", () => {
  assert.deepEqual(pricingFor("claude-opus-5-5"), { input: 4, output: 20, cacheWrite: 8, cacheRead: 0.2 });
  assert.deepEqual(pricingFor("claude-sonnet-5-5"), { input: 2, output: 10, cacheWrite: 4, cacheRead: 0.1 });
  assert.equal(pricingFor("claude-haiku-5-5").input, 0.1);
});

test("older models keep their own rates", () => {
  assert.equal(pricingFor("claude-sonnet-4-6").input, 3);
  assert.equal(pricingFor("claude-opus-4-8").input, 5); // Opus 4.5+ is $5, not the Opus 4 $15
  assert.equal(pricingFor("claude-opus-4-1").input, 15);
  assert.equal(pricingFor("claude-haiku-4-5-20251001").input, 1);
});

test("platform prefixes and renamed gateway ids still price", () => {
  assert.equal(pricingFor("us.anthropic.claude-sonnet-4-6").input, 3);
  assert.equal(pricingFor("claude-sonnet").input, 2); // unknown version → current generation
  assert.equal(pricingFor("gpt-x"), null);
});

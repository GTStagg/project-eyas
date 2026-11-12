#!/usr/bin/env node
// Tests for the prompt-cache helpers (lib/llm/prompt-cache.ts).
// Run as: node scripts/test-prompt-cache.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.PROMPT_CACHE_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-prompt-cache.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, PROMPT_CACHE_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const pc = await import(pathToFileURL(path.join(root, "lib/llm/prompt-cache.ts")).href);

const tool = (name, examples, required = ["a", "b"]) => ({
  name,
  description: `d ${name}`,
  input_schema: {
    type: "object",
    properties: {
      a: { type: "string", examples, enum: ["z", "y"] },
      b: { anyOf: [{ type: "string" }, { type: "null" }], default: null },
    },
    required,
  },
});

test("two orderings of the same tools serialize identically", () => {
  const one = [tool("falcon_b", ["x2", "x1"]), tool("falcon_a", ["p", "q"], ["b", "a"])];
  const two = [tool("falcon_a", ["q", "p"]), tool("falcon_b", ["x1", "x2"], ["b", "a"])];
  assert.equal(JSON.stringify(pc.canonicalTools(one)), JSON.stringify(pc.canonicalTools(two)));
  const out = pc.canonicalTools(one);
  assert.deepEqual(out.map((t) => t.name), ["falcon_a", "falcon_b"]);
  assert.deepEqual(out[0].input_schema.properties.a.enum, ["y", "z"]);
  assert.deepEqual(out[0].input_schema.required, ["a", "b"]);
  // Ordered arrays (anyOf) keep their order; the input isn't mutated.
  assert.deepEqual(out[0].input_schema.properties.b.anyOf, [{ type: "string" }, { type: "null" }]);
  assert.deepEqual(one[0].input_schema.properties.a.examples, ["x2", "x1"]);
});

test("a property literally named `required` or `enum` keeps its object shape", () => {
  const t = { name: "t", description: "", input_schema: { type: "object", properties: { required: { type: "boolean" }, enum: { type: "string" } } } };
  assert.deepEqual(pc.canonicalTools([t])[0].input_schema, t.input_schema);
});

test("resources sort by uri", () => {
  const r = pc.canonicalResources([{ uri: "falcon://b" }, { uri: "falcon://a", description: "x" }]);
  assert.deepEqual(r.map((x) => x.uri), ["falcon://a", "falcon://b"]);
});

test("history marker goes on the last markable block of the last message, on a copy", () => {
  const conv = [
    { role: "user", content: "hi" },
    { role: "assistant", content: [{ type: "thinking", thinking: "…", signature: "s" }, { type: "tool_use", id: "t1", name: "x", input: {} }] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "r" }, { type: "text", text: "and" }] },
  ];
  const before = JSON.stringify(conv);
  const out = pc.withHistoryCacheMarker(conv, "1h");
  assert.equal(JSON.stringify(conv), before);
  assert.deepEqual(out[2].content[1], { type: "text", text: "and", cache_control: { type: "ephemeral", ttl: "1h" } });
  assert.equal(out[2].content[0].cache_control, undefined);
  assert.equal(out[0], conv[0]);
  assert.equal(out[1], conv[1]);
  const marked = JSON.stringify(out).match(/cache_control/g) ?? [];
  assert.equal(marked.length, 1);
});

test("a string message becomes one marked text block; nothing markable is left alone", () => {
  assert.deepEqual(pc.withHistoryCacheMarker([{ role: "user", content: "go" }], "5m"), [
    { role: "user", content: [{ type: "text", text: "go", cache_control: { type: "ephemeral", ttl: "5m" } }] },
  ]);
  const onlyThinking = [{ role: "assistant", content: [{ type: "thinking", thinking: "x", signature: "s" }] }];
  assert.equal(pc.withHistoryCacheMarker(onlyThinking, "5m"), onlyThinking);
  assert.deepEqual(pc.withHistoryCacheMarker([], "5m"), []);
});

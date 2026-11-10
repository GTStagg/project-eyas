#!/usr/bin/env node
// Wire-level tests for lib/llm/messages.ts (server-side refusal fallbacks and
// the gateway degrade) and lib/llm/anthropic.ts::anthropicClientOptions (the
// headers each credential goes out in on SDK 1.x). A local HTTP server stands
// in for the Claude API or a gateway; nothing leaves the machine.
//
// Run as: node scripts/test-llm-messages.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.LLM_MESSAGES_CHILD) {
  const r = spawnSync(
    process.execPath,
    [root + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-llm-messages.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, LLM_MESSAGES_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import Module from "node:module";

// "server-only" → Next's bundled stub (same convention as test-approvals.mjs).
const stubPath = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stubPath;
  return origResolve.call(this, request, ...rest);
};

const imp = (rel) => import(pathToFileURL(path.join(root, rel)).href);
// Load the SDK the way tsx loads it for the .ts modules (CommonJS), so the
// client below and lib/llm/messages.ts share one copy and `instanceof
// Anthropic.APIError` holds across them.
const Anthropic = Module.createRequire(path.join(root, "lib/llm/messages.ts"))("@anthropic-ai/sdk").default;
const { createMessage, streamMessage, resetServerFallbackMemo } = await imp("lib/llm/messages.ts");
const { anthropicClientOptions } = await imp("lib/llm/anthropic.ts");

// ── fake endpoint ────────────────────────────────────────────────────────────
// mode "accept": answers every request. "reject-fallbacks": a gateway that
// 400s any body carrying `fallbacks`. "reject-all": a request the API rejects
// whatever it carries.
let mode = "accept";
let requests = [];
let server;
let baseURL;

const message = (model) => ({
  id: "msg_test",
  type: "message",
  role: "assistant",
  model,
  content: [{ type: "text", text: "hello" }],
  stop_reason: "end_turn",
  stop_sequence: null,
  stop_details: null,
  usage: { input_tokens: 3, output_tokens: 1 },
});

function sse(res, model) {
  res.writeHead(200, { "content-type": "text/event-stream" });
  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  const m = message(model);
  send("message_start", { type: "message_start", message: { ...m, content: [], stop_reason: null } });
  send("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } });
  send("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "hello" } });
  send("content_block_stop", { type: "content_block_stop", index: 0 });
  send("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 1 } });
  send("message_stop", { type: "message_stop" });
  res.end();
}

before(async () => {
  server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = JSON.parse(raw || "{}");
      requests.push({ headers: req.headers, body, url: req.url });
      const reject =
        mode === "reject-all" || (mode === "reject-fallbacks" && body.fallbacks !== undefined);
      if (reject) {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ type: "error", error: { type: "invalid_request_error", message: "fallbacks: Extra inputs are not permitted" } }));
        return;
      }
      if (body.stream) return sse(res, body.model);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(message(body.model)));
    });
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  baseURL = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());
beforeEach(() => {
  mode = "accept";
  requests = [];
  resetServerFallbackMemo();
});

const client = (cfg = { apiKey: "sk-test-key" }) =>
  new Anthropic({ ...anthropicClientOptions({ ...cfg, baseURL }), maxRetries: 0 });
const params = (model = "claude-sonnet-5-5") => ({
  model,
  max_tokens: 1024,
  messages: [{ role: "user", content: "hi" }],
});

// ── tests ────────────────────────────────────────────────────────────────────

test("5.5 requests carry fallbacks, the beta and the new API version", async () => {
  await createMessage(client(), params());
  const [r] = requests;
  assert.equal(r.body.fallbacks, "default");
  assert.match(r.headers["anthropic-beta"], /server-side-fallback-2026-07-01/);
  assert.equal(r.headers["anthropic-version"], "2026-10-21");
  assert.equal(r.body.output_config.effort, "medium");
  assert.equal(r.body.max_tokens, 16000);
});

test("models without server-side fallback get neither field nor beta", async () => {
  await createMessage(client(), params("claude-haiku-5-5"));
  const [r] = requests;
  assert.equal("fallbacks" in r.body, false);
  assert.equal(r.headers["anthropic-beta"], undefined);
});

test("a gateway that rejects fallbacks degrades to none, then is remembered", async () => {
  mode = "reject-fallbacks";
  const first = await createMessage(client(), params());
  assert.equal(first.content[0].text, "hello");
  assert.equal(requests.length, 2);
  assert.equal(requests[1].body.fallbacks, undefined);
  assert.equal(requests[1].headers["anthropic-beta"], undefined);

  requests = [];
  await createMessage(client(), params());
  assert.equal(requests.length, 1, "second call skips the rejected attempt");
  assert.equal(requests[0].body.fallbacks, undefined);
});

test("streaming degrades the same way and streams the text once", async () => {
  mode = "reject-fallbacks";
  const texts = [];
  const final = await streamMessage(client(), params("claude-opus-5-5"), {
    onEvent: (e) => {
      if (e.type === "content_block_delta" && e.delta.type === "text_delta") texts.push(e.delta.text);
    },
  });
  assert.equal(final.stop_reason, "end_turn");
  assert.deepEqual(texts, ["hello"]);
  assert.equal(requests.length, 2);
  assert.equal(requests[1].body.stream, true);
});

test("a request error unrelated to fallbacks still throws and isn't remembered", async () => {
  mode = "reject-all";
  await assert.rejects(createMessage(client(), params()), (err) => err instanceof Anthropic.BadRequestError);
  mode = "accept";
  requests = [];
  await createMessage(client(), params());
  assert.equal(requests[0].body.fallbacks, "default", "fallbacks still attempted");
});

test("an API key goes out as X-Api-Key, not Authorization", async () => {
  await createMessage(client({ apiKey: "sk-test-key" }), params());
  const [r] = requests;
  assert.equal(r.headers["x-api-key"], "sk-test-key");
  assert.equal(r.headers.authorization, undefined);
});

test("an auth token goes out as Authorization: Bearer", async () => {
  await createMessage(client({ authToken: "tok-test" }), params());
  const [r] = requests;
  assert.equal(r.headers.authorization, "Bearer tok-test");
  assert.equal(r.headers["x-api-key"], undefined);
});

test("a config with both sends both, as before SDK 1.x", async () => {
  await createMessage(client({ apiKey: "sk-test-key", authToken: "tok-test" }), params());
  const [r] = requests;
  assert.equal(r.headers.authorization, "Bearer tok-test");
  assert.equal(r.headers["x-api-key"], "sk-test-key");
});

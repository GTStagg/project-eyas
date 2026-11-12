#!/usr/bin/env node
// Tests for the Shadow-AI hunting tools (lib/eyas-tools/shadow-ai/{catalog,hunt}.ts)
// against a fake eyas-mcp. Includes the port of falcon-extras'
// shadow_ai/test_catalog_cleanup.py.
// Run as: node scripts/test-shadow-ai.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.SHADOW_AI_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-shadow-ai.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, SHADOW_AI_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const load = (p) => import(pathToFileURL(path.join(root, p)).href);
const cat = await load("lib/eyas-tools/shadow-ai/catalog.ts");
const hunt = await load("lib/eyas-tools/shadow-ai/hunt.ts");

const AID = "a".repeat(32);
const APPX = "host-uninstall-appx-package";

// ------------------------------------------------ cleanup routing (port)

test("cleanup: Squirrel install takes the curated uninstaller", () => {
  assert.deepEqual(cat.cleanupPlan("cursor", ["C:\\Users\\jdoe\\AppData\\Local\\Programs\\cursor\\Cursor.exe"]), [
    "squirrel",
    false,
    [{ script_id: "host-uninstall-cursor", params: {} }],
  ]);
});

test("cleanup: MSIX install takes the appx uninstaller with the package pattern", () => {
  assert.deepEqual(cat.cleanupPlan("claude_desktop", ["C:\\Program Files\\WindowsApps\\Claude_1.2.3_x64__8x0abc\\Claude.exe"]), [
    "msix",
    false,
    [{ script_id: APPX, params: { package_name_pattern: "Claude" } }],
  ]);
});

test("cleanup: a Microsoft Store package is never uninstalled", () => {
  assert.deepEqual(
    cat.cleanupPlan("copilot_cli", ["C:\\Program Files\\WindowsApps\\Microsoft.Copilot_1.0_x64__8wekyb3d8bbwe\\Copilot.exe"]),
    ["msix", true, []],
  );
});

test("cleanup: both forms fire both, appx first", () => {
  assert.deepEqual(
    cat.cleanupPlan("cursor", [
      "C:\\Program Files\\WindowsApps\\Cursor_1.0_x64__abc\\Cursor.exe",
      "C:\\Users\\jdoe\\AppData\\Local\\Programs\\cursor\\Cursor.exe",
    ]),
    [
      "both",
      false,
      [
        { script_id: APPX, params: { package_name_pattern: "Cursor" } },
        { script_id: "host-uninstall-cursor", params: {} },
      ],
    ],
  );
});

test("cleanup: unknown form, missing curated script, state-only MSIX, empty paths", () => {
  assert.deepEqual(cat.cleanupPlan("ollama", ["C:\\Program Files\\Ollama\\ollama.exe"]), [
    "unknown",
    false,
    [{ script_id: "host-uninstall-ollama", params: {} }],
  ]);
  assert.deepEqual(cat.cleanupPlan("jan", ["C:\\Program Files\\Jan\\Jan.exe"]), ["unknown", false, []]);
  assert.deepEqual(cat.cleanupPlan("claude_desktop", ["C:\\Users\\jdoe\\AppData\\Local\\Packages\\AnthropicClaude_abc\\LocalCache\\x.exe"]), [
    "msix",
    false,
    [],
  ]);
  assert.equal(cat.classifyDistributionForm([]), "unknown");
  assert.deepEqual(cat.cleanupPlan("cursor", [])[2], [{ script_id: "host-uninstall-cursor", params: {} }]);
});

// ------------------------------------------------ classifiers

test("app, egress, MCP and port classification", () => {
  assert.deepEqual(cat.classifyAppImage("C:\\Users\\a\\AppData\\Local\\Programs\\cursor\\Cursor.exe"), ["Cursor", "cursor", "agentic_client"]);
  assert.deepEqual(cat.classifyAppImage("/x/LM Studio.exe"), ["LM Studio", "lmstudio", "model_developer"]);
  assert.deepEqual(cat.classifyAppImage("C:\\x\\curl.exe"), [null, null, null]);
  assert.deepEqual(cat.classifyEgressDomain("API.OpenAI.com."), ["OpenAI API", "saas_inference_api"]);
  assert.deepEqual(cat.classifyEgressDomain("foo.character.ai"), ["Character.ai", "saas_chat_browser"]);
  assert.deepEqual(cat.classifyEgressDomain("notclaude.ai"), [null, null]);
  assert.deepEqual(cat.classifyMcpCmdline("npx -y @modelcontextprotocol/server-filesystem /"), {
    tool: "MCP server (npm)",
    family: "mcp_npm",
    posture: "mcp_host",
    matched_token: "@modelcontextprotocol/server-",
  });
  assert.equal(cat.classifyMcpCmdline("uvx --from git+x awslabs.mcp-foo").family, "mcp_uvx");
  assert.equal(cat.classifyMcpCmdline("python mcp_server.py").family, "mcp_generic");
  // No word boundary before `mcp` here, so the generic pattern doesn't fire.
  assert.equal(cat.classifyMcpCmdline("python my_mcp_server.py"), null);
  assert.equal(cat.classifyMcpCmdline("notepad.exe"), null);
  assert.equal(cat.classifyLocalInferencePort(11434), "Ollama");
  assert.equal(cat.classifyLocalInferencePort(22), null);
  assert.equal(cat.isLoopbackIpv4("127.0.0.1"), true);
  assert.equal(cat.isLoopbackIpv4("10.0.0.1"), false);
});

test("posture verdict precedence", () => {
  assert.equal(cat.classifyPosture([]), "no_signal");
  assert.equal(cat.classifyPosture([["egress", "saas_chat_browser"], ["app", "model_developer"]]), "model_developer");
  assert.equal(cat.classifyPosture([["mcp", "mcp_host"], ["app", "agentic_client"]]), "mcp_host");
  assert.equal(cat.classifyPosture([["app", "agentic_client"]]), "agentic_developer");
  assert.equal(cat.classifyPosture([["egress", "code_assistant_api"]]), "code_assistant");
  assert.equal(cat.classifyPosture([["egress", "code_assistant_api"], ["egress", "saas_chat_browser"]]), "unsanctioned_saas");
  assert.equal(cat.classifyPosture([["app", "image_video_gen"], ["egress", "model_hub"]]), "image_video_gen");
  assert.equal(cat.verdictSeverity("model_developer"), 0);
  assert.equal(cat.verdictSeverity("nope"), 8);
});

test("Python re.escape", () => {
  assert.equal(hunt.pyEscape("npx -y @modelcontextprotocol"), "npx\\ \\-y\\ @modelcontextprotocol");
  assert.equal(hunt.pyEscape("llama_index"), "llama_index");
});

// ------------------------------------------------ tools against a fake eyas-mcp

function fakeCtx(handler) {
  const calls = [];
  return {
    calls,
    ctx: {
      callNative: async (name, args) => {
        calls.push({ name, args });
        const out = await handler(name, args);
        return out && out.__error ? { obj: null, error: out.__error } : { obj: out, error: null };
      },
      searchNative: async () => {
        throw new Error("unexpected searchNative");
      },
    },
  };
}

const PR2 = [
  { "@timestamp": 3000, ImageFileName: "C:\\Users\\a\\AppData\\Local\\Programs\\cursor\\Cursor.exe", CommandLine: "Cursor.exe --x", UserName: "a" },
  { "@timestamp": 1000, ImageFileName: "C:\\Users\\a\\AppData\\Local\\Programs\\cursor\\Cursor.exe", UserName: "a" },
  { "@timestamp": 2000, ImageFileName: "C:\\n\\node.exe", CommandLine: "npx -y @modelcontextprotocol/server-git", UserName: "b" },
];
const DNS = [
  { "@timestamp": 5000, DomainName: "api.openai.com", ContextImageFileName: "C:\\a\\python.exe" },
  { "@timestamp": 4000, DomainName: "api.openai.com.", ContextImageFileName: "C:\\a\\python.exe" },
  { "@timestamp": 4500, DomainName: "claude.ai", ContextImageFileName: "C:\\b\\chrome.exe" },
  { "@timestamp": 4500, DomainName: "example.com" },
];
const NC = [
  { "@timestamp": 6000, RemotePort: "11434", RemoteAddressIP4: "127.0.0.1", ImageFileName: "C:\\o\\ollama.exe" },
  { "@timestamp": 7000, RemotePort: 11434, RemoteAddressIP4: "10.1.1.9", ImageFileName: "C:\\b\\chrome.exe", UserName: "a" },
  { "@timestamp": 7000, RemotePort: "x" },
];

test("host scan: three parallel bounded searches, aggregated", async () => {
  const { ctx, calls } = fakeCtx((name, args) => {
    assert.equal(name, "falcon_search_ngsiem");
    const q = args.query_string;
    if (q.startsWith("#event_simpleName=ProcessRollup2")) return { ok: true, results: PR2, partial: false };
    if (q.startsWith("#event_simpleName=DnsRequest")) return { ok: true, results: DNS, partial: false };
    return { ok: true, results: NC, partial: false };
  });
  const out = await hunt.hostShadowAiScan(ctx, { device_id: AID });
  assert.equal(calls.length, 3);
  for (const c of calls) {
    assert.deepEqual(
      { hb: c.args.hours_back, cc: c.args.check_cql, mr: c.args.max_rows, tb: c.args.time_budget_seconds },
      { hb: 72, cc: true, mr: 2000, tb: 40 },
    );
  }
  assert.equal(out.ok, true);
  assert.equal(out.verdict, "model_developer");
  assert.equal(out.partial, false);
  assert.equal(out.errors, null);
  assert.equal(out.events_scanned, 10);
  assert.deepEqual(out.apps[0].cleanup, [{ script_id: "host-uninstall-cursor", params: {} }]);
  assert.deepEqual([out.apps[0].exec_count, out.apps[0].first_seen_ms, out.apps[0].last_seen_ms], [2, 1000, 3000]);
  assert.equal(out.mcp[0].family, "mcp_npm");
  assert.deepEqual(out.egress.map((e) => [e.domain, e.query_count]), [["api.openai.com", 2], ["claude.ai", 1]]);
  assert.deepEqual(out.local_inference.map((l) => [l.scope, l.port, l.remote_addresses]), [
    ["peer", 11434, ["10.1.1.9"]],
    ["loopback", 11434, ["127.0.0.1"]],
  ]);
  assert.ok([...out.apps, ...out.mcp, ...out.egress, ...out.local_inference].every((r) => r.sanctioned === false));
});

test("host scan: sanctioned tools leave the verdict; all sanctioned → sanctioned", () => {
  const some = hunt.aggregateHostScan(PR2.slice(0, 2), DNS.slice(0, 2), [], new Set(["cursor"]));
  assert.equal(some.apps[0].sanctioned, true);
  assert.equal(some.verdict, "unsanctioned_saas");
  const all = hunt.aggregateHostScan(PR2.slice(0, 2), [], [], new Set(["cursor"]));
  assert.equal(all.verdict, "sanctioned");
});

test("host scan: one pass failing or partial still returns the rest", async () => {
  const { ctx } = fakeCtx((name, args) => {
    const q = args.query_string;
    if (q.includes("ProcessRollup2")) return { __error: "NGSIEM 500" };
    if (q.includes("DnsRequest")) return { ok: true, results: DNS, partial: true };
    return { ok: true, results: [] };
  });
  const out = await hunt.hostShadowAiScan(ctx, { device_id: AID, hours_back: 24 });
  assert.equal(out.partial, true);
  assert.deepEqual(out.errors.process_rollup2, { ok: false, error: "NGSIEM 500", surface: "NGSIEM" });
  assert.equal(out.errors.dns_request, null);
  assert.equal(out.egress.length, 2);
  assert.equal(out.verdict, "unsanctioned_saas");
});

test("host scan: input checks", async () => {
  const { ctx, calls } = fakeCtx(() => ({}));
  assert.match((await hunt.hostShadowAiScan(ctx, { device_id: "x" })).error, /32-char hex/);
  assert.match((await hunt.hostShadowAiScan(ctx, { device_id: AID, hours_back: 337 })).error, /1-336/);
  assert.equal(calls.length, 0);
});

test("fleet egress: grouped per host, sanctioned-only hosts dropped, busiest first", () => {
  const rows = [
    { "@timestamp": 1, aid: "h1", DomainName: "api.openai.com" },
    { "@timestamp": 2, aid: "h2", DomainName: "claude.ai" },
    { "@timestamp": 3, aid: "h2", DomainName: "claude.ai" },
    { "@timestamp": 4, aid: "h2", DomainName: "api.anthropic.com" },
    { "@timestamp": 5, aid: "h3", DomainName: "api.github.com" },
    { "@timestamp": 6, DomainName: "claude.ai" },
  ];
  const items = hunt.aggregateFleetEgress(rows, new Set(["github api (incl. copilot)"]));
  assert.deepEqual(items.map((i) => i.aid), ["h2", "h1"]);
  assert.deepEqual(items[0].tools.map((t) => [t.tool, t.query_count]), [["Claude (web)", 2], ["Anthropic API", 1]]);
  assert.deepEqual(items[0].tools[0].sample_domains, ["claude.ai"]);
});

test("fleet egress: bounded search, scope denial, input checks", async () => {
  const ok = fakeCtx(() => ({ ok: true, results: [{ "@timestamp": 1, aid: "h1", DomainName: "claude.ai" }], partial: false }));
  const out = await hunt.fleetShadowAiEgress(ok.ctx, {});
  assert.deepEqual(
    { hb: ok.calls[0].args.hours_back, mr: ok.calls[0].args.max_rows, tb: ok.calls[0].args.time_budget_seconds },
    { hb: 24, mr: 5000, tb: 45 },
  );
  assert.equal(out.items.length, 1);
  assert.equal(out.truncated, false);

  const denied = fakeCtx(() => ({ __error: "Permission denied. The API credentials don't have the required access. (status 403)" }));
  const d = await hunt.fleetShadowAiEgress(denied.ctx, {});
  assert.equal(d.scope_pending, true);

  assert.match((await hunt.fleetShadowAiEgress(ok.ctx, { limit: 50 })).error, /100-10000/);
  assert.match((await hunt.fleetShadowAiEgress(ok.ctx, { hours_back: 0 })).error, /1-168/);
});

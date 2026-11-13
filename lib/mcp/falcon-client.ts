import "server-only";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { childProcessEnv } from "@/lib/config/spawn-env";
import versions from "@/versions.json";

type Transport = StreamableHTTPClientTransport | StdioClientTransport;

function buildTransport(): Transport {
  const url = process.env.FALCON_MCP_URL;
  if (url) {
    const apiKey = process.env.FALCON_MCP_API_KEY;
    if (!apiKey) {
      throw new Error(
        "FALCON_MCP_URL is set but FALCON_MCP_API_KEY is missing — required for the HTTP transport.",
      );
    }
    return new StreamableHTTPClientTransport(new URL(url), {
      requestInit: { headers: { "x-api-key": apiKey } },
    });
  }

  // Dev path: `uvx` builds + runs the MCP server (eyas-mcp, the maintained
  // falcon-mcp fork) from its git repo at a pinned commit. Never resolve it by
  // bare package name — that would pull whatever PyPI serves under the name.
  // We pin to a full commit SHA, not a PyPI version: uv caches git
  // checkouts by commit, so dev tracks the exact tree the standalone bundle
  // builds its wheel from — single source of truth in versions.json. An
  // unpinned spec would silently strand dev on a stale uv cache (observed with
  // the old PyPI pin: dev still ran 0.9.0 with 0.10.0 pinned). Standalone sets
  // FALCON_MCP_COMMAND/ARGS explicitly (start.sh) so this default is dev-only;
  // an explicit FALCON_MCP_ARGS still overrides for power users.
  const command = process.env.FALCON_MCP_COMMAND ?? "uvx";
  const fromSpec = `git+${versions["mcp-server-git"]}@${versions["mcp-server-ref"]}`;
  const args = process.env.FALCON_MCP_ARGS
    ? process.env.FALCON_MCP_ARGS.split(" ").filter(Boolean)
    : ["--from", fromSpec, versions["mcp-server-package"], "--transport", "stdio"];

  // uv resolves the server's Python deps from PyPI by default. Networks that
  // need a mirror or a TLS-inspecting proxy's CA set UV_INDEX_URL /
  // UV_SYSTEM_CERTS (and UV_CONSTRAINT) in .env — they reach the spawn via
  // process.env. Inert in standalone (explicit FALCON_MCP_COMMAND,
  // offline-installed deps — uv never runs).
  const env = childProcessEnv();

  return new StdioClientTransport({
    command,
    args,
    env,
    stderr: "inherit",
    // The SDK drops the connection ("Connection closed") on any single message
    // over 10 MB. Full host records run ~10 KB each, so falcon_search_hosts at
    // limit 5000 (the vulnerabilities page's managed-host check) can reach
    // ~53 MB on a large tenant. This is a ceiling, not a preallocation.
    maxBufferSize: 128 * 1024 * 1024,
  });
}

// One Client per call. We tried a globalThis-pinned persistent singleton (saved
// ~2s of stdio handshake per call) but reverted: falcon-mcp's Python server
// processes JSON-RPC requests serially, so a shared client serialized every
// concurrent caller behind one queue. Under realistic load (Promise.all in a
// dashboard, or two SSE streams from different tabs) request times jumped from
// ~6s to 60–120s and hit the MCP 60s timeout. Spawning fresh per call keeps
// callers parallel — each gets its own falcon-mcp process. See the "MCP
// concurrency" gotcha in CLAUDE.md before reintroducing pooling.
export async function withFalconMcpClient<T>(fn: (client: Client) => Promise<T>): Promise<T> {
  const transport = buildTransport();
  const client = new Client(
    { name: "project-eyas", version: "0.1.0" },
    { capabilities: {} },
  );
  try {
    await client.connect(transport);
    return await fn(client);
  } finally {
    await client.close().catch(() => {});
  }
}

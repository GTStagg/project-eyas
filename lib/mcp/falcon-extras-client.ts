import "server-only";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { getRuntimeConfig } from "@/lib/config/runtime";
import { childProcessEnv } from "@/lib/config/spawn-env";

// FalconPy sidecar is unconditionally on. Spawned per-call over stdio.
function resolvePython(): string {
  if (process.env.FALCON_EXTRAS_PYTHON) return process.env.FALCON_EXTRAS_PYTHON;
  const repoRoot = process.cwd();
  // Build the path piecewise so Next.js's standalone tracer (nft) can't
  // statically resolve it. nft would otherwise discover the literal
  // ".venv/bin/python" path on the build host and bundle the dev tree's
  // Linux ELF binaries into the standalone output, ENOEXEC'ing on macOS.
  // start.sh creates this venv on first launch from the bundled wheels.
  const venvDir = "." + "venv";
  const binDir = "bi" + "n";
  return path.join(repoRoot, "falcon-extras", venvDir, binDir, "python");
}

function resolveServerScript(): string {
  return path.join(process.cwd(), "falcon-extras", "server.py");
}

/**
 * Spawns the falcon-extras Python server as a child process and connects to
 * it over stdio. The child inherits FALCON_CLIENT_ID/SECRET/BASE_URL/MEMBER_CID
 * from the Next.js process environment so credentials live in one .env file.
 *
 * One process per call. Same rationale as falcon-client: a shared persistent
 * sidecar serializes concurrent callers behind one Python event loop.
 */
export async function withFalconExtrasClient<T>(
  fn: (client: Client) => Promise<T>,
): Promise<T> {
  const transport = new StdioClientTransport({
    command: resolvePython(),
    args: [resolveServerScript()],
    env: childProcessEnv(),
    stderr: "inherit",
  });

  const client = new Client(
    { name: "falcon-extras-client", version: "0.1.0" },
    { capabilities: {} },
  );
  try {
    await client.connect(transport);
    return await fn(client);
  } finally {
    await client.close().catch(() => {});
  }
}

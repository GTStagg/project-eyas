import "server-only";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";

export type BundlePins = {
  "mcp-server": string;
  "crowdstrike-falconpy": string;
  mcp: string;
};

export type BuildKind = "standalone" | "docker";

export type BundleBuildInfo = {
  appVersion: string;
  builtAt: string;
  gitSha: string;
  nodeVersion: string;
  pins: BundlePins;
  // The MCP server (eyas-mcp) is built from a pinned git commit (not a PyPI
  // release). Present on builds that pin via git; absent on older bundles.
  mcpServer?: { package: string; git: string; ref: string };
  // Standalone bundles target a specific Python wheel platform; the docker
  // image bundles its own venv so this is omitted in that path.
  wheelTarget?: { pythonVersion: string; platform: string };
  // Older standalone bundles predate this field — default to "standalone".
  buildKind?: BuildKind;
  // Build-time deployment lock baked by make-dist.sh (see build-flags.ts +
  // deployment-policy.ts). Present only on locked standalone builds; absent on
  // dev/docker. /validate-bundle asserts gatewayOnly === true AND that
  // forcedGatewayUrl is physically present in the compiled bundle, so a build
  // that silently shipped without the lock can't pass validation.
  deploymentLock?: { gatewayOnly: boolean; forcedGatewayUrl: string | null };
};

export type BuildInfoResponse =
  | {
      mode: "standalone";
      bundle: BundleBuildInfo;
      runtime: { node: string };
    }
  | {
      mode: "dev";
      runtime: { node: string };
      mcpServer: { name: string; version: string } | null;
      mcpError?: string;
    };

async function readBundleInfo(): Promise<BundleBuildInfo | null> {
  const filePath = path.join(process.cwd(), "build-info.json");
  try {
    const raw = await readFile(filePath, "utf8");
    return JSON.parse(raw) as BundleBuildInfo;
  } catch {
    return null;
  }
}

export async function getBuildInfo(): Promise<BuildInfoResponse> {
  const runtime = { node: process.version };
  const bundle = await readBundleInfo();
  if (bundle) {
    return { mode: "standalone", bundle, runtime };
  }
  // Dev path: query the live MCP server so the audience sees a real version.
  try {
    const mcpServer = await withFalconMcpClient(async (client) => {
      const info = client.getServerVersion();
      return info ? { name: info.name, version: info.version } : null;
    });
    return { mode: "dev", runtime, mcpServer };
  } catch (err) {
    return {
      mode: "dev",
      runtime,
      mcpServer: null,
      mcpError: err instanceof Error ? err.message : String(err),
    };
  }
}

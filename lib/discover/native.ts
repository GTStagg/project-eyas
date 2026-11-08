import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { nativeSidecarPayload } from "@/lib/mcp/native-payload";

// Discover accounts come from eyas-mcp's falcon_search_accounts (a strict
// superset of the former sidecar tool's fields, verified live); assets and
// applications still come from the sidecar. normalizeEntity reads the
// sidecar-shaped payload nativeSidecarPayload returns.
export function nativeDiscoverEntity(
  mcp: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return nativeSidecarPayload(mcp, name, args);
}

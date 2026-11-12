import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { nativeSidecarPayload } from "@/lib/mcp/native-payload";
import {
  identityDetectionSearchArgs,
  shapeIdentityDetections,
  type IdentityDetection,
  type IdentityDetectionOptions,
} from "./detections";

/** Identity detections in the payload shape the identity surfaces read:
 *  { ok: true, items, count } | { ok: true, scope_pending: true } | { ok: false, error }. */
export async function fetchIdentityDetections(
  mcp: Client,
  opts: IdentityDetectionOptions = {},
): Promise<Record<string, unknown>> {
  const p = await nativeSidecarPayload(
    mcp,
    "falcon_search_detections",
    identityDetectionSearchArgs(opts),
  );
  if (p.ok !== true || p.scope_pending === true) return p;
  const items: IdentityDetection[] = shapeIdentityDetections(
    Array.isArray(p.items) ? p.items : [],
    opts,
  );
  return { ok: true, items, count: items.length };
}

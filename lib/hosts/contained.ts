import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { nativeSearchPayload } from "@/lib/mcp/native-payload";
import { withFalconMcpClient } from "@/lib/mcp/falcon-client";

// Hosts in network containment, including pending transitions so the operator
// sees in-flight changes. Read from the native host search (it replaced the
// sidecar's extras_host_list_contained). The comma ORs the three states.
export const CONTAINED_HOSTS_FILTER =
  "status:'contained',status:'containment_pending',status:'lift_containment_pending'";

export type ContainedHost = {
  device_id?: string;
  hostname?: string;
  platform_name?: string;
  os_product_name?: string;
  os_version?: string;
  rtr_state?: string;
  status?: string;
  last_seen?: string;
};

const CONTAINED_HOST_FIELDS: (keyof ContainedHost)[] = [
  "device_id",
  "hostname",
  "platform_name",
  "os_product_name",
  "os_version",
  "rtr_state",
  "status",
  "last_seen",
];

function projectContainedHost(row: unknown): ContainedHost {
  const r = (row ?? {}) as Record<string, unknown>;
  const out: ContainedHost = {};
  for (const f of CONTAINED_HOST_FIELDS) {
    if (typeof r[f] === "string") out[f] = r[f] as string;
  }
  return out;
}

export type ContainedHostsResult =
  | { ok: true; items: ContainedHost[]; total: number }
  | { ok: true; scope_pending: true; items: []; total: 0 }
  | { ok: false; error: string };

export async function fetchContainedHosts(
  mcp: Client,
  limit = 200,
): Promise<ContainedHostsResult> {
  const p = await nativeSearchPayload(mcp, "falcon_search_hosts", {
    filter: CONTAINED_HOSTS_FILTER,
    limit,
    sort: "last_seen.desc",
  });
  if (p.scope_pending === true) return { ok: true, scope_pending: true, items: [], total: 0 };
  if (p.ok !== true) return { ok: false, error: String(p.error ?? "host search failed") };
  // The native search returns full host records (~100 fields, including the
  // CID); keep only what the containment surfaces read.
  const items = (Array.isArray(p.items) ? p.items : []).map(projectContainedHost);
  // pagination.total counts every contained host, not just this page.
  const total = typeof p.total === "number" ? p.total : items.length;
  return { ok: true, items, total };
}

/** AIDs of contained hosts, for overlaying containment state on a list. Opens
 *  its own MCP client; an error degrades to an empty set by design. */
export async function fetchContainedAids(limit = 200): Promise<Set<string>> {
  try {
    const r = await withFalconMcpClient((client) => fetchContainedHosts(client, limit));
    if (!r.ok) return new Set();
    return new Set(r.items.map((h) => h.device_id).filter((x): x is string => Boolean(x)));
  } catch {
    return new Set();
  }
}

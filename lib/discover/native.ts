import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { nativeSidecarPayload } from "@/lib/mcp/native-payload";
import {
  normalizeAccounts,
  normalizeApplications,
  normalizeAssetPair,
  type DiscoverSnapshot,
} from "@/lib/discover/inventory";

// Falcon Discover inventory, entirely from eyas-mcp's native tools. Shared by
// /discover (app/api/discover/route.ts) and the posture snapshot
// (lib/posture/snapshot.ts) so the two can't drift.
//
// - Assets: falcon_search_managed_assets + falcon_search_unmanaged_assets (each
//   tool pins its own entity_type), merged by normalizeAssetPair.
// - Applications: falcon_search_applications with NO filter, which lists every
//   application through the Discover query + entities endpoints (eyas-mcp
//   2d87088); there is no reliable match-all filter. fields="compact" keeps a
//   page small.
// - Accounts: falcon_search_accounts.
export async function fetchDiscoverSnapshot(mcp: Client, sample = 100): Promise<DiscoverSnapshot> {
  const safe = (name: string, args: Record<string, unknown>) =>
    nativeSidecarPayload(mcp, name, args).catch(
      (e): Record<string, unknown> => ({ ok: false, error: e instanceof Error ? e.message : String(e) }),
    );
  const [managed, unmanaged, apps, accounts] = await Promise.all([
    safe("falcon_search_managed_assets", { limit: sample, sort: "last_seen_timestamp.desc" }),
    safe("falcon_search_unmanaged_assets", { limit: sample, sort: "last_seen_timestamp.desc" }),
    safe("falcon_search_applications", { limit: sample, sort: "last_used_timestamp.desc", fields: "compact" }),
    safe("falcon_search_accounts", { limit: sample }),
  ]);
  return {
    assets: normalizeAssetPair(managed, unmanaged),
    applications: normalizeApplications(apps),
    accounts: normalizeAccounts(accounts),
  };
}

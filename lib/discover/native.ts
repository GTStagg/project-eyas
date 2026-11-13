import "server-only";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { nativeSearchPayload } from "@/lib/mcp/native-payload";
import {
  normalizeAccounts,
  normalizeApplications,
  normalizeAssetSearch,
  type DiscoverSnapshot,
} from "@/lib/discover/inventory";

// Falcon Discover inventory, entirely from eyas-mcp's native tools. Shared by
// /discover (app/api/discover/route.ts) and the posture snapshot
// (lib/posture/snapshot.ts) so the two can't drift.
//
// - Assets: falcon_search_assets (eyas-mcp ≥ 7fd4031) twice — every entity type
//   with include_type_totals for the tenant-wide per-type counts, and
//   entity_type='unmanaged' for the coverage-gap sample — merged by
//   normalizeAssetSearch.
// - Applications: falcon_search_applications with NO filter, which lists every
//   application through the Discover query + entities endpoints (eyas-mcp
//   2d87088); there is no reliable match-all filter. fields="compact" keeps a
//   page small.
// - Accounts: falcon_search_accounts.
export async function fetchDiscoverSnapshot(mcp: Client, sample = 100): Promise<DiscoverSnapshot> {
  const safe = (name: string, args: Record<string, unknown>) =>
    nativeSearchPayload(mcp, name, args).catch(
      (e): Record<string, unknown> => ({ ok: false, error: e instanceof Error ? e.message : String(e) }),
    );
  const [allAssets, unmanaged, apps, accounts] = await Promise.all([
    safe("falcon_search_assets", { limit: sample, sort: "last_seen_timestamp.desc", include_type_totals: true }),
    safe("falcon_search_assets", { entity_type: "unmanaged", limit: sample, sort: "last_seen_timestamp.desc" }),
    safe("falcon_search_applications", { limit: sample, sort: "last_used_timestamp.desc", fields: "compact" }),
    safe("falcon_search_accounts", { limit: sample }),
  ]);
  return {
    assets: normalizeAssetSearch(allAssets, unmanaged),
    applications: normalizeApplications(apps),
    accounts: normalizeAccounts(accounts),
  };
}

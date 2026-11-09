// Deterministic enrichment for the /discover surface. Pure functions — no I/O;
// `now` is injected so staleness math unit-tests cleanly (same precedent as
// lib/quarantine/review.ts).
//
// Input is the native MCP-server Discover tools' rows, shaped by
// lib/mcp/native-shape.ts: falcon_search_managed_assets +
// falcon_search_unmanaged_assets (full Discover host records),
// falcon_search_applications (fields="compact"; host nested under `host`) and
// falcon_search_accounts. Every extractor is tolerant of missing keys —
// anything unreadable degrades, never throws.
//
// The point of /discover is a POSTURE decision document, not a flat catalog:
// the aggregates below surface coverage gaps (unmanaged endpoints), privileged-
// account hygiene, and suspicious software — the three things an operator acts
// on. Raw rows ride along for the page tables; the agent only ever sees the
// rendered summary.

const DAY_MS = 86_400_000;
const STALE_ASSET_DAYS = 30;
const STALE_PASSWORD_DAYS = 365;

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v.trim() ? v.trim() : undefined;

const num = (v: unknown): number | undefined =>
  typeof v === "number" && Number.isFinite(v) ? v : undefined;

function ms(ts: string | undefined): number | undefined {
  if (!ts) return undefined;
  const t = Date.parse(ts);
  return Number.isNaN(t) ? undefined : t;
}

// ---- normalized shapes ----------------------------------------------------

export interface DiscoverAsset {
  id?: string;
  hostname?: string;
  entityType?: string; // "managed" | "unmanaged"
  platform?: string;
  osVersion?: string;
  productType?: string;
  localIp?: string;
  externalIp?: string;
  manufacturer?: string;
  firstSeen?: string;
  lastSeen?: string;
}

export interface DiscoverApplication {
  id?: string;
  name?: string;
  vendor?: string;
  version?: string;
  softwareType?: string;
  suspicious?: boolean;
  lastUsed?: string;
  hostHostname?: string;
  paths: string[];
}

export interface DiscoverAccount {
  id?: string;
  accountName?: string;
  username?: string;
  accountType?: string; // "Local" | "Domain"
  admin?: boolean;
  lastLogin?: string;
  lastLoginType?: string;
  lastLoginHost?: string;
  passwordLastSet?: string;
}

export interface DiscoverEntity<T> {
  /** Total in the tenant per the API pagination meta. */
  total: number;
  /** The hydrated sample we actually pulled (capped at the sidecar limit). */
  items: T[];
  scopePending?: boolean;
  error?: string;
  /** Assets only: tenant-wide managed / unmanaged totals, when both calls answered. */
  breakdown?: { managed: number; unmanaged: number };
}

export interface DiscoverSnapshot {
  assets: DiscoverEntity<DiscoverAsset>;
  applications: DiscoverEntity<DiscoverApplication>;
  accounts: DiscoverEntity<DiscoverAccount>;
}

export interface DiscoverSummary {
  assets: {
    total: number;
    sampled: number;
    managed: number;
    unmanaged: number;
    byPlatform: Array<{ platform: string; count: number }>;
    stale: DiscoverAsset[]; // last seen > STALE_ASSET_DAYS ago
    unmanagedList: DiscoverAsset[]; // coverage gap
  };
  accounts: {
    total: number;
    sampled: number;
    privileged: number;
    localAdmins: DiscoverAccount[];
    stalePassword: DiscoverAccount[]; // admin + password older than a year
  };
  applications: {
    total: number;
    sampled: number;
    suspicious: DiscoverApplication[];
    byType: Array<{ type: string; count: number }>;
    topVendors: Array<{ vendor: string; count: number }>;
  };
  scopePending: boolean;
  errors: string[];
}

// ---- normalization --------------------------------------------------------

function normAsset(r: Record<string, unknown>, entityType?: string): DiscoverAsset {
  return {
    id: str(r.id),
    hostname: str(r.hostname),
    entityType: str(r.entity_type) ?? entityType,
    platform: str(r.platform_name),
    osVersion: str(r.os_version),
    productType: str(r.product_type_desc),
    localIp: str(r.current_local_ip),
    externalIp: str(r.external_ip),
    manufacturer: str(r.system_manufacturer),
    firstSeen: str(r.first_seen_timestamp),
    lastSeen: str(r.last_seen_timestamp),
  };
}

function normApp(r: Record<string, unknown>): DiscoverApplication {
  const paths = Array.isArray(r.installation_paths)
    ? (r.installation_paths.filter((p) => typeof p === "string") as string[])
    : [];
  return {
    id: str(r.id),
    name: str(r.name),
    vendor: str(r.vendor),
    version: str(r.version),
    softwareType: str(r.software_type),
    suspicious: r.is_suspicious === true,
    lastUsed: str(r.last_used_timestamp),
    // Native rows nest the host (`host.hostname`); the old flat key still reads.
    hostHostname:
      str(r.host_hostname) ??
      (r.host && typeof r.host === "object" ? str((r.host as Record<string, unknown>).hostname) : undefined),
    paths,
  };
}

function normAccount(r: Record<string, unknown>): DiscoverAccount {
  const adminRaw = (str(r.admin_privileges) ?? "").toLowerCase();
  return {
    id: str(r.id),
    accountName: str(r.account_name),
    username: str(r.username),
    accountType: str(r.account_type),
    admin: adminRaw === "yes" || adminRaw === "true",
    lastLogin: str(r.last_successful_login_timestamp),
    lastLoginType: str(r.last_successful_login_type),
    lastLoginHost: str(r.last_successful_login_hostname),
    passwordLastSet: str(r.password_last_set_timestamp),
  };
}

/** Parse one shaped native payload (lib/mcp/native-shape.ts) into a normalized entity bucket. */
export function normalizeEntity<T>(
  payload: Record<string, unknown> | null,
  norm: (r: Record<string, unknown>) => T,
): DiscoverEntity<T> {
  if (!payload || typeof payload !== "object") {
    return { total: 0, items: [], error: "no response" };
  }
  if (payload.scope_pending === true) {
    return { total: 0, items: [], scopePending: true };
  }
  if (payload.ok === false) {
    return { total: 0, items: [], error: str(payload.error) ?? "upstream error" };
  }
  const rawItems = Array.isArray(payload.items) ? payload.items : [];
  const items = rawItems
    .filter((x): x is Record<string, unknown> => !!x && typeof x === "object")
    .map(norm);
  const total = num(payload.total) ?? items.length;
  return { total, items };
}

export function normalizeAssets(p: Record<string, unknown> | null) {
  return normalizeEntity(p, (r) => normAsset(r));
}

/**
 * Managed and unmanaged assets come from two native tools. Merge them into one
 * bucket: rows from both samples, the summed tenant total, and the per-type
 * totals in `breakdown` (only when both calls answered, so a partial answer
 * never reads as a real zero).
 */
export function normalizeAssetPair(
  managed: Record<string, unknown> | null,
  unmanaged: Record<string, unknown> | null,
): DiscoverEntity<DiscoverAsset> {
  const m = normalizeEntity(managed, (r) => normAsset(r, "managed"));
  const u = normalizeEntity(unmanaged, (r) => normAsset(r, "unmanaged"));
  if (m.scopePending && u.scopePending) return { total: 0, items: [], scopePending: true };
  const errors = [m.error, u.error].filter((e): e is string => !!e);
  const bothOk = !m.error && !u.error && !m.scopePending && !u.scopePending;
  return {
    total: m.total + u.total,
    items: [...m.items, ...u.items],
    ...(errors.length ? { error: errors.join("; ") } : {}),
    ...(bothOk ? { breakdown: { managed: m.total, unmanaged: u.total } } : {}),
  };
}
export function normalizeApplications(p: Record<string, unknown> | null) {
  return normalizeEntity(p, normApp);
}
export function normalizeAccounts(p: Record<string, unknown> | null) {
  return normalizeEntity(p, normAccount);
}

// ---- summarization --------------------------------------------------------

function countBy<T>(items: T[], key: (t: T) => string | undefined): Array<{ k: string; count: number }> {
  const m = new Map<string, number>();
  for (const it of items) {
    const k = key(it);
    if (!k) continue;
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return [...m.entries()]
    .map(([k, count]) => ({ k, count }))
    .sort((a, b) => b.count - a.count);
}

export function summarizeDiscover(
  snap: DiscoverSnapshot,
  nowMs: number = Date.now(),
): DiscoverSummary {
  const staleAssetCut = nowMs - STALE_ASSET_DAYS * DAY_MS;
  const stalePwCut = nowMs - STALE_PASSWORD_DAYS * DAY_MS;

  const a = snap.assets.items;
  const managed = a.filter((x) => x.entityType === "managed").length;
  const unmanagedList = a.filter((x) => x.entityType === "unmanaged");
  const stale = a.filter((x) => {
    const t = ms(x.lastSeen);
    return t !== undefined && t < staleAssetCut;
  });

  const acc = snap.accounts.items;
  const privileged = acc.filter((x) => x.admin).length;
  const localAdmins = acc.filter((x) => x.admin && (x.accountType ?? "").toLowerCase() === "local");
  const stalePassword = acc.filter((x) => {
    if (!x.admin) return false;
    const t = ms(x.passwordLastSet);
    return t !== undefined && t < stalePwCut;
  });

  const app = snap.applications.items;
  const suspicious = app.filter((x) => x.suspicious);

  const scopePending =
    !!snap.assets.scopePending && !!snap.applications.scopePending && !!snap.accounts.scopePending;
  const errors = [snap.assets.error, snap.applications.error, snap.accounts.error].filter(
    (e): e is string => !!e,
  );

  return {
    assets: {
      total: snap.assets.total,
      sampled: a.length,
      // Tenant-wide totals when both asset calls answered; sample counts otherwise.
      managed: snap.assets.breakdown?.managed ?? managed,
      unmanaged: snap.assets.breakdown?.unmanaged ?? unmanagedList.length,
      byPlatform: countBy(a, (x) => x.platform).map(({ k, count }) => ({ platform: k, count })),
      stale,
      unmanagedList,
    },
    accounts: {
      total: snap.accounts.total,
      sampled: acc.length,
      privileged,
      localAdmins,
      stalePassword,
    },
    applications: {
      total: snap.applications.total,
      sampled: app.length,
      suspicious,
      byType: countBy(app, (x) => x.softwareType).map(({ k, count }) => ({ type: k, count })),
      topVendors: countBy(app, (x) => x.vendor)
        .slice(0, 10)
        .map(({ k, count }) => ({ vendor: k, count })),
    },
    scopePending,
    errors,
  };
}

// ---- agent context block --------------------------------------------------

export function renderDiscoverContext(s: DiscoverSummary): string {
  const lines: string[] = [
    "# Deterministic Falcon Discover inventory summary (computed server-side)",
    "Counts marked 'total' are tenant-wide (API pagination meta); 'sampled' is the hydrated subset analyzed below.",
    "",
    `## Assets — ${s.assets.total} total (${s.assets.sampled} sampled): managed ${s.assets.managed}, unmanaged ${s.assets.unmanaged}.`,
    `Platforms (sample): ${s.assets.byPlatform.map((p) => `${p.platform} ${p.count}`).join(", ") || "n/a"}.`,
  ];
  if (s.assets.unmanagedList.length) {
    lines.push(`Unmanaged endpoints (no Falcon sensor — coverage gap):`);
    for (const x of s.assets.unmanagedList.slice(0, 20)) {
      lines.push(`- ${x.hostname ?? "?"} · ${x.platform ?? "?"} · last seen ${x.lastSeen ?? "?"} · ${x.localIp ?? x.externalIp ?? "?"}`);
    }
  }
  if (s.assets.stale.length) {
    lines.push(`Stale assets (not seen in ${STALE_ASSET_DAYS}+ days): ${s.assets.stale.length} — e.g. ${s.assets.stale.slice(0, 8).map((x) => x.hostname ?? "?").join(", ")}.`);
  }

  lines.push(
    "",
    `## Accounts — ${s.accounts.total} total (${s.accounts.sampled} sampled): ${s.accounts.privileged} with admin privileges.`,
  );
  if (s.accounts.localAdmins.length) {
    lines.push("Local administrator accounts (lateral-movement / privilege-hygiene risk):");
    for (const x of s.accounts.localAdmins.slice(0, 20)) {
      lines.push(`- ${x.accountName ?? x.username ?? "?"} · last login ${x.lastLogin ?? "?"} (${x.lastLoginType ?? "?"}) on ${x.lastLoginHost ?? "?"}`);
    }
  }
  if (s.accounts.stalePassword.length) {
    lines.push(`Admin accounts with passwords older than ${STALE_PASSWORD_DAYS} days: ${s.accounts.stalePassword.length} — ${s.accounts.stalePassword.slice(0, 8).map((x) => x.accountName ?? x.username ?? "?").join(", ")}.`);
  }

  lines.push(
    "",
    `## Applications — ${s.applications.total} total (${s.applications.sampled} sampled).`,
    `Software types (sample): ${s.applications.byType.map((t) => `${t.type} ${t.count}`).join(", ") || "n/a"}.`,
    `Top vendors (sample): ${s.applications.topVendors.map((v) => `${v.vendor} ${v.count}`).join(", ") || "n/a"}.`,
  );
  if (s.applications.suspicious.length) {
    lines.push("Applications flagged suspicious by Falcon Discover:");
    for (const x of s.applications.suspicious.slice(0, 20)) {
      lines.push(`- ${x.name ?? "?"} ${x.version ?? ""} (${x.vendor ?? "?"}) on ${x.hostHostname ?? "?"}`);
    }
  }
  return lines.join("\n");
}

// Shadow-AI hunting: the per-host four-layer scan (extras_host_shadow_ai_scan)
// and the fleet-wide egress search (extras_fleet_shadow_ai_egress).
//
// Every NGSIEM search runs on eyas-mcp's falcon_search_ngsiem with the CQL
// checked first, rows capped and a time budget, so a slow search returns the
// rows found so far instead of failing. The host scan's three searches run in
// parallel (the sidecar ran them one after another at 12 s each). Matching,
// grouping, the cleanup plan and the verdict are Eyas's catalog
// (./catalog.ts). Ported from the sidecar's shadow_ai/tools.py; tested in
// scripts/test-shadow-ai.mjs.

import type { EyasToolContext } from "../types";
import {
  classifyAppImage,
  classifyEgressDomain,
  classifyLocalInferencePort,
  classifyMcpCmdline,
  classifyPosture,
  cleanupPlan,
  domainRegexAlternation,
  imageRegexAlternation,
  isLoopbackIpv4,
  LOCAL_INFERENCE_PORTS_HIGH_CONFIDENCE,
} from "./catalog";

type Obj = Record<string, unknown>;

const AID = /^[a-fA-F0-9]{32}$/;

/** Sanctioned tool names for the active environment, lowercased (set in
 *  /config, read at call time). */
export async function sanctionedTools(): Promise<Set<string>> {
  const { getRuntimeConfig } = await import("@/lib/config/runtime");
  const out = new Set<string>();
  for (const t of getRuntimeConfig().shadowAiSanctionedTools ?? []) {
    const n = String(t).trim().toLowerCase();
    if (n) out.add(n);
  }
  return out;
}

function scopePayload(surface: string, diagnostic: string): Obj {
  return {
    ok: true,
    scope_pending: true,
    surface,
    items: [],
    count: 0,
    note:
      `This call returned a permission error. The ${surface} surface renders empty until the Falcon ` +
      "API client is granted the required scope. Tell the operator: 'No data — required Falcon API " +
      `scope for ${surface} is not yet granted on this tenant.'`,
    _diagnostic: diagnostic.slice(0, 200),
  };
}

// Python's re.escape (3.7+): the characters that can have a special meaning.
const PY_SPECIAL = new Set("()[]{}?*+-|^$\\.&~# \t\n\r\v\f");
export const pyEscape = (s: string) => [...s].map((c) => (PY_SPECIAL.has(c) ? `\\${c}` : c)).join("");

// Cmdline keywords that catch most MCP / agent signatures; the full
// classifier runs over the rows that come back.
const CMDLINE_KEYWORDS = [
  "modelcontextprotocol",
  "mcp-server",
  "langchain",
  "langgraph",
  "autogen",
  "crewai",
  "llama_index",
  "llamaindex",
  "openinterpreter",
  "open-interpreter",
  "@anthropic-ai",
  "uvx mcp",
  "npx -y @modelcontextprotocol",
];

/** The host scan's three CQL queries (the AID is validated first). Every OR
 *  alternative has the same `field=/regex/i` shape: mixing in wildcard()
 *  makes LogScale return a bare 400. */
export function hostScanCql(deviceId: string): { pr2: string; dns: string; nc: string } {
  const kwAlt = CMDLINE_KEYWORDS.map(pyEscape).join("|");
  const pr2 =
    `#event_simpleName=ProcessRollup2 aid="${deviceId}"\n` +
    `| (ImageFileName=/.*\\\\(?:${imageRegexAlternation()})\\.exe$/i or CommandLine=/(?:${kwAlt})/i)\n` +
    "| select([@timestamp, ImageFileName, CommandLine, ParentBaseFileName, FileSignInfo, UserName])\n" +
    "| sort(@timestamp, order=desc, limit=2000)\n" +
    "| head(2000)";
  const dns =
    `#event_simpleName=DnsRequest aid="${deviceId}"\n` +
    `| DomainName=/^(?:${domainRegexAlternation()})$/i\n` +
    "| select([@timestamp, DomainName, ContextImageFileName])\n" +
    "| sort(@timestamp, order=desc, limit=2000)\n" +
    "| head(2000)";
  const portOr = LOCAL_INFERENCE_PORTS_HIGH_CONFIDENCE.map((p) => `RemotePort=${p}`).join(" or ");
  const nc =
    `#event_simpleName=NetworkConnect aid="${deviceId}"\n` +
    `| (${portOr})\n` +
    "| select([@timestamp, ImageFileName, RemoteAddressIP4, RemotePort, UserName])\n" +
    "| sort(@timestamp, order=desc, limit=2000)\n" +
    "| head(2000)";
  return { pr2, dns, nc };
}

/** The fleet egress CQL. */
export function fleetEgressCql(limit: number): string {
  return (
    "#event_simpleName=DnsRequest\n" +
    `| DomainName=/^(?:${domainRegexAlternation()})$/i\n` +
    "| select([@timestamp, aid, DomainName, ContextImageFileName])\n" +
    `| sort(@timestamp, order=desc, limit=${limit})\n` +
    `| head(${limit})`
  );
}

type Search =
  | { ok: true; rows: Obj[]; partial: boolean }
  | { ok: false; error: Obj };

/** One bounded falcon_search_ngsiem: rows, or an error payload (a scope
 *  denial becomes the usual scope_pending payload). */
async function search(ctx: EyasToolContext, cql: string, hoursBack: number, maxRows: number, budgetS: number): Promise<Search> {
  const r = await ctx.callNative(
    "falcon_search_ngsiem",
    { query_string: cql, hours_back: hoursBack, check_cql: true, max_rows: maxRows, time_budget_seconds: budgetS },
    { timeoutMs: (budgetS + 20) * 1000 },
  );
  if (r.error) {
    const { isScopeDenied } = await import("@/lib/mcp/parse");
    if (isScopeDenied(r.error)) return { ok: false, error: scopePayload("NGSIEM", r.error) };
    return { ok: false, error: { ok: false, error: r.error, surface: "NGSIEM" } };
  }
  const res = r.obj ?? {};
  if (res.ok === false) return { ok: false, error: res };
  const rows = (Array.isArray(res.results) ? res.results : []).filter(
    (e): e is Obj => !!e && typeof e === "object" && !Array.isArray(e),
  );
  return { ok: true, rows, partial: res.partial === true };
}

/** Python's int(): whole numbers and digit strings. */
function toInt(v: unknown): number | null {
  if (v === null || v === undefined || typeof v === "boolean") return null;
  if (typeof v === "number" && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === "string" && /^\s*[+-]?\d+\s*$/.test(v)) return Number.parseInt(v, 10);
  return null;
}

type Seen = { first_seen_ms: number | null; last_seen_ms: number | null };
function touch(g: Seen, ts: number | null) {
  if (ts === null) return;
  if (g.first_seen_ms === null || ts < g.first_seen_ms) g.first_seen_ms = ts;
  if (g.last_seen_ms === null || ts > g.last_seen_ms) g.last_seen_ms = ts;
}
const bump = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) ?? 0) + 1);
/** The most frequent key (first seen wins a tie), or null. */
function top(m: Map<string, number>): string | null {
  let best: [string, number] | null = null;
  for (const [k, n] of m) if (!best || n > best[1]) best = [k, n];
  return best ? best[0] : null;
}
const strSort = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
const byLastSeenDesc = (a: Obj, b: Obj) => ((b.last_seen_ms as number) || 0) - ((a.last_seen_ms as number) || 0);

/** (domain, image) of a DnsRequest row, domain lowercased without a trailing
 *  dot; null when it has no domain. */
function dnsDomain(ev: Obj): [string, string] | null {
  const d = ev.DomainName || ev.DnsRequestQuery || ev.DomainQueryName;
  if (typeof d !== "string" || !d.trim()) return null;
  const image = ev.ContextImageFileName || ev.ImageFileName || "";
  return [d.trim().toLowerCase().replace(/\.+$/, ""), String(image)];
}

/** Group the host scan's rows into apps / mcp / egress / local_inference and
 *  the verdict. Pure. */
export function aggregateHostScan(pr2: Obj[], dns: Obj[], nc: Obj[], sanctioned: Set<string>): Obj {
  type App = Seen & { tool: string; family: string; posture: string; paths: Set<string>; users: Map<string, number>; exec: number; sample: string | null };
  type Mcp = Seen & { tool: string; family: string; posture: string; tokens: Set<string>; images: Set<string>; users: Map<string, number>; exec: number; sample: string | null };
  const apps = new Map<string, App>();
  const mcps = new Map<string, Mcp>();
  for (const ev of pr2) {
    const image = String(ev.ImageFileName || "");
    const cmdline = String(ev.CommandLine || "");
    const user = ev.UserName;
    const ts = toInt(ev["@timestamp"]);

    const [tool, family, posture] = classifyAppImage(image);
    if (tool && family && posture) {
      let g = apps.get(family);
      if (!g) {
        g = { tool, family, posture, paths: new Set(), users: new Map(), exec: 0, first_seen_ms: null, last_seen_ms: null, sample: null };
        apps.set(family, g);
      }
      g.paths.add(image);
      if (user) bump(g.users, String(user));
      g.exec += 1;
      if (cmdline && !g.sample) g.sample = cmdline.slice(0, 240);
      touch(g, ts);
    }

    const m = classifyMcpCmdline(cmdline);
    if (m) {
      let g = mcps.get(m.family);
      if (!g) {
        g = { tool: m.tool, family: m.family, posture: m.posture, tokens: new Set(), images: new Set(), users: new Map(), exec: 0, first_seen_ms: null, last_seen_ms: null, sample: null };
        mcps.set(m.family, g);
      }
      g.tokens.add(m.matched_token.slice(0, 80));
      if (image) g.images.add(image);
      if (user) bump(g.users, String(user));
      g.exec += 1;
      if (!g.sample) g.sample = cmdline.slice(0, 240);
      touch(g, ts);
    }
  }

  type Egress = Seen & { tool: string; posture: string; domain: string; count: number; images: Map<string, number> };
  const egress = new Map<string, Egress>();
  for (const ev of dns) {
    const dd = dnsDomain(ev);
    if (!dd) continue;
    const [domain, image] = dd;
    const [tool, posture] = classifyEgressDomain(domain);
    if (!tool || !posture) continue;
    let g = egress.get(domain);
    if (!g) {
      g = { tool, posture, domain, count: 0, images: new Map(), first_seen_ms: null, last_seen_ms: null };
      egress.set(domain, g);
    }
    g.count += 1;
    if (image) bump(g.images, image);
    touch(g, toInt(ev["@timestamp"]));
  }

  // Local inference, by (port, scope): loopback = this host serves a model,
  // peer = this host uses someone else's.
  type Local = Seen & { tool: string; port: number; scope: string; remotes: Map<string, number>; images: Map<string, number>; users: Map<string, number>; conns: number };
  const local = new Map<string, Local>();
  for (const ev of nc) {
    const port = toInt(ev.RemotePort);
    if (port === null) continue;
    const tool = classifyLocalInferencePort(port);
    if (!tool) continue;
    const remote = ev.RemoteAddressIP4;
    const scope = isLoopbackIpv4(remote) ? "loopback" : "peer";
    const k = `${port}|${scope}`;
    let g = local.get(k);
    if (!g) {
      g = { tool, port, scope, remotes: new Map(), images: new Map(), users: new Map(), conns: 0, first_seen_ms: null, last_seen_ms: null };
      local.set(k, g);
    }
    if (typeof remote === "string" && remote) bump(g.remotes, remote);
    const image = String(ev.ImageFileName || "");
    if (image) bump(g.images, image);
    if (ev.UserName) bump(g.users, String(ev.UserName));
    g.conns += 1;
    touch(g, toInt(ev["@timestamp"]));
  }

  const appRows: Obj[] = [...apps.values()].map((g) => {
    const paths = [...g.paths].sort(strSort);
    const [form, msManaged, cleanup] = cleanupPlan(g.family, paths);
    return {
      tool: g.tool,
      family: g.family,
      posture: g.posture,
      image_paths: paths,
      // Deterministic uninstall routing: the ban-and-clean workflow runs
      // cleanup[] as-is.
      distribution_form: form,
      microsoft_managed: msManaged,
      cleanup,
      exec_count: g.exec,
      first_seen_ms: g.first_seen_ms,
      last_seen_ms: g.last_seen_ms,
      top_user: top(g.users),
      sample_command_line: g.sample,
    };
  });
  appRows.sort(byLastSeenDesc);

  const mcpRows: Obj[] = [...mcps.values()].map((g) => ({
    tool: g.tool,
    family: g.family,
    posture: g.posture,
    matched_tokens: [...g.tokens].sort(strSort),
    images: [...g.images].sort(strSort),
    exec_count: g.exec,
    first_seen_ms: g.first_seen_ms,
    last_seen_ms: g.last_seen_ms,
    top_user: top(g.users),
    sample_command_line: g.sample,
  }));
  mcpRows.sort(byLastSeenDesc);

  const egressRows: Obj[] = [...egress.values()].map((g) => ({
    tool: g.tool,
    posture: g.posture,
    domain: g.domain,
    query_count: g.count,
    first_seen_ms: g.first_seen_ms,
    last_seen_ms: g.last_seen_ms,
    top_image: top(g.images),
  }));
  egressRows.sort((a, b) => ((b.query_count as number) || 0) - ((a.query_count as number) || 0));

  const localRows: Obj[] = [...local.values()].map((g) => ({
    tool: g.tool,
    port: g.port,
    scope: g.scope,
    posture: "model_developer",
    // Stable sort by count, descending: ties keep first-seen order.
    remote_addresses: [...g.remotes.entries()].sort((a, b) => b[1] - a[1]).map(([k]) => k).slice(0, 10),
    conn_count: g.conns,
    first_seen_ms: g.first_seen_ms,
    last_seen_ms: g.last_seen_ms,
    top_image: top(g.images),
    top_user: top(g.users),
  }));
  // Peer connections first (the interesting case), then most recent.
  localRows.sort((a, b) => {
    const s = (a.scope === "peer" ? 0 : 1) - (b.scope === "peer" ? 0 : 1);
    return s !== 0 ? s : ((b.last_seen_ms as number) || 0) - ((a.last_seen_ms as number) || 0);
  });

  // Sanctioned tools are tagged and left out of the verdict; if every
  // observed tool is sanctioned the verdict is "sanctioned".
  const anySignal = appRows.length + mcpRows.length + egressRows.length + localRows.length > 0;
  const bag: Array<[string, string]> = [];
  for (const [layer, rows] of [
    ["app", appRows],
    ["mcp", mcpRows],
    ["egress", egressRows],
    ["local_inference", localRows],
  ] as const) {
    for (const r of rows) {
      r.sanctioned = sanctioned.has(String(r.tool).toLowerCase());
      if (!r.sanctioned) bag.push([layer, String(r.posture)]);
    }
  }
  const verdict = anySignal && bag.length === 0 ? "sanctioned" : classifyPosture(bag);
  return { verdict, apps: appRows, mcp: mcpRows, egress: egressRows, local_inference: localRows };
}

// Each of the three parallel searches finishes within this.
const HOST_PASS_BUDGET_S = 40;

/** extras_host_shadow_ai_scan. */
export async function hostShadowAiScan(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const deviceId = input.device_id;
  const hoursBack = input.hours_back ?? 72;
  if (typeof deviceId !== "string" || !AID.test(deviceId)) return { ok: false, error: "device_id must be a 32-char hex AID" };
  if (typeof hoursBack !== "number" || !Number.isInteger(hoursBack) || hoursBack < 1 || hoursBack > 336) {
    return { ok: false, error: "hours_back must be an integer in 1-336" };
  }
  const q = hostScanCql(deviceId);
  const [pr2, dns, nc] = await Promise.all([
    search(ctx, q.pr2, hoursBack, 2000, HOST_PASS_BUDGET_S),
    search(ctx, q.dns, hoursBack, 2000, HOST_PASS_BUDGET_S),
    search(ctx, q.nc, hoursBack, 2000, HOST_PASS_BUDGET_S),
  ]);
  // Soft-fail per pass: another layer may still carry signal.
  const rows = (s: Search) => (s.ok ? s.rows : []);
  const partialOf = (s: Search) => !s.ok || s.partial;
  const errOf = (s: Search) => (s.ok ? null : s.error);
  const partial = partialOf(pr2) || partialOf(dns) || partialOf(nc);
  const agg = aggregateHostScan(rows(pr2), rows(dns), rows(nc), await sanctionedTools());
  return {
    ok: true,
    device_id: deviceId,
    ...agg,
    events_scanned: rows(pr2).length + rows(dns).length + rows(nc).length,
    hours_back: hoursBack,
    partial,
    errors: partial ? { process_rollup2: errOf(pr2), dns_request: errOf(dns), network_connect: errOf(nc) } : null,
  };
}

/** Group fleet DNS rows by host and tool. Hosts whose only signals are
 *  sanctioned tools are left out (the fleet view surfaces unsanctioned
 *  exposure; the per-host scan still shows them). Busiest host first. Pure. */
export function aggregateFleetEgress(events: Obj[], sanctioned: Set<string>): Obj[] {
  type G = Seen & { tool: string; posture: string; count: number; domains: Set<string> };
  const perAid = new Map<string, Map<string, G>>();
  for (const ev of events) {
    const dd = dnsDomain(ev);
    if (!dd) continue;
    const aid = ev.aid;
    if (typeof aid !== "string" || !aid) continue;
    const [tool, posture] = classifyEgressDomain(dd[0]);
    if (!tool || !posture) continue;
    let tools = perAid.get(aid);
    if (!tools) {
      tools = new Map();
      perAid.set(aid, tools);
    }
    let g = tools.get(tool);
    if (!g) {
      g = { tool, posture, count: 0, domains: new Set(), first_seen_ms: null, last_seen_ms: null };
      tools.set(tool, g);
    }
    g.count += 1;
    g.domains.add(dd[0]);
    touch(g, toInt(ev["@timestamp"]));
  }
  const items: Obj[] = [];
  for (const [aid, tools] of perAid) {
    const list = [...tools.values()].map((g) => ({
      tool: g.tool,
      posture: g.posture,
      query_count: g.count,
      first_seen_ms: g.first_seen_ms,
      last_seen_ms: g.last_seen_ms,
      sample_domains: [...g.domains].sort(strSort).slice(0, 5),
      sanctioned: sanctioned.has(g.tool.toLowerCase()),
    }));
    list.sort((a, b) => b.query_count - a.query_count);
    if (list.length && list.every((t) => t.sanctioned)) continue;
    items.push({ aid, tools: list });
  }
  const total = (h: Obj) => (h.tools as Array<{ query_count: number }>).reduce((s, t) => s + (t.query_count || 0), 0);
  items.sort((a, b) => total(b) - total(a));
  return items;
}

const FLEET_BUDGET_S = 45;

/** extras_fleet_shadow_ai_egress. */
export async function fleetShadowAiEgress(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const hoursBack = input.hours_back ?? 24;
  const limit = input.limit ?? 5000;
  if (typeof hoursBack !== "number" || !Number.isInteger(hoursBack) || hoursBack < 1 || hoursBack > 168) {
    return { ok: false, error: "hours_back must be an integer in 1-168" };
  }
  if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 100 || limit > 10000) {
    return { ok: false, error: "limit must be an integer in 100-10000" };
  }
  const s = await search(ctx, fleetEgressCql(limit), hoursBack, limit, FLEET_BUDGET_S);
  if (!s.ok) return s.error;
  const items = aggregateFleetEgress(s.rows, await sanctionedTools());
  const out: Obj = {
    ok: true,
    items,
    events_scanned: s.rows.length,
    hours_back: hoursBack,
    truncated: s.partial || s.rows.length >= limit,
  };
  if (s.partial) {
    out.note = `NGSIEM fleet egress search did not complete within ${FLEET_BUDGET_S}s, so these are the rows found so far. Reduce hours_back or limit.`;
  }
  return out;
}

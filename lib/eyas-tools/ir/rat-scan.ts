// IR Phase 0 remote-access-tool install scan (extras_host_rat_install_scan).
//
// One NGSIEM ProcessRollup2 search over the host's recent history for known
// remote-access tools (RATs / RMMs), so an install is caught even when the
// installer exited long ago. Complements the cheap `Process` Falcon script,
// which only sees what is running now. ATT&CK T1219: attackers install
// legitimate, signed remote-access tools so their access survives cleanup of
// the original detection.
//
// The catalog is deliberately narrow: products that look suspicious when
// unexpected. Corp-managed agents (SCCM, Intune, Tanium) are left out.
// Findings group by canonical tool, so two AnyDesk runs from different paths
// are one item with both paths. Phase 0's invariant: every item maps to a
// Phase 2 cleanup action.
//
// The search runs on eyas-mcp's falcon_search_ngsiem (CQL checked first, rows
// capped, time-bounded). Ported from the sidecar's ir/rat_scan.py; tested in
// scripts/test-process-tree.mjs.

import type { EyasToolContext } from "../types";

type Obj = Record<string, unknown>;

// [image-name regex atom, canonical tool, family]. The atoms join into one
// CQL alternation; a basename match routes to the tool (dedupe + display) and
// the family the playbook acts on.
export const RAT_IMAGE_CATALOG: ReadonlyArray<readonly [string, string, string]> = [
  [String.raw`AnyDesk[\w]*`, "AnyDesk", "anydesk"],
  [String.raw`TeamViewer[\w]*`, "TeamViewer", "teamviewer"],
  [String.raw`ScreenConnect[\w.]*`, "ConnectWise ScreenConnect", "screenconnect"],
  [String.raw`ConnectWiseControl[\w.]*`, "ConnectWise ScreenConnect", "screenconnect"],
  [String.raw`AteraAgent[\w]*`, "Atera RMM", "atera"],
  [String.raw`Splashtop[\w]*`, "Splashtop", "splashtop"],
  [String.raw`SRStreamer[\w]*`, "Splashtop", "splashtop"],
  [String.raw`RustDesk[\w]*`, "RustDesk", "rustdesk"],
  [String.raw`Supremo[\w]*`, "Supremo", "supremo"],
  ["client32", "NetSupport Manager", "netsupport"],
  [String.raw`NSM[\w]*`, "NetSupport Manager", "netsupport"],
  ["tvnserver", "TightVNC", "tightvnc"],
  [String.raw`winvnc[\w]*`, "UltraVNC / TightVNC", "vnc"],
  [String.raw`vncserver[\w]*`, "VNC", "vnc"],
  [String.raw`DWAGENT[\w]*`, "DWService", "dwservice"],
  [String.raw`dwagsvc[\w]*`, "DWService", "dwservice"],
  [String.raw`rutserv[\w]*`, "Remote Utilities", "remoteutilities"],
  [String.raw`rfusclient[\w]*`, "Remote Utilities", "remoteutilities"],
  [String.raw`LogMeIn[\w]*`, "LogMeIn", "logmein"],
  [String.raw`g2[mw][\w]*`, "GoToAssist / GoToMyPC", "gotomypc"],
  [String.raw`AgentMon[\w]*`, "Kaseya VSA", "kaseya"],
  [String.raw`KaseyaAgent[\w]*`, "Kaseya VSA", "kaseya"],
  [String.raw`NinjaRMMAgent[\w]*`, "NinjaOne (NinjaRMM)", "ninjaone"],
  [String.raw`PulsewayAgent[\w]*`, "Pulseway", "pulseway"],
  [String.raw`Action1Agent[\w]*`, "Action1", "action1"],
  ["chromeremotedesktophost", "Chrome Remote Desktop", "chromeremote"],
];

const CATALOG_RX = RAT_IMAGE_CATALOG.map(([atom, tool, family]) => [new RegExp(`^(?:${atom})\\.exe$`, "i"), tool, family] as const);

/** [tool, family] for an image path whose basename is a catalogued
 *  remote-access tool, else [null, null]. */
export function classifyRatImage(imagePath: string): [string | null, string | null] {
  if (!imagePath) return [null, null];
  const parts = imagePath.split("\\");
  const base = parts[parts.length - 1].split("/").pop() as string;
  for (const [rx, tool, family] of CATALOG_RX) {
    if (rx.test(base)) return [tool, family];
  }
  return [null, null];
}

/** The CQL the scan runs (the AID is validated before it gets here). */
export function ratScanCql(deviceId: string): string {
  const alt = RAT_IMAGE_CATALOG.map(([atom]) => atom).join("|");
  return (
    `#event_simpleName=ProcessRollup2 aid="${deviceId}"\n` +
    `| ImageFileName=/.*\\\\(?:${alt})\\.exe$/i\n` +
    "| select([@timestamp, ImageFileName, CommandLine, ParentBaseFileName, FileSignInfo, UserName])\n" +
    "| sort(@timestamp, order=desc, limit=500)\n" +
    "| head(500)"
  );
}

/** Python's int(): whole numbers and digit strings only. */
function toInt(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === "string" && /^\s*[+-]?\d+\s*$/.test(v)) return Number.parseInt(v, 10);
  return null;
}

/** Group NGSIEM rows into one finding per tool, newest last-seen first. */
export function groupRatEvents(events: unknown[]): Obj[] {
  type Group = {
    tool: string;
    family: string;
    paths: Set<string>;
    cmds: string[];
    parents: Map<string, number>;
    signers: Map<string, number>;
    users: Map<string, number>;
    exec: number;
    first: number | null;
    last: number | null;
  };
  const groups = new Map<string, Group>();
  for (const ev of events) {
    if (!ev || typeof ev !== "object" || Array.isArray(ev)) continue;
    const e = ev as Obj;
    const image = String(e.ImageFileName ?? "") || "";
    const [tool, family] = classifyRatImage(image);
    if (!tool || !family) continue;
    const ts = e["@timestamp"] === null || e["@timestamp"] === undefined ? null : toInt(e["@timestamp"]);
    let g = groups.get(tool);
    if (!g) {
      g = { tool, family, paths: new Set(), cmds: [], parents: new Map(), signers: new Map(), users: new Map(), exec: 0, first: null, last: null };
      groups.set(tool, g);
    }
    g.paths.add(image);
    const cmd = String(e.CommandLine ?? "") || "";
    if (cmd && g.cmds.length < 3) g.cmds.push(cmd.slice(0, 240));
    for (const [field, map] of [
      ["ParentBaseFileName", g.parents],
      ["FileSignInfo", g.signers],
      ["UserName", g.users],
    ] as const) {
      const v = e[field];
      if (v) map.set(String(v), (map.get(String(v)) ?? 0) + 1);
    }
    g.exec += 1;
    if (ts !== null) {
      if (g.first === null || ts < g.first) g.first = ts;
      if (g.last === null || ts > g.last) g.last = ts;
    }
  }
  const top = (m: Map<string, number>): string | null => {
    let best: [string, number] | null = null;
    for (const [k, n] of m) if (!best || n > best[1]) best = [k, n];
    return best ? best[0] : null;
  };
  const items = [...groups.values()].map((g) => ({
    tool: g.tool,
    family: g.family,
    image_paths: [...g.paths].sort(),
    exec_count: g.exec,
    first_seen_ms: g.first,
    last_seen_ms: g.last,
    top_parent: top(g.parents),
    top_signer: top(g.signers),
    top_user: top(g.users),
    sample_command_line: g.cmds[0] ?? null,
  }));
  items.sort((a, b) => (b.last_seen_ms || 0) - (a.last_seen_ms || 0));
  return items;
}

const AID = /^[a-fA-F0-9]{32}$/;
// Under the 60 s tool timeout, with room for the CQL check and row transfer.
const SEARCH_BUDGET_SECONDS = 45;

/** extras_host_rat_install_scan. */
export async function hostRatInstallScan(ctx: EyasToolContext, input: Obj): Promise<Obj> {
  const deviceId = input.device_id;
  const hoursBack = input.hours_back ?? 48;
  if (typeof deviceId !== "string" || !AID.test(deviceId)) return { ok: false, error: "device_id must be a 32-char hex AID" };
  if (typeof hoursBack !== "number" || !Number.isInteger(hoursBack) || hoursBack < 1 || hoursBack > 168) {
    return { ok: false, error: "hours_back must be an integer in 1-168" };
  }
  const r = await ctx.callNative(
    "falcon_search_ngsiem",
    {
      query_string: ratScanCql(deviceId),
      hours_back: hoursBack,
      check_cql: true,
      max_rows: 500,
      time_budget_seconds: SEARCH_BUDGET_SECONDS,
    },
    { timeoutMs: 65_000 },
  );
  if (r.error) return { ok: false, error: r.error };
  const res = r.obj ?? {};
  if (res.ok === false) return res;
  const events = Array.isArray(res.results) ? res.results : [];
  const items = groupRatEvents(events);
  const out: Obj = { ok: true, items, count: items.length, events_scanned: events.length, hours_back: hoursBack };
  if (res.partial === true) {
    out.truncated = true;
    out.note =
      `NGSIEM search did not complete within ${SEARCH_BUDGET_SECONDS}s, so these are the rows found so far. ` +
      "Re-run with a smaller hours_back, or fall back to the Process falconscript for currently-running RATs only.";
  }
  return out;
}

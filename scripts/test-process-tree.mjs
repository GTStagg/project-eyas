#!/usr/bin/env node
// Tests for the process-tree family (lib/eyas-tools/process-tree/classifier.ts,
// lib/eyas-tools/ir/{process-tree,campaign-scope,rat-scan}.ts) against a fake
// eyas-mcp. Includes the port of falcon-extras' ir/test_campaign_scope.py.
// Run as: node scripts/test-process-tree.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.PROCESS_TREE_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-process-tree.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, PROCESS_TREE_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

import Module from "node:module";
const stub = path.join(root, "node_modules/next/dist/compiled/server-only/empty.js");
const origResolve = Module._resolveFilename;
Module._resolveFilename = function patched(request, ...rest) {
  if (request === "server-only") return stub;
  return origResolve.call(this, request, ...rest);
};

const load = (p) => import(pathToFileURL(path.join(root, p)).href);
const cls = await load("lib/eyas-tools/process-tree/classifier.ts");
const pt = await load("lib/eyas-tools/ir/process-tree.ts");
const cs = await load("lib/eyas-tools/ir/campaign-scope.ts");
const rat = await load("lib/eyas-tools/ir/rat-scan.ts");

const AID = "a".repeat(32);

// ---------------------------------------------------------------- classifier

const n = (image, cmdline = "", pid = 1) => ({ pid, image, cmdline });

test("phishing doc: Outlook → WINWORD with the document path", () => {
  const chain = [
    n("C:\\Windows\\System32\\cmd.exe", "cmd /c x", 3),
    n("C:\\Program Files\\Microsoft Office\\WINWORD.EXE", '"WINWORD.EXE" "C:\\Users\\a\\Q1-Invoice.docm"', 2),
    n("C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE", "", 1),
  ];
  cls.annotateNodeVerdicts(chain);
  const dv = cls.classifyDeliveryVector(chain);
  assert.equal(dv.kind, "phishing_doc");
  assert.equal(dv.confidence, "high");
  assert.equal(dv.initial_access_pid, 1);
  assert.equal(dv.weaponized_artifact, "C:\\Users\\a\\Q1-Invoice.docm");
  assert.equal(dv.rationale, "OUTLOOK.EXE → WINWORD.EXE opened C:\\Users\\a\\Q1-Invoice.docm before child process spawn");
  assert.deepEqual(chain.map((x) => x.verdict), ["lolbin", "office-with-doc", "initial-access-anchor"]);
});

test("a widened window demotes high to medium", () => {
  const dv = cls.classifyDeliveryVector([n("cmd.exe"), n("wsmprovhost.exe")], { windowWidened: true });
  assert.equal(dv.kind, "lateral_winrm");
  assert.equal(dv.confidence, "medium");
});

test("user-executed dropper from the Public desktop", () => {
  const chain = [
    n("\\Device\\HarddiskVolume3\\Users\\Public\\Desktop\\Malware\\Revil\\REVIL.EXE", '"C:\\Users\\Public\\Desktop\\Malware\\Revil\\REVIL.EXE"'),
    n("\\Device\\HarddiskVolume3\\Windows\\explorer.exe"),
    n("\\Device\\HarddiskVolume3\\Windows\\System32\\userinit.exe"),
  ];
  cls.annotateNodeVerdicts(chain);
  const dv = cls.classifyDeliveryVector(chain);
  assert.equal(dv.kind, "user_executed_dropper");
  assert.equal(dv.weaponized_artifact, chain[0].image);
  assert.equal(chain[1].verdict, "initial-access-anchor");
});

test("c2 agent, lolbin_initial, malicious_service, browser, unknown", () => {
  const c2 = cls.classifyDeliveryVector([n("C:\\py\\python.exe", "python C:\\x\\agent-windows.py --server http://10.0.0.5:4444/b")]);
  assert.equal(c2.kind, "c2_agent");
  assert.equal(c2.weaponized_artifact, "http://10.0.0.5:4444/b");
  assert.equal(cls.classifyDeliveryVector([n("a.exe"), n("powershell.exe")]).kind, "lolbin_initial");
  assert.equal(cls.classifyDeliveryVector([n("a.exe"), n("services.exe")]).kind, "malicious_service");
  const br = cls.classifyDeliveryVector([n("C:\\Users\\a\\Downloads\\x.exe"), n("chrome.exe")]);
  assert.deepEqual([br.kind, br.confidence], ["browser_drive_by", "medium"]);
  assert.equal(cls.classifyDeliveryVector([n("a.exe")]).kind, "unknown");
  assert.equal(cls.classifyDeliveryVector([]).rationale, "No ancestry data available for the pivot process.");
});

test("scheduled-task host only counts above the pivot", () => {
  assert.equal(cls.classifyDeliveryVector([n("taskhostw.exe")]).kind, "unknown");
  assert.equal(cls.classifyDeliveryVector([n("x.exe"), n("taskhostw.exe")]).kind, "scheduled_task_persistence");
});

// ---------------------------------------------------------------- native nodes

test("native node maps to the sidecar shape", () => {
  const node = pt.nodeFromNative({
    process_id: "4688197558",
    parent_process_id: "123",
    os_pid: "4321",
    image: "\\Device\\X\\a.exe",
    command_line: "x".repeat(600),
    user_name: "demo",
    user_sid: null,
    sha256: "ab",
    signing: { sign_info_flags: "8683520" },
    process_start_time: "2026-11-12T15:55:09.000Z",
    timestamp: "2026-11-12T15:55:10.000Z",
  });
  assert.equal(node.pid, 4688197558);
  assert.equal(node.ppid, 123);
  assert.equal(node.os_pid, 4321);
  assert.equal(node.cmdline.length, 480);
  assert.equal(node.user, "demo");
  assert.equal(node.user_sid, null);
  assert.equal(node.signed, null);
  assert.equal(node.ts, "2026-11-12T15:55:09.000Z");
  assert.deepEqual(node.signing, { sign_info_flags: "8683520" });
  assert.equal(pt.nodeFromNative({ signing: { file_sign_info: "Signed: Microsoft" } }).signed, true);
  assert.equal(pt.nodeFromNative({ signing: { file_sign_info: "Unsigned" } }).signed, false);
  assert.equal(pt.toPid("99999999999999999999"), "99999999999999999999");
  assert.equal(pt.toPid("abc"), null);
});

test("pivot times are cut to milliseconds", () => {
  assert.equal(pt.normalizePivotTime("2026-11-12T15:55:11.361606730Z"), "2026-11-12T15:55:11.361Z");
  assert.equal(pt.normalizePivotTime("2026-11-12T10:55:11+05:00"), "2026-11-12T05:55:11.000Z");
  assert.equal(pt.normalizePivotTime("2026-11-12"), "2026-11-12T00:00:00.000Z");
  assert.equal(pt.normalizePivotTime("yesterday"), null);
});

// A fake eyas-mcp: per-tool handlers, recording calls.
function fakeCtx(handlers) {
  const calls = [];
  const run = async (name, args) => {
    calls.push({ name, args });
    const h = handlers[name];
    if (!h) throw new Error(`unexpected native ${name}`);
    return h(args, calls);
  };
  return {
    calls,
    ctx: {
      callNative: async (name, args) => {
        const out = await run(name, args);
        return out && out.__error ? { obj: null, error: out.__error } : { obj: out, error: null };
      },
      searchNative: async (name, args) => run(name, args),
    },
  };
}

const nativeNode = (id, parent, image, extra = {}) => ({
  process_id: String(id),
  parent_process_id: parent === null ? null : String(parent),
  image,
  command_line: extra.cmd ?? "",
  process_start_time: extra.ts ?? "2026-11-12T15:55:09.000Z",
  timestamp: "2026-11-12T15:55:09.000Z",
  ...extra.more,
});

test("host process tree: native call, pivot-first ancestry, classifier", async () => {
  const { ctx, calls } = fakeCtx({
    falcon_get_process_tree: () => ({
      pivot: nativeNode(30, 20, "C:\\Users\\a\\Downloads\\evil.exe"),
      ancestry: [{ ...nativeNode(20, 10, "C:\\Windows\\explorer.exe"), depth: 1 }, { ...nativeNode(10, 5, "userinit.exe"), depth: 2 }],
      descendants: [{ ...nativeNode(40, 30, "cmd.exe"), depth: 1 }],
      window: { events_scanned: 812, anchor_recovered: false },
      unresolved_parent_process_id: "5",
      descendants_truncated: false,
      searches: [{ purpose: "window", status: "completed", event_count: 812 }],
      notes: ["Parent process 5 was not found, so the ancestry stops there."],
    }),
  });
  const out = await pt.hostProcessTree(ctx, { device_id: AID, pivot_pid: 30, pivot_ts_iso: "2026-11-12T15:55:11.361606730Z" });
  assert.equal(calls[0].args.pivot_time, "2026-11-12T15:55:11.361Z");
  assert.equal(calls[0].args.pivot_process_id, "30");
  assert.equal(calls[0].args.time_budget_seconds, 45);
  assert.equal(out.ok, true);
  assert.deepEqual(out.ancestry.map((x) => [x.pid, x.depth]), [[30, 0], [20, 1], [10, 2]]);
  assert.equal(out.delivery_vector.kind, "user_executed_dropper");
  assert.equal(out.ancestry[1].verdict, "initial-access-anchor");
  assert.deepEqual(out.unaccounted_pids, [5]);
  assert.equal(out.descendants[0].depth, 1);
  assert.equal(out.window_widened, false);
  assert.equal(out.events_scanned, 812);
  assert.deepEqual(out.pivot, { pid: 30, image: "C:\\Users\\a\\Downloads\\evil.exe", cmdline: "", ts: "2026-11-12T15:55:09.000Z" });
});

test("host process tree: parent lookup demotes; no pivot; input errors", async () => {
  const widened = fakeCtx({
    falcon_get_process_tree: () => ({
      pivot: nativeNode(2, 1, "cmd.exe"),
      ancestry: [{ ...nativeNode(1, null, "wsmprovhost.exe"), depth: 1 }],
      descendants: [],
      window: { events_scanned: 3 },
      searches: [{ purpose: "window", status: "completed", event_count: 3 }, { purpose: "parent_lookup", status: "completed", event_count: 1 }],
    }),
  });
  const w = await pt.hostProcessTree(widened.ctx, { device_id: AID, pivot_pid: 2, pivot_ts_iso: "2026-11-12T00:00:00Z" });
  assert.equal(w.window_widened, true);
  assert.equal(w.delivery_vector.confidence, "medium");

  const empty = fakeCtx({
    falcon_get_process_tree: () => ({ pivot: null, ancestry: [], descendants: [], window: { events_scanned: 0 }, searches: [{ purpose: "window", status: "completed", event_count: 0 }] }),
  });
  const e = await pt.hostProcessTree(empty.ctx, { device_id: AID, pivot_image: "a.exe", pivot_ts_iso: "2026-11-12T00:00:00Z" });
  assert.equal(e.pivot, null);
  assert.match(e.delivery_vector.rationale, /No ProcessRollup2 events found on this host within ±10m/);

  const timedOut = fakeCtx({
    falcon_get_process_tree: () => ({ pivot: null, window: {}, searches: [{ purpose: "window", status: "timed_out" }], partial: true }),
  });
  const t = await pt.hostProcessTree(timedOut.ctx, { device_id: AID, pivot_pid: 9, pivot_ts_iso: "2026-11-12T00:00:00Z" });
  assert.equal(t.truncated, true);
  assert.equal(t.partial, true);

  const none = fakeCtx({});
  assert.match((await pt.hostProcessTree(none.ctx, { device_id: "x" })).error, /32-char hex/);
  assert.match((await pt.hostProcessTree(none.ctx, { device_id: AID, pivot_pid: 1 })).error, /pivot_ts_iso/);
  assert.match((await pt.hostProcessTree(none.ctx, { device_id: AID, pivot_ts_iso: "2026-11-12" })).error, /pivot_pid or pivot_image/);
  assert.match((await pt.hostProcessTree(none.ctx, { device_id: AID, pivot_image: "a';b", pivot_ts_iso: "2026-11-12" })).error, /basename/);
  assert.match((await pt.hostProcessTree(none.ctx, { device_id: AID, pivot_pid: 1, pivot_ts_iso: "nope" })).error, /could not be parsed/);
  assert.equal(none.calls.length, 0);

  const failing = fakeCtx({ falcon_get_process_tree: () => ({ __error: "NGSIEM 403" }) });
  assert.deepEqual(await pt.hostProcessTree(failing.ctx, { device_id: AID, pivot_pid: 1, pivot_ts_iso: "2026-11-12" }), { ok: false, error: "NGSIEM 403" });
});

// ---------------------------------------------------------------- clustering
// Port of falcon-extras/ir/test_campaign_scope.py.

const node = (pid, image) => ({ pid, image });
const cluster = (obj) => cs.clusterBySharedAncestry(new Map(Object.entries(obj).map(([k, v]) => [Number(k), v])));
const groups = (m) => [...m.values()].map((v) => [...v].sort((a, b) => a - b)).sort((a, b) => a[0] - b[0]);

test("clustering: trivial shapes", () => {
  assert.equal(cluster({}).size, 0);
  assert.deepEqual([...cluster({ 1234: [] })], [[1234, [1234]]]);
  assert.deepEqual(groups(cluster({ 1234: [node(900, "C:\\Users\\a\\dropper.exe"), node(800, "explorer.exe")] })), [[1234]]);
});

test("clustering: independent pivots stay separate", () => {
  assert.deepEqual(groups(cluster({ 100: [node(50, "C:\\a\\one.exe")], 200: [node(60, "C:\\b\\two.exe")] })), [[100], [200]]);
  assert.deepEqual(
    groups(cluster({ 100: [node(900, "C:\\a\\one.exe"), node(50, "explorer.exe")], 200: [node(901, "C:\\b\\two.exe"), node(50, "explorer.exe")] })),
    [[100], [200]],
  );
  const svc = "C:\\Windows\\System32\\svchost.exe";
  assert.deepEqual(groups(cluster({ 100: [node(900, "C:\\a\\one.exe"), node(50, svc)], 200: [node(901, "C:\\b\\two.exe"), node(50, svc)] })), [[100], [200]]);
});

test("clustering: shared non-system ancestors merge, transitively", () => {
  const dropper = node(999, "C:\\Users\\victim\\dropper.exe");
  assert.deepEqual(groups(cluster({ 100: [dropper, node(50, "explorer.exe")], 200: [dropper, node(50, "explorer.exe")] })), [[100, 200]]);
  const a = node(900, "C:\\a.exe");
  const b = node(901, "C:\\b.exe");
  assert.deepEqual(groups(cluster({ 100: [a], 200: [a, b], 300: [b] })), [[100, 200, 300]]);
  assert.deepEqual(groups(cluster({ 100: [a], 200: [a], 300: [b], 400: [b] })), [[100, 200], [300, 400]]);
});

test("clustering: malformed nodes are skipped; a node with no image still anchors", () => {
  assert.deepEqual(groups(cluster({ 100: [{ image: "C:\\noisy.exe" }], 200: [{ pid: "not an int", image: "x" }] })), [[100], [200]]);
  const noImage = { pid: 999 };
  assert.deepEqual(groups(cluster({ 100: [noImage], 200: [noImage] })), [[100, 200]]);
});

test("pivot pid extraction", () => {
  assert.equal(cs.extractPivotPid({ process_id: "4688197558" }), 4688197558);
  assert.equal(cs.extractPivotPid({ process_id: "x", behaviors: [{ process_id: null, target_process_id: 77 }] }), 77);
  assert.equal(cs.extractPivotPid({}), null);
});

// ---------------------------------------------------------------- campaign scope

const alert = (cid, pid, created) => ({ composite_id: cid, status: "new", created_timestamp: created, process_id: pid, display_name: cid });

test("campaign scope: two campaigns, an unclustered pivot, a no-pivot detection", async () => {
  const trees = {
    // 30 and 31 share dropper 20; 50 has its own chain; 60 has no telemetry.
    30: { pivot: nativeNode(30, 20, "a.exe"), ancestry: [{ ...nativeNode(20, 10, "C:\\Users\\a\\Downloads\\drop.exe"), depth: 1 }, { ...nativeNode(10, 1, "explorer.exe"), depth: 2 }] },
    31: { pivot: nativeNode(31, 20, "b.exe"), ancestry: [{ ...nativeNode(20, 10, "C:\\Users\\a\\Downloads\\drop.exe"), depth: 1 }] },
    50: { pivot: nativeNode(50, 40, "c.exe"), ancestry: [{ ...nativeNode(40, 1, "wsmprovhost.exe"), depth: 1 }] },
    60: { pivot: null, ancestry: [] },
  };
  const { ctx, calls } = fakeCtx({
    falcon_search_detections: () => ({
      ok: true,
      items: [
        alert("d1", "30", "2026-11-12T10:00:00Z"),
        alert("d2", "31", "2026-11-12T10:05:00Z"),
        alert("d3", "30", "2026-11-12T10:06:00Z"),
        alert("d4", "50", "2026-11-12T09:00:00Z"),
        alert("d5", "60", "2026-11-12T08:00:00Z"),
        { composite_id: "d6", status: "new", created_timestamp: "2026-11-12T07:00:00Z" },
        { composite_id: "d7", status: "closed", process_id: "30" },
      ],
    }),
    falcon_get_process_tree: (args) => trees[args.pivot_process_id],
  });
  const out = await cs.irCampaignScope(ctx, { device_id: AID });
  const treeCalls = calls.filter((c) => c.name === "falcon_get_process_tree");
  assert.equal(treeCalls.length, 4);
  for (const c of treeCalls) {
    assert.equal(c.args.window_minutes, 30);
    assert.equal(c.args.descendants_max, 1);
    assert.ok(c.args.time_budget_seconds >= 10 && c.args.time_budget_seconds <= 35);
  }
  assert.equal(out.ok, true);
  assert.equal(out.total_open, 6);
  assert.equal(out.unique_pivots_total, 4);
  assert.equal(out.unique_pivots_walked, 3);
  assert.equal(out.campaigns.length, 2);
  const [big, small] = out.campaigns;
  assert.deepEqual(big.composite_ids.sort(), ["d1", "d2", "d3"]);
  assert.deepEqual(big.member_pivot_pids, [30, 31]);
  assert.equal(big.root_pid, 20);
  assert.equal(big.delivery_vector.kind, "user_executed_dropper");
  assert.equal(big.first_ts, "2026-11-12T10:00:00Z");
  assert.equal(big.last_ts, "2026-11-12T10:06:00Z");
  assert.equal(small.delivery_vector.kind, "lateral_winrm");
  assert.deepEqual(
    out.unclustered.map((u) => [u.composite_id, u.reason]).sort(),
    [
      ["d5", "ancestry not reconstructible (telemetry aged out or pivot missing)"],
      ["d6", "no pivot_pid on detection"],
    ],
  );
  assert.equal(out.deadline_reached, false);
  assert.equal(out.capped, false);
});

test("campaign scope: no open detections; scope denial; deadline", async () => {
  const empty = fakeCtx({ falcon_search_detections: () => ({ ok: true, items: [] }) });
  const e = await cs.irCampaignScope(empty.ctx, { device_id: AID });
  assert.equal(e.total_open, 0);
  assert.equal(e.note, "No open detections on this host.");

  const denied = fakeCtx({ falcon_search_detections: () => ({ ok: true, scope_pending: true, items: [] }) });
  assert.equal((await cs.irCampaignScope(denied.ctx, { device_id: AID })).scope_pending, true);

  assert.match((await cs.irCampaignScope(empty.ctx, { device_id: "bad" })).error, /32-character hex/);

  // A clock past the deadline: nothing is walked, everything is unclustered.
  let t = 0;
  const late = fakeCtx({
    falcon_search_detections: () => {
      t = 60_000;
      return { ok: true, items: [alert("d1", "30", "2026-11-12T10:00:00Z")] };
    },
  });
  const l = await cs.irCampaignScope(late.ctx, { device_id: AID }, () => t);
  assert.equal(late.calls.filter((c) => c.name === "falcon_get_process_tree").length, 0);
  assert.equal(l.deadline_reached, true);
  assert.equal(l.unclustered[0].reason, "deadline reached before walk completed");
  assert.match(l.note, /PARTIAL RESULT: walked 0 of 1 unique pivots \(deadline reached\)/);
});

// ---------------------------------------------------------------- RAT scan

test("RAT image classification", () => {
  assert.deepEqual(rat.classifyRatImage("C:\\Program Files\\AnyDesk\\AnyDesk.exe"), ["AnyDesk", "anydesk"]);
  assert.deepEqual(rat.classifyRatImage("\\Device\\X\\client32.exe"), ["NetSupport Manager", "netsupport"]);
  assert.deepEqual(rat.classifyRatImage("/opt/x/TeamViewer_Service.exe"), ["TeamViewer", "teamviewer"]);
  assert.deepEqual(rat.classifyRatImage("C:\\x\\notanydesk.exe"), [null, null]);
  assert.deepEqual(rat.classifyRatImage(""), [null, null]);
});

test("RAT scan CQL keeps the sidecar's query", () => {
  const q = rat.ratScanCql(AID);
  assert.ok(q.startsWith(`#event_simpleName=ProcessRollup2 aid="${AID}"\n| ImageFileName=/.*\\\\(?:AnyDesk[\\w]*|TeamViewer[\\w]*|`));
  assert.ok(q.endsWith("|chromeremotedesktophost)\\.exe$/i\n| select([@timestamp, ImageFileName, CommandLine, ParentBaseFileName, FileSignInfo, UserName])\n| sort(@timestamp, order=desc, limit=500)\n| head(500)"));
});

test("RAT scan groups by tool, newest first", async () => {
  const rows = [
    { "@timestamp": 1000, ImageFileName: "C:\\a\\AnyDesk.exe", CommandLine: "AnyDesk --install", ParentBaseFileName: "cmd.exe", UserName: "u1" },
    { "@timestamp": 3000, ImageFileName: "C:\\b\\AnyDesk.exe", ParentBaseFileName: "explorer.exe", UserName: "u1" },
    { "@timestamp": 2000, ImageFileName: "C:\\b\\AnyDesk.exe", ParentBaseFileName: "explorer.exe" },
    { "@timestamp": "5000", ImageFileName: "C:\\t\\TeamViewer.exe" },
    { ImageFileName: "C:\\x\\other.exe" },
  ];
  const { ctx, calls } = fakeCtx({ falcon_search_ngsiem: () => ({ ok: true, results: rows, partial: false }) });
  const out = await rat.hostRatInstallScan(ctx, { device_id: AID });
  assert.deepEqual(calls[0].args, {
    query_string: rat.ratScanCql(AID),
    hours_back: 48,
    check_cql: true,
    max_rows: 500,
    time_budget_seconds: 45,
  });
  assert.equal(out.count, 2);
  assert.equal(out.events_scanned, 5);
  const [tv, ad] = out.items;
  assert.equal(tv.tool, "TeamViewer");
  assert.equal(tv.last_seen_ms, 5000);
  assert.deepEqual(ad, {
    tool: "AnyDesk",
    family: "anydesk",
    image_paths: ["C:\\a\\AnyDesk.exe", "C:\\b\\AnyDesk.exe"],
    exec_count: 3,
    first_seen_ms: 1000,
    last_seen_ms: 3000,
    top_parent: "explorer.exe",
    top_signer: null,
    top_user: "u1",
    sample_command_line: "AnyDesk --install",
  });
  assert.equal(out.truncated, undefined);
});

test("RAT scan: partial result, lint failure, bad input", async () => {
  const partial = fakeCtx({ falcon_search_ngsiem: () => ({ ok: true, results: [], partial: true }) });
  const p = await rat.hostRatInstallScan(partial.ctx, { device_id: AID, hours_back: 168 });
  assert.equal(p.truncated, true);
  assert.match(p.note, /did not complete within 45s/);

  const lint = fakeCtx({ falcon_search_ngsiem: () => ({ ok: false, error: "The CQL query has mistakes", cql_lint: [] }) });
  assert.equal((await rat.hostRatInstallScan(lint.ctx, { device_id: AID })).ok, false);

  const none = fakeCtx({});
  assert.match((await rat.hostRatInstallScan(none.ctx, { device_id: AID, hours_back: 0 })).error, /1-168/);
  assert.match((await rat.hostRatInstallScan(none.ctx, { device_id: "x" })).error, /32-char hex/);
});

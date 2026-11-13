#!/usr/bin/env node
// Pure-function tests for the IR safety-core ground truth:
// lib/chat/ir-ground-truth-pure.ts. These cover the deterministic backstops the
// route's guard relies on — the invariants that moved out of the system
// prompt / playbook prose and into code (feedback_deterministic_over_agent_instruction):
//
//   * containTargetsAid — the aid-match used to scope every IR guard decision.
//     MUST be case-insensitive: the route captures the aid via a [A-Fa-f0-9]+
//     regex, so an upper/mixed-case aid must still match or the guard would fail
//     OPEN (skip the backstop) while the ground-truth reader fails SAFE.
//   * extractDeviceIds — the device_ids a release write targets, used by the
//     route's guard to re-arm the backstop AID-KEYED when no live session
//     identity matches (a release from a different chat session, or after the
//     IR-mode idle TTL). Must mirror containTargetsAid's array/bare-string
//     shapes or a cross-session release could resolve to no host and bypass.
//   * deriveContainmentFromTurns — "did THIS workflow contain / quarantine this
//     host?" derived from the persisted audit rows, never the agent's prose.
//     Drives the F1 lift backstop AND the F1-group remove backstop.
//   * parsePhase0Scope — the exact Phase-0 originals the F2b release gate
//     re-checks (so a release can't skip an original detection that predates the
//     post-kickoff scan window), AND the `captured` discriminator that tells a
//     genuine clean kickoff (zero originals) apart from a capture that never
//     happened — the latter fails the release gate CLOSED.
//
// Run as:  node scripts/test-ir-ground-truth.mjs

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.IR_GT_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-ir-ground-truth.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, IR_GT_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const {
  containTargetsAid,
  extractDeviceIds,
  isDomainController,
  deriveContainmentFromTurns,
  parsePhase0Scope,
  containResultConfirms,
} = await import(path.join(root, "lib/chat/ir-ground-truth-pure.ts"));

const AID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; // 32 hex
const OTHER = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ── containTargetsAid ────────────────────────────────────────────────────────

test("containTargetsAid: array containing the exact aid → true", () => {
  assert.equal(containTargetsAid({ device_ids: [AID] }, AID), true);
});

test("containTargetsAid: UPPER-cased aid in input, lowercase want → true (case-insensitive)", () => {
  assert.equal(containTargetsAid({ device_ids: [AID.toUpperCase()] }, AID), true);
});

test("containTargetsAid: lowercase input, UPPER-cased want → true (both sides normalized)", () => {
  // This is the fail-OPEN asymmetry the audit flagged: the route may pass an
  // upper-cased aid; if only one side were lowered the guard would skip.
  assert.equal(containTargetsAid({ device_ids: [AID] }, AID.toUpperCase()), true);
});

test("containTargetsAid: mixed-case both sides → true", () => {
  const mixed = "AaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa";
  assert.equal(containTargetsAid({ device_ids: [mixed] }, mixed.toLowerCase()), true);
});

test("containTargetsAid: bare-string device_ids matching → true", () => {
  assert.equal(containTargetsAid({ device_ids: AID }, AID), true);
});

test("containTargetsAid: bare-string device_ids, case-insensitive → true", () => {
  assert.equal(containTargetsAid({ device_ids: AID.toUpperCase() }, AID), true);
});

test("containTargetsAid: array NOT containing the aid → false", () => {
  assert.equal(containTargetsAid({ device_ids: [OTHER] }, AID), false);
});

test("containTargetsAid: bare-string different host → false", () => {
  assert.equal(containTargetsAid({ device_ids: OTHER }, AID), false);
});

test("containTargetsAid: missing device_ids → false", () => {
  assert.equal(containTargetsAid({ group_id: "g1" }, AID), false);
});

test("containTargetsAid: non-object inputs → false (no throw)", () => {
  assert.equal(containTargetsAid(null, AID), false);
  assert.equal(containTargetsAid(undefined, AID), false);
  assert.equal(containTargetsAid("aaaa", AID), false);
  assert.equal(containTargetsAid(42, AID), false);
});

test("containTargetsAid: array with multiple ids, one matching → true", () => {
  assert.equal(containTargetsAid({ device_ids: [OTHER, AID] }, AID), true);
});

// ── extractDeviceIds ─────────────────────────────────────────────────────────

test("extractDeviceIds: array of strings → returned as-is", () => {
  assert.deepEqual(extractDeviceIds({ device_ids: [AID, OTHER] }), [AID, OTHER]);
});

test("extractDeviceIds: bare-string device_ids → single-element array", () => {
  assert.deepEqual(extractDeviceIds({ device_ids: AID }), [AID]);
});

test("extractDeviceIds: missing device_ids → []", () => {
  assert.deepEqual(extractDeviceIds({ group_id: "g1" }), []);
});

test("extractDeviceIds: non-object inputs → [] (no throw)", () => {
  assert.deepEqual(extractDeviceIds(null), []);
  assert.deepEqual(extractDeviceIds(undefined), []);
  assert.deepEqual(extractDeviceIds("aaaa"), []);
  assert.deepEqual(extractDeviceIds(42), []);
});

test("extractDeviceIds: non-string array elements are filtered out", () => {
  assert.deepEqual(extractDeviceIds({ device_ids: [AID, 123, null, OTHER] }), [
    AID,
    OTHER,
  ]);
});

test("extractDeviceIds: empty array → []", () => {
  assert.deepEqual(extractDeviceIds({ device_ids: [] }), []);
});

test("extractDeviceIds: numeric device_ids (not array, not string) → []", () => {
  assert.deepEqual(extractDeviceIds({ device_ids: 42 }), []);
});

// ── isDomainController ───────────────────────────────────────────────────────

test("isDomainController: exact 'Domain Controller' → true", () => {
  assert.equal(isDomainController("Domain Controller"), true);
});

test("isDomainController: lowercase / substring → true", () => {
  assert.equal(isDomainController("domain controller"), true);
  assert.equal(isDomainController("Windows Server (Domain Controller)"), true);
});

test("isDomainController: plain Server / Workstation → false", () => {
  assert.equal(isDomainController("Server"), false);
  assert.equal(isDomainController("Workstation"), false);
});

test("isDomainController: null / undefined → false", () => {
  assert.equal(isDomainController(null), false);
  assert.equal(isDomainController(undefined), false);
});

// ── deriveContainmentFromTurns ───────────────────────────────────────────────

/** Build a single-call turn row (the persisted shape: { toolCallsJson }). */
function turn(calls) {
  return { toolCallsJson: JSON.stringify(calls) };
}
// Default excerpt = what a SUCCESSFUL call of that tool really returns (the
// retired sidecar's {ok:true,…}; eyas-mcp's {succeeded_ids:[…]}), since ground truth
// now confirms a contain from the result, not just isError.
function call(name, input, { approval = "allow", isError = false, excerpt } = {}) {
  const ids = input?.device_ids ?? input?.ids ?? [];
  const okBody =
    name === "falcon_contain_hosts" || name === "falcon_lift_host_containment"
      ? { succeeded_ids: ids, failed_ids: [], resources: [] }
      : { ok: true, device_ids: ids, resources: [], errors: [] };
  return {
    id: `${name}-${Math.random()}`,
    name,
    input,
    approval,
    result: { isError, contentExcerpt: excerpt ?? JSON.stringify(okBody) },
    ts: 1,
  };
}

test("derive: an approved, successful contain targeting the aid → agentContained", () => {
  const turns = [turn([call("extras_host_contain", { device_ids: [AID] })])];
  const d = deriveContainmentFromTurns(turns, AID);
  assert.equal(d.agentContained, true);
  assert.deepEqual(d.agentAddedGroupIds, []);
});

test("derive: a DENIED contain does NOT count", () => {
  const turns = [
    turn([call("extras_host_contain", { device_ids: [AID] }, { approval: "deny" })]),
  ];
  assert.equal(deriveContainmentFromTurns(turns, AID).agentContained, false);
});

test("derive: a contain that ERRORED does NOT count", () => {
  const turns = [
    turn([call("extras_host_contain", { device_ids: [AID] }, { isError: true })]),
  ];
  assert.equal(deriveContainmentFromTurns(turns, AID).agentContained, false);
});

test("derive: a contain targeting a DIFFERENT host does NOT count", () => {
  const turns = [turn([call("extras_host_contain", { device_ids: [OTHER] })])];
  assert.equal(deriveContainmentFromTurns(turns, AID).agentContained, false);
});

test("derive: contain match is case-insensitive (UPPER device_ids)", () => {
  const turns = [
    turn([call("extras_host_contain", { device_ids: [AID.toUpperCase()] })]),
  ];
  assert.equal(deriveContainmentFromTurns(turns, AID).agentContained, true);
});

test("derive: a successful group-add records the group_id", () => {
  const turns = [
    turn([
      call("extras_host_group_add_members", { device_ids: [AID], group_id: "quarantine-1" }),
    ]),
  ];
  const d = deriveContainmentFromTurns(turns, AID);
  assert.deepEqual(d.agentAddedGroupIds, ["quarantine-1"]);
});

test("derive: a DENIED group-add is NOT recorded (the F1-group invariant)", () => {
  const turns = [
    turn([
      call(
        "extras_host_group_add_members",
        { device_ids: [AID], group_id: "g1" },
        { approval: "deny" },
      ),
    ]),
  ];
  assert.deepEqual(deriveContainmentFromTurns(turns, AID).agentAddedGroupIds, []);
});

test("derive: a group-add for a DIFFERENT host is NOT recorded", () => {
  const turns = [
    turn([
      call("extras_host_group_add_members", { device_ids: [OTHER], group_id: "g1" }),
    ]),
  ];
  assert.deepEqual(deriveContainmentFromTurns(turns, AID).agentAddedGroupIds, []);
});

test("derive: scans EVERY turn (contain in turn 1, group-add in turn 3) and dedups", () => {
  const turns = [
    turn([call("extras_host_contain", { device_ids: [AID] })]),
    turn([call("falcon_search_detections", { foo: "bar" })]),
    turn([
      call("extras_host_group_add_members", { device_ids: [AID], group_id: "g1" }),
      call("extras_host_group_add_members", { device_ids: [AID], group_id: "g1" }),
      call("extras_host_group_add_members", { device_ids: [AID], group_id: "g2" }),
    ]),
  ];
  const d = deriveContainmentFromTurns(turns, AID);
  assert.equal(d.agentContained, true);
  assert.deepEqual([...d.agentAddedGroupIds].sort(), ["g1", "g2"]);
});

test("derive: malformed toolCallsJson is skipped (no throw)", () => {
  const turns = [
    { toolCallsJson: "not json {" },
    { toolCallsJson: JSON.stringify({ not: "an array" }) },
    turn([call("extras_host_contain", { device_ids: [AID] })]),
  ];
  assert.equal(deriveContainmentFromTurns(turns, AID).agentContained, true);
});

test("derive: a group-add with a non-string / empty group_id is ignored", () => {
  const turns = [
    turn([
      call("extras_host_group_add_members", { device_ids: [AID], group_id: "" }),
      call("extras_host_group_add_members", { device_ids: [AID], group_id: 123 }),
    ]),
  ];
  assert.deepEqual(deriveContainmentFromTurns(turns, AID).agentAddedGroupIds, []);
});

// ── parsePhase0Scope ─────────────────────────────────────────────────────────

test("parsePhase0: unions campaigns[].composite_ids", () => {
  const json = JSON.stringify({
    campaigns: [{ composite_ids: ["c1", "c2"] }, { composite_ids: ["c3"] }],
    unclustered: [],
  });
  const r = parsePhase0Scope(json);
  assert.equal(r.captured, true);
  assert.deepEqual(r.ids.sort(), ["c1", "c2", "c3"]);
});

test("parsePhase0: includes unclustered[].composite_id (ancestry-less originals)", () => {
  const json = JSON.stringify({
    campaigns: [{ composite_ids: ["c1"] }],
    unclustered: [{ composite_id: "u1" }, { composite_id: "u2" }],
  });
  const r = parsePhase0Scope(json);
  assert.equal(r.captured, true);
  assert.deepEqual(r.ids.sort(), ["c1", "u1", "u2"]);
});

test("parsePhase0: dedups across campaigns + unclustered", () => {
  const json = JSON.stringify({
    campaigns: [{ composite_ids: ["x", "x"] }],
    unclustered: [{ composite_id: "x" }, { composite_id: "y" }],
  });
  const r = parsePhase0Scope(json);
  assert.equal(r.captured, true);
  assert.deepEqual(r.ids.sort(), ["x", "y"]);
});

test("parsePhase0: clean kickoff (both arrays empty) → captured, no ids", () => {
  // The success shape ALWAYS carries both arrays; zero open detections means
  // both are []. This is a GENUINE clean kickoff — captured, nothing to
  // re-check — and the release gate proceeds (does NOT fail closed).
  const json = JSON.stringify({
    ok: true,
    campaigns: [],
    unclustered: [],
    total_open: 0,
  });
  const r = parsePhase0Scope(json);
  assert.equal(r.captured, true);
  assert.deepEqual(r.ids, []);
});

test("parsePhase0: capture failed / pending / non-scope payload → NOT captured", () => {
  // None of these carry BOTH scope arrays, so none is a real captured scope.
  // The release gate must fail CLOSED on each (never silently degrade to a
  // post-kickoff-only gate) — captured:false is how it tells them apart from a
  // genuine clean kickoff.
  for (const json of [
    JSON.stringify({ ok: false, error: "upstream 500" }), // scope call errored
    JSON.stringify({ ok: false, error: "scope_pending" }), // staged build
    JSON.stringify({ campaigns: [{ composite_ids: ["c1"] }] }), // only one array
    JSON.stringify({ unclustered: [{ composite_id: "u1" }] }), // only the other
    "not json {",
    "null",
    "5",
    '"just a string"',
    "{}",
  ]) {
    const r = parsePhase0Scope(json);
    assert.equal(r.captured, false, `expected not-captured for ${json}`);
    assert.deepEqual(r.ids, [], `expected no ids for ${json}`);
  }
});

test("parsePhase0: tolerates malformed entry shapes (composite_ids not array, missing id)", () => {
  const json = JSON.stringify({
    campaigns: [{ composite_ids: "oops" }, { composite_ids: ["ok"] }],
    unclustered: [{ nope: 1 }, { composite_id: "u" }],
  });
  const r = parsePhase0Scope(json);
  assert.equal(r.captured, true);
  assert.deepEqual(r.ids.sort(), ["ok", "u"]);
});


// ── contain must be CONFIRMED by its result, not just non-error ─────────────
// The retired sidecar reported an API failure as a normal {ok:false, errors} payload and
// eyas-mcp reports a partial failure as {partial_failure, succeeded_ids,
// failed_ids} — both with isError=false. Counting either as "this workflow
// contained the host" would let the F1 lift backstop release a containment the
// workflow never applied (e.g. a host already contained at kickoff).

test("derive: sidecar contain that FAILED ({ok:false}, isError=false) → NOT agentContained", () => {
  const excerpt = JSON.stringify({ ok: false, device_ids: [AID], errors: [{ code: 409, message: "already contained" }] });
  const d = deriveContainmentFromTurns([turn([call("extras_host_contain", { device_ids: [AID] }, { excerpt })])], AID);
  assert.equal(d.agentContained, false);
});

test("derive: native contain with the aid in succeeded_ids → agentContained (ids param)", () => {
  const d = deriveContainmentFromTurns([turn([call("falcon_contain_hosts", { ids: [AID] })])], AID);
  assert.equal(d.agentContained, true);
});

test("derive: native PARTIAL failure with the aid in failed_ids → NOT agentContained", () => {
  const excerpt = JSON.stringify({ partial_failure: true, succeeded_ids: [OTHER], failed_ids: [AID], errors: [] });
  const d = deriveContainmentFromTurns([turn([call("falcon_contain_hosts", { ids: [AID, OTHER] }, { excerpt })])], AID);
  assert.equal(d.agentContained, false);
});

test("derive: unparseable / truncated contain excerpt → NOT agentContained (safe failure)", () => {
  const d = deriveContainmentFromTurns([turn([call("extras_host_contain", { device_ids: [AID] }, { excerpt: '{"ok": tru' })])], AID);
  assert.equal(d.agentContained, false);
});

test("containResultConfirms: accepts the raw MCP block array shape", () => {
  const blocks = [{ type: "text", text: JSON.stringify({ succeeded_ids: [AID.toUpperCase()] }) }];
  assert.equal(containResultConfirms(blocks, AID), true);
});

test("extractDeviceIds / containTargetsAid: native `ids` param", () => {
  assert.deepEqual(extractDeviceIds({ ids: [AID] }), [AID]);
  assert.equal(containTargetsAid({ ids: [AID] }, AID), true);
});

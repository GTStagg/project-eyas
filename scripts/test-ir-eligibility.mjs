#!/usr/bin/env node
// Pure-function tests for IR button eligibility: lib/hosts/ir-eligibility.ts.
// This encodes the user-facing fixes: (1) /queue now applies the SAME platform
// gate as /hosts (a Linux host no longer gets a live IR chip), (2) an
// unconfigured environment shows an explicit "off" state (link to Config)
// rather than the chip vanishing, (3) sparse data stays lenient.
//
// Run as:  node scripts/test-ir-eligibility.mjs

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.IR_ELIG_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-ir-eligibility.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, IR_ELIG_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const { endpointIrEligibility, identityIrEligibility } = await import(
  path.join(root, "lib/hosts/ir-eligibility.ts")
);

const WIN = { device_id: "aid1", hostname: "WIN-1", platform_name: "Windows" };

test("endpoint: off when IR not configured (links operator to Config)", () => {
  const e = endpointIrEligibility(WIN, false);
  assert.equal(e.state, "off");
  assert.match(e.reason, /Config/);
});

test("endpoint: eligible for a Windows host when configured", () => {
  const e = endpointIrEligibility(WIN, true);
  assert.equal(e.state, "eligible");
  assert.ok(e.primer.includes("WIN-1") && e.primer.includes("aid1"));
});

test("endpoint: Linux host is ineligible (the /queue bug fix)", () => {
  const e = endpointIrEligibility(
    { device_id: "aid2", hostname: "LNX-1", platform_name: "Linux" },
    true,
  );
  assert.equal(e.state, "ineligible");
  assert.match(e.reason, /Windows/);
});

test("endpoint: explicit non-enabled RTR is ineligible", () => {
  const e = endpointIrEligibility(
    { ...WIN, rtr_state: "unsupported" },
    true,
  );
  assert.equal(e.state, "ineligible");
});

test("endpoint: sparse data (no platform/rtr) stays lenient → eligible", () => {
  const e = endpointIrEligibility({ device_id: "aid3", hostname: "HOST-3" }, true);
  assert.equal(e.state, "eligible");
});

test("endpoint: Domain Controller stays eligible but carries a blast-radius caution", () => {
  const e = endpointIrEligibility(
    { ...WIN, product_type_desc: "Domain Controller" },
    true,
  );
  assert.equal(e.state, "eligible");
  assert.ok(e.caution, "DC eligible result must carry a caution");
  assert.match(e.caution, /Domain Controller/);
});

test("endpoint: DC match is case-insensitive / substring-tolerant", () => {
  const e = endpointIrEligibility(
    { ...WIN, product_type_desc: "Windows Server (domain controller)" },
    true,
  );
  assert.equal(e.state, "eligible");
  assert.ok(e.caution);
});

test("endpoint: non-DC server has no caution (caution is absent, not empty)", () => {
  const e = endpointIrEligibility({ ...WIN, product_type_desc: "Server" }, true);
  assert.equal(e.state, "eligible");
  assert.equal(e.caution, undefined);
});

test("endpoint: workstation with no product_type_desc has no caution", () => {
  const e = endpointIrEligibility(WIN, true);
  assert.equal(e.state, "eligible");
  assert.equal(e.caution, undefined);
});

test("endpoint: missing device id/hostname is ineligible, not eligible", () => {
  assert.equal(endpointIrEligibility({ hostname: "H" }, true).state, "ineligible");
  assert.equal(endpointIrEligibility({ device_id: "a" }, true).state, "ineligible");
});

test("identity: eligible with a samAccountName", () => {
  const e = identityIrEligibility("jsmith", true);
  assert.equal(e.state, "eligible");
  assert.ok(e.primer.includes("jsmith"));
});

test("identity: off when not configured; ineligible when no sam", () => {
  assert.equal(identityIrEligibility("jsmith", false).state, "off");
  assert.equal(identityIrEligibility(undefined, true).state, "ineligible");
});

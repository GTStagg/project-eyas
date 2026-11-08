#!/usr/bin/env node
// Pure-function tests for the chat hand-off humanizer: components/primer.ts
// (describePrimer). This is the single source of operator-facing copy for every
// `?primer=…` hand-off, and it works by regex-matching the exact instruction
// templates the action buttons + route system prompts emit — so a drifted
// template silently falls back to raw text. These tests pin the real templates.
//
// Run as:  node scripts/test-primer.mjs
//
// Mirrors scripts/test-knowledge.mjs: re-spawn under tsx --test so the .ts
// source loads without a build step.

import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.PRIMER_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-primer.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, PRIMER_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

// ───────────────────────────────────────────────────────── child (tsx --test)

import { test } from "node:test";
import assert from "node:assert/strict";

const { describePrimer } = await import(path.join(root, "components/primer.ts"));

// Each case is the VERBATIM instruction a sender emits (see the senders in
// components/*.tsx and app/api/*/route.ts), paired with the operator-facing
// title + kind we expect. Keep these instructions in sync with the senders.
const CASES = [
  {
    name: "endpoint IR",
    instruction:
      "Run the agentic IR workflow on host `WIN-ACCT-01` (AID `abc123def456`). Load the playbook with extras_ir_workflow_playbook and proceed.",
    kind: "ir",
    titleIncludes: "Run guided incident response on WIN-ACCT-01",
  },
  {
    name: "identity IR",
    instruction:
      "Run the agentic identity IR workflow on user `jsmith`. Load the playbook with extras_identity_ir_workflow_playbook (sam_account_name=`jsmith`) and proceed. Phase 1's endpoint cascade will run the host IR playbook on each machine this user has been logged into recently.",
    kind: "ir",
    titleIncludes: "identity incident response for jsmith",
  },
  {
    name: "host triage (multi)",
    instruction:
      "Triage 7 open detections on host `WIN-DB-02`:\n- Foo · High · Execution · 3h ago",
    kind: "triage",
    titleIncludes: "Triage 7 open detections on WIN-DB-02",
  },
  {
    name: "single detection triage",
    instruction: "Triage detection [Malware](https://x) on host `WIN-9`. Tactic: Execution.",
    kind: "triage",
    titleIncludes: "Triage a detection on WIN-9",
  },
  {
    name: "remediate (route link)",
    instruction:
      "Remediate detection on host WIN-FOO (AID abc123): use cleanup script id host-delete-file with params path=C:\\Temp\\foo.exe. Run dry_run first.",
    kind: "triage",
    titleIncludes: "Remediate a detection on WIN-FOO",
  },
  {
    name: "reconstruct campaign",
    instruction:
      'Reconstruct the cross-host campaign anchored on the binary SHA-256 `deadbeef`. Affected hosts: WIN-1, WIN-2, WIN-3. AIDs: ["a","b","c"]. Lead composite_ids: ["x"].',
    kind: "reconstruct",
    titleIncludes: "across 3 hosts",
  },
  {
    name: "tune",
    instruction:
      'Draft a tuning recommendation for rule `Suspicious PowerShell`. Evidence: 9/10 closed as FP (90%), 4 hosts, max severity High. Sample composite_ids: ["x"].',
    kind: "tune",
    titleIncludes: "Draft a tuning recommendation for Suspicious PowerShell",
  },
  {
    name: "intel active hit",
    instruction:
      "Investigate the active intel hit on indicator `1.2.3.4` (ipv4). 5 fires across hosts: WIN-1. Actors: FANCY BEAR.",
    kind: "intel",
    titleIncludes: "Investigate intel hit on 1.2.3.4",
  },
  {
    name: "intel lookup",
    instruction: "Look up indicator `evil.com` (domain) in Falcon Intel. Actors: X.",
    kind: "intel",
    titleIncludes: "Look up evil.com in Falcon Intelligence",
  },
  {
    name: "adversary",
    instruction:
      "Tell me about adversary `WIZARD SPIDER` (Falcon ID abc). What detections in this tenant are attributed to them? Use falcon_get_actor_details.",
    kind: "intel",
    titleIncludes: "Profile adversary WIZARD SPIDER",
  },
  {
    name: "patch (single host)",
    instruction:
      "Patch Google Chrome via the curated RTR script library on 1 host: [aid1].",
    kind: "patch",
    titleIncludes: "Patch Google Chrome on 1 host",
  },
  {
    name: "patch (multi host plural)",
    instruction:
      "Patch Mozilla Firefox via the curated RTR script library on 4 hosts: [a,b,c,d].",
    kind: "patch",
    titleIncludes: "on 4 hosts",
  },
  {
    // Regression: a truncated host list must still match (not fall through to
    // raw text, which would leak the embedded AID array + tool jargon).
    name: "patch (truncated host list)",
    instruction:
      'Patch Google Chrome via the curated RTR script library on 25 (truncated from 40) hosts: ["a","b","c"].',
    kind: "patch",
    titleIncludes: "on 25 hosts",
  },
  {
    name: "generic installer (single host, no hash)",
    instruction:
      'Install Notepad++ via the generic Windows installer from https://example.com/npp.x64.exe on 1 host: ["aid1"].',
    kind: "patch",
    titleIncludes: "Install Notepad++ on 1 host",
  },
  {
    // Truncated host clause + a SHA-256 pin clause must both be absorbed (the
    // URL, AID array, and hash must never reach the humanized copy).
    name: "generic installer (truncated + hash pin)",
    instruction:
      'Install 7-Zip via the generic Windows installer from https://www.7-zip.org/a/7z2400-x64.msi on 25 (truncated from 40) hosts: ["a","b","c"]. Verify the download against SHA-256 deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.',
    kind: "patch",
    titleIncludes: "Install 7-Zip on 25 hosts",
  },
  {
    name: "save patch profile",
    instruction:
      "Save a reusable patch profile for 7-Zip from vendor URL https://www.7-zip.org/a/7z2400-x64.msi. Pin SHA-256 deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef.",
    kind: "provision",
    titleIncludes: "Save a reusable patch source for 7-Zip",
  },
  {
    name: "triage hash (with host)",
    instruction:
      "Triage hash `deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef` (type sha256) from detection ldt:abc:123 on host `WIN-9`: Suspicious binary.",
    kind: "triage",
    titleIncludes: "threat intelligence on WIN-9",
  },
  {
    name: "triage hash (no host)",
    instruction:
      "Triage hash `abc123` (type md5) from detection ldt:abc:123: Suspicious binary.",
    kind: "triage",
    titleIncludes: "Check a file hash against threat intelligence",
  },
  {
    name: "CVE triage",
    instruction:
      "Help me triage CVE-2024-1234 on host WIN-1. Affected product: OpenSSL. Severity Critical.",
    kind: "triage",
    titleIncludes: "Triage CVE-2024-1234",
  },
  {
    name: "case",
    instruction: "Triage Falcon case `INC-42` (case id `abc`). Load it with falcon_get_cases and proceed.",
    kind: "case",
    titleIncludes: "Triage Falcon case INC-42",
  },
  {
    name: "workflow failure",
    instruction:
      "Investigate Fusion workflow execution `exec-1` from `Nightly Sync` (failed at 2026-06-01). Call extras_workflows_execution_result.",
    kind: "workflow",
    titleIncludes: 'failed automation "Nightly Sync"',
  },
  {
    name: "data protection provision",
    instruction:
      "Provision Data Protection coverage. Load the playbook with extras_data_protection_provision_playbook and proceed — first ask me what sensitive data to protect.",
    kind: "provision",
    titleIncludes: "Set up Data Protection coverage",
  },
  {
    name: "IR setup create",
    instruction:
      'Create the IR quarantine host group on this tenant. Call extras_create_quarantine_host_group with name="Project Eyas - IR Quarantine". The new group id is saved to the active environment automatically.',
    kind: "provision",
    titleIncludes: "incident-response quarantine group",
  },
  {
    name: "Shadow-AI setup create",
    instruction:
      'Create the Shadow-AI Banned host group on this tenant. Call extras_create_shadow_ai_banned_host_group with name="Project Eyas - Shadow-AI Banned".',
    kind: "provision",
    titleIncludes: "Shadow-AI blocked host group",
  },
  {
    name: "Shadow-AI ban-and-clean workflow",
    instruction:
      "Run the agentic Shadow-AI ban-and-clean workflow on host `WIN-ACCT-01` (AID `abc123def456`). Load the playbook with extras_shadow_ai_workflow_playbook and proceed.",
    kind: "workflow",
    titleIncludes: "Ban and clean unsanctioned AI tools on WIN-ACCT-01",
  },
  {
    name: "Shadow-AI remediation plan",
    instruction:
      "Build a Shadow-AI remediation plan for host `WIN-DB-02` (AID `def456abc123`). Posture verdict: unsanctioned_in_use. Apps: ChatGPT Desktop (unsanctioned).",
    kind: "ask",
    titleIncludes: "Plan Shadow-AI remediation for WIN-DB-02",
  },
  {
    name: "prevention posture gap (dashboard)",
    instruction:
      "Review the 3 detect-only prevention policies and recommend which should move to blocking.",
    kind: "tune",
    titleIncludes: "Review 3 detect-only prevention policies",
  },
  {
    name: "ask host",
    instruction:
      "Tell me about host `WIN-ACCT-01` (Windows · Windows 11, last seen 2h ago, status normal). What's its detection history?",
    kind: "ask",
    titleIncludes: "Ask about host WIN-ACCT-01",
  },
];

for (const c of CASES) {
  test(`describePrimer — ${c.name}`, () => {
    const a = describePrimer(c.instruction);
    assert.equal(a.matched, true, `expected ${c.name} to match a template`);
    assert.equal(a.kind, c.kind, `kind for ${c.name}`);
    assert.ok(
      a.title.includes(c.titleIncludes),
      `title for ${c.name} should include "${c.titleIncludes}" — got "${a.title}"`,
    );
    // The precise instruction is always preserved verbatim (trimmed).
    assert.equal(a.instruction, c.instruction.trim());
    // No leaked jargon in any operator-facing field.
    const surface = `${a.title} ${a.subtitle ?? ""} ${a.description}`;
    assert.ok(
      !/extras_|falcon_|composite_id|sam_account_name|host_group_id|AID `/.test(surface),
      `operator copy for ${c.name} leaked jargon: "${surface}"`,
    );
  });
}

test("describePrimer — free text falls through to matched=false (verbatim)", () => {
  const a = describePrimer("What hosts have a critical vuln and a recent detection?");
  assert.equal(a.matched, false);
  assert.equal(a.instruction, "What hosts have a critical vuln and a recent detection?");
});

test("describePrimer — unrecognized long text clips a title but stays unmatched", () => {
  const long = "Do a thing ".repeat(40);
  const a = describePrimer(long);
  assert.equal(a.matched, false);
  assert.ok(a.title.length <= 100);
});

test("describePrimer — endpoint IR title survives no-backtick AID form", () => {
  const a = describePrimer("Run the agentic IR workflow on host HOST7 (AID deadbeef). Load the playbook.");
  assert.equal(a.matched, true);
  assert.equal(a.kind, "ir");
  assert.ok(a.title.includes("HOST7"));
});

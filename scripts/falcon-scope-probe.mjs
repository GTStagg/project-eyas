#!/usr/bin/env node
// Live Falcon API posture probe.
//
// Mints an OAuth token from the ACTIVE environment's stored credentials
// (data/eyas.db is the source of truth — not .env), then hits one
// representative read endpoint per API scope and classifies the result:
//
//   403            -> DENIED   (CrowdStrike's authoritative "scope not granted")
//   2xx            -> GRANTED
//   400/405/429/500-> GRANTED  (auth passed; only the request shape was off)
//   404            -> AMBIGUOUS (endpoint path may be wrong on our side)
//   401            -> AUTH ERROR (token problem, not a scope signal)
//
// Purpose: reconcile components/ScopeChecklist.tsx against what the tenant
// actually grants, so console-name / read-write drift gets caught empirically
// instead of by hand. Read-only — issues only GETs (one POST for IDP GraphQL
// introspection), never writes.
//
// Usage:
//   node scripts/falcon-scope-probe.mjs            # active env from DB
//   node scripts/falcon-scope-probe.mjs --json     # machine-readable
//   FALCON_CLIENT_ID=.. FALCON_CLIENT_SECRET=.. FALCON_BASE_URL=.. \
//     node scripts/falcon-scope-probe.mjs --env     # probe raw env creds instead

import { readFileSync } from "node:fs";
import { hkdfSync, createDecipheriv } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Database from "better-sqlite3";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const JSON_OUT = process.argv.includes("--json");
const USE_ENV = process.argv.includes("--env");

// --- .env / .env.local parse (only for AUTH_SESSION_SECRET + optional raw creds) ---
// Reads .env first, then overlays .env.local (Next.js precedence: .env.local wins).
function loadEnvLocal() {
  const out = {};
  for (const file of [".env", ".env.local"]) {
    try {
      const raw = readFileSync(path.join(ROOT, file), "utf8");
      for (const line of raw.split("\n")) {
        const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
        if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, "");
      }
    } catch {
      /* fine */
    }
  }
  return out;
}

// --- replicate lib/db/crypto.ts decryptColumn ---
function masterKey(secret) {
  return Buffer.from(
    hkdfSync(
      "sha256",
      Buffer.from(secret, "utf8"),
      Buffer.from("falcon-eyas-db-v1"),
      Buffer.from("column-encryption-key"),
      32,
    ),
  );
}
function decryptColumn(blob, aad, secret) {
  if (!blob || blob.length < 28) return null;
  const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
  try {
    const nonce = buf.subarray(0, 12);
    const tag = buf.subarray(buf.length - 16);
    const ct = buf.subarray(12, buf.length - 16);
    const d = createDecipheriv("aes-256-gcm", masterKey(secret), nonce);
    d.setAAD(Buffer.from(aad, "utf8"));
    d.setAuthTag(tag);
    return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
  } catch (e) {
    return null;
  }
}

const PROBE_ALL = process.argv.includes("--all");

function resolveCreds() {
  const envLocal = loadEnvLocal();
  if (USE_ENV) {
    return [
      {
        label: "raw env creds",
        clientId: process.env.FALCON_CLIENT_ID || envLocal.FALCON_CLIENT_ID,
        clientSecret: process.env.FALCON_CLIENT_SECRET || envLocal.FALCON_CLIENT_SECRET,
        baseUrl: (process.env.FALCON_BASE_URL || envLocal.FALCON_BASE_URL || "https://api.crowdstrike.com").replace(/\/$/, ""),
      },
    ];
  }
  const secret = process.env.AUTH_SESSION_SECRET || envLocal.AUTH_SESSION_SECRET;
  if (!secret) throw new Error("AUTH_SESSION_SECRET not found in env, .env, or .env.local");
  const db = new Database(path.join(ROOT, "data", "eyas.db"), { readonly: true });
  const activeId = db.prepare("SELECT active_env_id FROM settings LIMIT 1").get()?.active_env_id;
  const rows = PROBE_ALL
    ? db.prepare("SELECT * FROM environments").all()
    : [
        activeId
          ? db.prepare("SELECT * FROM environments WHERE id = ?").get(activeId)
          : db.prepare("SELECT * FROM environments LIMIT 1").get(),
      ].filter(Boolean);
  if (!rows.length) throw new Error("no environment row in DB");
  return rows.map((row) => ({
    label: `env "${row.name}"${row.id === activeId ? " [ACTIVE]" : ""} (id=${row.id})`,
    clientId: decryptColumn(row.falcon_client_id_enc, `env.${row.id}.falcon_client_id`, secret),
    clientSecret: decryptColumn(row.falcon_client_secret_enc, `env.${row.id}.falcon_client_secret`, secret),
    baseUrl: (row.falcon_base_url || "https://api.crowdstrike.com").replace(/\/$/, ""),
  }));
}

// --- probe map: scope label -> representative read endpoint ---
// conf: "high" = path is stable/known; "low" = path uncertain, a 404 here is
// likely our wrong path rather than a scope signal.
const PROBES = [
  // tier, console scope, method, path, confidence
  ["core", "Alerts", "GET", "/alerts/queries/alerts/v2?limit=1", "high"],
  ["core", "Detections (legacy)", "GET", "/detects/queries/detects/v1?limit=1", "high"],
  ["core", "Hosts", "GET", "/devices/queries/devices/v1?limit=1", "high"],
  ["core", "Host Group", "GET", "/devices/queries/host-groups/v1?limit=1", "high"],
  ["core", "Real Time Response", "GET", "/real-time-response/queries/sessions/v1?limit=1", "high"],
  ["core", "Real Time Response (Admin)", "GET", "/real-time-response/entities/scripts/v1", "low"],
  ["core", "Vulnerabilities (Spotlight)", "GET", "/spotlight/queries/vulnerabilities/v1?limit=1", "high"],
  ["core", "Indicators (Custom IOC)", "GET", "/iocs/queries/indicators/v1?limit=1", "high"],
  ["core", "Custom IOA Rules", "GET", "/ioarules/queries/rule-groups/v1?limit=1", "high"],
  ["core", "Firewall Management", "GET", "/fwmgr/queries/rule-groups/v1?limit=1", "high"],
  ["core", "Sensor Usage", "GET", "/billing-dashboards-usage/aggregates/daily/v1", "low"],
  ["core", "Scheduled Reports", "GET", "/reports/queries/report-executions/v1?limit=1", "low"],

  // --- Discover (the reason we're here) ---
  ["discover", "Discover · Applications", "GET", "/discover/queries/applications/v1?limit=1", "high"],
  ["discover", "Discover · Hosts/Assets", "GET", "/discover/queries/hosts/v1?limit=1", "high"],
  ["discover", "Discover · Accounts", "GET", "/discover/queries/accounts/v1?limit=1", "high"],
  ["discover", "Discover · Logins", "GET", "/discover/queries/logins/v1?limit=1", "high"],

  // --- Cases (falcon-mcp 0.10.0) ---
  ["cases", "Cases", "GET", "/cases/queries/cases/v1?limit=1", "low"],

  // --- falcon-mcp 0.11.0 ---
  ["falcon011", "Quarantine", "GET", "/quarantine/queries/quarantined-files/v1?limit=1", "low"],
  ["falcon011", "Correlation Rules", "GET", "/correlation-rules/queries/rules/v1?limit=1", "low"],
  ["falcon011", "Data Protection", "GET", "/data-protection/queries/classifications/v2?limit=1", "high"],

  // --- Intel + hunting ---
  ["intel", "Falcon Intelligence: Actors", "GET", "/intel/queries/actors/v1?limit=1", "high"],
  ["intel", "Falcon Intelligence: Indicators", "GET", "/intel/queries/indicators/v1?limit=1", "high"],
  ["intel", "Monitoring Rules (Recon)", "GET", "/recon/queries/rules/v1?limit=1", "high"],
  ["intel", "MalQuery", "GET", "/malquery/aggregates/quotas/v1", "low"],
  ["intel", "Threat Graph", "GET", "/threatgraph/queries/edge-types/v1", "high"],
  ["intel", "Workflow", "GET", "/workflows/definitions/combined/v1?limit=1", "low"],

  // --- Identity Protection (GraphQL) ---
  ["identity", "Identity Protection (GraphQL)", "POST", "/identity-protection/combined/graphql/v1", "low"],

  // --- Cloud + SaaS ---
  ["cloud", "Cloud Security API Assets", "GET", "/cloud-security-assets/queries/resources/v1?limit=1", "low"],
  ["cloud", "Cloud Security API Detections", "GET", "/cloud-security-evaluations/queries/ioms/v1?limit=1", "low"],
  ["cloud", "Falcon Container Image", "GET", "/container-security/aggregates/images/count/v1", "low"],
  ["cloud", "Kubernetes Protection", "GET", "/container-security/aggregates/clusters/count/v1", "low"],
  ["cloud", "Falcon Shield (SaaS Security)", "GET", "/saas-security/entities/supported-saas/v3", "low"],
];

function classify(status) {
  if (status === 403) return "DENIED";
  if (status >= 200 && status < 300) return "GRANTED";
  if (status === 401) return "AUTH-ERR";
  if (status === 404) return "AMBIGUOUS";
  if (status === 400 || status === 405 || status === 429 || status === 500) return "GRANTED*";
  return `HTTP ${status}`;
}

async function probeTenant(creds) {
  if (!creds.clientId || !creds.clientSecret) {
    throw new Error(`could not resolve creds for ${creds.label} (decrypt returned null — wrong AUTH_SESSION_SECRET?)`);
  }
  const tokRes = await fetch(`${creds.baseUrl}/oauth2/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ client_id: creds.clientId, client_secret: creds.clientSecret }),
  });
  if (!tokRes.ok) throw new Error(`OAuth failed: ${tokRes.status} ${await tokRes.text()}`);
  const token = (await tokRes.json()).access_token;
  const auth = { Authorization: `Bearer ${token}` };

  const results = [];
  for (const [tier, scope, method, ep, conf] of PROBES) {
    let status = 0;
    try {
      const opts = { method, headers: { ...auth }, signal: AbortSignal.timeout(15000) };
      if (method === "POST") {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify({ query: "{__typename}" });
      }
      const r = await fetch(`${creds.baseUrl}${ep}`, opts);
      status = r.status;
    } catch (e) {
      status = -1;
    }
    results.push({ tier, scope, method, ep, conf, status, verdict: status === -1 ? "TIMEOUT" : classify(status) });
  }
  return results;
}

function printReport(label, baseUrl, results) {
  console.log(`\nFalcon API posture — probed: ${label}`);
  console.log(`Base URL: ${baseUrl}\n`);
  const pad = (s, n) => String(s).padEnd(n);
  console.log(pad("SCOPE", 34), pad("VERDICT", 11), pad("HTTP", 6), "ENDPOINT");
  console.log("-".repeat(110));
  let lastTier = null;
  for (const r of results) {
    if (r.tier !== lastTier) {
      console.log(`\n[${r.tier}]`);
      lastTier = r.tier;
    }
    const flag = r.conf === "low" && (r.verdict === "AMBIGUOUS" || r.verdict.startsWith("HTTP")) ? " ⚠path?" : "";
    console.log(pad(r.scope, 34), pad(r.verdict, 11), pad(r.status, 6), r.ep + flag);
  }
  const denied = results.filter((r) => r.verdict === "DENIED");
  console.log("\n" + "=".repeat(110));
  console.log(`DENIED (scope not granted): ${denied.length ? denied.map((r) => r.scope).join(", ") : "none"}`);
  console.log("⚠path? = low-confidence endpoint path; a 404/4xx here may be our wrong path, not a scope denial.");
}

async function main() {
  const tenants = resolveCreds();
  const all = [];
  for (const creds of tenants) {
    const results = await probeTenant(creds);
    all.push({ probed: creds.label, baseUrl: creds.baseUrl, results });
    if (!JSON_OUT) printReport(creds.label, creds.baseUrl, results);
  }
  if (JSON_OUT) console.log(JSON.stringify(all.length === 1 ? all[0] : all, null, 2));
}

main().catch((e) => {
  console.error("probe failed:", e.message);
  process.exit(1);
});

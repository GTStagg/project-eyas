#!/usr/bin/env node
// cost-summary — segment the cost_log table in data/eyas.db by surface +
// model, print USD spend with % share, cache hit %, and ⌀ iterations.
// Pricing table mirrors lib/cost/pricing.ts; keep in sync when Anthropic
// changes prices. (Cost moved from a JSONL file to SQLite — see lib/cost/log.ts.)

import Database from "better-sqlite3";
import path from "node:path";

// cacheWrite priced at the 1h-TTL rate (2x input), mirroring lib/cost/pricing.ts
// — the tool catalog + chat system prompt are cached at ttl=1h. Keep in sync.
const SONNET = { input: 3.0, output: 15.0, cacheWrite: 6.0, cacheRead: 0.3 };
const OPUS = { input: 15.0, output: 75.0, cacheWrite: 30.0, cacheRead: 1.5 };
const HAIKU = { input: 1.0, output: 5.0, cacheWrite: 2.0, cacheRead: 0.1 };

const PRICING = [
  { prefix: "claude-opus-4", p: OPUS },
  { prefix: "claude-sonnet-4", p: SONNET },
  { prefix: "claude-haiku-4", p: HAIKU },
  { prefix: "claude-3-5-sonnet", p: SONNET },
  { prefix: "claude-3-5-haiku", p: HAIKU },
  { prefix: "claude-3-opus", p: OPUS },
];

function priceFor(model) {
  if (!model) return SONNET;
  for (const { prefix, p } of PRICING) if (model.startsWith(prefix)) return p;
  if (model.includes("opus")) return OPUS;
  if (model.includes("haiku")) return HAIKU;
  return SONNET;
}

function costOf(usage, p) {
  const i = usage.input_tokens ?? 0;
  const o = usage.output_tokens ?? 0;
  const cw = usage.cache_creation_input_tokens ?? 0;
  const cr = usage.cache_read_input_tokens ?? 0;
  return {
    total: ((i * p.input + o * p.output + cw * p.cacheWrite + cr * p.cacheRead) / 1_000_000),
    input: (i * p.input) / 1_000_000,
    output: (o * p.output) / 1_000_000,
    cacheWrite: (cw * p.cacheWrite) / 1_000_000,
    cacheRead: (cr * p.cacheRead) / 1_000_000,
    inputTok: i, outputTok: o, cwTok: cw, crTok: cr,
  };
}

const args = process.argv.slice(2);
const opt = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : null; };

const dataDir = process.env.FALCON_DATA_DIR ?? path.join(process.cwd(), "data");
const dbPath = path.join(dataDir, "eyas.db");

const sinceArg = opt("--since");
function parseSince(s) {
  if (!s) return null;
  const rel = /^(\d+)([smhd])$/.exec(s);
  if (rel) {
    const n = parseInt(rel[1], 10);
    const mult = rel[2] === "d" ? 86400000 : rel[2] === "h" ? 3600000 : rel[2] === "m" ? 60000 : 1000;
    return Date.now() - n * mult;
  }
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}
const sinceMs = parseSince(sinceArg);

let db;
try { db = new Database(dbPath, { readonly: true, fileMustExist: true }); }
catch {
  console.error(`No database at ${dbPath} — nothing to summarize.`);
  process.exit(0);
}

// ts is an ISO-8601 string, so a lexical >= comparison is an indexed range
// scan over cost_log_ts_idx.
const sinceIso = sinceMs != null ? new Date(sinceMs).toISOString() : null;
const dbRows = sinceIso
  ? db.prepare(
      "SELECT ts, model, surface, iterations, usage_json FROM cost_log WHERE ts >= ? ORDER BY ts",
    ).all(sinceIso)
  : db.prepare(
      "SELECT ts, model, surface, iterations, usage_json FROM cost_log ORDER BY ts",
    ).all();

const rows = [];
let parseFailures = 0;
for (const r of dbRows) {
  let usage;
  try { usage = JSON.parse(r.usage_json); } catch { parseFailures++; continue; }
  rows.push({ ts: r.ts, model: r.model, surface: r.surface, iterations: r.iterations ?? 0, usage });
}

let firstTs = null, lastTs = null;
const filtered = rows.filter((r) => {
  const t = r.ts ? Date.parse(r.ts) : null;
  if (!t) return false;
  if (firstTs == null || t < firstTs) firstTs = t;
  if (lastTs == null || t > lastTs) lastTs = t;
  return true;
});

if (filtered.length === 0) {
  console.error("No log entries in window.");
  process.exit(0);
}

// Aggregate.
const bySurface = new Map();
const byModel = new Map();
const totals = { total: 0, input: 0, output: 0, cacheWrite: 0, cacheRead: 0,
                 inputTok: 0, outputTok: 0, cwTok: 0, crTok: 0, calls: 0, iter: 0 };

function bucket(map, key) {
  if (!map.has(key)) map.set(key, { total: 0, input: 0, output: 0, cacheWrite: 0, cacheRead: 0,
                                     inputTok: 0, outputTok: 0, cwTok: 0, crTok: 0, calls: 0, iter: 0 });
  return map.get(key);
}

for (const r of filtered) {
  const p = priceFor(r.model);
  const c = costOf(r.usage ?? {}, p);
  const surface = r.surface || "(unknown)";
  const model = r.model || "(unknown)";
  for (const acc of [bySurface.get(surface) ?? bucket(bySurface, surface),
                     byModel.get(model) ?? bucket(byModel, model),
                     totals]) {
    acc.total += c.total;
    acc.input += c.input;
    acc.output += c.output;
    acc.cacheWrite += c.cacheWrite;
    acc.cacheRead += c.cacheRead;
    acc.inputTok += c.inputTok;
    acc.outputTok += c.outputTok;
    acc.cwTok += c.cwTok;
    acc.crTok += c.crTok;
    acc.calls += 1;
    acc.iter += r.iterations ?? 0;
  }
}

// Helpers.
const usd = (n) => `$${n.toFixed(2).padStart(7)}`;
const pct = (n, d) => d > 0 ? ((n / d) * 100).toFixed(1).padStart(5) : "  0.0";
const fmtIso = (ms) => new Date(ms).toISOString().slice(0, 10);
const cacheHitPctOf = (acc) => {
  const denom = acc.crTok + acc.cwTok + acc.inputTok;
  return denom > 0 ? (acc.crTok / denom) * 100 : 0;
};

const BOLD = "\x1b[1m", DIM = "\x1b[2m", NC = "\x1b[0m";

console.log(`${BOLD}Cost summary${NC} · ${fmtIso(firstTs)} → ${fmtIso(lastTs)} · ${filtered.length.toLocaleString()} calls`);
if (parseFailures > 0) console.log(`${DIM}(skipped ${parseFailures} unparseable rows)${NC}`);
console.log();

// By surface, sorted by spend desc.
const surfaces = [...bySurface.entries()].sort((a, b) => b[1].total - a[1].total);
console.log(`${BOLD}By surface${NC}`);
console.log("  " + "name".padEnd(28) + "spend".padStart(8) + "  %".padStart(6) +
            "calls".padStart(8) + "⌀ iter".padStart(9) + "cache hit %".padStart(14));
for (const [name, acc] of surfaces) {
  const iterAvg = acc.calls > 0 ? (acc.iter / acc.calls) : 0;
  console.log(
    "  " + name.padEnd(28) +
    usd(acc.total) + pct(acc.total, totals.total) +
    String(acc.calls).padStart(8) +
    iterAvg.toFixed(1).padStart(9) +
    cacheHitPctOf(acc).toFixed(1).padStart(13)
  );
}
console.log("  " + "TOTAL".padEnd(28) + usd(totals.total) + " 100.0".padStart(6) +
            String(totals.calls).padStart(8));
console.log();

// By model.
console.log(`${BOLD}By model${NC}`);
const models = [...byModel.entries()].sort((a, b) => b[1].total - a[1].total);
for (const [name, acc] of models) {
  console.log("  " + name.padEnd(28) + usd(acc.total) + " " + pct(acc.total, totals.total).trimStart() + "%");
}
console.log();

// Cost shape.
console.log(`${BOLD}Cost shape${NC}`);
const shape = [
  ["output           (writing answers)", totals.output],
  ["cache write      (first turn / tools-block change)", totals.cacheWrite],
  ["cache read       (cached prefix replay)", totals.cacheRead],
  ["input (uncached) (fresh tokens, no cache)", totals.input],
];
for (const [label, n] of shape) {
  console.log("  " + label.padEnd(50) + usd(n) + pct(n, totals.total) + "%");
}
console.log();

console.log(`${BOLD}Headline ratios${NC}`);
const cacheHit = cacheHitPctOf(totals);
console.log(`  output / total           ${(totals.total > 0 ? (totals.output / totals.total) * 100 : 0).toFixed(1).padStart(5)}%`);
console.log(`  cache read / total       ${(totals.total > 0 ? (totals.cacheRead / totals.total) * 100 : 0).toFixed(1).padStart(5)}%`);
console.log(`  cache hit %              ${cacheHit.toFixed(1).padStart(5)}%   ${DIM}(target ≥ 80; < 60 = cache rebuild churn)${NC}`);

// Soft-flag headline drift.
const chatRow = bySurface.get("chat");
if (chatRow) {
  const chatPct = (chatRow.total / totals.total) * 100;
  if (chatPct > 80) console.log(`  ${DIM}chat % is ${chatPct.toFixed(1)}% — well above 68% baseline; check for prompt drift${NC}`);
  if (chatPct < 50) console.log(`  ${DIM}chat % is ${chatPct.toFixed(1)}% — well below 68% baseline; chat usage dropped${NC}`);
}
if (cacheHit < 60) console.log(`  ${DIM}cache hit % below 60 — prompt prefix likely changing call-to-call${NC}`);

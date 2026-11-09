#!/usr/bin/env node
// Vendors npm packages that a restricted package mirror does not carry
// (zero mirrored versions, or our pinned range is newer than the mirror has)
// into vendor/npm-offline/*.tgz, so `npm ci` resolves offline against the
// reachable mirror + these local tarballs.
//
// Source is jsDelivr, which serves the PUBLISHED package contents (the built
// dist/, fonts, etc.) — not the GitHub source — so no build/prepare step runs.
// Files are fetched in parallel and packed under a `package/` prefix (the npm
// tarball layout) so no lifecycle script (e.g. aidr's `prepare: pnpm build`)
// fires.
//
//   node scripts/vendor-offline-deps.mjs                 # every package below
//   node scripts/vendor-offline-deps.mjs lucide-react    # just the named ones
//
// Re-packing changes a tarball's bytes (and its lockfile integrity hash), so
// only re-vendor the packages you're bumping. Then point package.json at
// `file:vendor/npm-offline/<tarball>` and run `npm install` to refresh the
// lockfile.
import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const PACKAGES = [
  { name: "geist", version: "1.7.0" },
  { name: "iron-session", version: "8.0.4" },
  { name: "@anthropic-ai/sdk", version: "0.69.0" },
  { name: "@crowdstrike/aidr", version: "1.2.1" },
  // Newer than some package mirrors serve: mammoth 1.11+ carries the
  // CVE-2025-11849 path-traversal fix.
  { name: "mammoth", version: "1.13.0" },
  { name: "@modelcontextprotocol/sdk", version: "1.32.2" },
  { name: "drizzle-orm", version: "0.45.4" },
  { name: "drizzle-kit", version: "0.31.11" },
  { name: "lucide-react", version: "0.577.0" },
];

const REPO_ROOT = path.resolve(import.meta.dirname, "..");
const OUT_DIR = path.join(REPO_ROOT, "vendor", "npm-offline");
const CONCURRENCY = 32;

async function fetchRetry(url) {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url).catch(() => null);
    if (res?.ok) return res;
    if (attempt >= 4) throw new Error(`GET ${url} -> ${res?.status ?? "network error"}`);
    await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
  }
}

async function vendorOne({ name, version }) {
  const spec = `${name}@${version}`;
  const listing = await (await fetchRetry(`https://data.jsdelivr.com/v1/package/npm/${spec}/flat`)).json();
  const files = listing.files.map((f) => f.name);
  const work = mkdtempSync(path.join(tmpdir(), "vendor-"));
  let next = 0;
  const worker = async () => {
    while (next < files.length) {
      const f = files[next++];
      const res = await fetchRetry(`https://cdn.jsdelivr.net/npm/${spec}${f}`);
      const dest = path.join(work, "package", f);
      mkdirSync(path.dirname(dest), { recursive: true });
      writeFileSync(dest, Buffer.from(await res.arrayBuffer()));
    }
  };
  await Promise.all(Array.from({ length: CONCURRENCY }, worker));
  const tarName = `${name.replace("/", "-").replace("@", "")}-${version}.tgz`;
  execFileSync("tar", ["-czf", path.join(OUT_DIR, tarName), "-C", work, "package"]);
  rmSync(work, { recursive: true, force: true });
  console.log(`  ${spec} ... ${files.length} files -> vendor/npm-offline/${tarName}`);
}

const wanted = process.argv.slice(2);
const targets = wanted.length ? PACKAGES.filter((p) => wanted.includes(p.name)) : PACKAGES;
if (wanted.length && targets.length !== wanted.length) {
  console.error(`Unknown package(s): ${wanted.filter((w) => !PACKAGES.some((p) => p.name === w)).join(", ")}`);
  process.exit(1);
}
mkdirSync(OUT_DIR, { recursive: true });
console.log(`Vendoring ${targets.length} offline tarball(s) from jsDelivr:`);
for (const p of targets) await vendorOne(p);

#!/usr/bin/env node
// Vendors npm packages that a restricted package mirror does not carry
// (zero mirrored versions, or our pinned range is newer than the mirror has)
// into vendor/npm-offline/*.tgz, so `npm ci` resolves offline against the
// reachable mirror + these local tarballs.
//
// Source is unpkg, which serves the PUBLISHED package contents (the built
// dist/, fonts, etc.) — not the GitHub source — so no build/prepare step runs.
// We assemble the tarball manually under a `package/` prefix (the npm tarball
// layout) so no lifecycle script (e.g. aidr's `prepare: pnpm build`) fires.
//
// Re-run after bumping any of these pins, then `npm install` to refresh the
// lockfile. Network egress here goes through the corporate TLS-intercepting
// proxy; curl uses -k for that reason (the proxy is the MITM either way).
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

const PACKAGES = [
  { name: "geist", version: "1.7.0" },
  { name: "iron-session", version: "8.0.4" },
  { name: "@anthropic-ai/sdk", version: "0.69.0" },
  { name: "@crowdstrike/aidr", version: "1.2.1" },
];

const REPO_ROOT = path.resolve(import.meta.dirname, "..");
const OUT_DIR = path.join(REPO_ROOT, "vendor", "npm-offline");
const UNPKG = "https://unpkg.com";

function curl(url, { binary = false } = {}) {
  // -k: corporate proxy intercepts TLS with its own CA.
  // -g: some published paths (e.g. geist's `Geist-Italic[wght].ttf`) contain
  // literal brackets that curl would otherwise parse as glob ranges.
  const args = ["-k", "-g", "-sS", "-fL", "--max-time", "60", url];
  return execFileSync("curl", args, {
    encoding: binary ? "buffer" : "utf8",
    maxBuffer: 256 * 1024 * 1024,
  });
}

function listFiles(spec) {
  // unpkg ?meta returns a recursive file tree for the published package.
  const meta = JSON.parse(curl(`${UNPKG}/${spec}/?meta`));
  const files = [];
  // unpkg ?meta: directory nodes (and the root) carry a `files[]` array; file
  // nodes carry a `path` and a MIME `type` (e.g. "text/javascript"), not
  // type:"file". Recurse on anything with `files`, collect anything with `path`.
  const walk = (node) => {
    if (Array.isArray(node.files)) node.files.forEach(walk);
    else if (node.path) files.push(node.path);
  };
  walk(meta);
  return files;
}

function vendorOne({ name, version }) {
  const spec = `${name}@${version}`;
  const tarName = `${name.replace("/", "-").replace("@", "")}-${version}.tgz`;
  const outPath = path.join(OUT_DIR, tarName);
  process.stdout.write(`  ${spec} ... `);

  const work = mkdtempSync(path.join(tmpdir(), "vendor-"));
  const pkgRoot = path.join(work, "package");
  try {
    const files = listFiles(spec);
    for (const rel of files) {
      const dest = path.join(pkgRoot, rel);
      mkdirSync(path.dirname(dest), { recursive: true });
      const bytes = curl(`${UNPKG}/${spec}${rel}`, { binary: true });
      execFileSync("tee", [dest], { input: bytes, stdio: ["pipe", "ignore", "inherit"] });
    }
    // npm tarball layout: every entry under `package/`.
    execFileSync("tar", ["-czf", outPath, "-C", work, "package"]);
    console.log(`${files.length} files -> ${path.relative(REPO_ROOT, outPath)}`);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

if (!existsSync(OUT_DIR)) mkdirSync(OUT_DIR, { recursive: true });
console.log(`Vendoring ${PACKAGES.length} offline tarballs from unpkg:`);
for (const p of PACKAGES) vendorOne(p);
console.log("Done.");

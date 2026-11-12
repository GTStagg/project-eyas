import fs from "node:fs";
import path from "node:path";

// Eyas's curated RTR script library (formerly falcon-extras patching/ and
// cleanup/library.py). Two catalogs share one renderer:
//   patching/ → vulnerability remediation (Spotlight-driven version updates)
//   cleanup/  → incident-response remediation (persistence, kill, stop, …)
//
// The agent never authors script bytes. It picks a script id from a manifest
// and supplies parameters, which are validated here against the manifest's
// per-script schema. The only path from the agent to a host shell is an id
// that resolves to a file on disk plus params that passed the regex. eyas-mcp
// runs the rendered script (lib/mcp/native-dispatch.ts).
//
// The manifests and scripts are read with fs at call time, so they ship in the
// standalone bundle through next.config.ts outputFileTracingIncludes.
//
// Regex parity with the former Python: manifest patterns are matched with
// fullmatch semantics (^(?:p)$) for params and search semantics for Spotlight
// matching; a leading (?i) becomes the JS "i" flag (JS has no inline flags).

export type Catalog = "patching" | "cleanup";
type Obj = Record<string, unknown>;

export type ParamSpec = {
  type?: string;
  values?: unknown[];
  pattern?: string;
  evidence_pattern?: string;
  default?: unknown;
  optional?: boolean;
  [k: string]: unknown;
};

export type ScriptSpec = {
  id: string;
  title: string;
  os: string;
  script: string;
  preambles?: string[];
  params?: Record<string, ParamSpec>;
  expected_runtime_minutes?: number;
  reboot_risk?: string;
  read_only?: boolean;
  spotlight_match?: { vendor_pattern?: string; product_pattern?: string } | null;
  intent?: string;
  [k: string]: unknown;
};

export class ParamError extends Error {}

export function catalogDir(catalog: Catalog): string {
  return path.join(process.cwd(), "lib", "eyas-tools", "rtr", catalog);
}

export function loadManifest(catalog: Catalog): { scripts: ScriptSpec[] } {
  const raw = fs.readFileSync(path.join(catalogDir(catalog), "manifest.json"), "utf8");
  const parsed = JSON.parse(raw) as { scripts?: ScriptSpec[] };
  return { scripts: Array.isArray(parsed.scripts) ? parsed.scripts : [] };
}

export function findById(catalog: Catalog, scriptId: string): ScriptSpec | null {
  return loadManifest(catalog).scripts.find((s) => s.id === scriptId) ?? null;
}

/** Compile a manifest pattern. `full` anchors it like Python's re.fullmatch. */
export function compilePattern(pattern: string, full: boolean): RegExp {
  let src = pattern;
  let flags = "";
  if (src.startsWith("(?i)")) {
    src = src.slice(4);
    flags = "i";
  }
  return new RegExp(full ? `^(?:${src})$` : src, flags);
}

export function listPatchScripts(osFilter?: string | null): Obj[] {
  let scripts = loadManifest("patching").scripts;
  if (osFilter) scripts = scripts.filter((s) => s.os === osFilter);
  return scripts.map((s) => ({
    id: s.id,
    title: s.title,
    os: s.os,
    params: s.params ?? {},
    expected_runtime_minutes: s.expected_runtime_minutes ?? null,
    reboot_risk: s.reboot_risk ?? "unknown",
    read_only: Boolean(s.read_only),
    spotlight_match: s.spotlight_match ?? null,
  }));
}

export function listCleanupScripts(osFilter?: string | null): Obj[] {
  let scripts = loadManifest("cleanup").scripts;
  if (osFilter) scripts = scripts.filter((s) => s.os === osFilter);
  return scripts.map((s) => ({
    id: s.id,
    title: s.title,
    os: s.os,
    intent: s.intent ?? "",
    params: s.params ?? {},
  }));
}

// Linux package naming (Debian + RPM): same regex as the linux-pkg-upgrade
// param schema, so render-time validation is self-consistent.
const LINUX_PACKAGE_RX = /^[a-z0-9][a-z0-9.+-]{0,49}$/;

/** Route an unmatched Linux remediation to linux-pkg-upgrade when its product
 *  string starts with a valid package name. The regex is the security
 *  boundary: anything with a shell metacharacter, quote or space fails. */
export function linuxPkgFallback(product: string): { spec: ScriptSpec; params: Obj } | null {
  if (!product) return null;
  const candidate = (product.trim().split(/\s+/)[0] ?? "").toLowerCase();
  if (!LINUX_PACKAGE_RX.test(candidate)) return null;
  const spec = findById("patching", "linux-pkg-upgrade");
  if (!spec) return null;
  return { spec, params: { package: candidate } };
}

/** First patch script whose spotlight_match patterns match. First declared
 *  wins; osFilter narrows to one OS family. */
export function matchRemediation(vendor: string, product: string, osFilter?: string | null): ScriptSpec | null {
  const v = (vendor ?? "").trim();
  const p = (product ?? "").trim();
  for (const s of loadManifest("patching").scripts) {
    if (osFilter && s.os !== osFilter) continue;
    const m = s.spotlight_match;
    if (!m) continue;
    if (m.vendor_pattern && !compilePattern(m.vendor_pattern, false).test(v)) continue;
    if (m.product_pattern && !compilePattern(m.product_pattern, false).test(p)) continue;
    return s;
  }
  return null;
}

// Error text keeps the former Python wording, which prompts and playbooks quote.
const pyRepr = (v: unknown): string =>
  typeof v === "string" ? `'${v}'` : v === null || v === undefined ? "None" : typeof v === "boolean" ? (v ? "True" : "False") : JSON.stringify(v);
const pyList = (vs: unknown[]): string => `[${vs.map(pyRepr).join(", ")}]`;
const hasOwn = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

/** Validate supplied params and fill defaults. Throws ParamError. Keys the
 *  caller vouched for with detection evidence use `evidence_pattern` (still
 *  bounded) instead of the strict `pattern`. Unknown keys are refused. */
export function validateParams(
  schema: Record<string, ParamSpec>,
  supplied: Obj,
  evidenceVouchedKeys?: ReadonlySet<string>,
): Obj {
  const resolved: Obj = {};
  const vouched = evidenceVouchedKeys ?? new Set<string>();
  for (const [key, spec] of Object.entries(schema)) {
    if (hasOwn(supplied, key)) {
      const value = supplied[key];
      const t = spec.type;
      if (t === "enum") {
        const values = Array.isArray(spec.values) ? spec.values : [];
        if (!values.includes(value)) {
          throw new ParamError(`param '${key}': ${pyRepr(value)} not in ${pyList(values)}`);
        }
      } else if (t === "string") {
        if (typeof value !== "string") throw new ParamError(`param '${key}': must be string`);
        const useEvidence = vouched.has(key) && Boolean(spec.evidence_pattern);
        const pattern = useEvidence ? spec.evidence_pattern : spec.pattern;
        if (pattern && !compilePattern(pattern, true).test(value)) {
          throw new ParamError(
            `param '${key}': does not match pattern '${pattern}'` + (useEvidence ? " (evidence-vouched)" : ""),
          );
        }
      } else {
        throw new ParamError(`param '${key}': unknown type '${String(t)}'`);
      }
      resolved[key] = value;
    } else if (hasOwn(spec, "default")) {
      resolved[key] = spec.default;
    } else if (spec.optional) {
      continue;
    } else {
      throw new ParamError(`param '${key}': required, not supplied`);
    }
  }
  const extra = Object.keys(supplied).filter((k) => !hasOwn(schema, k)).sort();
  if (extra.length > 0) {
    throw new ParamError(`unknown params: [${extra.map((k) => `'${k}'`).join(", ")}]`);
  }
  return resolved;
}

/** PowerShell literal: single-quoted with internal single quotes doubled. */
export function toPwshLiteral(value: unknown): string {
  if (value === null || value === undefined) return "$null";
  if (typeof value === "boolean") return value ? "$true" : "$false";
  if (typeof value === "number") return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
}

/** bash single-quoted literal ('"'"' for embedded quotes). Validation, not
 *  this encoding, is the security boundary. */
export function toBashLiteral(value: unknown): string {
  if (value === null || value === undefined) return "''";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

// RTR does not deliver UTF-8 cleanly to the host shell under SYSTEM, so the
// rendered script is coerced to 7-bit ASCII: common smart punctuation becomes
// its ASCII form and anything else non-ASCII is dropped. ("?" is kept: the
// Python renderer dropped every "?", which broke `rc=$?`, URLs with a query
// string and regexes like `(?i)` in the scripts.)
const ASCII_SUBSTITUTIONS: [string, string][] = [
  ["—", "--"],
  ["–", "-"],
  ["…", "..."],
  ["‘", "'"],
  ["’", "'"],
  ["“", '"'],
  ["”", '"'],
  [" ", " "],
];

export function asciiCoerce(text: string): string {
  let out = text;
  for (const [src, dst] of ASCII_SUBSTITUTIONS) out = out.split(src).join(dst);
  // eslint-disable-next-line no-control-regex
  return out.replace(/[^\x00-\x7f]/gu, "");
}

function capitalize(part: string): string {
  return part.length === 0 ? part : part[0].toUpperCase() + part.slice(1).toLowerCase();
}

/** Params header in the target OS's language: a PowerShell $Params
 *  hashtable on Windows, UPPERCASE bash assignments on Linux / macOS. */
export function renderParamsBlock(params: Obj, os: string): string {
  const entries = Object.entries(params);
  if (os === "windows") {
    if (entries.length === 0) return "$Params = @{}\n";
    const lines = ["$Params = @{"];
    for (const [k, v] of entries) {
      const pkey = k.split("_").map(capitalize).join("");
      lines.push(`    ${pkey} = ${toPwshLiteral(v)}`);
    }
    lines.push("}\n");
    return lines.join("\n");
  }
  if (entries.length === 0) return "# (no params)\n";
  const lines = entries.map(([k, v]) => `${k.toUpperCase().replace(/-/g, "_")}=${toBashLiteral(v)}`);
  return lines.join("\n") + "\n";
}

export type ResolvedPlan = {
  script_id: string;
  title: string;
  os: string;
  params: Obj;
  rendered: string;
  preview: string;
  reboot_risk: string;
  expected_runtime_minutes: number;
  read_only: boolean;
  intent: string;
};

const PREVIEW_LINES = 40;

/** Python str.splitlines() for the line breaks a script can contain. */
function splitLines(text: string): string[] {
  const lines = text.split(/\r\n|\r|\n/);
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return lines;
}

export function resolvePlan(
  catalog: Catalog,
  scriptId: string,
  suppliedParams: Obj = {},
  evidenceVouchedKeys?: ReadonlySet<string>,
): ResolvedPlan {
  const spec = findById(catalog, scriptId);
  if (!spec) {
    throw new ParamError(
      catalog === "patching" ? `unknown script id: '${scriptId}'` : `unknown cleanup script id: '${scriptId}'`,
    );
  }
  const params = validateParams(spec.params ?? {}, suppliedParams, evidenceVouchedKeys);
  const dir = catalogDir(catalog);
  const os = spec.os ?? "windows";

  const parts: string[] = [
    `# Rendered by Eyas (${catalog} library)\n# script_id: ${spec.id}\n`,
    renderParamsBlock(params, os),
  ];
  for (const rel of spec.preambles ?? []) parts.push(fs.readFileSync(path.join(dir, rel), "utf8"));
  parts.push(fs.readFileSync(path.join(dir, spec.script), "utf8"));
  const rendered = asciiCoerce(parts.join("\n"));

  const lines = splitLines(rendered);
  let preview = lines.slice(0, PREVIEW_LINES).join("\n");
  if (lines.length > PREVIEW_LINES) preview += "\n# ... (truncated for preview)";

  return {
    script_id: spec.id,
    title: spec.title,
    os: spec.os,
    params,
    rendered,
    preview,
    reboot_risk: spec.reboot_risk ?? "unknown",
    expected_runtime_minutes: spec.expected_runtime_minutes ?? 0,
    read_only: Boolean(spec.read_only),
    intent: spec.intent ?? "",
  };
}

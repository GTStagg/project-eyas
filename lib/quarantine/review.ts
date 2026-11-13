// Deterministic enrichment for the /quarantine surface. Pure functions — no
// I/O, no clock unless passed in — so they unit-test cleanly (same precedent as
// lib/queue/campaigns.ts and the lib/eyas-tools pure-function suites).
//
// falcon-mcp 0.11.0's quarantine module returns FalconPy's GetQuarantineFiles
// records pass-through. The FQL-documented fields (hostname, sha256, state,
// date_updated) are authoritative; the paths / alert-id / detection-id arrays
// are NOT enumerated in upstream source, so every extractor here is tolerant of
// missing or differently-named keys (confirmed against a live record before
// shipping). Anything we can't read degrades to "unknown", never throws.

export interface QuarantineRecord {
  id?: string;
  sha256?: string;
  hostname?: string;
  state?: string;
  dateUpdated?: string;
  paths: string[];
  /** Alert / detection ids carried on the record, if present (key names vary). */
  alertIds: string[];
  detectionIds: string[];
}

export interface HostCluster {
  hostname: string;
  count: number;
  hashes: string[]; // distinct sha256s quarantined on this host
}

export interface HashCluster {
  sha256: string;
  count: number;
  hosts: string[]; // distinct hosts where this hash is quarantined
}

export interface QuarantineSummary {
  total: number;
  byState: { quarantined: number; released: number; other: number };
  hostCount: number;
  hashCount: number;
  /** Hosts carrying more than one DISTINCT quarantined hash — concentration. */
  repeatHosts: HostCluster[];
  /** Hashes quarantined on more than one host — possible campaign spread. */
  spreadHashes: HashCluster[];
  records: QuarantineRecord[];
}

const str = (v: unknown): string | undefined =>
  typeof v === "string" && v.trim() ? v.trim() : undefined;

// Pull a string array from a value that might be: a string[], a single string,
// or an array of objects each carrying a string under a common key.
function strArray(v: unknown, objKeys: string[] = ["path", "filepath", "value", "id"]): string[] {
  if (!v) return [];
  if (typeof v === "string") return v.trim() ? [v.trim()] : [];
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const item of v) {
    if (typeof item === "string") {
      if (item.trim()) out.push(item.trim());
    } else if (item && typeof item === "object") {
      for (const k of objKeys) {
        const s = str((item as Record<string, unknown>)[k]);
        if (s) {
          out.push(s);
          break;
        }
      }
    }
  }
  return out;
}

// Read the first present key from a set of candidates (tolerant of upstream
// field-name drift between FalconPy versions).
function firstKey(r: Record<string, unknown>, keys: string[]): unknown {
  for (const k of keys) if (k in r && r[k] != null) return r[k];
  return undefined;
}

export function normalizeQuarantineRecords(raw: unknown[]): QuarantineRecord[] {
  const out: QuarantineRecord[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const r = item as Record<string, unknown>;
    out.push({
      id: str(firstKey(r, ["id", "quarantine_id"]) as unknown),
      sha256: str(firstKey(r, ["sha256", "sha256_hash"]) as unknown),
      hostname: str(firstKey(r, ["hostname", "host_name"]) as unknown),
      state: str(firstKey(r, ["state", "status"]) as unknown),
      dateUpdated: str(firstKey(r, ["date_updated", "date_created", "updated"]) as unknown),
      paths: strArray(firstKey(r, ["paths", "path", "filepath", "file_paths"])),
      alertIds: strArray(firstKey(r, ["alert_ids", "alerts", "composite_ids"])),
      detectionIds: strArray(firstKey(r, ["detection_ids", "detections"])),
    });
  }
  return out;
}

function classifyState(state: string | undefined): "quarantined" | "released" | "other" {
  const s = (state ?? "").toLowerCase();
  if (s.includes("quarantin")) return "quarantined";
  if (s.includes("releas") || s.includes("unrelease") || s.includes("restore")) return "released";
  return "other";
}

export function summarizeQuarantine(records: QuarantineRecord[]): QuarantineSummary {
  const byState = { quarantined: 0, released: 0, other: 0 };
  const hostMap = new Map<string, Set<string>>(); // host → distinct hashes
  const hashMap = new Map<string, Set<string>>(); // hash → distinct hosts

  for (const r of records) {
    byState[classifyState(r.state)]++;
    if (r.hostname) {
      const set = hostMap.get(r.hostname) ?? new Set<string>();
      if (r.sha256) set.add(r.sha256);
      hostMap.set(r.hostname, set);
    }
    if (r.sha256) {
      const set = hashMap.get(r.sha256) ?? new Set<string>();
      if (r.hostname) set.add(r.hostname);
      hashMap.set(r.sha256, set);
    }
  }

  const repeatHosts: HostCluster[] = [...hostMap.entries()]
    .filter(([, hashes]) => hashes.size > 1)
    .map(([hostname, hashes]) => ({ hostname, count: hashes.size, hashes: [...hashes] }))
    .sort((a, b) => b.count - a.count);

  const spreadHashes: HashCluster[] = [...hashMap.entries()]
    .filter(([, hosts]) => hosts.size > 1)
    .map(([sha256, hosts]) => ({ sha256, count: hosts.size, hosts: [...hosts] }))
    .sort((a, b) => b.count - a.count);

  return {
    total: records.length,
    byState,
    hostCount: hostMap.size,
    hashCount: hashMap.size,
    repeatHosts,
    spreadHashes,
    records,
  };
}

// Compact text rendering of the deterministic summary, injected as an UNcached
// agent context block. Bounded so a large quarantine set can't blow the prompt.
export function renderQuarantineContext(summary: QuarantineSummary): string {
  const lines: string[] = [
    "# Deterministic quarantine summary (computed server-side)",
    `Total quarantine records: ${summary.total} — quarantined ${summary.byState.quarantined}, released ${summary.byState.released}, other ${summary.byState.other}.`,
    `Distinct hosts: ${summary.hostCount}. Distinct file hashes: ${summary.hashCount}.`,
  ];
  if (summary.repeatHosts.length) {
    lines.push("", "Hosts with multiple distinct quarantined hashes (concentration):");
    for (const h of summary.repeatHosts.slice(0, 15)) {
      lines.push(`- ${h.hostname}: ${h.count} distinct hashes`);
    }
  }
  if (summary.spreadHashes.length) {
    lines.push("", "Hashes quarantined across multiple hosts (possible spread):");
    for (const h of summary.spreadHashes.slice(0, 15)) {
      lines.push(`- ${h.sha256} on ${h.count} hosts`);
    }
  }
  lines.push("", "Sample records (host · sha256 · state · id):");
  for (const r of summary.records.slice(0, 40)) {
    lines.push(
      `- ${r.hostname ?? "?"} · ${r.sha256 ?? "?"} · ${r.state ?? "?"} · ${r.id ?? "?"}`,
    );
  }
  return lines.join("\n");
}

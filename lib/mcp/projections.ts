import "server-only";
import { parseConcatenatedJson } from "./parse";

// Per-tool result projections. Falcon tool results carry far more nested data
// than the agent needs to reason — full host records can be 7KB each, full
// vulnerability records 10KB+. Projecting to the salient fields cuts per-turn
// token usage by 5-20× and keeps requests under the Sonnet starter-tier
// rate limit (30K ITPM). The dashboard endpoints don't go through here —
// they render raw data themselves.
//
// Trimming is appended with a [Note: ...] line so the model knows results
// were summarized and can request a specific item's full details via the
// falcon_get_*_details tool when needed.

type Projection = (obj: Record<string, unknown>) => Record<string, unknown>;
type Filter = (obj: Record<string, unknown>) => boolean;

// Per-tool drop filters applied BEFORE projection. Returning false drops
// the row. Used to strip lab/QA noise that has no analyst value — the
// canonical case is CrowdStrike SE/QA "Test Rule - …" NGSIEM correlation
// detections that pollute production-style tenants.
const FILTERS: Record<string, Filter> = {
  falcon_search_detections: (d) => {
    const name = String(d.display_name ?? d.name ?? "");
    if (/^test rule\b/i.test(name)) return false;
    return true;
  },
};

const undef = (v: unknown) => (v === null || v === undefined || v === "" ? undefined : v);
const trunc = (v: unknown, max: number): unknown => {
  if (typeof v !== "string") return undef(v);
  if (v === "") return undefined;
  return v.length > max ? v.slice(0, max) + "…" : v;
};
const get = (o: Record<string, unknown>, path: string): unknown => {
  let cur: unknown = o;
  for (const part of path.split(".")) {
    if (cur && typeof cur === "object" && part in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return cur;
};

// Pull RegistryPersistEdit / T1546 (Event Triggered Execution) registry
// artifacts off a detection's behaviors[] array. Returns a compact array
// of {pattern, path, value, kind} or undefined when nothing matches, so
// the agent can issue a precise host-remove-* cleanup without paging the
// whole behaviors[] blob through. `kind` classifies the path so the
// playbook can route IFEO findings to host-remove-ifeo-hijack and
// run-key findings to host-remove-run-key.
function classifyRegistryPath(path: string): string | undefined {
  const p = path.toLowerCase();
  if (p.includes("\\image file execution options\\")) return "ifeo";
  if (p.includes("\\silentprocessexit\\")) return "ifeo-silent-exit";
  if (/\\(run|runonce)(\\|$)/.test(p)) return "run-key";
  if (p.includes("\\winlogon")) return "winlogon";
  if (p.includes("appinit_dlls")) return "appinit-dlls";
  if (p.includes("\\appcertdlls")) return "appcert-dlls";
  return "other";
}
function extractRegistryPersistence(
  d: Record<string, unknown>,
): unknown[] | undefined {
  const behaviors = d.behaviors;
  if (!Array.isArray(behaviors) || behaviors.length === 0) return undefined;
  const out: Record<string, unknown>[] = [];
  for (const raw of behaviors) {
    if (!raw || typeof raw !== "object") continue;
    const b = raw as Record<string, unknown>;
    const pattern = String(
      b.behavior_id ?? b.name ?? b.display_name ?? b.pattern_id ?? "",
    );
    const technique = String(b.technique_id ?? b.technique ?? "");
    const iocType = String(b.ioc_type ?? "").toLowerCase();
    const iocValue = String(b.ioc_value ?? "");
    const isRegistryPattern = /registry/i.test(pattern);
    const isT1546 = /^T1546/i.test(technique);
    const isRegistryIoc = iocType.startsWith("registry");
    if (!isRegistryPattern && !isT1546 && !isRegistryIoc) continue;
    if (!iocValue && !b.ioc_description) continue;
    out.push({
      pattern: pattern || undefined,
      technique: technique || undefined,
      path: iocValue || undefined,
      kind: iocValue ? classifyRegistryPath(iocValue) : undefined,
      description: trunc(b.ioc_description, 200),
    });
  }
  return out.length ? out : undefined;
}

// Walk a detection's command-line surfaces (top-level cmdline,
// parent_details.cmdline, behaviors[].cmdline) and pull out the
// breadcrumbs an analyst should be chasing: URLs, file paths, archive
// names, extract destinations, downloader output paths. The full
// behaviors[] blob is dropped from the projection for token economy,
// so unless we surface this here the agent only sees the immediate
// process's cmdline -- and a `curl ... -o foo.zip; Expand-Archive foo.zip
// -DestinationPath C:\extracted` chain frequently lives on a sibling
// behavior or the parent. Same lesson as registry_persistence: chase
// what's on the detection deterministically, don't ask the agent to.
function dedup(arr: string[]): string[] {
  return Array.from(new Set(arr.map((s) => s.trim()).filter(Boolean)));
}
// The triggering process's *Falcon graph id* is the load-bearing input
// for extras_host_process_tree — that's what NGSIEM ProcessRollup2 keys
// every row on as `TargetProcessId` (and parent links as
// `ParentProcessId`). Confusingly Falcon's unified Alerts API surfaces
// this as `process_id` (10-digit graph id) and ALSO surfaces a
// `local_process_id` field which is the OS pid (4-digit, what Task
// Manager / RTR shows) — only useful for human display.
//
// We extract the graph id here; if the detection record only has the OS
// pid (legacy v2), fall through to behaviors[].pid as the last resort
// since the OS pid won't match TargetProcessId on its own.
function toPid(v: unknown): number | undefined {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) {
    const n = Number(v);
    return Number.isFinite(n) ? n : undefined;
  }
  return undefined;
}
function extractPivotPid(d: Record<string, unknown>): number | undefined {
  // process_id (graph id) is the right key for ProcessRollup2 lookup.
  const direct = toPid(d.process_id);
  if (direct !== undefined) return direct;
  const behaviors = d.behaviors;
  if (!Array.isArray(behaviors)) return undefined;
  for (let i = behaviors.length - 1; i >= 0; i--) {
    const raw = behaviors[i];
    if (raw && typeof raw === "object") {
      const b = raw as Record<string, unknown>;
      const pid =
        toPid(b.process_id) ??
        toPid(b.target_process_id) ??
        toPid(b.pid);
      if (pid !== undefined) return pid;
    }
  }
  return undefined;
}

function extractCmdlineArtifacts(
  d: Record<string, unknown>,
): Record<string, unknown> | undefined {
  const lines: string[] = [];
  if (typeof d.cmdline === "string" && d.cmdline) lines.push(d.cmdline);
  const parentCmd = get(d, "parent_details.cmdline");
  if (typeof parentCmd === "string" && parentCmd) lines.push(parentCmd);
  const behaviors = d.behaviors;
  if (Array.isArray(behaviors)) {
    for (const raw of behaviors) {
      if (raw && typeof raw === "object") {
        const c = (raw as Record<string, unknown>).cmdline;
        if (typeof c === "string" && c) lines.push(c);
      }
    }
  }
  if (lines.length === 0) return undefined;
  const blob = lines.join(" \n ");

  const urls = dedup(blob.match(/https?:\/\/[^\s'"<>|`]+/gi) ?? []);
  const quoted = (blob.match(/['"]([A-Za-z]:\\[^'"]+)['"]/g) ?? []).map((s) =>
    s.slice(1, -1),
  );
  const unquoted = blob.match(/[A-Za-z]:\\[\w\-. \\()]+\.\w{1,8}/g) ?? [];
  const allPaths = dedup([...quoted, ...unquoted]);
  const archives = allPaths.filter((p) =>
    /\.(zip|7z|rar|tar|tgz|gz|cab|iso|bz2|xz)$/i.test(p),
  );

  const extractTargets = new Set<string>();
  // Expand-Archive / Compress-Archive style.
  for (const m of blob.matchAll(
    /-DestinationPath\s+(?:'([^']+)'|"([^"]+)"|(\S+))/gi,
  )) {
    extractTargets.add(m[1] || m[2] || m[3]);
  }
  // tar -C <dir> / unzip -d <dir>
  for (const m of blob.matchAll(
    /(?:^|[\s;|&])(?:tar|unzip)\b[^\n]*?(?:-C|-d)\s+(?:'([^']+)'|"([^"]+)"|(\S+))/gi,
  )) {
    extractTargets.add(m[1] || m[2] || m[3]);
  }
  // 7z x archive -o<dir> (no space allowed before path)
  for (const m of blob.matchAll(/7z\b[^\n]*?\s-o(\S+)/gi)) {
    extractTargets.add(m[1]);
  }

  const downloaded = new Set<string>();
  for (const m of blob.matchAll(
    /(?:-o|--output|-OutFile|-O|>)\s+(?:'([^']+)'|"([^"]+)"|([A-Za-z]:\\[^\s'"`]+|[^\s'"`]+\.\w{1,8}))/gi,
  )) {
    downloaded.add(m[1] || m[2] || m[3]);
  }

  if (
    urls.length === 0 &&
    allPaths.length === 0 &&
    extractTargets.size === 0 &&
    downloaded.size === 0
  ) {
    return undefined;
  }
  const cap = (arr: string[], n: number): string[] | undefined =>
    arr.length === 0 ? undefined : arr.slice(0, n);
  return {
    urls: cap(urls, 10),
    paths: cap(allPaths, 20),
    archives: cap(archives, 10),
    extract_targets: cap(Array.from(extractTargets), 10),
    downloaded_files: cap(Array.from(downloaded), 10),
  };
}

// Falcon Cases (falcon-mcp 0.10.0 cases module). search_cases and get_cases
// both return the full case record via entities_cases_post_v2 — name +
// description + the entire evidence array (alerts[] + events[], up to 100
// combined items) + analysis blob. The evidence ids are bulky and the agent
// almost never needs the raw alert/event id list to reason about a case;
// surfacing the COUNTS keeps "how much is attached" while dropping the
// payload. reference_id is the human-facing handle; id is the opaque system
// id every Cases write tool keys on, so both are load-bearing.
function countEvidence(c: Record<string, unknown>, kind: string): number | undefined {
  const ev = (c.evidence as Record<string, unknown> | undefined) ?? c;
  const arr = ev?.[kind] ?? c[kind];
  return Array.isArray(arr) ? arr.length : undefined;
}
function caseProjection(c: Record<string, unknown>): Record<string, unknown> {
  return {
    id: undef(c.id),
    reference_id: undef(c.reference_id),
    name: undef(c.name),
    status: undef(c.status),
    severity: undef(c.severity),
    created_timestamp: undef(c.created_timestamp),
    updated_timestamp: undef(c.updated_timestamp),
    assigned_to_name: undef(
      c.assigned_to_name ?? c.assigned_to ?? c.assignee ?? get(c, "assigned_to.name"),
    ),
    description: trunc(c.description, 400),
    tags: Array.isArray(c.tags) && c.tags.length ? c.tags : undefined,
    alert_evidence_count: countEvidence(c, "alerts"),
    event_evidence_count: countEvidence(c, "events"),
    version: undef(c.version),
  };
}

// Slim host projection: just enough for OS routing, RTR readiness, and
// recency. Bulky / rarely-used fields (external_ip, local_ip, service_provider,
// instance_id, serial_number, agent_version, reduced_functionality_mode,
// product_type_desc, first_seen) are reachable via falcon_get_host_details when
// actually needed. Smaller projection means more hosts fit visibly in one
// response, which discourages the agent from re-fanning per-host calls. Shared
// by falcon_search_hosts and the two falcon-mcp 0.12.0 member reads
// (falcon_search_host_group_members / falcon_search_policy_members), both of
// which return full device entities (queryCombinedGroupMembers / the policy
// members combined endpoint).
function hostProjection(h: Record<string, unknown>): Record<string, unknown> {
  return {
    device_id: undef(h.device_id),
    hostname: undef(h.hostname),
    platform_name: undef(h.platform_name),
    os_product_name: undef(h.os_product_name),
    os_version: undef(h.os_version),
    last_seen: undef(h.last_seen),
    status: undef(h.status),
    rtr_state: undef(h.rtr_state),
  };
}

// Aggregation reads (falcon-mcp 0.16.0 — falcon_aggregate_detections #483 +
// the five falcon_aggregate_case_* #495). Each returns one object per
// aggregation: { name, buckets: [{ label, count }, ...] } for terms/histogram
// aggs, or { name, value } for single-value aggs (cardinality/max/min/avg/sum).
// Deliberately NON-LOSSY: keep the whole object and only cap an oversized
// buckets[] (a terms agg can request size up to 1000) so a big run can't blow
// the token budget. Unlike a field-picking projection it can never empty a
// valid aggregation — the worst case is an unchanged pass-through.
const AGG_BUCKET_CAP = 50;
function aggregateProjection(a: Record<string, unknown>): Record<string, unknown> {
  const buckets = a.buckets;
  if (Array.isArray(buckets) && buckets.length > AGG_BUCKET_CAP) {
    return {
      ...a,
      buckets: buckets.slice(0, AGG_BUCKET_CAP),
      _truncated: `showing top ${AGG_BUCKET_CAP} of ${buckets.length} buckets — narrow the filter or lower size for the rest`,
    };
  }
  return a;
}

// Data Security search records vary by entity_type, so project by value shape
// rather than field name: scalars pass through (long strings truncated); short
// scalar arrays (host_groups, domains, group ids) pass through; anything
// heavier (policy_properties, classification_properties, regexes, a cloud
// app's urls[]) collapses to a summary that names its size and points at
// falcon_get_data_security_entities for the full record. The cid is dropped
// as noise, matching the other projections.
// Threat Graph edge records (eyas-mcp ran-on / edges). Keep what an analyst
// pivots on; drop the self-link URL, customer id, the repeated object hash, the
// (usually empty) properties bag, and the vertex `id` (`mod:<aid>:<hash>`,
// ~100 chars, derivable — and a summary lookup on it 404'd live). Sized so a
// full 50-device ran-on page stays under the 12 KB generic cap (it overflowed
// with `id` kept: 14.3 KB, last ~8 devices truncated).
function threatGraphEdgeProjection(e: Record<string, unknown>): Record<string, unknown> {
  return {
    device_id: undef(e.device_id),
    timestamp: undef(e.timestamp),
    edge_type: undef(e.edge_type),
    scope: undef(e.scope),
  };
}

// List fields on hunting guides hold objects ({name,…} / {technique_id,…});
// keep a capped list of their identifying value.
function pickList(v: unknown, key: string, cap: number): unknown {
  if (!Array.isArray(v)) return undef(v);
  const vals = v
    .map((x) => (x && typeof x === "object" ? (x as Record<string, unknown>)[key] : x))
    .filter((x) => x !== undefined && x !== null && x !== "");
  return vals.length > cap ? [...vals.slice(0, cap), `+${vals.length - cap} more`] : vals;
}

// --- Finished intelligence (eyas-mcp falcon_get_intel_reports / _actors) ---
// Shapes confirmed live (XDR us-2, FANCY BEAR). The report BODY is in
// `description` (≈20 KB, with WordPress [vc_*] shortcodes) — `summary` was
// null on every report sampled, which is why the former sidecar tool (body
// from `summary`) silently returned no body. Lists are {id,slug,value} /
// {family_name} objects; flatten to names. Exported so /intel-dossier (which
// bundles the records into the model's context, outside the 12 KB agent cap)
// shares the projection with a larger body budget.
const textOf = (v: unknown, key: string): unknown => {
  if (Array.isArray(v)) return pickList(v, key, 20);
  return v && typeof v === "object" ? (v as Record<string, unknown>)[key] : undef(v);
};
function cleanBody(v: unknown, max: number): unknown {
  if (typeof v !== "string" || !v.trim()) return undefined;
  const text = v
    .replace(/\[\/?vc_[^\]]*\]/g, "")
    .replace(/\r/g, "")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  return trunc(text, max);
}
export function projectIntelReport(r: Record<string, unknown>, bodyChars = 3000): Record<string, unknown> {
  return {
    id: undef(r.id),
    name: undef(r.name),
    type: textOf(r.type, "name"),
    sub_type: textOf(r.sub_type, "name"),
    created_date: undef(r.created_date),
    last_modified_date: undef(r.last_modified_date),
    url: undef(r.url),
    short_description: cleanBody(r.short_description, 600),
    body: cleanBody(r.description ?? r.summary, bodyChars),
    actors: Array.isArray(r.actors)
      ? (r.actors as Array<Record<string, unknown>>).map((a) => ({ id: a.id, name: a.name }))
      : undefined,
    motivations: textOf(r.motivations, "value"),
    target_industries: textOf(r.target_industries, "value"),
    target_countries: textOf(r.target_countries, "value"),
    malware: textOf(r.malware, "family_name"),
    mitre: pickList(r.mitre_attacks, "technique_id", 20),
    tags: textOf(r.tags, "value"),
  };
}
export function projectIntelActor(a: Record<string, unknown>, bodyChars = 3000): Record<string, unknown> {
  const kc = a.kill_chain && typeof a.kill_chain === "object" ? (a.kill_chain as Record<string, unknown>) : null;
  return {
    id: undef(a.id),
    name: undef(a.name),
    known_as: undef(a.known_as),
    actor_type: undef(a.actor_type),
    status: undef(a.status),
    active: undef(a.active),
    first_activity_date: undef(a.first_activity_date),
    last_activity_date: undef(a.last_activity_date),
    url: undef(a.url),
    origins: textOf(a.origins, "value"),
    motivations: textOf(a.motivations, "value"),
    objectives: textOf(a.objectives, "value"),
    capabilities: textOf(a.capabilities, "value"),
    target_industries: textOf(a.target_industries, "value"),
    target_countries: textOf(a.target_countries, "value"),
    target_regions: textOf(a.target_regions, "value"),
    uses_threats: textOf(a.uses_threats, "family_name"),
    short_description: cleanBody(a.short_description, 600),
    description: cleanBody(a.description, bodyChars),
    kill_chain: kc
      ? Object.fromEntries(
          Object.entries(kc)
            // kill_chain carries each phase twice — plain and rich_text_* HTML.
            .filter(([k]) => !k.startsWith("rich_text_"))
            .map(([k, v]) => [k, typeof v === "string" ? trunc(v.replace(/\s+/g, " ").trim(), 300) : undefined])
            .filter(([, v]) => v),
        )
      : undefined,
  };
}

const DS_SCALAR_ARRAY_CAP = 10;
function dataSecurityProjection(r: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(r)) {
    if (k === "cid") continue;
    if (Array.isArray(v)) {
      const scalar = v.every((x) => x === null || typeof x !== "object");
      out[k] =
        scalar && v.length <= DS_SCALAR_ARRAY_CAP
          ? v
          : `[${v.length} item${v.length === 1 ? "" : "s"} — see falcon_get_data_security_entities]`;
    } else if (v && typeof v === "object") {
      out[k] = `{${Object.keys(v).length} fields — see falcon_get_data_security_entities}`;
    } else {
      out[k] = trunc(v, 300);
    }
  }
  return out;
}

const PROJECTIONS: Record<string, Projection> = {
  // --- falcon-mcp 0.16.0 aggregation reads (counts/distributions, not records) ---
  falcon_aggregate_detections: aggregateProjection,
  falcon_aggregate_case_slas: aggregateProjection,
  falcon_aggregate_case_templates: aggregateProjection,
  falcon_aggregate_case_access_tags: aggregateProjection,
  falcon_aggregate_case_notification_groups: aggregateProjection,
  falcon_aggregate_case_file_details: aggregateProjection,
  // falcon-mcp 0.17.0 Recon aggregates (#527) — same non-lossy bucket-capping.
  falcon_aggregate_recon_notifications: aggregateProjection,
  falcon_aggregate_recon_exposed_data_records: aggregateProjection,

  falcon_search_cases: caseProjection,
  falcon_get_cases: caseProjection,

  // Case templates are small but list_case_templates returns full custom-field
  // + SLA config blobs the agent doesn't need to pick a template — id + name
  // + a short description is enough to drive create_case(template_id=…).
  falcon_list_case_templates: (t) => ({
    id: undef(t.id),
    name: undef(t.name),
    description: trunc(t.description, 200),
    custom_field_count: Array.isArray(t.custom_fields)
      ? t.custom_fields.length
      : undefined,
  }),

  falcon_search_hosts: hostProjection,
  // 0.12.0 host-group / policy member reads return full device entities — same
  // shape as falcon_search_hosts, so reuse the slim host projection.
  falcon_search_host_group_members: hostProjection,
  falcon_search_policy_members: hostProjection,

  falcon_search_detections: (d) => ({
    composite_id: undef(d.composite_id),
    created_timestamp: undef(d.created_timestamp),
    severity: undef(d.severity),
    severity_name: undef(d.severity_name),
    status: undef(d.status),
    display_name: undef(d.display_name),
    tactic: undef(d.tactic),
    technique: undef(d.technique),
    technique_id: undef(d.technique_id),
    description: trunc(d.description, 300),
    hostname: undef(get(d, "device.hostname")),
    platform: undef(d.platform ?? get(d, "device.platform_name")),
    cmdline: trunc(d.cmdline, 240),
    filepath: trunc(d.filepath, 240),
    sha256: undef(d.sha256),
    user_name: undef(d.user_name),
    pattern_disposition_description: undef(d.pattern_disposition_description),
    falcon_host_link: undef(d.falcon_host_link),
    // Registry-persistence behaviors (RegistryPersistEdit / MITRE T1546 family
    // including IFEO Debugger hijacks, SilentProcessExit, AppInit_DLLs).
    // The full behaviors[] array is dropped for token economy, but the
    // registry artifact (path + value) is the load-bearing remediation
    // input — without it the IR playbook can't issue a precise cleanup.
    // Surfacing it as a top-level field is deterministic enrichment;
    // relying on a prompt instruction to dig into behaviors[] reliably
    // gets ignored.
    registry_persistence: extractRegistryPersistence(d),
    // Command-line breadcrumbs (URLs, file paths, archives, extract
    // destinations, downloader output paths) parsed from cmdline +
    // parent_details.cmdline + behaviors[].cmdline. Surfacing these
    // means the agent treats every artifact named in a cmdline as a
    // remediation lead instead of stopping at the immediate process.
    cmdline_artifacts: extractCmdlineArtifacts(d),
    // Triggering process pid — fed into extras_host_process_tree to
    // reconstruct ancestry and classify the delivery vector
    // (phishing_doc / browser_drive_by / lateral_winrm / ...). Loadbearing
    // for IR Phase 0 — the agent should call extras_host_process_tree
    // once per open detection that has a pivot_pid.
    pivot_pid: extractPivotPid(d),
  }),

  falcon_search_vulnerabilities: (v) => ({
    id: undef(v.id),
    cve_id: undef(get(v, "cve.id")),
    severity: undef(get(v, "cve.severity")),
    cvss_base_score: undef(get(v, "cve.base_score")),
    cvss_v3: undef(get(v, "cve.cvss_v3_score.score")),
    exprt_rating: undef(get(v, "cve.exprt_rating")),
    status: undef(v.status),
    created_timestamp: undef(v.created_timestamp),
    hostname: undef(get(v, "host_info.hostname")),
    platform: undef(get(v, "host_info.platform")),
    os_version: undef(get(v, "host_info.os_version")),
    product: Array.isArray(v.apps)
      ? (v.apps[0] as Record<string, unknown> | undefined)?.product_name_version
      : undefined,
    apps_count: Array.isArray(v.apps) ? v.apps.length : undefined,
    // Spotlight remediation lives in `remediation.entities[]` — vendor /
    // product / version / KB on each entity is what drives patch
    // recommendations. `remediation.ids` is a parallel list of opaque IDs
    // with no fix detail; surfacing only the IDs leaves the agent unable
    // to propose a patch (CLAUDE.md "Spotlight remediation shape").
    remediation: undef(get(v, "remediation.entities") ?? get(v, "remediation.ids")),
  }),

  falcon_search_actors: (a) => ({
    id: undef(a.id),
    name: undef(a.name),
    short_description: undef(
      a.short_description ?? (typeof a.description === "string" ? a.description.slice(0, 300) : undefined),
    ),
    region: undef(get(a, "region.value")),
    motivations: Array.isArray(a.motivations)
      ? (a.motivations as Array<Record<string, unknown>>).map((m) => m.value).filter(Boolean)
      : undefined,
    target_industries: Array.isArray(a.target_industries)
      ? (a.target_industries as Array<Record<string, unknown>>)
          .slice(0, 8)
          .map((t) => t.value)
          .filter(Boolean)
      : undefined,
    target_countries: Array.isArray(a.target_countries)
      ? (a.target_countries as Array<Record<string, unknown>>)
          .slice(0, 5)
          .map((t) => t.value)
          .filter(Boolean)
      : undefined,
    capabilities: Array.isArray(a.capabilities)
      ? (a.capabilities as Array<Record<string, unknown>>)
          .slice(0, 8)
          .map((c) => c.value)
          .filter(Boolean)
      : undefined,
    first_activity_date: undef(a.first_activity_date),
    last_activity_date: undef(a.last_activity_date),
  }),

  falcon_search_indicators: (i) => ({
    id: undef(i.id),
    type: undef(i.type),
    indicator: undef(i.indicator),
    published_date: undef(i.published_date),
    last_updated: undef(i.last_updated),
    malicious_confidence: undef(i.malicious_confidence),
    threat_types: undef(i.threat_types),
    malware_families: undef(i.malware_families),
    actors: undef(i.actors),
  }),

  falcon_search_unmanaged_assets: (a) => ({
    asset_id: undef(a.asset_id ?? a.id),
    hostname: undef(a.hostname),
    last_seen_timestamp: undef(a.last_seen_timestamp),
    confidence: undef(a.confidence),
    asset_type: undef(a.asset_type),
    platform_name: undef(a.platform_name),
    os_version: undef(a.os_version),
    local_ip_addresses: undef(a.local_ip_addresses),
    discoverer_count: undef(a.discoverer_count),
  }),

  falcon_search_iocs: (i) => ({
    id: undef(i.id),
    type: undef(i.type),
    value: undef(i.value),
    action: undef(i.action),
    severity: undef(i.severity),
    description: trunc(i.description, 200),
    source: undef(i.source),
    platforms: undef(i.platforms),
    created_on: undef(i.created_on),
    expiration: undef(i.expiration),
  }),

  // --- falcon-mcp 0.12.0 native config-surface reads ---
  // The agent reaches these directly (the write paths route to sidecar twins,
  // but the reads have no curated twin). Project to list-level fields and drop
  // the heavy nested blobs. falcon_get_certificate_details intentionally has NO
  // projection — a single certificate record is tiny and sits comfortably under
  // the generic cap, and a wrong-field projection would risk emptying it.
  falcon_search_host_groups: (g) => ({
    id: undef(g.id),
    name: undef(g.name),
    group_type: undef(g.group_type),
    description: trunc(g.description, 200),
    // Only dynamic groups carry an assignment_rule (an FQL string); static
    // groups leave it empty.
    assignment_rule: trunc(g.assignment_rule, 300),
    created_by: undef(g.created_by),
    created_timestamp: undef(g.created_timestamp),
    modified_timestamp: undef(g.modified_timestamp),
  }),

  falcon_search_exclusions: (e) => ({
    id: undef(e.id),
    value: trunc(e.value, 240),
    regexp_value: trunc(e.regexp_value, 240),
    value_hash: undef(e.value_hash),
    excluded_from: undef(e.excluded_from),
    applied_globally: undef(e.applied_globally),
    // groups[] scopes the exclusion to host groups; surface names (id fallback)
    // rather than the full group objects.
    groups: Array.isArray(e.groups)
      ? (e.groups as Array<Record<string, unknown>>).map((g) => g.name ?? g.id).filter(Boolean)
      : undefined,
    created_by: undef(e.created_by),
    created_on: undef(e.created_on),
    last_modified: undef(e.last_modified),
  }),

  falcon_search_policies: (p) => ({
    id: undef(p.id),
    name: undef(p.name),
    platform_name: undef(p.platform_name),
    enabled: undef(p.enabled),
    description: trunc(p.description, 200),
    // groups[] lists the host GROUPS the policy targets (not resolved hosts);
    // surface names (id fallback). The heavy prevention_settings / settings
    // slider blob is dropped — route posture questions to
    // falcon_get_prevention_posture, which summarizes it per slider.
    groups: Array.isArray(p.groups)
      ? (p.groups as Array<Record<string, unknown>>).map((g) => g.name ?? g.id).filter(Boolean)
      : undefined,
    created_timestamp: undef(p.created_timestamp),
    modified_timestamp: undef(p.modified_timestamp),
  }),

  // --- Falcon Intelligence Recon reads (native; the sidecar twins are retired) ---
  // /recon (app/api/recon/route.ts) and the intel dossier call these, and the
  // capability gate probes falcon_search_recon_rules (lib/health.ts).
  // Records can be numerous (limit up to 500) and bulky, so
  // token-bound them rather than leaning on the 12KB generic cap.
  //
  // Field names below were confirmed against a LIVE us-2 tenant dump (2026-06-29)
  // — NOT copied from the sidecar's _project_* maps, which turned out to carry
  // latent drift (they read flat notification fields + user_name/credentials_url
  // that the API actually nests / omits; harmless there only because recon data
  // is sparse in demo tenants). The real shapes:
  //   - rules: flat record; timestamp field is `updated_timestamp` (NOT
  //     `last_updated_timestamp` — that is only a sort key).
  //   - notifications: record is { id, notification: {...}, breach_details },
  //     so every useful field is nested under `notification.*` (rule_* are flat
  //     INSIDE that object; there is no `content`, the substance is
  //     `breach_summary` + item_*).
  //   - exposed records: flat scalars + nested `rule` and `file` objects; the
  //     identity field is `full_name` (not user_name). The projection
  //     deliberately omits the leaked-credential file payload — only exposure
  //     metadata + file.name are surfaced.
  falcon_search_recon_rules: (r) => ({
    id: undef(r.id),
    name: undef(r.name),
    topic: undef(r.topic),
    filter: trunc(r.filter, 300),
    status: undef(r.status),
    priority: undef(r.priority),
    breach_monitoring_enabled: undef(r.breach_monitoring_enabled),
    substring_matching_enabled: undef(r.substring_matching_enabled),
    created_by: undef(r.created_by ?? r.user_name),
    created_timestamp: undef(r.created_timestamp),
    updated_timestamp: undef(r.updated_timestamp),
  }),

  falcon_search_recon_notifications: (n) => {
    // The record nests the notification body; fall back to the top level so a
    // future flattened passthrough still projects.
    const note =
      n.notification && typeof n.notification === "object"
        ? (n.notification as Record<string, unknown>)
        : n;
    return {
      id: undef(n.id ?? note.id),
      status: undef(note.status),
      created_date: undef(note.created_date),
      updated_date: undef(note.updated_date),
      rule_id: undef(note.rule_id),
      rule_name: undef(note.rule_name),
      rule_topic: undef(note.rule_topic),
      rule_priority: undef(note.rule_priority),
      item_type: undef(note.item_type),
      item_date: undef(note.item_date),
      item_site: undef(note.item_site),
      item_author: undef(note.item_author),
      source_category: undef(note.source_category),
      actor_slug: undef(note.actor_slug),
      risk_score_label: undef(note.risk_score_label),
      // breach_summary is the substance of a breach notification (small
      // metadata object); the bulky logs[] / matching-criteria[] are dropped.
      breach_summary: undef(note.breach_summary),
    };
  },

  falcon_search_recon_exposed_data_records: (e) => ({
    id: undef(e.id),
    email: undef(e.email),
    domain: undef(e.domain),
    credentials_domain: undef(e.credentials_domain),
    credential_status: undef(e.credential_status),
    full_name: undef(e.full_name),
    source_category: undef(e.source_category),
    site: undef(e.site),
    exposure_date: undef(e.exposure_date),
    event_date: undef(e.event_date),
    created_date: undef(e.created_date),
    notification_id: undef(e.notification_id),
    // rule + file are nested objects.
    rule_id: undef(get(e, "rule.id")),
    rule_topic: undef(get(e, "rule.topic")),
    file_name: undef(get(e, "file.name")),
  }),

  // --- falcon-mcp 0.17.0 Discover managed-assets read (#537) ---
  // Managed assets are Discover host records (shape confirmed against live
  // Discover), a sibling of falcon_search_unmanaged_assets above. /discover
  // reads the raw rows through lib/discover/native.ts; this projection only
  // bounds the agent path.
  // Discover applications (eyas-mcp ≥ 2d87088 lists them with no filter). A full
  // row is ~3 KB and even fields="compact" is ~600 B, so a 100-row page blew
  // past the generic cap in a live test. Keep identity, type, the suspicious
  // flag, last use and the host name; drop install paths and host detail.
  // Field names confirmed live (compact and full rows; host nested under `host`).
  falcon_search_applications: (r) => ({
    id: undef(r.id),
    name: undef(r.name),
    vendor: undef(r.vendor),
    version: undef(r.version),
    software_type: undef(r.software_type),
    is_suspicious: undef(r.is_suspicious),
    last_used_timestamp: undef(r.last_used_timestamp),
    host_id: undef(get(r, "host.id")),
    hostname: undef(get(r, "host.hostname")),
  }),

  falcon_search_managed_assets: (a) => ({
    id: undef(a.id),
    aid: undef(a.aid),
    hostname: undef(a.hostname),
    entity_type: undef(a.entity_type),
    platform_name: undef(a.platform_name),
    os_version: undef(a.os_version),
    external_ip: undef(a.external_ip),
    first_seen_timestamp: undef(a.first_seen_timestamp),
    last_seen_timestamp: undef(a.last_seen_timestamp),
    discoverer_count: undef(a.discoverer_count),
  }),

  // --- falcon-mcp 0.17.0 Fusion SOAR reads (#543) ---
  // falcon_search_workflow_executions mirrors the sidecar's _project_execution
  // (falcon-extras/workflows.py): a full execution record carries per-step
  // results + trigger payload + internal state that tips the MCP token cap on
  // busy tenants. The KEEP twin extras_workflows_execute owns the WRITE path;
  // this native read auto-exposes and is token-bound here. Workflow scope is
  // granted on our tenants. The other two Fusion reads
  // (falcon_search_workflow_definitions, falcon_get_workflow_execution_results)
  // have shapes the sidecar doesn't confirm → they fall through to the generic
  // 12KB cap rather than risk a field-guess that empties the record (the
  // recon-drift lesson). Same for the AgentWorks / ZTA / Cloud Insights reads:
  // those scopes aren't granted on our tenants (no live shape to confirm), and
  // the generic cap already prevents a token blow-up — add field projections
  // once a granting tenant lets us confirm the shapes.
  falcon_search_workflow_executions: (e) => ({
    id: undef(e.id ?? e.execution_id),
    definition_id: undef(e.definition_id),
    definition_name: undef(e.definition_name ?? e.name),
    status: undef(e.status),
    started_timestamp: undef(e.started_timestamp ?? e.start_timestamp),
    ended_timestamp: undef(e.end_timestamp ?? e.ended_timestamp),
    trigger_source: undef(e.trigger_source ?? get(e, "trigger.source")),
  }),

  // --- falcon-mcp 0.20.0 Data Security read (#576) ---
  // One tool, ten entity_type record shapes (policy, classification,
  // content_pattern, cloud_application, web_location, …), so a field-picking
  // projection would empty some of them. dataSecurityProjection is
  // shape-agnostic instead. falcon_get_data_security_entities is deliberately
  // NOT projected: it's the agent's path to the full record.
  falcon_search_data_security_entities: dataSecurityProjection,

  // --- eyas-mcp Threat Graph reads (#13, formerly sidecar extras_threatgraph_*) ---
  // ran-on returns ~1 KB of raw edge per device (50 devices ≈ 50 KB); the
  // projection keeps the pivot fields (~150 B each). Shape confirmed live (XDR
  // us-2). Summary / edge-types fall through to the generic cap.
  falcon_get_threatgraph_ran_on: threatGraphEdgeProjection,
  falcon_get_threatgraph_edges: threatGraphEdgeProjection,

  // --- eyas-mcp NGSIEM listings (#13, formerly sidecar extras_ngsiem_list_*) ---
  // Shapes confirmed live (XDR us-2). Connections: drop the per-connection HEC
  // ingest_url (long, and not something the agent should be repeating).
  // Parsers: ~750 B raw each (465 on XDR = 346 KB) — keep identity, type,
  // vendor/product and update status. Lookup files are bare name strings and
  // fall through to the generic cap.
  falcon_list_ngsiem_data_connections: (c) => ({
    id: undef(c.id),
    name: trunc(c.name, 120),
    vendor: undef(c.vendor_name),
    product: undef(c.vendor_product_name),
    parser_name: undef(c.parser_name),
    status: undef(c.status),
    source_type: undef(c.source_type),
    last_ingested_volume_one_day: undef(c.last_ingested_volume_one_day),
  }),
  // --- eyas-mcp hunting guides / workflow triggers (#13, formerly sidecar) ---
  // Shapes confirmed live (XDR us-2). A single guide carries its whole query
  // list (561 refs ≈ 118 KB) and full MITRE objects (≈ 47 KB) — 5 guides were
  // 718 KB raw. Keep the descriptive fields, a query COUNT, and technique ids;
  // the queries themselves are one falcon_get_hunting_guides /
  // falcon_search_hunting_queries call away. Hunting queries are small and
  // fall through to the generic cap.
  falcon_search_hunting_guides: (g) => ({
    id: undef(g.id),
    name: undef(g.name),
    description: trunc(g.ai_short_description ?? g.description, 300),
    category: undef(g.category),
    adversaries: pickList(g.adversaries, "name", 10),
    malware_families: pickList(g.malware_families, "name", 10),
    mitre_techniques: pickList(g.mitre, "technique_id", 15),
    languages: undef(g.languages),
    environments: undef(g.environments),
    hunt_count: undef(g.hunt_count),
    cql_query_count: undef(g.cql_query_count),
    query_count: Array.isArray(g.queries) ? g.queries.length : undefined,
    last_updated_at: undef(g.last_updated_at),
  }),
  // Triggers' `fields` is the full input schema (~2.3 KB each; 50 = 464 KB).
  // The listing only needs to say what each trigger is and which fields it
  // takes; extras_workflows_execute resolves the trigger itself.
  falcon_list_workflow_triggers: (t) => ({
    id: undef(t.id),
    name: undef(t.name),
    category: undef(t.category),
    description: trunc(t.description, 200),
    api_scope: undef(t.api_scope),
    version: undef(t.version),
    fields: pickList(t.fields, "name", 25),
  }),
  // Agent-path budgets sized so 3 reports / 2 actors (the dossier's own
  // limits) fit the 12 KB generic cap; the dossier bundle uses 8000.
  // --- eyas-mcp Identity Protection reads (#13/#15, formerly sidecar) ---
  // Shapes confirmed live (XDR us-2). Policy rules: 178 rules = 1 MB raw —
  // ruleAction (~2.3 KB: grace periods, periodicity) and emailNotification
  // (~1 KB) dominate; keep identity / state / action name / condition count.
  // Risky identities: 15 = 17.8 KB raw; flatten riskFactors and accounts.
  // Sensors / endpoint history / correlation are small (generic cap).
  falcon_search_idp_policy_rules: (r) => ({
    id: undef(r._id ?? r.id),
    name: undef(r.name),
    enabled: undef(r.enabled),
    simulation_mode: undef(r.simulationMode),
    action: undef(get(r, "ruleAction.action")),
    template_id: undef(r.templateId),
    condition_count: Array.isArray(r.ruleConditions) ? r.ruleConditions.length : undefined,
  }),
  falcon_search_risky_identities: (e) => ({
    entity_id: undef(e.entityId),
    name: undef(e.primaryDisplayName),
    secondary_name: undef(e.secondaryDisplayName),
    type: undef(e.type),
    risk_score: undef(e.riskScore),
    risk_severity: undef(e.riskScoreSeverity),
    risk_factors: Array.isArray(e.riskFactors)
      ? (e.riskFactors as Array<Record<string, unknown>>).map((f) => `${f.type}:${f.severity}`)
      : undefined,
    accounts: Array.isArray(e.accounts)
      ? (e.accounts as Array<Record<string, unknown>>)
          .filter((a) => a && a.samAccountName)
          .map((a) => ({ sam: a.samAccountName, domain: a.domain, enabled: a.enabled }))
      : undefined,
  }),
  // --- eyas-mcp Falcon-published RTR script catalog (#14, formerly sidecar) ---
  // 23 scripts = 32 KB raw, mostly the JSON-Schema string per script. Keep
  // what the agent needs to call one: name, platform, description, and the
  // json_input field names (required ones marked with *).
  falcon_list_falcon_scripts: (sc) => {
    let inputs: string[] | undefined;
    try {
      const schema =
        typeof sc.workflow_input_schema === "string" ? JSON.parse(sc.workflow_input_schema) : sc.workflow_input_schema;
      const props = schema && typeof schema === "object" ? (schema.properties ?? {}) : {};
      const required = new Set<string>(Array.isArray(schema?.required) ? schema.required : []);
      inputs = Object.keys(props).map((k) => (required.has(k) ? `${k}*` : k));
    } catch {
      inputs = undefined;
    }
    return {
      name: undef(sc.name),
      platform: undef(sc.platform),
      description: trunc(sc.description, 200),
      json_input: inputs && inputs.length ? inputs : undefined,
    };
  },
  falcon_get_intel_reports: (r) => projectIntelReport(r, 1800),
  falcon_get_intel_actors: (a) => projectIntelActor(a, 1500),
  falcon_list_ngsiem_parsers: (p) => ({
    name: undef(p.Name ?? p.name),
    id: undef(p.ID ?? p.id),
    parser_type: undef(p.parser_type),
    vendor: undef(p.vendor),
    product: undef(p.product),
    update_available: undef(p.update_available),
  }),
};

const GENERIC_CAP_BYTES = 12_000;

function stripUndefined(o: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(o)) {
    if (v !== undefined) out[k] = v;
  }
  return out;
}

function capLength(text: string, max: number): string {
  if (text.length <= max) return text;
  return (
    text.slice(0, max) +
    `\n\n[Truncated: result was ${text.length} chars, capped at ${max}. Refine the query (lower limit, tighter filter) or fetch a specific item via the matching falcon_get_*_details tool.]`
  );
}

// Falcon-published RTR scripts return a wrapper envelope, not a flat list:
// { ok, script_name, results: [{ device_id, result: [...] }] }. The heavy
// weight is in each host's result[] (Process can return 200+ rows; EventLog
// thousands). Cap each host's array to a sane preview and add a [Truncated]
// note so the agent doesn't think it's the full story.
const FALCON_SCRIPT_RESULT_ITEMS_CAP = 50;

function projectFalconScriptRun(rawText: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return capLength(rawText, GENERIC_CAP_BYTES);
  }
  if (!parsed || typeof parsed !== "object") return capLength(rawText, GENERIC_CAP_BYTES);
  const obj = parsed as Record<string, unknown>;
  const results = obj.results;
  if (Array.isArray(results)) {
    // eyas-mcp shape: results[].output = { script, result: [...], cid, aid }.
    obj.results = results.map((r) => {
      if (!r || typeof r !== "object") return r;
      const host = { ...(r as Record<string, unknown>) };
      const output = host.output;
      if (output && typeof output === "object" && !Array.isArray(output)) {
        const { cid: _cid, ...out } = output as Record<string, unknown>;
        const arr = out.result;
        if (Array.isArray(arr) && arr.length > FALCON_SCRIPT_RESULT_ITEMS_CAP) {
          out.result = arr.slice(0, FALCON_SCRIPT_RESULT_ITEMS_CAP);
          out._truncated = `Showed first ${FALCON_SCRIPT_RESULT_ITEMS_CAP} of ${arr.length} items. Re-run with json_input narrowing the query if you need more.`;
        }
        host.output = out;
      }
      return host;
    });
  }
  // Compact encoding: 50 small process / service records pretty-printed blow
  // past the 12 KB cap (≈18 KB); compact they're ≈6 KB.
  return capLength(JSON.stringify(obj), GENERIC_CAP_BYTES);
}

// Native falcon_search_ngsiem (falcon-mcp 0.16.0 #475) echoes the full ~4KB CQL
// authoring guide inline on its EMPTY and ERROR paths — the empty shape is
// { results: [], query_used, cql_guide, hint } with NO `error` key, so
// detectFalconError doesn't strip it and the whole guide reaches the model on
// every empty NGSIEM search. The guide is already reachable via the
// falcon://ngsiem/search/cql-guide resource + the tool docstring, so echoing it
// per-call is pure token waste. Drop cql_guide + hint when present; leave the
// successful-search path (a bare event list) untouched.
function projectNgsiemSearch(rawText: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    // Success returns a list serialized one-block-per-event → concatenated
    // objects, not a single JSON doc; pass through capped.
    return capLength(rawText, GENERIC_CAP_BYTES);
  }
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const obj = parsed as Record<string, unknown>;
    if ("cql_guide" in obj || "hint" in obj) {
      const rest = { ...obj };
      delete rest.cql_guide;
      delete rest.hint;
      return capLength(JSON.stringify(rest, null, 2), GENERIC_CAP_BYTES);
    }
  }
  return capLength(rawText, GENERIC_CAP_BYTES);
}

// falcon_get_prevention_posture returns every ML slider and toggle count per
// policy (~1 KB each), so a tenant with many policies blows past the generic cap and
// the agent sees a handful of policies. Render one line per policy instead,
// keeping the two sliders Eyas treats as protection (sensor ML, cloud AV) plus
// the names of any other detect-only sliders.
const POSTURE_CAP_BYTES = 24_000;
function projectPreventionPosture(rawText: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return capLength(rawText, GENERIC_CAP_BYTES);
  }
  const obj = parsed as { summary?: unknown; policies?: unknown; warning?: unknown };
  if (!obj || typeof obj !== "object" || !Array.isArray(obj.policies)) return capLength(rawText, GENERIC_CAP_BYTES);
  const lv = (s: unknown) => {
    const o = (s ?? {}) as { detection?: unknown; prevention?: unknown };
    return `${String(o.detection ?? "-")}/${String(o.prevention ?? "-")}`;
  };
  const lines = (obj.policies as Array<Record<string, unknown>>).map((p) => {
    const sliders = (p.ml_sliders ?? {}) as Record<string, unknown>;
    const groups = Array.isArray(p.groups) ? p.groups.length : 0;
    const other = (Array.isArray(p.detect_only_sliders) ? (p.detect_only_sliders as string[]) : []).filter(
      (s) => s !== "OnSensorMLSlider" && s !== "CloudAntiMalware",
    );
    const flags = Array.isArray(p.flags) ? (p.flags as string[]).join(",") : "";
    return [
      p.name,
      p.platform,
      p.enabled === false ? "disabled" : "enabled",
      `groups=${groups}`,
      `sensorML=${lv(sliders.OnSensorMLSlider)}`,
      `cloudAV=${lv(sliders.CloudAntiMalware)}`,
      `flags=${flags || "-"}`,
      other.length ? `other_detect_only=${other.join(",")}` : "",
    ]
      .filter(Boolean)
      .join(" | ");
  });
  const header = [
    `summary: ${JSON.stringify(obj.summary ?? {})}`,
    ...(typeof obj.warning === "string" ? [`warning: ${obj.warning}`] : []),
    `${lines.length} policies (name | platform | state | host groups | sensor ML det/prev | cloud AV det/prev | flags | other detect-only sliders):`,
  ];
  return capLength([...header, ...lines].join("\n"), POSTURE_CAP_BYTES);
}

export function projectToolResult(
  toolName: string,
  rawText: string,
  // The bridge already parses rawText once (for detectFalconError); pass that
  // array here to avoid a second parse of the same (potentially large) blob on
  // the hot agent path.
  preParsed?: Record<string, unknown>[],
): string {
  if (!rawText) return "";
  if (toolName === "falcon_run_falcon_script") {
    return projectFalconScriptRun(rawText);
  }
  if (toolName === "falcon_get_prevention_posture") {
    return projectPreventionPosture(rawText);
  }
  if (toolName === "falcon_search_ngsiem") {
    return projectNgsiemSearch(rawText);
  }
  const projection = PROJECTIONS[toolName];
  if (!projection) return capLength(rawText, GENERIC_CAP_BYTES);

  const objects = preParsed ?? parseConcatenatedJson<Record<string, unknown>>(rawText);
  if (objects.length === 0) return capLength(rawText, GENERIC_CAP_BYTES);

  const filter = FILTERS[toolName];
  const filtered = filter ? objects.filter(filter) : objects;
  const droppedCount = objects.length - filtered.length;

  const projected = filtered.map((o) => stripUndefined(projection(o)));
  const body = projected.map((o) => JSON.stringify(o, null, 2)).join("\n");

  const fieldCount = projected[0] ? Object.keys(projected[0]).length : 0;
  const dropNote =
    droppedCount > 0
      ? ` ${droppedCount} noise row(s) dropped (lab/QA "Test Rule" entries).`
      : "";
  // Wording matters: earlier "projected to fit context" + "for full details"
  // reliably caused the model to re-query, treating the note as a truncation
  // signal even though every item was present. The cap-truncation case below
  // gets its own (much harsher) message; this one explicitly states no items
  // were dropped.
  const note = `\n\n[Note: ${filtered.length} item(s) returned in full — none dropped from this set. Each item shows ${fieldCount} curated fields out of the upstream record's full schema.${dropNote} Only call falcon_get_*_details if you need a field that isn't in this projection.]`;
  return capLength(body + note, GENERIC_CAP_BYTES);
}

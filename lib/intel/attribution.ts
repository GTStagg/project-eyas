// Deterministic threat-actor attribution for /intel.
//
// The exposure report used to ask the agent to (1) extract hashes from
// detections, (2) re-attribute via falcon_search_indicators, (3)
// keyword-search falcon_search_actors by malware family. Two structural
// gaps:
//   - hashes only — domains, IPs, URLs from the same detection were
//     dropped, so a beacon to e.g. adobeincorp.com never reached Intel.
//   - relied entirely on Intel's hash-→-actor coverage, which is sparse
//     on this tenant (measured 0/30 on a CVE pivot).
//
// Detections often carry actor/family attribution directly in their
// text fields (display_name / description / behaviors[].description /
// technique). This module surfaces those mentions deterministically and
// joins them against the same Intel lookups, so the agent's job becomes
// synthesis over a pre-attributed bundle rather than re-running
// attribution from scratch.
//
// Pure functions only — no MCP I/O. The route does the I/O and hands
// raw lists to attributeFromDetections().
//
// Per `feedback_deterministic_over_agent_instruction`: agents bias hard
// toward known upstream falcon_* tools and routinely ignore even
// "REQUIRED" instructions for new attribution paths. Doing the join in
// the route is the only reliable way to surface FANCY BEAR / ransomware
// actor activity that Intel hash-coverage misses.

const HEX64 = /\b[a-f0-9]{64}\b/gi;
const HEX40 = /\b[a-f0-9]{40}\b/gi;
const HEX32 = /\b[a-f0-9]{32}\b/gi;
const URL_RX = /https?:\/\/([^\s'"<>|`/]+)(\/[^\s'"<>|`]*)?/gi;
const IPV4_RX = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
// Conservative FQDN — at least one dot, TLD 2+ chars. Filters out file
// extensions like "powershell.exe" by requiring a non-numeric TLD AND
// rejecting the executable suffix list explicitly.
const FQDN_RX = /\b(?=[a-z0-9-]{1,63}\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;
const EXE_SUFFIXES = new Set([
  "exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "msi", "scr", "com",
  "sys", "ocx", "cpl", "lnk", "tmp", "log", "txt", "json", "xml", "ini",
  "config", "dat", "bin", "zip", "rar", "7z", "tar", "gz", "iso", "cab",
  "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "html", "htm",
  "csv", "py", "rb", "sh", "go", "rs", "ts", "tsx", "jsx", "css", "svg",
  "png", "jpg", "jpeg", "gif", "ico", "woff", "woff2",
]);
// FQDNs that are infrastructure noise, not malicious indicators.
const FQDN_DENYLIST = new Set([
  "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
  "office.com", "office365.com", "azure.com", "azureedge.net",
  "google.com", "gstatic.com", "googleapis.com", "youtube.com",
  "apple.com", "icloud.com", "github.com", "githubusercontent.com",
  "amazonaws.com", "cloudfront.net",
  "crowdstrike.com", "cs.falconhoseclient.com",
]);

// Canonical actor name = ALL-CAPS, NO SPACES — matching the form Falcon
// Intel actually returns on indicator records (`actors: ["FANCYBEAR"]`,
// `["PINCHYSPIDER"]`, `["STARDUSTCHOLLIMA"]`). The previous version
// stored canonicals as "FANCY BEAR" / "PINCHY SPIDER" with spaces, which
// caused the join to split a single actor across two buckets when one
// path (text mention) produced the spaced form and another (Intel
// indicator's `actors[]`) produced the no-space form. Use canonicalActor()
// at every storage + lookup boundary.
//
// CS taxonomy: SPIDER (eCrime), BEAR (Russia), PANDA (China),
// CHOLLIMA (DPRK), KITTEN (Iran), JACKAL (hacktivist), CRANE (Vietnam),
// TIGER (India), BUFFALO (Vietnam), LEOPARD (Pakistan).
const ACTOR_ALIASES: Record<string, string> = {
  // Russia
  "fancy bear": "FANCYBEAR",
  "fancybear": "FANCYBEAR",
  "apt28": "FANCYBEAR",
  "sofacy": "FANCYBEAR",
  "sednit": "FANCYBEAR",
  "pawn storm": "FANCYBEAR",
  "strontium": "FANCYBEAR",
  "forest blizzard": "FANCYBEAR",
  "cozy bear": "COZYBEAR",
  "cozybear": "COZYBEAR",
  "apt29": "COZYBEAR",
  "the dukes": "COZYBEAR",
  "nobelium": "COZYBEAR",
  "midnight blizzard": "COZYBEAR",
  "venomous bear": "VENOMOUSBEAR",
  "venomousbear": "VENOMOUSBEAR",
  "turla": "VENOMOUSBEAR",
  "snake": "VENOMOUSBEAR",
  "voodoo bear": "VOODOOBEAR",
  "voodoobear": "VOODOOBEAR",
  "sandworm": "VOODOOBEAR",
  "berserk bear": "BERSERKBEAR",
  "berserkbear": "BERSERKBEAR",
  "energetic bear": "BERSERKBEAR",
  "dragonfly": "BERSERKBEAR",
  "primitive bear": "PRIMITIVEBEAR",
  "primitivebear": "PRIMITIVEBEAR",
  "gamaredon": "PRIMITIVEBEAR",
  // China
  "apt1": "COMMENTPANDA",
  "comment panda": "COMMENTPANDA",
  "commentpanda": "COMMENTPANDA",
  "comment crew": "COMMENTPANDA",
  "apt10": "STONEPANDA",
  "stone panda": "STONEPANDA",
  "stonepanda": "STONEPANDA",
  "mustang panda": "MUSTANGPANDA",
  "mustangpanda": "MUSTANGPANDA",
  "wicked panda": "WICKEDPANDA",
  "wickedpanda": "WICKEDPANDA",
  "apt41": "WICKEDPANDA",
  "barium": "WICKEDPANDA",
  // DPRK
  "lazarus": "LABYRINTHCHOLLIMA",
  "labyrinth chollima": "LABYRINTHCHOLLIMA",
  "labyrinthchollima": "LABYRINTHCHOLLIMA",
  "stardust chollima": "STARDUSTCHOLLIMA",
  "stardustchollima": "STARDUSTCHOLLIMA",
  "hidden cobra": "LABYRINTHCHOLLIMA",
  "andariel": "SILENTCHOLLIMA",
  "silent chollima": "SILENTCHOLLIMA",
  "silentchollima": "SILENTCHOLLIMA",
  // Iran
  "charming kitten": "CHARMINGKITTEN",
  "charmingkitten": "CHARMINGKITTEN",
  "apt35": "CHARMINGKITTEN",
  "phosphorus": "CHARMINGKITTEN",
  "mint sandstorm": "CHARMINGKITTEN",
  "muddywater": "STATICKITTEN",
  "static kitten": "STATICKITTEN",
  "statickitten": "STATICKITTEN",
  // eCrime
  "wizard spider": "WIZARDSPIDER",
  "wizardspider": "WIZARDSPIDER",
  "trickbot": "WIZARDSPIDER",
  "ryuk": "WIZARDSPIDER",
  "conti": "WIZARDSPIDER",
  "pinchy spider": "PINCHYSPIDER",
  "pinchyspider": "PINCHYSPIDER",
  "revil": "PINCHYSPIDER",
  "sodinokibi": "PINCHYSPIDER",
  "carbon spider": "CARBONSPIDER",
  "carbonspider": "CARBONSPIDER",
  "fin7": "CARBONSPIDER",
  "darkside": "CARBONSPIDER",
  "blackmatter": "CARBONSPIDER",
  "alphv": "ALPHASPIDER",
  "blackcat": "ALPHASPIDER",
  "alpha spider": "ALPHASPIDER",
  "alphaspider": "ALPHASPIDER",
  "bitwise spider": "BITWISESPIDER",
  "bitwisespider": "BITWISESPIDER",
  "lockbit": "BITWISESPIDER",
  "scattered spider": "SCATTEREDSPIDER",
  "scatteredspider": "SCATTEREDSPIDER",
  "muddled libra": "SCATTEREDSPIDER",
  "octo tempest": "SCATTEREDSPIDER",
  "indrik spider": "INDRIKSPIDER",
  "indrikspider": "INDRIKSPIDER",
  "evil corp": "INDRIKSPIDER",
  "dridex": "INDRIKSPIDER",
  "bitpaymer": "INDRIKSPIDER",
  "dopplepaymer": "DOPPELSPIDER",
  "doppel spider": "DOPPELSPIDER",
  "doppelspider": "DOPPELSPIDER",
  "graceful spider": "GRACEFULSPIDER",
  "gracefulspider": "GRACEFULSPIDER",
  "cl0p": "GRACEFULSPIDER",
  "clop": "GRACEFULSPIDER",
  "ta505": "GRACEFULSPIDER",
  "vice spider": "VICESPIDER",
  "vicespider": "VICESPIDER",
  "viceroy tiger": "VICEROYTIGER",
  "viceroytiger": "VICEROYTIGER",
};

// Strip whitespace and uppercase. Used at every storage + lookup
// boundary so "FANCY BEAR" / "FancyBear" / "FANCYBEAR" all collapse.
export function canonicalActor(name: string): string {
  return name.replace(/\s+/g, "").toUpperCase();
}

// Pretty-print a canonical actor name with spaces inserted at the SPIDER /
// BEAR / PANDA / CHOLLIMA / KITTEN / TIGER / PANDA / JACKAL / LIBRA /
// TEMPEST / BLIZZARD / SANDSTORM suffix boundary. "FANCYBEAR" → "FANCY BEAR".
// Cosmetic only — internal joins all run on the no-space form.
const SUFFIX_SPLIT_RX = /^(.+?)(BEAR|SPIDER|PANDA|CHOLLIMA|KITTEN|TIGER|JACKAL|CRANE|BUFFALO|LEOPARD)$/;
export function prettyActor(canonical: string): string {
  const m = SUFFIX_SPLIT_RX.exec(canonical);
  if (!m) return canonical;
  return `${m[1]} ${m[2]}`;
}

// Tooling / family names worth surfacing on their own — they don't
// always carry actor attribution but are loud signal in detection
// text. Not in the actor map because they're not actors; they get
// surfaced as `family_mentions` and the agent can include them in the
// "indicators with no actor attribution" section if Intel doesn't tie
// them to one.
const FAMILY_NAMES = [
  "cobalt strike", "metasploit", "meterpreter", "mimikatz", "lazagne",
  "rubeus", "bloodhound", "sharphound", "impacket", "powersploit",
  "empire", "covenant", "sliver", "havoc", "brute ratel", "brc4",
  "mythic", "winnti", "plugx", "shadowpad", "qakbot", "qbot", "emotet",
  "icedid", "bumblebee", "gootloader", "raspberry robin", "wannacry",
  "notpetya", "ryuk", "conti", "lockbit", "blackcat", "alphv", "revil",
  "sodinokibi", "darkside", "blackmatter", "hive", "play", "akira",
  "rhysida", "8base", "cl0p", "clop", "babuk", "maze", "egregor",
  "netwalker", "darkgate", "asyncrat", "njrat", "remcos", "agenttesla",
  "formbook", "lokibot", "snake keylogger", "redline", "raccoon",
  "vidar", "stealc", "lumma", "amadey", "pikabot",
];

export type RawDetection = Record<string, unknown>;
export type RawIndicator = Record<string, unknown>;
export type RawActor = Record<string, unknown>;

export type DetectionExtraction = {
  composite_id: string;
  hostname: string;
  display_name: string;
  technique: string;
  created_timestamp: string;
  hashes: string[]; // sha256 / sha1 / md5
  domains: string[];
  ipv4s: string[];
  actor_mentions: string[]; // canonical CS actor names
  family_mentions: string[]; // canonical malware family names
  // Falcon-native adversary attribution: numeric IDs Falcon Console
  // resolves against the Intel actor catalog. THIS is what Console uses
  // when it labels a detection "FANCY BEAR" — not display_name parsing,
  // not indicator-→-actor lookups. `has_adversary: true` marks any
  // detection where Falcon's own correlation tagged a known adversary;
  // `adversary_ids: ["2139", ...]` resolves via
  // falcon_search_actors(filter: "id:2139") to the canonical name.
  // Surfacing this lifts attribution from "best-effort text mining" to
  // "ground truth from Falcon's own attribution graph."
  adversary_ids: string[];
};

export type AttributionEvidence = {
  detection_id: string;
  host: string;
  indicator_type:
    | "sha256"
    | "sha1"
    | "md5"
    | "domain"
    | "ipv4"
    | "falcon-attribution" // Falcon's own correlation engine tagged the detection's adversary_ids
    | "text-mention" // Ad-hoc actor/alias match in detection text
    | "family-mention";
  indicator_value: string;
  detection_name: string;
  technique?: string;
  first_seen: string; // ISO
  source: "intel-indicator" | "intel-actor" | "detection-text" | "falcon-native";
};

export type AttributedActor = {
  actor: string; // canonical name
  motivation?: string;
  region?: string;
  target_industries?: string[];
  short_description?: string;
  evidence: AttributionEvidence[];
  unique_indicators: number;
  unique_hosts: number;
  // Confidence: how many distinct corroborating signals we have.
  // - high: ≥2 intel-indicator hits OR (intel-actor record + ≥1 indicator)
  // - medium: 1 intel-indicator OR (intel-actor record + text mention)
  // - low: text mention only, no Intel record found
  confidence: "high" | "medium" | "low";
  confidence_reasons: string[];
};

export type UnattributedIndicator = {
  indicator: string;
  type: string;
  malicious_confidence?: string;
  threat_types?: string[];
  malware_families?: string[];
  detection_hits: number;
  hosts: string[];
};

function lower(s: unknown): string {
  return typeof s === "string" ? s.toLowerCase() : "";
}

function asString(v: unknown): string {
  return typeof v === "string" ? v : "";
}

function asArr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}

function dedupLower(arr: string[]): string[] {
  return Array.from(new Set(arr.map((s) => s.trim().toLowerCase()).filter(Boolean)));
}

// Falcon Intel returns list-typed fields (`actors`, `malware_families`,
// `threat_types`, `aliases`) inconsistently: sometimes plain `string[]`,
// sometimes `[{value, slug}]`, sometimes mixed. The first-pass code
// cast everything to `string[]` and then called canonicalActor() on
// each entry, which silently corrupted object entries to "[OBJECT OBJECT]"
// — meaning every FANCYBEAR / WICKEDPANDA / etc. attribution on a tenant
// where Intel returned the object form was lost. Use this helper at
// every Intel-list read site so the join is robust to either shape.
export function readStringList(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  const out: string[] = [];
  for (const item of v) {
    if (typeof item === "string") {
      if (item) out.push(item);
    } else if (item && typeof item === "object") {
      const val = (item as Record<string, unknown>).value;
      if (typeof val === "string" && val) out.push(val);
    }
  }
  return out;
}

function isLikelyExeSuffix(host: string): boolean {
  const tld = host.toLowerCase().split(".").pop() ?? "";
  return EXE_SUFFIXES.has(tld);
}

// Build a single text blob from every detection text surface.
function detectionTextBlob(d: RawDetection): string {
  const parts: string[] = [];
  for (const k of ["display_name", "name", "description", "cmdline", "filepath", "filename", "scenario", "objective", "technique", "pattern_disposition_description"]) {
    const v = d[k];
    if (typeof v === "string") parts.push(v);
  }
  // parent_details.cmdline
  const pd = d.parent_details;
  if (pd && typeof pd === "object") {
    const pc = (pd as Record<string, unknown>).cmdline;
    if (typeof pc === "string") parts.push(pc);
  }
  // behaviors[]
  for (const b of asArr(d.behaviors)) {
    if (b && typeof b === "object") {
      const r = b as Record<string, unknown>;
      for (const k of ["display_name", "description", "cmdline", "ioc_value", "ioc_description", "filename", "filepath", "technique"]) {
        const v = r[k];
        if (typeof v === "string") parts.push(v);
      }
    }
  }
  return parts.join(" \n ");
}

export function extractFromDetection(d: RawDetection): DetectionExtraction {
  const blob = detectionTextBlob(d);
  const lc = blob.toLowerCase();

  // Hashes — direct field plus any embedded in cmdline/description text.
  // Keep the buckets separate so the route can prefer sha256 for indicator
  // lookups (Intel hash coverage is sha256-first).
  const sha256s = new Set<string>();
  const sha1s = new Set<string>();
  const md5s = new Set<string>();
  const sha = asString(d.sha256);
  if (sha) sha256s.add(sha.toLowerCase());
  const md5 = asString(d.md5);
  if (md5) md5s.add(md5.toLowerCase());
  for (const m of blob.matchAll(HEX64)) sha256s.add(m[0].toLowerCase());
  for (const m of blob.matchAll(HEX40)) sha1s.add(m[0].toLowerCase());
  for (const m of blob.matchAll(HEX32)) {
    // HEX32 also matches the first 32 chars of any HEX64 — exclude those.
    const v = m[0].toLowerCase();
    let inSha = false;
    for (const s of sha256s) {
      if (s.startsWith(v)) {
        inSha = true;
        break;
      }
    }
    if (!inSha) md5s.add(v);
  }
  const hashes = [...sha256s, ...sha1s, ...md5s];

  // Domains — from URLs and bare FQDNs in text, minus exe-suffix false
  // positives (powershell.exe → "powershell.exe" matches FQDN_RX without
  // the suffix denylist) and infrastructure noise.
  const domains = new Set<string>();
  for (const m of blob.matchAll(URL_RX)) {
    const host = m[1].toLowerCase();
    if (!isLikelyExeSuffix(host) && !FQDN_DENYLIST.has(host) && !isInfraSuffix(host)) {
      domains.add(host);
    }
  }
  for (const m of blob.matchAll(FQDN_RX)) {
    const host = m[0].toLowerCase();
    if (isLikelyExeSuffix(host)) continue;
    if (FQDN_DENYLIST.has(host) || isInfraSuffix(host)) continue;
    domains.add(host);
  }

  // IPv4 — drop obvious-private and link-local.
  const ipv4s = new Set<string>();
  for (const m of blob.matchAll(IPV4_RX)) {
    const ip = m[0];
    if (isPrivateIpv4(ip)) continue;
    ipv4s.add(ip);
  }

  // Actor / family text mentions. Stored canonical (no-space all-caps).
  const actorMentions = new Set<string>();
  for (const [alias, canonical] of Object.entries(ACTOR_ALIASES)) {
    // Word-boundary match on the alias. `apt28` is fine as substring;
    // `lazarus` should not match `lazarussolution.com` — require a
    // non-letter on either side.
    const rx = new RegExp(`(^|[^a-z0-9])${escapeRx(alias)}([^a-z0-9]|$)`, "i");
    if (rx.test(lc)) actorMentions.add(canonical);
  }

  const familyMentions = new Set<string>();
  for (const fam of FAMILY_NAMES) {
    const rx = new RegExp(`(^|[^a-z0-9])${escapeRx(fam)}([^a-z0-9]|$)`, "i");
    if (rx.test(lc)) familyMentions.add(fam);
  }

  // Falcon-native adversary attribution. Array of stringified numeric
  // IDs; coerce numbers to strings for consistent map keys downstream.
  const advIds: string[] = [];
  if (d.has_adversary === true) {
    const raw = d.adversary_ids;
    if (Array.isArray(raw)) {
      for (const id of raw) {
        if (typeof id === "string" && id) advIds.push(id);
        else if (typeof id === "number" && Number.isFinite(id)) advIds.push(String(id));
      }
    }
  }

  return {
    composite_id: asString(d.composite_id) || asString(d.id),
    hostname: asString((d.device as Record<string, unknown> | undefined)?.hostname) || "",
    display_name: asString(d.display_name) || asString(d.name),
    technique: asString(d.technique),
    created_timestamp: asString(d.created_timestamp),
    hashes: dedupLower(hashes),
    domains: dedupLower([...domains]),
    ipv4s: Array.from(ipv4s),
    actor_mentions: [...actorMentions],
    family_mentions: [...familyMentions],
    adversary_ids: advIds,
  };
}

function escapeRx(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Render-side truncation. Full sha256/sha1/md5 strings in a markdown
// table are unreadable — operator skims the column and the row blows
// out the table width. Keep enough leading hex (8 chars) for visual
// uniqueness within the report; the full value lives in the underlying
// detection record. Other indicator types pass through untouched.
function truncateForDisplay(value: string, type: string): string {
  if (type === "sha256" || type === "sha1" || type === "md5") {
    if (value.length > 12) return `${value.slice(0, 8)}…${value.slice(-4)}`;
  }
  return value;
}

function isInfraSuffix(host: string): boolean {
  // Cheap second-level filter: anything ending in well-known cloud
  // provider zones we already listed in DENYLIST as base domains.
  for (const d of FQDN_DENYLIST) {
    if (host === d || host.endsWith("." + d)) return true;
  }
  return false;
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map((x) => Number(x));
  if (parts.length !== 4) return true;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 0) return true;
  if (a >= 224) return true; // multicast / reserved
  return false;
}

// Joins extractions with Intel responses (indicators by value, actors
// by canonical name) into an attributed-actor list.
//
// indicatorByValue: lowercase value → indicator record (whatever Intel
// returned — we read `actors`, `malware_families`, `malicious_confidence`).
// actorByName: lowercase canonical name → actor record (we read
// `name`, `motivation`, `origins`/`region`, `target_industries`,
// `short_description` / `description`).
export function attributeFromDetections(
  detections: RawDetection[],
  indicatorByValue: Map<string, RawIndicator>,
  actorByName: Map<string, RawActor>,
  // Falcon-native adversary attribution: numeric ID → resolved actor
  // record (from falcon_search_actors with filter: "id:<n>"). Keyed by
  // the same string the detection's adversary_ids[] uses.
  adversaryById: Map<string, RawActor> = new Map(),
): { actors: AttributedActor[]; unattributed: UnattributedIndicator[] } {
  const extractions = detections.map(extractFromDetection);

  // actor canonical → evidence list
  const byActor = new Map<string, AttributionEvidence[]>();
  // indicators that Intel knows about but didn't tie to an actor
  const unattribMap = new Map<string, UnattributedIndicator>();

  const pushEvidence = (actor: string, ev: AttributionEvidence) => {
    if (!byActor.has(actor)) byActor.set(actor, []);
    byActor.get(actor)!.push(ev);
  };

  for (const ex of extractions) {
    if (!ex.composite_id) continue;
    const baseEv = {
      detection_id: ex.composite_id,
      host: ex.hostname,
      detection_name: ex.display_name,
      technique: ex.technique || undefined,
      first_seen: ex.created_timestamp,
    };

    // Path 0: Falcon-native adversary attribution. This is the highest-
    // fidelity path — Falcon's own correlation engine has tagged the
    // detection with one or more adversary IDs (the same IDs the Console
    // uses to render "FANCY BEAR" / "PANDA" labels). When this is set,
    // we don't need indicator hits or text mentions to attribute.
    for (const advId of ex.adversary_ids) {
      const actorRec = adversaryById.get(advId);
      const actorName = actorRec ? asString(actorRec.name) : "";
      if (!actorName) continue; // unresolved id — skip rather than push a numeric placeholder
      const canon = canonicalActor(actorName);
      // Make sure profile lookups in the second pass can find this
      // actor. The Path 0 record is the most authoritative profile we
      // have for it.
      if (!actorByName.has(canon)) actorByName.set(canon, actorRec!);
      pushEvidence(canon, {
        ...baseEv,
        indicator_type: "falcon-attribution",
        indicator_value: actorName,
        source: "falcon-native",
      });
    }

    // Path A: indicator-based attribution. Walk every extracted IOC,
    // look it up in Intel; if Intel has actors, attribute to each.
    const iocs: { value: string; type: AttributionEvidence["indicator_type"] }[] = [];
    for (const h of ex.hashes) {
      const t: AttributionEvidence["indicator_type"] =
        h.length === 64 ? "sha256" : h.length === 40 ? "sha1" : "md5";
      iocs.push({ value: h, type: t });
    }
    for (const dom of ex.domains) iocs.push({ value: dom, type: "domain" });
    for (const ip of ex.ipv4s) iocs.push({ value: ip, type: "ipv4" });

    for (const ioc of iocs) {
      const ind = indicatorByValue.get(ioc.value);
      if (!ind) continue;
      const intelActors = readStringList(ind.actors);
      const fams = readStringList(ind.malware_families);
      if (intelActors.length > 0) {
        for (const a of intelActors) {
          pushEvidence(canonicalActor(a), {
            ...baseEv,
            indicator_type: ioc.type,
            indicator_value: truncateForDisplay(ioc.value, ioc.type),
            source: "intel-indicator",
          });
        }
      } else {
        // Intel knows the IOC but no actor — record as unattributed.
        const key = ioc.value;
        if (!unattribMap.has(key)) {
          const tt = readStringList(ind.threat_types);
          unattribMap.set(key, {
            indicator: truncateForDisplay(ioc.value, ioc.type),
            type: ioc.type,
            malicious_confidence: asString(ind.malicious_confidence) || undefined,
            threat_types: tt.length > 0 ? tt : undefined,
            malware_families: fams.length > 0 ? fams : undefined,
            detection_hits: 0,
            hosts: [],
          });
        }
        const u = unattribMap.get(key)!;
        u.detection_hits += 1;
        if (ex.hostname && !u.hosts.includes(ex.hostname)) u.hosts.push(ex.hostname);
      }
    }

    // Path B: detection-text actor mentions. These attribute the
    // detection directly, regardless of Intel coverage. Use the actor
    // record from actorByName if we have one for the profile; the
    // mention itself is evidence even when Intel returns nothing.
    for (const actor of ex.actor_mentions) {
      const canon = canonicalActor(actor);
      pushEvidence(canon, {
        ...baseEv,
        indicator_type: "text-mention",
        indicator_value: prettyActor(canon),
        source: actorByName.has(canon) ? "intel-actor" : "detection-text",
      });
    }

    // Path C: family-mention with no actor — only surface as
    // unattributed. The agent already knows REvil is associated with
    // PINCHY SPIDER if Intel returned a profile via family-name search;
    // the route handles that lookup and adds the actor record to
    // actorByName, in which case Path B already covered it.
    for (const fam of ex.family_mentions) {
      const key = `family:${fam}`;
      if (!unattribMap.has(key)) {
        unattribMap.set(key, {
          indicator: fam,
          type: "family-mention",
          detection_hits: 0,
          hosts: [],
        });
      }
      const u = unattribMap.get(key)!;
      u.detection_hits += 1;
      if (ex.hostname && !u.hosts.includes(ex.hostname)) u.hosts.push(ex.hostname);
    }
  }

  // Build a quick lookup so the confidence scoring can tell Path 0
  // (Falcon-native adversary attribution from adversary_ids) apart from
  // ad-hoc text-mention attribution that happens to land on an actor
  // we have a profile for. Both surface as `source: "intel-actor"`
  // today; this set marks the canonical actors that came out of an
  // adversary-id resolution and therefore deserve `high` confidence.
  const falconNativeActors = new Set<string>();
  for (const rec of adversaryById.values()) {
    const n = asString(rec.name);
    if (n) falconNativeActors.add(canonicalActor(n));
  }

  const attributed: AttributedActor[] = [];
  for (const [actor, evList] of byActor) {
    const profile = actorByName.get(actor); // actor is already canonical
    const intelHits = evList.filter((e) => e.source === "intel-indicator").length;
    const textHits = evList.filter((e) => e.source === "detection-text" || e.source === "intel-actor").length;
    const nativeHits = evList.filter((e) => e.source === "falcon-native").length;
    const falconNative = falconNativeActors.has(actor) || nativeHits > 0;
    const uniqIndicators = new Set(evList.map((e) => `${e.indicator_type}:${e.indicator_value}`)).size;
    const uniqHosts = new Set(evList.map((e) => e.host).filter(Boolean)).size;

    let confidence: AttributedActor["confidence"];
    const reasons: string[] = [];
    if (falconNative) {
      // Falcon's own correlation engine attributed at least one
      // detection on this actor. That's ground truth — same signal the
      // Console uses to render the actor label.
      confidence = "high";
      reasons.push(`Falcon-native adversary attribution on ${nativeHits} detection(s)`);
      if (intelHits > 0) reasons.push(`${intelHits} corroborating Intel indicator hit(s)`);
    } else if (intelHits >= 2) {
      confidence = "high";
      reasons.push(`${intelHits} Falcon Intel indicator hits`);
    } else if (intelHits >= 1 && profile) {
      confidence = "high";
      reasons.push("Intel indicator hit + actor profile available");
    } else if (intelHits >= 1) {
      confidence = "medium";
      reasons.push("1 Falcon Intel indicator hit");
    } else if (profile && textHits >= 1) {
      confidence = "medium";
      reasons.push(`${textHits} detection text mention(s) + Intel actor profile`);
    } else {
      confidence = "low";
      reasons.push(`${textHits} detection text mention(s); no Intel record`);
    }
    if (uniqHosts >= 2) reasons.push(`${uniqHosts} hosts affected`);

    attributed.push({
      actor: prettyActor(actor),
      motivation: profile ? extractActorField(profile, "motivations") : undefined,
      region: profile ? extractActorField(profile, "origins") : undefined,
      target_industries: profile ? extractActorListField(profile, "target_industries") : undefined,
      short_description: profile
        ? asString(profile.short_description) || asString(profile.description).slice(0, 300) || undefined
        : undefined,
      evidence: evList,
      unique_indicators: uniqIndicators,
      unique_hosts: uniqHosts,
      confidence,
      confidence_reasons: reasons,
    });
  }

  // Sort: high confidence + most evidence first.
  const conf = (c: AttributedActor["confidence"]): number =>
    c === "high" ? 0 : c === "medium" ? 1 : 2;
  attributed.sort((a, b) => {
    if (conf(a.confidence) !== conf(b.confidence)) return conf(a.confidence) - conf(b.confidence);
    if (b.evidence.length !== a.evidence.length) return b.evidence.length - a.evidence.length;
    return b.unique_hosts - a.unique_hosts;
  });

  const unattributed = [...unattribMap.values()]
    .filter((u) => u.detection_hits > 0 || u.type !== "family-mention")
    .sort((a, b) => b.detection_hits - a.detection_hits);

  return { actors: attributed, unattributed };
}

// Falcon actor records nest values as either plain strings, arrays of
// {value, slug} objects, or arrays of strings depending on the field.
// Be lenient.
function extractActorField(profile: RawActor, key: string): string | undefined {
  const v = profile[key];
  if (typeof v === "string") return v;
  if (Array.isArray(v)) {
    const names: string[] = [];
    for (const item of v) {
      if (typeof item === "string") names.push(item);
      else if (item && typeof item === "object") {
        const val = (item as Record<string, unknown>).value;
        if (typeof val === "string") names.push(val);
      }
    }
    return names.length > 0 ? names.join(", ") : undefined;
  }
  return undefined;
}

function extractActorListField(profile: RawActor, key: string): string[] | undefined {
  const v = profile[key];
  if (!Array.isArray(v)) return undefined;
  const names: string[] = [];
  for (const item of v) {
    if (typeof item === "string") names.push(item);
    else if (item && typeof item === "object") {
      const val = (item as Record<string, unknown>).value;
      if (typeof val === "string") names.push(val);
    }
  }
  return names.length > 0 ? names : undefined;
}

// Exported so tests / route can dedupe across detections before firing
// Intel queries.
export function uniqueIndicatorsForLookup(
  extractions: DetectionExtraction[],
  caps: { hashes: number; domains: number; ipv4s: number },
): { hashes: string[]; domains: string[]; ipv4s: string[]; actor_mentions: string[]; family_mentions: string[] } {
  const hashes = new Set<string>();
  const domains = new Set<string>();
  const ipv4s = new Set<string>();
  const actors = new Set<string>();
  const families = new Set<string>();
  for (const e of extractions) {
    for (const h of e.hashes) if (hashes.size < caps.hashes) hashes.add(h);
    for (const d of e.domains) if (domains.size < caps.domains) domains.add(d);
    for (const ip of e.ipv4s) if (ipv4s.size < caps.ipv4s) ipv4s.add(ip);
    for (const a of e.actor_mentions) actors.add(a);
    for (const f of e.family_mentions) families.add(f);
  }
  return {
    hashes: [...hashes],
    domains: [...domains],
    ipv4s: [...ipv4s],
    actor_mentions: [...actors],
    family_mentions: [...families],
  };
}

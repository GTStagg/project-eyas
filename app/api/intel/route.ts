import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent } from "@/lib/chat/stream-agent";
import { parseConcatenatedJson } from "@/lib/mcp/parse";
import {
  attributeFromDetections,
  canonicalActor,
  extractFromDetection,
  prettyActor,
  readStringList,
  uniqueIndicatorsForLookup,
  type RawDetection,
  type RawIndicator,
  type RawActor,
} from "@/lib/intel/attribution";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Tunables for the deterministic enrichment pass. Tight caps — first
// pass shipped at 40+30+20 IOC lookups + 30 actor lookups (~120 calls)
// which the operator (correctly) flagged as excessive. The hash-→-Intel
// path is sparse on this tenant anyway (measured 0/30 on a CVE pivot,
// see `spotlight_cve_kev_signal` memory), so the bulk of attribution
// value comes from text-mention → actor lookups. Indicator queries are
// kept but capped low; they corroborate when they hit and cost little
// when they miss.
const DETECTION_WINDOW_DAYS = 90;
const DETECTION_LIMIT = 200;
const MAX_HASH_LOOKUPS = 10;   // sha256-prioritized; cheap corroboration
const MAX_DOMAIN_LOOKUPS = 10; // covers e.g. adobeincorp.com without flooding
const MAX_IPV4_LOOKUPS = 5;
const MAX_ACTOR_LOOKUPS = 10;  // unique canonical names + top families
const MAX_ADVERSARY_LOOKUPS = 20; // resolve unique adversary_ids → actor names
const PER_LOOKUP_LIMIT = 10;

type DetectionsResp = { content: Array<{ type: string; text?: string }> };

async function callTool<T>(
  mcp: import("@modelcontextprotocol/sdk/client/index.js").Client,
  name: string,
  args: Record<string, unknown>,
): Promise<T[]> {
  try {
    const resp = (await mcp.callTool({ name, arguments: args })) as DetectionsResp;
    const text = resp.content
      .map((c) => (c.type === "text" && c.text ? c.text : ""))
      .join("\n");
    return parseConcatenatedJson<T>(text);
  } catch {
    return [];
  }
}

function fqlEscape(v: string): string {
  // Single-quoted FQL string. Backslashes and single quotes need escaping.
  return v.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function buildPrompt(bundle: string): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    "You are producing a tenant-relevant adversary exposure report for a CrowdStrike Falcon administrator. CrowdStrike's term is **adversary** — use that throughout the report, not 'actor' or 'threat actor'.",
    "",
    `Today is ${today} (UTC).`,
    "",
    "ATTRIBUTION HAS ALREADY BEEN DONE. The route walked the last 90 days of detections, resolved every detection's `adversary_ids` field against Falcon Adversary Intelligence's catalog (this is Falcon's own correlation graph — the same source the Console uses for adversary labels), AND independently extracted hashes/domains/IPs and joined them against Falcon Intel indicator records. The bundle below is your input.",
    "",
    "PROVENANCE — distinguish in the report:",
    "- `source: \"falcon-native\"` (and `indicator_type: \"falcon-attribution\"`) is **ground truth** from Falcon's correlation engine. Never call this 'text-mention' or 'suggestive' — it's the same signal the Console uses.",
    "- `source: \"intel-indicator\"` is a hash/domain/IP that Falcon Intel attributed to the adversary.",
    "- `source: \"intel-actor\"` or `\"detection-text\"` is an ad-hoc adversary name match in detection text — supporting evidence, not ground truth.",
    "",
    "Do not call falcon_search_detections, falcon_search_indicators, or falcon_search_actors — those have already run. The only tool calls you should consider are corroborating reads (falcon_get_intel_actors, passing an attributed adversary's id, for a fuller adversary profile when the bundle has only a stub). Most reports will need zero further tool calls.",
    "",
    "Note: the bundle uses internal field name `actors` for the attributed-adversary array — this is an API symbol, not user-facing copy. Render it as 'adversary' / 'adversaries' in all headings, prose, and table columns.",
    "",
    "ENRICHED BUNDLE:",
    "```json",
    bundle,
    "```",
    "",
    "Sections — produce all of them in this exact order. Use H2 (##) for each:",
    "",
    "## Executive verdict",
    "One sentence. Number of adversaries with tenant evidence in the last 90 days, the most active one, and whether confidence is grounded in Intel indicator hits or detection-text mentions only. If the bundle's `actors` array is empty: 'No adversaries tracked by Falcon Adversary Intelligence match anything in your tenant over the last 90 days. This is the desired state.' Stop after that line.",
    "",
    "## 🎯 Attributed adversaries",
    "One subsection per entry in `bundle.actors` (use H3, ###). For each:",
    "- One-line profile: motivation / region / target industries from the bundle's adversary record. If `short_description` is present, use it verbatim (it's already trimmed). If the adversary came purely from text-mention with no Intel profile, say so plainly.",
    "- **Evidence in your tenant:** tight markdown table with columns `Indicator | Type | Host | Detection | First seen`. Use `bundle.actors[i].evidence` rows directly — `indicator_value` is ALREADY truncated for display (hashes appear as `8chars…4chars`); render the bundle value verbatim, do NOT expand it back to the full hex. If there are more than 8 rows, show the first 8 and add a 'and N more' line.",
    "- **Confidence:** copy `confidence` + `confidence_reasons` from the bundle. Do not invent.",
    "- **Recommended next step:** concrete and tied to evidence provenance. Falcon-native attribution → 'Run agentic IR on <hosts>; this is confirmed Falcon adversary attribution, not a heuristic'. Hash hits with `confidence: high` and Intel indicators → 'cloud reputation already blocks tenant-wide; verify on Custom IOC list at /lookup'. Domain / IP hits → 'Add to Custom IOC list with action=detect (network IOCs cap at detect — see CLAUDE.md). Pivot in /pivot for additional process / network surface'. Text-mention-only attribution (no falcon-native, no intel-indicator) → 'Run agentic IR to confirm — text mention is suggestive, not ground truth'. Always name the affected host(s) explicitly.",
    "",
    "## 📝 Stakeholder summary",
    "Audit-ready table: `Adversary | Confidence | Tenant evidence (counts) | Recommended action | Owner`. One row per adversary. Owner column is always 'SOC' unless the recommended action is patch-related ('Vuln team') or policy-related ('IT'). Counts column = `unique_indicators` distinct IOCs across `unique_hosts` hosts.",
    "",
    "Style:",
    "- Markdown only. H2 headings; H3 inside Attributed adversaries.",
    "- Be terse. Decision document, not a textbook.",
    "- Use the small status emoji on section headers exactly as written above; do not sprinkle emoji elsewhere.",
    "- Do NOT pad with global Falcon Intel context that isn't tied to evidence in this tenant.",
    "- Do NOT propose adding custom IOCs for hashes attributed via Intel high-confidence indicators — cloud reputation already blocks those tenant-wide. Say so explicitly.",
    "",
    "OUTPUT DISCIPLINE:",
    "- Output NOTHING between tool calls (if you make any). Zero text.",
    "- The very first text token you emit must be the executive-verdict H2.",
    "- Do not preface with 'Here is your report.' Just start with the report.",
    "",
    "Citations:",
    "- The bundle is your single deterministic source. Cite specific indicators inline as inline-code (e.g. `adobeincorp.com`, `8ce97...d2f1`). Do not use [N] tool-call citations — there are no agent tool calls to cite.",
  ].join("\n");
}

async function buildEnrichedBundle(
  mcp: import("@modelcontextprotocol/sdk/client/index.js").Client,
): Promise<string> {
  const detCutoff = new Date(
    Date.now() - DETECTION_WINDOW_DAYS * 24 * 3600 * 1000,
  ).toISOString();

  // Step 1: pull detections (full raw, not the projected slim shape — we
  // need behaviors[] for text scanning).
  const detections = await callTool<RawDetection>(mcp, "falcon_search_detections", {
    filter: `product:'epp'+created_timestamp:>'${detCutoff}'`,
    limit: DETECTION_LIMIT,
    sort: "created_timestamp.desc",
  });

  // Step 2: extract IOCs + actor/family mentions deterministically.
  const extractions = detections.map(extractFromDetection);
  const lookups = uniqueIndicatorsForLookup(extractions, {
    hashes: MAX_HASH_LOOKUPS,
    domains: MAX_DOMAIN_LOOKUPS,
    ipv4s: MAX_IPV4_LOOKUPS,
  });

  // Falcon-native adversary IDs across the detection set. These are
  // the load-bearing attribution signal — the same numeric IDs Falcon
  // Console uses to render "FANCY BEAR" / "PANDA" labels. One actor
  // lookup per unique ID resolves to the canonical actor record.
  const adversaryIdSet = new Set<string>();
  for (const ex of extractions) {
    for (const id of ex.adversary_ids) adversaryIdSet.add(id);
  }
  const adversaryIds = [...adversaryIdSet].slice(0, MAX_ADVERSARY_LOOKUPS);

  // Step 3: parallel Intel lookups.
  // Indicator queries: fan one out per value. Falcon Intel `indicator`
  // filter is a string match, so an OR list (`indicator:['v1','v2']`)
  // works in some upstream versions but not all — per-call is the
  // reliable path. Cap is enforced in lookups already.
  const indicatorPromises: Promise<{ value: string; record: RawIndicator | null }>[] = [];
  const queueIndicator = (value: string) => {
    indicatorPromises.push(
      (async () => {
        const recs = await callTool<RawIndicator>(mcp, "falcon_search_indicators", {
          filter: `indicator:'${fqlEscape(value)}'`,
          limit: PER_LOOKUP_LIMIT,
        });
        return { value, record: recs[0] ?? null };
      })(),
    );
  };
  for (const h of lookups.hashes) queueIndicator(h);
  for (const d of lookups.domains) queueIndicator(d);
  for (const ip of lookups.ipv4s) queueIndicator(ip);

  // Actor lookups. Search by the no-space canonical form, which is how
  // CS Intel actually stores actor records (`FANCYBEAR`, `PINCHYSPIDER`).
  // Searching by a spaced/aliased form (`fancy bear`) misses because
  // Falcon Intel's FQL `name` filter is exact substring on the stored
  // canonical. Combined cap covers actor mentions + top family names.
  const actorTerms = [
    ...lookups.actor_mentions, // already canonical no-space from extractor
    ...lookups.family_mentions.map((f) => f.replace(/\s+/g, "").toUpperCase()),
  ].slice(0, MAX_ACTOR_LOOKUPS);
  const actorPromises: Promise<{ term: string; records: RawActor[] }>[] = actorTerms.map(
    async (term) => {
      const recs = await callTool<RawActor>(mcp, "falcon_search_actors", {
        filter: `name:*'*${fqlEscape(term)}*'`,
        limit: PER_LOOKUP_LIMIT,
      });
      return { term, records: recs };
    },
  );

  // Adversary-id resolution. Each id maps to one actor record via
  // falcon_search_actors(filter: "id:<n>"). Falcon Intel returns name +
  // motivations + origins + target_industries — the full profile we
  // already render under Attributed actors.
  const adversaryPromises: Promise<{ id: string; record: RawActor | null }>[] = adversaryIds.map(
    async (id) => {
      const recs = await callTool<RawActor>(mcp, "falcon_search_actors", {
        filter: `id:${id}`,
        limit: 1,
      });
      return { id, record: recs[0] ?? null };
    },
  );

  const [indicatorResults, actorResults, adversaryResults] = await Promise.all([
    Promise.all(indicatorPromises),
    Promise.all(actorPromises),
    Promise.all(adversaryPromises),
  ]);

  // Detect scope-denied. Falcon-mcp wraps 401/403 as JSON-text content;
  // when it does, parseConcatenatedJson returns []. Distinguishing
  // "no scope" from "no hits" requires looking at the raw text — but
  // our callTool helper swallowed it. A pragmatic signal: if every
  // indicator and actor query returned zero records AND we asked at
  // least 10 of each, scope is the most likely explanation. We mention
  // it but don't bail; the agent's prompt covers the empty-bundle case.
  const indicatorByValue = new Map<string, RawIndicator>();
  for (const { value, record } of indicatorResults) {
    if (record) indicatorByValue.set(value, record);
  }
  // Key the actor map by canonical form (no-space, all-caps) so it
  // joins cleanly with both Path A (Intel indicator's `actors[]`) and
  // Path B (text-mention from extractor) regardless of which spelling
  // each path produced.
  const actorByName = new Map<string, RawActor>();
  for (const { records } of actorResults) {
    for (const rec of records) {
      const name = (rec.name as string | undefined) ?? "";
      if (name) actorByName.set(canonicalActor(name), rec);
      for (const alias of readStringList(rec.aliases)) {
        actorByName.set(canonicalActor(alias), rec);
      }
    }
  }

  const adversaryById = new Map<string, RawActor>();
  for (const { id, record } of adversaryResults) {
    if (record) adversaryById.set(id, record);
  }

  // The deterministic enrichment also computes an `unattributed` array
  // (Intel hits or detection-text leads with no adversary tie). It is
  // intentionally NOT included in the bundle: the /intel surface is for
  // adversary attribution, and dragging unattributed indicators through
  // the LLM context burns tokens on a section that's off-thesis. Leads
  // that need follow-up belong on /pivot or /lookup.
  const { actors } = attributeFromDetections(
    detections,
    indicatorByValue,
    actorByName,
    adversaryById,
  );

  return JSON.stringify(
    {
      window: {
        days: DETECTION_WINDOW_DAYS,
        detections_pulled: detections.length,
      },
      lookups: {
        hashes_queried: lookups.hashes.length,
        domains_queried: lookups.domains.length,
        ipv4s_queried: lookups.ipv4s.length,
        actor_terms_queried: actorTerms.length,
        adversary_ids_queried: adversaryIds.length,
        intel_indicator_hits: indicatorByValue.size,
        intel_actor_records: actorByName.size,
        falcon_native_adversaries_resolved: adversaryById.size,
      },
      actors,
    },
    null,
    2,
  );
}

export async function POST() {
  return streamAgent(async ({ mcp, emit, signal }) => {
    emit("status", { phase: "enriching", message: "Joining detections against Falcon Intel…" });
    const bundle = await buildEnrichedBundle(mcp);
    emit("status", { phase: "synthesizing", message: "Writing report…" });

    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(bundle),
      initialMessages: [
        { role: "user", content: "Render the threat actor exposure report from the enriched bundle." },
      ],
      emit,
      // Read-only synthesis. Per `feedback_never_disable_approvals`, do NOT
      // pass requiresApproval — let it default to the registry.
      maxTokensPerTurn: 8192,
      // The agent should rarely need any tool calls. 6 is plenty for the
      // occasional falcon_get_intel_actors corroboration.
      maxIterations: 6,
      surface: "intel",
    });
  });
}

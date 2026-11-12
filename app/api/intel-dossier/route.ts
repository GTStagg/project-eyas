import { NextResponse } from "next/server";
import type { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { runAgentLoop } from "@/lib/chat/agent-loop";
import { streamAgent, type Emit } from "@/lib/chat/stream-agent";
import { parseConcatenatedJson, detectFalconError, isScopeDenied } from "@/lib/mcp/parse";
import { projectIntelReport, projectIntelActor } from "@/lib/mcp/projections";
import { reconPreviewArgs, summarizeReconPreview } from "@/lib/recon/preview";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// The deterministic finished-intelligence DOSSIER.
//
// Unlike free-form chat (where the agent *might* reach for the finished-intel
// tools — the tool-name-bias gotcha means it's unreliable), this route fans the
// tools out SERVER-SIDE, every time: search reports + fetch their full bodies,
// search actors (+ any actors the reports attribute) + fetch full profiles, and
// pull the Recon corpus aggregate. The agent then does synthesis ONLY over the
// assembled bundle. Enrichment never depends on the model choosing a tool — the
// deterministic-enrichment + agentic-synthesis pattern (see CLAUDE.md).

// Free-text subject: actor name, campaign, or keyword. Same allowlist as the
// Recon keyword filter, so garbage is rejected before spending calls.
const SUBJECT_RX = /^[A-Za-z0-9 ._%+@:/\-]{1,200}$/;
const MAX_REPORTS = 3; // fetch full bodies for the top few; bounds prompt size
const MAX_ACTORS = 2;
// Per-record body budget for the bundle (report body / actor narrative). The
// native tools return the full ~20 KB report body; 6000 keeps the bundle
// moderate while carrying the substance.
const DOSSIER_BODY_CHARS = 6000;

type Body = { subject?: string };
type ToolContent = { content: Array<{ type: string; text?: string }> };

async function callList<T>(client: Client, name: string, args: Record<string, unknown>): Promise<T[]> {
  try {
    const resp = (await client.callTool({ name, arguments: args })) as ToolContent;
    const text = resp.content.map((c) => (c.type === "text" && c.text ? c.text : "")).join("\n");
    return parseConcatenatedJson<T>(text);
  } catch {
    return [];
  }
}

type RawId = { id?: unknown; name?: unknown };

async function buildDossierBundle(
  mcp: Client,
  emit: Emit,
  subject: string,
): Promise<string> {
  let n = 0;
  // Forward each deterministic call to the UI as a synthetic tool bubble so the
  // operator SEES the reliable fan-out (and it doubles as the trace for the
  // comparison demo). Mirrors the /investigate synthetic-event pattern.
  const trace = (name: string, input: unknown, result: unknown, isErr: boolean, dt: number) => {
    const id = `dossier-${++n}`;
    emit("tool_use", { id, name, input });
    emit("tool_result", {
      tool_use_id: id,
      content: (typeof result === "string" ? result : JSON.stringify(result)).slice(0, 4000),
      is_error: isErr,
      duration_ms: dt,
    });
  };

  // 1. Finished-intel reports → full bodies.
  let t = Date.now();
  const reportHits = await callList<RawId>(mcp, "falcon_search_reports", { q: subject, limit: 5 });
  const reportIds = reportHits.map((r) => String(r.id ?? "")).filter(Boolean).slice(0, MAX_REPORTS);
  trace("falcon_search_reports", { q: subject, limit: 5 }, { hits: reportHits.length, ids: reportIds }, false, Date.now() - t);

  let reports: Record<string, unknown>[] = [];
  if (reportIds.length) {
    t = Date.now();
    const rows = await callList<Record<string, unknown>>(mcp, "falcon_get_intel_reports", { ids: reportIds });
    const err = detectFalconError(rows);
    reports = err ? [] : rows.map((r) => projectIntelReport(r, DOSSIER_BODY_CHARS));
    trace("falcon_get_intel_reports", { ids: reportIds }, err ? { error: err } : { count: reports.length }, Boolean(err), Date.now() - t);
  }

  // 2. Actors — from the subject search AND any actors the reports attribute.
  t = Date.now();
  const actorHits = await callList<RawId>(mcp, "falcon_search_actors", { q: subject, limit: 3 });
  trace("falcon_search_actors", { q: subject, limit: 3 }, { hits: actorHits.length }, false, Date.now() - t);
  const actorIds = new Set<string>();
  for (const a of actorHits) if (a?.id) actorIds.add(String(a.id));
  for (const r of reports) {
    for (const a of ((r.actors as RawId[]) ?? [])) if (a?.id) actorIds.add(String(a.id));
  }
  const actorIdList = [...actorIds].slice(0, MAX_ACTORS);
  let actors: Record<string, unknown>[] = [];
  if (actorIdList.length) {
    t = Date.now();
    const rows = await callList<Record<string, unknown>>(mcp, "falcon_get_intel_actors", { ids: actorIdList });
    const err = detectFalconError(rows);
    actors = err ? [] : rows.map((a) => projectIntelActor(a, DOSSIER_BODY_CHARS));
    trace("falcon_get_intel_actors", { ids: actorIdList }, err ? { error: err } : { count: actors.length }, Boolean(err), Date.now() - t);
  }

  // 3. Recon corpus aggregate (underground footprint). Keyword topic.
  t = Date.now();
  const previewArgs = reconPreviewArgs(subject, "keyword");
  let corpus: ReturnType<typeof summarizeReconPreview> | null = null;
  let corpusScopePending = false;
  let corpusError: string | null = null;
  if (previewArgs) {
    try {
      const resp = (await mcp.callTool({ name: "falcon_preview_recon_rule", arguments: previewArgs })) as ToolContent;
      const text = resp.content.map((c) => (c.type === "text" && c.text ? c.text : "")).join("\n");
      const rows = parseConcatenatedJson<unknown>(text);
      corpusScopePending = isScopeDenied(text);
      corpusError = detectFalconError(rows);
      if (!corpusScopePending && !corpusError) corpus = summarizeReconPreview(rows);
    } catch (e) {
      corpusError = e instanceof Error ? e.message : String(e);
    }
  }
  trace(
    "falcon_preview_recon_rule",
    previewArgs ?? { topic: "SA_CUSTOM" },
    corpus ? { total_hits: corpus.total_hits } : { scope_pending: corpusScopePending, error: corpusError ?? undefined },
    !corpus,
    Date.now() - t,
  );

  return JSON.stringify(
    {
      subject,
      report_search_hits: reportHits.length,
      reports, // projected reports: body (from `description`) + short_description + targeting
      actors, // full actor profiles (description, aliases, capabilities, …)
      corpus: corpus ?? { unavailable: true, scope_pending: corpusScopePending },
    },
    null,
    2,
  );
}

function buildPrompt(subject: string, bundle: string): string {
  const today = new Date().toISOString().slice(0, 10);
  return [
    `You are producing a finished-intelligence DOSSIER on \`${subject}\` for a CrowdStrike Counter Adversary Operations leader. This is an organization / activity summary — lead with who they are and what they do, not raw indicators.`,
    "",
    `Today is ${today} (UTC).`,
    "",
    "THE DATA HAS ALREADY BEEN GATHERED for you, deterministically, and is in the bundle below: the FULL bodies of matching finished-intelligence reports (`reports[]` — the `summary` / `short_description` fields are the published analysis), FULL threat-actor profiles (`actors[]` — `description`, `known_as`, `capabilities`, `objectives`, targeting), and the Recon corpus aggregate (`corpus` — underground mention counts by channel/site). **Do NOT call any tools.** Synthesize from the bundle.",
    "",
    "By default do NOT enumerate technical indicators (hashes, IPs, domains, detection content) — this is an organization-and-activity summary. Describe tradecraft narratively.",
    "",
    "If `reports[]` is empty AND `actors[]` is empty AND `corpus.unavailable` is true (or total_hits is 0): produce only a one-line `## Verdict` stating no finished intelligence or Recon corpus data matches the subject, and stop. If `corpus.unavailable` is true but reports/actors exist, produce the dossier and note under Underground presence that Recon corpus data was not available (scope not granted).",
    "",
    "ENRICHED BUNDLE:",
    "```json",
    bundle,
    "```",
    "",
    "Sections — produce all that have data, in this order, H2 (##):",
    "",
    "## Verdict",
    "One or two sentences: who the subject is, threat characterization (e.g. data-extortion group, state-nexus adversary), whether they are a named/attributed adversary or previously-unknown, and the finished-intelligence basis for the assessment.",
    "",
    "## Who they are",
    "Attribution status, motivation, first observed, and known aliases (`actors[].known_as`, or as stated in the report). If unattributed, say so plainly.",
    "",
    "## Activities & tradecraft",
    "What they do, narratively, from the report `summary` and actor `description` / `capabilities` / `objectives`. Their operating model and methodology at the summary level.",
    "",
    "## Victimology",
    "Target industries, countries, and regions (union of report and actor targeting). A tight table or tight prose. Note whether targeting looks opportunistic or focused, if the source says.",
    "",
    "## Underground presence",
    "From `corpus`: total mentions and the channel breakdown (translate machine labels — criminal_marketplace → 'Criminal marketplaces', chat_medium → 'Chat platforms (Telegram/Discord)', public_repo → 'Public repos (GitHub)', etc.), plus top sites. One sentence interpreting the shape. If `corpus.unavailable`, state Recon corpus data was not available.",
    "",
    "## Assessment & recommended actions",
    "Decisive. Threat level, who should care, and 1-3 concrete recommendations tied to the evidence.",
    "",
    "## Sources",
    "List the finished-intelligence reports used by name + slug (from `reports[]`), and note the Recon corpus keyword scan. This is the provenance — keep it honest to what's in the bundle.",
    "",
    "Style: Markdown, H2 headings, terse and decisive. If a section has no data, omit it (except Verdict). Start the very first token with the `## Verdict` heading — no preamble.",
  ].join("\n");
}

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as Body;
  const subject = (body.subject ?? "").trim();
  if (!subject) {
    return NextResponse.json({ ok: false, error: "subject required" }, { status: 400 });
  }
  if (!SUBJECT_RX.test(subject)) {
    return NextResponse.json(
      { ok: false, error: "subject contains unsupported characters or exceeds 200 chars" },
      { status: 400 },
    );
  }

  return streamAgent(async ({ mcp, emit, signal }) => {
    emit("status", { phase: "enriching", message: "Gathering finished intelligence + Recon corpus…" });
    const bundle = await buildDossierBundle(mcp, emit, subject);
    emit("status", { phase: "synthesizing", message: "Writing dossier…" });

    await runAgentLoop({
      signal,
      mcp,
      systemPrompt: buildPrompt(subject, bundle),
      initialMessages: [
        { role: "user", content: `Produce the finished-intelligence dossier on ${subject} from the enriched bundle.` },
      ],
      emit,
      // Synthesis-only. Per feedback_never_disable_approvals, do NOT pass
      // requiresApproval — let it default to the registry (this surface makes
      // no writes anyway).
      maxTokensPerTurn: 8192,
      maxIterations: 4, // synthesis needs no tool calls; low cap is a backstop
      surface: "intel-dossier",
    });
  });
}

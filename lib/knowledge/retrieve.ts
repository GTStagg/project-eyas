import "server-only";
import { rawDb } from "@/lib/db/client";
import { sanitizeFtsQuery } from "./fts-query";

export { sanitizeFtsQuery };

// Deterministic lexical retrieval over the per-environment knowledge base.
// Runs server-side in the route BEFORE the agent loop (same pattern as the
// other deterministic enrichments — identity_overlap, campaigns, etc.). No
// embeddings, no external vendor, no new network egress: just an FTS5 MATCH
// against knowledge_chunks scoped to the active environment.

export interface KnowledgeHit {
  docId: string;
  title: string;
  body: string;
}

// Relevance floor: drop the weak long tail relative to the best match so an
// incidental single-token hit doesn't get injected into the agent context as
// "authoritative". bm25() in SQLite FTS5 returns negative scores where
// more-negative = stronger; we keep a hit only if its strength is at least
// this fraction of the top hit's strength. Corpus-relative on purpose — an
// absolute bm25 threshold doesn't transfer across knowledge bases of
// different sizes.
const RELEVANCE_FLOOR_RATIO = 0.25;

/**
 * Top-k chunks for `queryText` within environment `envId`, best match first.
 * Returns [] on empty query, no docs, or no match. Never throws on a bad query
 * — a malformed MATCH is swallowed and treated as "no hits".
 */
export function searchKnowledge(
  envId: string,
  queryText: string,
  opts: { k?: number } = {},
): KnowledgeHit[] {
  const k = opts.k ?? 6;
  const match = sanitizeFtsQuery(queryText);
  if (!match) return [];
  try {
    const rows = rawDb()
      .prepare(
        `SELECT doc_id AS docId, title, body, bm25(knowledge_chunks) AS score
           FROM knowledge_chunks
          WHERE env_id = ? AND knowledge_chunks MATCH ?
          ORDER BY bm25(knowledge_chunks) ASC
          LIMIT ?`,
      )
      .all(envId, match, k) as Array<KnowledgeHit & { score: number }>;
    if (rows.length === 0) return [];
    // bm25 is negative; flip to a positive "strength" and keep only hits at
    // least RELEVANCE_FLOOR_RATIO as strong as the best (first) row.
    const strength = (s: number) => -s;
    const floor = strength(rows[0].score) * RELEVANCE_FLOOR_RATIO;
    return rows
      .filter((r) => strength(r.score) >= floor)
      .map(({ docId, title, body }) => ({ docId, title, body }));
  } catch {
    // Defensive: FTS5 raised on the MATCH expression. Treat as no hits rather
    // than failing the whole chat turn.
    return [];
  }
}

/**
 * Render the top hits into a single system context block, or null when the
 * environment has no relevant knowledge. The header instructs the agent to
 * treat these as the organization's own authoritative reference material and to
 * cite the document title when it uses them.
 */
export function buildKnowledgeContext(
  envId: string,
  queryText: string,
  opts: { k?: number } = {},
): string | null {
  const hits = searchKnowledge(envId, queryText, opts);
  if (hits.length === 0) return null;

  const sections = hits.map(
    (h) => `### From: ${h.title}\n${h.body.trim()}`,
  );
  return [
    "# Organization knowledge base",
    "",
    "The passages below come from reference documents this team attached to the",
    "current environment (runbooks, internal process, org-specific context).",
    "Treat them as authoritative for how THIS organization operates, prefer them",
    "over generic assumptions, and cite the source document title when you rely",
    "on one. If they don't cover the question, proceed normally.",
    "",
    sections.join("\n\n"),
  ].join("\n");
}

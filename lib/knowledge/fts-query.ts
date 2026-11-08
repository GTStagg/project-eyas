// Pure FTS5 query sanitizer for knowledge-base retrieval. Kept free of the
// "server-only" guard and any DB import so it unit-tests directly under tsx.
//
// FTS5 MATCH has its own query grammar (AND/OR/NOT/NEAR, `*`, `^`, `:`, `()`,
// `"`...). Feeding raw user text in risks both syntax errors and accidental
// operator semantics. We extract bare word tokens and OR each as a quoted
// literal — injection-safe, and semantically "match any of these terms".

/**
 * Turn free user text into a safe FTS5 MATCH expression, or null when there's
 * nothing searchable (caller then skips retrieval entirely).
 */
export function sanitizeFtsQuery(queryText: string, maxTerms = 24): string | null {
  if (!queryText) return null;
  const seen = new Set<string>();
  const terms: string[] = [];
  for (const raw of queryText.toLowerCase().split(/[^\p{L}\p{N}]+/u)) {
    if (raw.length < 2) continue; // drop single chars + noise
    if (seen.has(raw)) continue;
    seen.add(raw);
    // Escape embedded double-quotes per FTS5 (double them), then quote-wrap so
    // the token is treated as a literal string, never an operator/column ref.
    terms.push(`"${raw.replace(/"/g, '""')}"`);
    if (terms.length >= maxTerms) break;
  }
  if (terms.length === 0) return null;
  return terms.join(" OR ");
}

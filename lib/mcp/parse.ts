import "server-only";

/**
 * Recognize the falcon-mcp error-envelope shape returned when the upstream
 * Falcon API itself errored (e.g. CrowdStrike returns a 500 with a trace
 * id). The MCP-protocol layer reports `isError: false` because its call
 * succeeded — but the JSON payload is `{error, details: {status_code, body}}`
 * rather than data rows. Without this check, parseConcatenatedJson cheerfully
 * returns the error object as if it were one Case/Detection/Host/Vuln and
 * the dashboard renders a single empty row.
 *
 * Only apply this to the falcon-mcp client path. The sidecar (falcon-extras)
 * returns its own structured `{ok:false, error, ...}` payloads — CQL lint
 * failures carry `cql_lint`+`fix`, scope-pending carries staged-build context
 * — and this matcher would collapse them to the bare error string, stripping
 * the context the agent needs. The caller (tool-bridge invoke) is responsible
 * for that gating.
 *
 * Returns a human-readable error string, or null if the payload looks like
 * real data.
 */
export function detectFalconError(parsed: unknown[]): string | null {
  if (parsed.length !== 1) return null;
  const first = parsed[0] as Record<string, unknown> | null | undefined;
  if (!first || typeof first !== "object") return null;
  if (typeof first.error !== "string") return null;
  // A local CQL check failure (falcon_search_ngsiem with check_cql) is not an
  // upstream error: its `cql_lint` issues and corrected `fix` query must reach
  // the agent intact so it can retry, not collapse to the bare message.
  if ("cql_lint" in first) return null;
  const details = first.details as
    | { status_code?: number; body?: { errors?: Array<{ message?: string }> } }
    | undefined;
  const status = details?.status_code;
  const upstreamMsg = details?.body?.errors?.[0]?.message;
  const parts: string[] = [first.error];
  if (typeof status === "number") parts.push(`(upstream HTTP ${status})`);
  if (upstreamMsg) parts.push(`— ${upstreamMsg}`);
  return parts.join(" ");
}

/**
 * Detect a falcon-mcp (or FalconPy-sidecar) scope / permission denial in a
 * tool result's joined text content.
 *
 * Prefer the STRUCTURED signal over prose. falcon-mcp packages a 401/403 as an
 * `{error, details:{status_code}, required_scopes?}` envelope with
 * isError:false (same shape detectFalconError keys on), and for a recognized
 * 403 it also attaches a top-level `required_scopes` list — both stable,
 * machine-readable. The human message is NOT stable: falcon-mcp 0.13.0's own
 * 403 description is "Permission denied. The API credentials don't have the
 * required access." and contains neither "scope not permitted" nor "access
 * denied" — those are raw CrowdStrike body phrasings that only sometimes ride
 * along via the appended "API said: …". The sidecar signals the same condition
 * structurally as `{scope_pending:true}`.
 *
 * Returns true only when a denial is positively identified, so callers keep
 * their fail-open default (treat "not denied" as granted) and a transient blip
 * never hides a surface. The substring fallback is retained and widened so the
 * raw-text path and legacy/appended wording still trip it.
 */
export function isScopeDenied(text: string): boolean {
  if (!text) return false;
  const objIsDenial = (o: unknown, depth = 0): boolean => {
    if (!o || typeof o !== "object") return false;
    const r = o as Record<string, unknown>;
    if (r.scope_pending === true) return true; // sidecar staged-build shape
    const status = (r.details as { status_code?: number } | undefined)?.status_code;
    if (typeof r.error === "string" && (status === 403 || status === 401)) return true;
    if (Array.isArray(r.required_scopes) && r.required_scopes.length > 0) return true;
    // The cases search tool nests its error dict under results[0] (the FQL
    // wrapper), so peek one level in.
    if (depth === 0 && Array.isArray(r.results) && r.results.length > 0) {
      return objIsDenial(r.results[0], depth + 1);
    }
    return false;
  };
  const parsed = parseConcatenatedJson<Record<string, unknown>>(text);
  if (parsed.some((o) => objIsDenial(o))) return true;
  return /scope not permitted|access denied|permission denied|unauthorized|required access/i.test(
    text,
  );
}

/**
 * falcon-mcp 0.15.0 (#470) wrapped every two-step/combined `falcon_search_*`
 * success payload in a pagination envelope — the tool now returns a single
 * object `{ results: [...rows], pagination: {total,offset?,limit?,next}, filter_used? }`
 * instead of a bare list of row objects (base.py::_build_pagination_envelope).
 * Since falcon-mcp registers tools with structured_output=False, FastMCP
 * serializes that dict as ONE TextContent block, so our parsers see a
 * single-element `[envelope]` and every downstream consumer that treats the
 * array as rows misreads it (agent-path projections emit `[{}]`; dashboards
 * render one junk row).
 *
 * Unwrap the envelope back to its `results` rows. The `pagination`-presence
 * guard is the discriminator: only `_build_pagination_envelope` (the success
 * path) emits `pagination`, so this deliberately does NOT fire on the
 * FQL-error shape `{results, fql_guide, hint}` (no `pagination` — isScopeDenied
 * still peeks its results[0]), on the native ngsiem `{results, cql_guide, hint}`
 * shape, or on any sidecar `{ok, results|items}` payload. Returns the rows, or
 * null when `value` is not a search envelope.
 */
export function unwrapSearchEnvelope(value: unknown): unknown[] | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const o = value as Record<string, unknown>;
  const { results, pagination } = o;
  if (
    Array.isArray(results) &&
    pagination != null &&
    typeof pagination === "object" &&
    !Array.isArray(pagination)
  ) {
    return results as unknown[];
  }
  return null;
}

// Replace any pagination-envelope element in a parsed array with its `results`
// rows. Only allocates a new array when an envelope is actually present, so the
// common (already-flat) case stays zero-copy on the hot path.
function flattenSearchEnvelopes<T>(arr: T[]): T[] {
  let out: T[] | null = null;
  for (let i = 0; i < arr.length; i++) {
    const rows = unwrapSearchEnvelope(arr[i]);
    if (rows) {
      if (!out) out = arr.slice(0, i);
      out.push(...(rows as T[]));
    } else if (out) {
      out.push(arr[i]);
    }
  }
  return out ?? arr;
}

/**
 * falcon-mcp tool results return text content as one or more JSON objects
 * separated by newlines (not a JSON array, not strict NDJSON). Convert that
 * into an array of parsed objects. Returns [] if the text is empty or
 * malformed beyond recovery. A search-tool pagination envelope (0.15.0 #470) is
 * unwrapped to its rows — see unwrapSearchEnvelope.
 */
export function parseConcatenatedJson<T = unknown>(text: string): T[] {
  const trimmed = text.trim();
  if (!trimmed) return [];

  // Fast path: wrap "}\n{" boundaries with "},{" and parse as a single array.
  try {
    const wrapped = `[${trimmed.replace(/}\s*\n\s*{/g, "},{")}]`;
    return flattenSearchEnvelopes(JSON.parse(wrapped) as T[]);
  } catch {
    // Fall through to brace-counting parser.
  }

  // Slow path: brace-count, respecting strings + escapes.
  const out: T[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escape = false;
  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed[i];
    if (inString) {
      if (escape) escape = false;
      else if (c === "\\") escape = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (c === "}") {
      depth--;
      if (depth === 0 && start >= 0) {
        try {
          out.push(JSON.parse(trimmed.slice(start, i + 1)) as T);
        } catch {
          // skip malformed object, keep going
        }
        start = -1;
      }
    }
  }
  return flattenSearchEnvelopes(out);
}

/**
 * Parse an MCP tool result's `content` blocks into row objects — the block-aware
 * counterpart to parseConcatenatedJson.
 *
 * The MCP Python SDK (FastMCP) serializes a tool's `list[dict]` return as ONE
 * TextContent block PER row, each block a valid standalone JSON document; a
 * single-object return (the sidecar's `{ok, items}` shape) is one block. So the
 * correct primitive is to JSON.parse each block directly rather than join every
 * block into one string and re-derive the boundaries (which is what a caller
 * does when it feeds parseConcatenatedJson a `content.map().join("\n")` blob).
 * A block that itself carries concatenated objects (older/edge shapes) falls
 * back to the brace-counting parser scoped to just that block, so this is
 * strictly at least as robust as the join-then-split path. Non-text blocks are
 * skipped; a JSON array block is flattened.
 */
export function parseToolResultObjects<T = unknown>(
  content: ReadonlyArray<{ type?: string; text?: string }> | undefined | null,
): T[] {
  if (!Array.isArray(content)) return [];
  const out: T[] = [];
  for (const block of content) {
    if (!block || block.type !== "text" || typeof block.text !== "string") continue;
    const text = block.text.trim();
    if (!text) continue;
    try {
      const v = JSON.parse(text);
      if (Array.isArray(v)) out.push(...(v as T[]));
      else {
        // A 0.15.0 search-tool pagination envelope is one block holding a
        // single {results, pagination} object — unwrap to its rows.
        const rows = unwrapSearchEnvelope(v);
        if (rows) out.push(...(rows as T[]));
        else out.push(v as T);
      }
    } catch {
      out.push(...parseConcatenatedJson<T>(text));
    }
  }
  return out;
}

/**
 * Parse a single-object JSON payload from a sidecar (falcon-extras) tool
 * result, surfacing the REAL failure instead of a generic "non-JSON" string.
 *
 * The extras tools return one JSON object (`{ok, case, ...}`). But when a tool
 * *raises* — e.g. a lazily-imported cluster package isn't present in the bundle
 * (the v0.8.5 flattened-sidecar regression) — FastMCP returns `isError:true`
 * with the exception text (`ModuleNotFoundError: No module named 'ir'`), which
 * isn't JSON. The old call sites collapsed that to a fixed "sidecar returned
 * non-JSON", hiding the actual cause: the /config cards showed "Couldn't read
 * tenant state" and the chat agent hallucinated a falcon-mcp `--modules ir`
 * fix. Echo a truncated slice of the real text so the failure is legible.
 *
 * Prefers `structuredContent` (MCP SDK ≥1.27 returns the object pre-parsed)
 * and falls back to parsing the joined text blocks.
 */
export function parseExtrasObjectResult(result: unknown): Record<string, unknown> {
  const r = (result ?? {}) as {
    content?: ReadonlyArray<{ type?: string; text?: string }>;
    structuredContent?: unknown;
    isError?: boolean;
  };
  const text = Array.isArray(r.content)
    ? r.content
        .map((c) => (c && c.type === "text" && typeof c.text === "string" ? c.text : ""))
        .join("\n")
        .trim()
    : "";

  // A raised tool: isError + the exception string as text. Surface it verbatim
  // (truncated) rather than masking it.
  if (r.isError) {
    const detail = text || "no detail returned";
    return { ok: false, error: `sidecar tool error: ${detail.slice(0, 400)}` };
  }

  if (text) {
    try {
      const v = JSON.parse(text);
      if (v && typeof v === "object" && !Array.isArray(v)) return v as Record<string, unknown>;
    } catch {
      /* fall through to structuredContent / error */
    }
  }

  if (r.structuredContent && typeof r.structuredContent === "object") {
    return r.structuredContent as Record<string, unknown>;
  }

  const detail = text ? `: ${text.slice(0, 400)}` : "";
  return { ok: false, error: `sidecar returned unparseable output${detail}` };
}
